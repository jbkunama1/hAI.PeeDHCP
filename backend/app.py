from flask import Flask, jsonify, request, send_from_directory
from itsdangerous import URLSafeTimedSerializer, BadSignature
from functools import wraps
from werkzeug.exceptions import BadRequest
from pathlib import Path
from collections import Counter
import os, re, json, ipaddress, logging, threading, time, hmac, tempfile, secrets
import requests

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024
logging.basicConfig(level=os.getenv('LOG_LEVEL', 'INFO'))
PIHOLE_URL = os.getenv('PIHOLE_URL', 'http://192.168.178.1').rstrip('/')
PIHOLE_PASSWORD = os.getenv('PIHOLE_PASSWORD', '')
FRONTEND_DIR = os.getenv('FRONTEND_DIR', '/app/frontend')
DATA_DIR = os.getenv('DATA_DIR', '/app/data')
ADMIN_PIN = os.getenv('ADMIN_PIN', '')
TOKEN_MAX_AGE = 12 * 3600
ALLOW_UNAUTHENTICATED_WRITES = os.getenv('ALLOW_UNAUTHENTICATED_WRITES', 'false').lower() == 'true'
REQUIRE_READ_AUTH = os.getenv('REQUIRE_READ_AUTH', 'false').lower() == 'true'
PIHOLE_VERIFY = False if os.getenv('PIHOLE_TLS_INSECURE', 'false').lower() == 'true' else (os.getenv('PIHOLE_CA_BUNDLE') or True)
_session_lock, _hosts_lock, _file_lock, _login_lock = threading.RLock(), threading.RLock(), threading.RLock(), threading.RLock()
_sid, _sid_expires = None, 0
_failures = {}
MAC_RE = re.compile(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$')
HOST_RE = re.compile(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$')
DEFAULTS = {'title':'hAI.PeeDHCP','theme':'dark','accent':'#4f98a3','density':'comfortable','radius':'md','font_scale':100,'mobile_cards':True,'default_view':'overview','refresh_seconds':0,'date_format':'de','confirm_delete':True,'show_mac':True,'show_expires':True,'show_type':True,'hide_unnamed':False,'suggest_start':'','suggest_end':''}
ENUMS = {'theme':{'dark','light','auto'},'density':{'comfortable','compact'},'radius':{'sm','md','lg'},'date_format':{'de','iso','rel'},'default_view':{'overview','all','leases','static','config','log'}}

class Failure(Exception):
    def __init__(self, message, status=400, **details):
        self.message, self.status, self.details = message, status, details

@app.errorhandler(Failure)
def failure_response(e):
    return jsonify(error=e.message, **e.details), e.status

@app.errorhandler(OSError)
def storage_failure(e):
    app.logger.error('Local storage failure: %s', type(e).__name__)
    return jsonify(error='Lokaler Speicherfehler; Daten und Berechtigungen pruefen'), 500

def norm_mac(m):
    m = str(m or '').strip().lower().replace('-', ':')
    return ':'.join(m[i:i+2] for i in range(0,12,2)) if re.fullmatch(r'[0-9a-f]{12}',m) else m

def norm_host(h):
    return str(h or '').strip().lower()

def valid_ip(value):
    try:
        return str(ipaddress.IPv4Address(str(value).strip()))
    except ValueError:
        return None

def body():
    try:
        value = request.get_json(silent=True)
    except BadRequest:
        value = None
    if not isinstance(value, dict):
        raise Failure('JSON-Objekt erforderlich')
    return value

def _path(name):
    Path(DATA_DIR).mkdir(parents=True, exist_ok=True)
    return str(Path(DATA_DIR) / name)

def read_json(name, default):
    with _file_lock:
        try:
            value = json.loads(Path(_path(name)).read_text(encoding='utf-8'))
        except FileNotFoundError:
            return dict(default)
        except (ValueError, UnicodeError):
            raise Failure('Beschaedigte Datendatei: ' + name + '; vor Wiederherstellung sichern', 500)
        if not isinstance(value, dict):
            raise Failure('Ungueltige Datendatei: ' + name, 500)
        if name == 'meta.json' and any(not isinstance(v,dict) or not isinstance(v.get('comment',''),str) for v in value.values()):
            raise Failure('Ungueltige Notizdaten', 500)
        return value

def write_json(name, data):
    with _file_lock:
        target = _path(name)
        fd, tmp = tempfile.mkstemp(dir=DATA_DIR, suffix='.tmp')
        try:
            with os.fdopen(fd,'w',encoding='utf-8') as f:
                json.dump(data,f,ensure_ascii=False,indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp,target)
        finally:
            if os.path.exists(tmp): os.unlink(tmp)

def signing_key():
    configured = os.getenv('SECRET_KEY','')
    if configured:
        if len(configured) < 32 or configured == ADMIN_PIN:
            raise RuntimeError('SECRET_KEY muss mindestens 32 Zeichen lang und unabhaengig von ADMIN_PIN sein')
        return configured
    path = _path('signing_secret.txt')
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        key = Path(path).read_text(encoding='utf-8').strip()
    else:
        key = secrets.token_urlsafe(48)
        with os.fdopen(fd,'w',encoding='utf-8') as f: f.write(key)
    if len(key) < 32: raise RuntimeError('Ungueltiger gespeicherter Signaturschluessel')
    return key

_signer = URLSafeTimedSerializer(signing_key(), salt='admin')

def is_admin():
    if not ADMIN_PIN: return ALLOW_UNAUTHENTICATED_WRITES
    try:
        return _signer.loads(request.headers.get('X-Admin-Token',''), max_age=TOKEN_MAX_AGE) == 'admin'
    except BadSignature:
        return False

def admin_required(fn):
    @wraps(fn)
    def wrapped(*a, **kw):
        if not is_admin(): raise Failure('Admin-Login erforderlich; ADMIN_PIN konfigurieren',401,auth=True)
        return fn(*a, **kw)
    return wrapped

@app.before_request
def read_guard():
    if REQUIRE_READ_AUTH and request.method == 'GET' and request.path.startswith('/api/') and request.path not in ('/api/settings','/api/livez') and not is_admin():
        raise Failure('Admin-Login erforderlich',401,auth=True)
    if request.method in ('POST','PUT','PATCH'):
        body()

def get_sid(force=False):
    global _sid, _sid_expires
    with _session_lock:
        if not force and _sid and time.time() < _sid_expires: return _sid
        try:
            r = requests.post(PIHOLE_URL+'/api/auth', json={'password':PIHOLE_PASSWORD}, timeout=10, verify=PIHOLE_VERIFY)
            r.raise_for_status()
            s = r.json()['session']
            validity = int(s['validity'])
            if s.get('valid') is not True or not isinstance(s.get('sid'),str) or not s['sid'] or validity <= 0: raise ValueError()
            _sid, _sid_expires = s['sid'], time.time()+max(0,validity-min(30,validity/10))
            return _sid
        except (requests.RequestException,ValueError,KeyError,TypeError):
            _sid, _sid_expires = None, 0
            app.logger.warning('Pi-hole authentication failed')
            return None

def ph(method,path,**kwargs):
    for attempt in range(2):
        sid = get_sid(force=attempt == 1)
        if not sid: return None,'Pi-hole-Anmeldung fehlgeschlagen'
        try:
            r = getattr(requests,method)(PIHOLE_URL+'/api'+path,headers={'X-FTL-SID':sid},timeout=10,verify=PIHOLE_VERIFY,**kwargs)
            if r.status_code == 401 and attempt == 0: continue
            if r.status_code >= 400: return None,'Pi-hole HTTP '+str(r.status_code)
            data = r.json() if r.content else {}
            if not isinstance(data,dict): return None,'Unerwartetes Pi-hole-Antwortformat'
            return data,None
        except (requests.RequestException,ValueError):
            return None,'Pi-hole-Verbindungs- oder Antwortfehler'
    return None,'Pi-hole-Anmeldung fehlgeschlagen'

def upstream(method,path,**kwargs):
    data,err = ph(method,path,**kwargs)
    if err: raise Failure(err,502,outcome_unknown=method != 'get')
    return data

def config_part(name):
    data = upstream('get','/config/'+name)
    config = data.get('config')
    if not isinstance(config,dict) or not isinstance(config.get(name),dict): raise Failure('Ungueltige Pi-hole-Konfiguration',502)
    return config[name]

def dhcp_cfg(): return config_part('dhcp')

def read_hosts():
    try:
        hosts = dhcp_cfg().get('hosts')
        if not isinstance(hosts,list) or any(not isinstance(x,str) for x in hosts): raise Failure('Ungueltige hosts-Antwort',502)
        return hosts,None
    except Failure as e: return None,e.message

def write_hosts(hosts):
    _,err = ph('patch','/config',json={'config':{'dhcp':{'hosts':hosts}}})
    if err: return err + '; Schreibstatus unklar, neu laden'
    check,err = read_hosts()
    return err or (None if check == hosts else 'Schreibkontrolle fehlgeschlagen; neu laden, nicht blind wiederholen')

def parse_entry(raw):
    parts = raw.split(',') if isinstance(raw,str) else []
    if len(parts)<2 or not MAC_RE.fullmatch(norm_mac(parts[0])) or not valid_ip(parts[1]): return None
    return {'mac':norm_mac(parts[0]),'ip':valid_ip(parts[1]),'hostname':parts[2].strip() if len(parts)>2 else '', 'extra':parts[3:],'raw':raw}

def parse_hosts(hosts):
    return [{**{k:e[k] for k in ('mac','ip','hostname')},'comment':''} for e in map(parse_entry,hosts) if e]

def build_entry(mac,ip,hostname,extra=()): return ','.join([mac,ip,hostname,*extra]).rstrip(',')

def get_leases():
    data,err = ph('get','/dhcp/leases')
    if err: return None,err
    raw = data.get('leases') if isinstance(data,dict) else None
    if not isinstance(raw,list) or any(not isinstance(x,dict) or not valid_ip(x.get('ip',x.get('address'))) for x in raw): return None,'Ungueltige Lease-Antwort'
    return [{'mac':norm_mac(x.get('hwaddr',x.get('mac'))),'ip':valid_ip(x.get('ip',x.get('address'))),'hostname':x.get('name',x.get('hostname')) if x.get('name',x.get('hostname')) not in ('*',None) else '', 'expires':x.get('expires','')} for x in raw],None

def checked_hosts():
    value,err = read_hosts()
    if err: raise Failure(err,502)
    return value

def checked_leases():
    value,err = get_leases()
    if err: raise Failure(err,502)
    return value

def clean_settings(d):
    if not isinstance(d,dict): raise Failure('settings muss ein Objekt sein')
    out = {}
    for k,v in d.items():
        if k not in DEFAULTS: continue
        if k in ENUMS:
            if not isinstance(v,str) or v not in ENUMS[k]: raise Failure('Ungueltige Einstellung: '+k)
        elif isinstance(DEFAULTS[k],bool):
            if type(v) is not bool: raise Failure('Boolean erforderlich: '+k)
        elif k in ('font_scale','refresh_seconds'):
            try: v = int(v)
            except (ValueError,TypeError,OverflowError): raise Failure('Zahl erforderlich: '+k)
            v = max(85,min(130,v)) if k == 'font_scale' else (0 if v<=0 else max(10,min(3600,v)))
        elif k in ('suggest_start','suggest_end'):
            if v != '' and not valid_ip(v): raise Failure('Ungueltige IP: '+k)
        elif not isinstance(v,str): raise Failure('Text erforderlich: '+k)
        elif k == 'accent' and not re.fullmatch(r'#[0-9a-fA-F]{6}',v): raise Failure('Ungueltige Farbe')
        elif k == 'title': v = v.strip()[:40] or DEFAULTS[k]
        out[k] = v
    return out

def get_settings(): return {**DEFAULTS,**clean_settings(read_json('settings.json',{}))}

def validate(items,hosts,leases):
    if not isinstance(items,list) or len(items)>1000 or any(not isinstance(x,dict) for x in items): return [],['items muss ein Array mit maximal 1000 Objekten sein'],[]
    clean,errors,warnings = [],[],[]
    cfg = dhcp_cfg()
    for x in items:
        mac,ip,host = norm_mac(x.get('mac')),valid_ip(x.get('ip')),norm_host(x.get('hostname'))
        if not MAC_RE.fullmatch(mac) or not ip or (host and not HOST_RE.fullmatch(host)) or ip == cfg.get('router'):
            errors.append('Ungueltige MAC, IP, Hostname oder Gateway-Adresse'); continue
        clean.append({'mac':mac,'ip':ip,'hostname':host})
    for field in ('mac','ip','hostname'):
        if any(n>1 for v,n in Counter(x[field] for x in clean if x[field]).items()): errors.append('Doppelter Wert im Batch: '+field)
    macs = {x['mac'] for x in clean}
    others = [e for e in map(parse_entry,hosts) if e and e['mac'] not in macs]
    for x in clean:
        if any(e['ip']==x['ip'] or (x['hostname'] and norm_host(e['hostname'])==x['hostname']) for e in others): errors.append('IP oder Hostname bereits reserviert')
        if any(l['ip']==x['ip'] and l['mac']!=x['mac'] for l in leases): warnings.append(x['ip']+': aktuell von anderem Client genutzt')
    return clean,errors,warnings

def upsert(items):
    with _hosts_lock:
        hosts,leases = checked_hosts(),checked_leases()
        clean,errors,warnings = validate(items,hosts,leases)
        if errors: raise Failure('; '.join(errors))
        out = list(hosts)
        for x in clean:
            matches = [i for i,h in enumerate(out) if (parse_entry(h) or {}).get('mac') == x['mac']]
            if len(matches)>1 or any(x['mac'] in h.lower() and parse_entry(h) is None for h in out): raise Failure('Mehrdeutiger/erweiterter DHCP-Eintrag; direkt in Pi-hole bearbeiten',409)
            extra = parse_entry(out[matches[0]])['extra'] if matches else []
            entry = build_entry(x['mac'],x['ip'],x['hostname'],extra)
            if matches: out[matches[0]] = entry
            else: out.append(entry)
        err = write_hosts(out)
        if err: raise Failure(err,502,outcome_unknown=True)
        return jsonify(ok=True,saved=len(clean),warnings=warnings)

@app.route('/')
def index(): return send_from_directory(FRONTEND_DIR,'index.html')
@app.route('/api/livez')
def livez(): return jsonify(status='ok')
@app.route('/api/health')
def health():
    _,err = ph('get','/stats/summary')
    return (jsonify(status='pihole_unreachable',error=err),502) if err else jsonify(status='ok',pihole=PIHOLE_URL)
@app.route('/api/settings')
def settings_get(): return jsonify(settings=get_settings(),pin_required=bool(ADMIN_PIN),is_admin=is_admin())
@app.route('/api/settings',methods=['POST'])
@admin_required
def settings_set():
    update = clean_settings(body())
    with _file_lock:
        cur = get_settings(); cur.update(update); write_json('settings.json',cur)
    return jsonify(ok=True,settings=cur)
@app.route('/api/settings/reset',methods=['POST'])
@admin_required
def settings_reset():
    write_json('settings.json',DEFAULTS)
    return jsonify(ok=True,settings=DEFAULTS)
@app.route('/api/admin/login',methods=['POST'])
def admin_login():
    if not ADMIN_PIN:
        if ALLOW_UNAUTHENTICATED_WRITES: return jsonify(ok=True,token='')
        raise Failure('ADMIN_PIN konfigurieren',403)
    now,key = time.monotonic(),request.remote_addr or 'unknown'
    with _login_lock:
        for k in list(_failures):
            _failures[k] = [t for t in _failures[k] if now-t<60]
            if not _failures[k]: del _failures[k]
        if len(_failures.get(key,[]))>=5 or len(_failures)>=4096: raise Failure('Zu viele Anmeldeversuche; spaeter erneut versuchen',429)
        pin = body().get('pin','')
        if not isinstance(pin,str) or not hmac.compare_digest(pin.encode(),ADMIN_PIN.encode()):
            _failures.setdefault(key,[]).append(now); raise Failure('Falsche PIN',403)
        _failures.pop(key,None)
    return jsonify(ok=True,token=_signer.dumps('admin'))
@app.route('/api/leases')
def api_leases(): return jsonify([{**x,'type':'dynamic'} for x in checked_leases()])
@app.route('/api/devices')
@app.route('/api/all_devices')
def all_devices():
    leases,statics,meta = checked_leases(),{x['mac']:x for x in parse_hosts(checked_hosts())},read_json('meta.json',{})
    result,seen = [],set()
    for x in leases:
        st = statics.get(x['mac']); seen.add(x['mac'])
        result.append({**x,'is_static':bool(st),'static_ip':st['ip'] if st else '', 'static_hostname':st['hostname'] if st else '', 'comment':meta.get(x['mac'],{}).get('comment',''),'type':'static+active' if st else 'dynamic'})
    for mac,x in statics.items():
        if mac not in seen: result.append({**x,'expires':'','is_static':True,'static_ip':x['ip'],'static_hostname':x['hostname'],'comment':meta.get(mac,{}).get('comment',''),'type':'static'})
    return jsonify(result)
@app.route('/api/static')
def get_static():
    meta = read_json('meta.json',{})
    return jsonify([{**x,'comment':meta.get(x['mac'],{}).get('comment','')} for x in parse_hosts(checked_hosts())])
def set_comment(mac,comment):
    if not MAC_RE.fullmatch(mac) or not isinstance(comment,str): raise Failure('Ungueltige MAC oder Notiz')
    with _file_lock:
        meta = read_json('meta.json',{}); comment = comment.strip()[:120]
        if comment: meta[mac] = {'comment':comment}
        else: meta.pop(mac,None)
        write_json('meta.json',meta)
@app.route('/api/meta/<mac>',methods=['POST'])
@admin_required
def api_meta(mac):
    set_comment(norm_mac(mac),body().get('comment','')); return jsonify(ok=True)
@app.route('/api/static',methods=['POST'])
@admin_required
def add_static():
    d = body()
    with _file_lock:
        read_json('meta.json',{})
        if 'comment' in d and not isinstance(d['comment'],str): raise Failure('Notiz muss Text sein')
    result = upsert([d])
    if 'comment' in d: set_comment(norm_mac(d.get('mac')),d['comment'])
    return result
@app.route('/api/static/bulk',methods=['POST'])
@admin_required
def bulk_static():
    items = body().get('items')
    if not items: raise Failure('items erforderlich')
    return upsert(items)
@app.route('/api/static/<mac>',methods=['PUT'])
@admin_required
def edit_static(mac):
    d,old = body(),norm_mac(mac)
    new = norm_mac(d.get('new_mac') or old)
    with _hosts_lock, _file_lock:
        hosts,meta = checked_hosts(),read_json('meta.json',{})
        matches = [(i,e) for i,h in enumerate(hosts) if (e:=parse_entry(h)) and e['mac']==old]
        if not matches: raise Failure('Eintrag nicht gefunden',404)
        if len(matches)!=1: raise Failure('Mehrdeutiger Eintrag',409)
        if new!=old and any(new in h.lower() for h in hosts): raise Failure('Neue MAC bereits vorhanden',409)
        if 'comment' in d and not isinstance(d['comment'],str): raise Failure('Notiz muss Text sein')
        clean,errors,warnings = validate([{'mac':new,'ip':d.get('ip'),'hostname':d.get('hostname','')}],[h for i,h in enumerate(hosts) if i!=matches[0][0]],checked_leases())
        if errors: raise Failure('; '.join(errors))
        x = clean[0]; out = list(hosts); out[matches[0][0]] = build_entry(new,x['ip'],x['hostname'],matches[0][1]['extra'])
        err = write_hosts(out)
        if err: raise Failure(err,502,outcome_unknown=True)
        comment = d.get('comment',meta.get(old,{}).get('comment',''))
        if old!=new: meta.pop(old,None)
        if comment.strip(): meta[new] = {'comment':comment.strip()[:120]}
        else: meta.pop(new,None)
        try: write_json('meta.json',meta)
        except OSError: raise Failure('Reservierung gespeichert; Notiz nicht gespeichert',500,partial=True)
    return jsonify(ok=True,saved=1,warnings=warnings)
@app.route('/api/static/<mac>',methods=['DELETE'])
@admin_required
def del_static(mac):
    mac = norm_mac(mac)
    if not MAC_RE.fullmatch(mac): raise Failure('Ungueltige MAC')
    with _hosts_lock:
        hosts = checked_hosts(); out = [h for h in hosts if (parse_entry(h) or {}).get('mac')!=mac]
        if out==hosts: raise Failure('Eintrag nicht gefunden',404)
        err = write_hosts(out)
        if err: raise Failure(err,502,outcome_unknown=True)
    return jsonify(ok=True)

def delete_lease(mac):
    mac = norm_mac(mac)
    if not MAC_RE.fullmatch(mac): raise Failure('Ungueltige MAC')
    matches = [x for x in checked_leases() if x['mac']==mac]
    if not matches: raise Failure('Lease nicht gefunden',404)
    if len(matches)!=1: raise Failure('Mehrere Leases fuer diese MAC; direkt in Pi-hole bearbeiten',409)
    upstream('delete','/dhcp/leases/'+matches[0]['ip'])
    return jsonify(ok=True,msg='Lease zurueckgesetzt; keine sofortige Client-Erneuerung erzwungen')
@app.route('/api/lease/<mac>',methods=['DELETE'])
@admin_required
def del_lease(mac): return delete_lease(mac)
@app.route('/api/lease/renew',methods=['POST'])
@admin_required
def renew_lease(): return delete_lease(body().get('mac'))

@app.route('/api/free_ips')
def free_ips():
    try: count = int(request.args.get('count','10'))
    except (ValueError,OverflowError): raise Failure('count muss eine Zahl sein')
    if not 1<=count<=50: raise Failure('count muss zwischen 1 und 50 liegen')
    cfg,st = dhcp_cfg(),get_settings()
    net = None
    if st['suggest_start'] and st['suggest_end']:
        lo,hi = (int(ipaddress.IPv4Address(st[k])) for k in ('suggest_start','suggest_end'))
    else:
        try:
            if cfg.get('netmask') in (None,'','0.0.0.0'): raise ValueError()
            net = ipaddress.IPv4Network(str(cfg['router'])+'/'+cfg['netmask'],strict=False)
            lo,hi = int(net.network_address)+1,int(net.broadcast_address)-1
        except (ValueError,KeyError): raise Failure('Netmask unbekannt; expliziten Vorschlagsbereich in Admin > Netzwerk setzen')
    if lo>hi or hi-lo>65535: raise Failure('Vorschlagsbereich muss aufsteigend sein und maximal 65536 Adressen enthalten')
    used = {x['ip'] for x in checked_leases()} | {x['ip'] for x in parse_hosts(checked_hosts())} | {cfg.get('router')}
    start,end = valid_ip(cfg.get('start')),valid_ip(cfg.get('end'))
    pool = (int(ipaddress.IPv4Address(start)),int(ipaddress.IPv4Address(end))) if start and end else None
    out = []
    for i in range(lo,hi+1):
        ip = str(ipaddress.IPv4Address(i))
        if ip in used or (net and pool and pool[0]<=i<=pool[1]): continue
        out.append(ip)
        if len(out)==count: break
    return jsonify(out)

@app.route('/api/export')
def export_all():
    with _hosts_lock, _file_lock:
        return jsonify(version=2,hosts=checked_hosts(),meta=read_json('meta.json',{}),settings=get_settings())
@app.route('/api/import',methods=['POST'])
@admin_required
def import_all():
    d = body(); mode = d.get('mode','merge')
    if type(d.get('version',1)) is not int or d.get('version',1) not in (1,2) or mode not in ('merge','replace'): raise Failure('Ungueltige Backup-Version oder Modus')
    hosts = d.get('hosts')
    if not isinstance(hosts,list) or len(hosts)>10000 or any(not isinstance(h,str) or not h or len(h)>1024 or any(c in h for c in '\r\n\x00') for h in hosts): raise Failure('hosts-Array fehlt oder ist ungueltig')
    meta = d.get('meta',{})
    if not isinstance(meta,dict) or any(not MAC_RE.fullmatch(k) or not isinstance(v,dict) or not isinstance(v.get('comment'),str) or len(v['comment'])>120 for k,v in meta.items()): raise Failure('Ungueltige Notizen im Backup')
    settings = clean_settings(d.get('settings',{}))
    with _hosts_lock, _file_lock:
        oldhosts,oldmeta,oldsettings = checked_hosts(),read_json('meta.json',{}),get_settings()
        parsed = [e for e in map(parse_entry,hosts) if e]
        items = [{k:e[k] for k in ('mac','ip','hostname')} for e in parsed]
        incoming = {e['mac'] for e in parsed}
        base = [] if mode=='replace' else [h for h in oldhosts if (parse_entry(h) or {}).get('mac') not in incoming]
        _,errors,warnings = validate(items,base,checked_leases())
        if errors: raise Failure('; '.join(errors))
        out = list(hosts) if mode=='replace' else base+[h for h in hosts if h not in base]
        targetmeta = meta if mode=='replace' else {**oldmeta,**meta}
        targetsettings = {**(DEFAULTS if mode=='replace' else oldsettings),**settings}
        checkpoint = 'restore-'+str(time.time_ns())+'.json'
        write_json(checkpoint,{'version':2,'hosts':oldhosts,'meta':oldmeta,'settings':oldsettings})
        err = write_hosts(out)
        if err: raise Failure(err,502,outcome_unknown=True,checkpoint=checkpoint)
        try:
            write_json('meta.json',targetmeta); write_json('settings.json',targetsettings)
        except OSError: raise Failure('DHCP gespeichert; lokale Wiederherstellung unvollstaendig. Checkpoint verwenden',500,partial=True,checkpoint=checkpoint)
    return jsonify(ok=True,saved=len(items),warnings=warnings,checkpoint=checkpoint)

@app.route('/api/config')
def get_config():
    cfg,dns = dhcp_cfg(),config_part('dns')
    ups = dns.get('upstreams')
    if not isinstance(ups,list) or any(not isinstance(x,str) for x in ups): raise Failure('Ungueltige DNS-Antwort',502)
    return jsonify(DHCP_START=cfg.get('start',''),DHCP_END=cfg.get('end',''),DHCP_ROUTER=cfg.get('router',''),DHCP_LEASETIME=cfg.get('leaseTime',''),PIHOLE_DNS_1=ups[0] if ups else '',PIHOLE_DNS_2=ups[1] if len(ups)>1 else '')
@app.route('/api/config',methods=['POST'])
@admin_required
def save_config():
    d = body(); changes = {}; dhcp = {}
    for key,field in [('DHCP_START','start'),('DHCP_END','end'),('DHCP_ROUTER','router')]:
        if key in d:
            if not valid_ip(d[key]): raise Failure('Ungueltige IPv4-Adresse: '+key)
            dhcp[field] = valid_ip(d[key])
    if 'DHCP_LEASETIME' in d:
        lt = d['DHCP_LEASETIME']
        if not isinstance(lt,str) or not re.fullmatch(r'(?:[1-9][0-9]*[smhdw]?|infinite)',lt): raise Failure('Ungueltige Leasetime')
        dhcp['leaseTime'] = lt
    with _hosts_lock:
        if dhcp:
            cfg = {**dhcp_cfg(),**dhcp}
            start,end,router = (valid_ip(cfg.get(k)) for k in ('start','end','router'))
            if not all((start,end,router)): raise Failure('Vollstaendige DHCP-Konfiguration erforderlich')
            a,z,r = (int(ipaddress.IPv4Address(x)) for x in (start,end,router))
            if a>z or a<=r<=z: raise Failure('Ungueltiger Pool oder Gateway innerhalb des Pools')
            changes['dhcp'] = dhcp
        if any(k in d for k in ('PIHOLE_DNS_1','PIHOLE_DNS_2')):
            current = config_part('dns').get('upstreams',[])
            if not isinstance(current,list): raise Failure('Ungueltige DNS-Konfiguration',502)
            ups = []
            for i,k in enumerate(('PIHOLE_DNS_1','PIHOLE_DNS_2')):
                value = d.get(k,current[i] if i<len(current) else '')
                if not isinstance(value,str) or (value and not re.fullmatch(r'[0-9a-zA-Z.:#\[\]-]+',value)): raise Failure('Ungueltiger DNS-Server')
                if value.strip(): ups.append(value.strip())
            if not ups: raise Failure('Mindestens ein DNS-Upstream erforderlich')
            changes['dns'] = {'upstreams':ups}
        if changes: upstream('patch','/config',json={'config':changes})
    return jsonify(ok=True)
@app.route('/api/log')
def get_log():
    data = upstream('get','/logs/dnsmasq')
    log = data.get('log')
    if not isinstance(log,list) or any(not isinstance(x,dict) or not isinstance(x.get('message'),str) for x in log): raise Failure('Ungueltige dnsmasq-Logantwort',502)
    lines = [str(x.get('timestamp',''))+'  '+x['message'] for x in log if 'DHCP' in x['message']][-200:]
    return jsonify(lines=lines or ['[Keine DHCP-Eintraege; DHCP-Logging in Pi-hole pruefen]'])

if __name__ == '__main__':
    app.run(host='0.0.0.0',port=8080,debug=False)
