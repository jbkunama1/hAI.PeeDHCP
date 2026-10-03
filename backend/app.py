from flask import Flask, jsonify, request, send_from_directory
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from functools import wraps
import os, re, json, ipaddress, logging, threading, time, hmac, tempfile
import requests
from requests.exceptions import RequestException
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

PIHOLE_URL      = os.getenv("PIHOLE_URL", "http://192.168.178.1").rstrip("/")
PIHOLE_PASSWORD = os.getenv("PIHOLE_PASSWORD", "")
FRONTEND_DIR    = os.getenv("FRONTEND_DIR", "/app/frontend")
DATA_DIR        = os.getenv("DATA_DIR", "/app/data")
ADMIN_PIN       = os.getenv("ADMIN_PIN", "")
SECRET_KEY      = os.getenv("SECRET_KEY") or ADMIN_PIN or "hai-peedhcp"
TOKEN_MAX_AGE   = 12 * 3600

_signer       = URLSafeTimedSerializer(SECRET_KEY, salt="admin")
_session_lock = threading.Lock()
_hosts_lock   = threading.RLock()
_file_lock    = threading.RLock()
_sid, _sid_expires = None, 0

# ── Validierung (verhindert u.a. Newline-Injection in dhcp.hosts) ──────────────
MAC_RE  = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def norm_mac(m):
    m = str(m or "").strip().lower().replace("-", ":")
    if re.fullmatch(r"[0-9a-f]{12}", m):
        m = ":".join(m[i:i + 2] for i in range(0, 12, 2))
    return m


def norm_host(h):
    return str(h or "").strip().lower()


def valid_ip(ip):
    try:
        return str(ipaddress.IPv4Address(str(ip).strip()))
    except ValueError:
        return None


# ── Pi-hole Session ──────────────────────────────────────────────────────
def get_sid(force=False):
    global _sid, _sid_expires
    with _session_lock:
        if not force and _sid and time.time() < _sid_expires - 30:
            return _sid
        try:
            r = requests.post(f"{PIHOLE_URL}/api/auth", json={"password": PIHOLE_PASSWORD},
                              timeout=10, verify=False)
            r.raise_for_status()
            s = r.json()["session"]
            _sid, _sid_expires = s["sid"], time.time() + s.get("validity", 1800)
            app.logger.info("PiHole session renewed")
            return _sid
        except Exception as e:
            app.logger.error(f"PiHole login failed: {e}")
            _sid = None
            return None


def ph(method, path, **kwargs):
    for attempt in range(2):
        sid = get_sid(force=attempt == 1)
        if not sid:
            return None, "PiHole login failed"
        try:
            r = getattr(requests, method)(f"{PIHOLE_URL}/api{path}", headers={"X-FTL-SID": sid},
                                          timeout=10, verify=False, **kwargs)
            if r.status_code == 401 and attempt == 0:
                continue
            r.raise_for_status()
            return (r.json() if r.content else {}), None
        except RequestException as e:
            app.logger.error(f"PiHole {method} {path}: {e}")
            return None, str(e)
    return None, "Auth failed after retry"


# ── Lokale Daten (Settings, Notizen) ───────────────────────────────────────
DEFAULTS = {
    "title": "hAI.PeeDHCP", "theme": "dark", "accent": "#4f98a3", "density": "comfortable",
    "radius": "md", "font_scale": 100, "mobile_cards": True, "default_view": "overview",
    "refresh_seconds": 0, "date_format": "de", "confirm_delete": True,
    "show_mac": True, "show_expires": True, "show_type": True, "hide_unnamed": False,
    "suggest_start": "", "suggest_end": "",
}
ENUMS = {"theme": {"dark", "light", "auto"}, "density": {"comfortable", "compact"},
         "radius": {"sm", "md", "lg"}, "date_format": {"de", "iso", "rel"},
         "default_view": {"overview", "all", "leases", "static", "config", "log"}}


def _path(name):
    os.makedirs(DATA_DIR, exist_ok=True)
    return os.path.join(DATA_DIR, name)


def read_json(name, default):
    try:
        with open(_path(name), encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return default


def write_json(name, data):
    with _file_lock:
        fd, tmp = tempfile.mkstemp(dir=DATA_DIR, suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, _path(name))


def clean_settings(d):
    out = {}
    for k, default in DEFAULTS.items():
        if k not in d:
            continue
        v = d[k]
        if k in ENUMS:
            if v in ENUMS[k]: out[k] = v
        elif k == "accent":
            if isinstance(v, str) and re.fullmatch(r"#[0-9a-fA-F]{6}", v): out[k] = v
        elif k == "font_scale":
            try: out[k] = max(85, min(130, int(v)))
            except (TypeError, ValueError): pass
        elif k == "refresh_seconds":
            try: out[k] = 0 if int(v) <= 0 else max(10, min(3600, int(v)))
            except (TypeError, ValueError): pass
        elif k in ("suggest_start", "suggest_end"):
            out[k] = valid_ip(v) or ""
        elif isinstance(default, bool):
            out[k] = bool(v)
        elif k == "title":
            out[k] = str(v).strip()[:40] or DEFAULTS["title"]
    return out


def get_settings():
    return {**DEFAULTS, **clean_settings(read_json("settings.json", {}))}


# ── Admin-Schutz (optional ueber ADMIN_PIN) ──────────────────────────────────────
def is_admin():
    if not ADMIN_PIN:
        return True
    tok = request.headers.get("X-Admin-Token", "")
    try:
        _signer.loads(tok, max_age=TOKEN_MAX_AGE)
        return True
    except (BadSignature, SignatureExpired):
        return False


def admin_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not is_admin():
            return jsonify({"error": "Admin-Login erforderlich", "auth": True}), 401
        return fn(*a, **kw)
    return wrapper


# ── Statische DHCP-Eintraege (Pi-hole dhcp.hosts) ─────────────────────────────────
def parse_entry(raw):
    parts = [p.strip() for p in str(raw).split(",")]
    mac = norm_mac(parts[0]) if parts else ""
    if not MAC_RE.match(mac) or len(parts) < 2:
        return None
    return {"mac": mac, "ip": parts[1], "hostname": parts[2] if len(parts) > 2 else "",
            "extra": parts[3:], "raw": raw}


def parse_hosts(hosts):
    return [{"mac": e["mac"], "ip": e["ip"], "hostname": e["hostname"], "comment": ""}
            for e in map(parse_entry, hosts) if e]


def build_entry(mac, ip, hostname, extra=()):
    return ",".join([mac, ip, hostname, *extra]).rstrip(",")


def read_hosts():
    data, err = ph("get", "/config/dhcp")
    if err:
        return None, err
    return list(data.get("config", {}).get("dhcp", {}).get("hosts", [])), None


def write_hosts(hosts):
    _, err = ph("patch", "/config/dhcp", json={"config": {"dhcp": {"hosts": hosts}}})
    if err:
        return err
    check, err = read_hosts()          # Gegenprobe: wirklich in Pi-hole gelandet?
    if err:
        return err
    if [h.lower() for h in check] != [h.lower() for h in hosts]:
        return "Pi-hole hat die Eintraege nicht wie erwartet uebernommen"
    return None


def get_leases():
    data, err = ph("get", "/dhcp/leases")
    if err:
        return None, err
    raw = data.get("leases", []) if isinstance(data, dict) else data
    return [{"mac": norm_mac(l.get("hwaddr", l.get("mac", ""))),
             "ip": l.get("ip", l.get("address", "")),
             "hostname": (lambda n: "" if n in ("*", None) else n)(l.get("name", l.get("hostname", ""))),
             "expires": l.get("expires", "")} for l in raw], None


def dhcp_cfg():
    data, _ = ph("get", "/config/dhcp")
    return (data or {}).get("config", {}).get("dhcp", {})


def validate(items, hosts, leases):
    """items: [{mac,ip,hostname}] -> (clean_items, errors, warnings)"""
    entries = [e for e in map(parse_entry, hosts) if e]
    batch_macs = {norm_mac(i.get("mac")) for i in items}
    others = [e for e in entries if e["mac"] not in batch_macs]
    cfg = dhcp_cfg()
    lease_ip = {l["ip"]: l["mac"] for l in leases or []}
    clean, errors, warns = [], [], []
    seen_ip, seen_host = set(), set()
    for i in items:
        mac, ip, host = norm_mac(i.get("mac")), valid_ip(i.get("ip")), norm_host(i.get("hostname"))
        tag = mac or "?"
        if not MAC_RE.match(mac): errors.append(f"{tag}: ungueltige MAC"); continue
        if not ip: errors.append(f"{tag}: ungueltige IPv4-Adresse"); continue
        if host and not HOST_RE.match(host):
            errors.append(f"{tag}: Hostname nur a-z, 0-9, '-' (max. 63 Zeichen)"); continue
        if ip == cfg.get("router"): errors.append(f"{tag}: {ip} ist das Gateway"); continue
        clash = next((e for e in others if e["ip"] == ip), None)
        if clash or ip in seen_ip:
            errors.append(f"{tag}: IP {ip} bereits vergeben" + (f" an {clash['mac']}" if clash else "")); continue
        if host and (host in seen_host or any(e["hostname"].lower() == host for e in others)):
            errors.append(f"{tag}: Hostname '{host}' bereits vergeben"); continue
        if lease_ip.get(ip) not in (None, mac):
            warns.append(f"{tag}: {ip} wird aktuell von {lease_ip[ip]} genutzt (Konflikt bis Lease ablaeuft)")
        seen_ip.add(ip); seen_host.add(host)
        clean.append({"mac": mac, "ip": ip, "hostname": host})
    return clean, errors, warns


def upsert(items):
    with _hosts_lock:
        hosts, err = read_hosts()
        if err: return jsonify({"error": err}), 502
        leases, _ = get_leases()
        clean, errors, warns = validate(items, hosts, leases)
        if errors: return jsonify({"error": "; ".join(errors), "errors": errors}), 400
        by_mac = {i["mac"]: i for i in clean}
        out, done = [], set()
        for raw in hosts:
            e = parse_entry(raw)
            if e and e["mac"] in by_mac:
                i = by_mac[e["mac"]]
                if e["mac"] not in done:
                    out.append(build_entry(i["mac"], i["ip"], i["hostname"], e["extra"])); done.add(e["mac"])
            else:
                out.append(raw)
        out += [build_entry(i["mac"], i["ip"], i["hostname"]) for m, i in by_mac.items() if m not in done]
        err = write_hosts(out)
        if err: return jsonify({"error": err}), 502
        return jsonify({"ok": True, "saved": len(clean), "warnings": warns})


# ── Routen: Basis ──────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/api/health")
def health():
    data, err = ph("get", "/stats/summary")
    if err: return jsonify({"status": "pihole_unreachable", "error": err}), 502
    return jsonify({"status": "ok", "pihole": PIHOLE_URL})


@app.route("/api/settings", methods=["GET"])
def settings_get():
    return jsonify({"settings": get_settings(), "pin_required": bool(ADMIN_PIN), "is_admin": is_admin()})


@app.route("/api/settings", methods=["POST"])
@admin_required
def settings_set():
    cur = get_settings()
    cur.update(clean_settings(request.get_json(silent=True) or {}))
    write_json("settings.json", cur)
    return jsonify({"ok": True, "settings": cur})


@app.route("/api/settings/reset", methods=["POST"])
@admin_required
def settings_reset():
    write_json("settings.json", DEFAULTS)
    return jsonify({"ok": True, "settings": DEFAULTS})


@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    pin = str((request.get_json(silent=True) or {}).get("pin", ""))
    if not ADMIN_PIN: return jsonify({"ok": True, "token": ""})
    if not hmac.compare_digest(pin, ADMIN_PIN):
        time.sleep(1)
        return jsonify({"error": "Falsche PIN"}), 403
    return jsonify({"ok": True, "token": _signer.dumps("admin")})


# ── Routen: Geraete ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/leases")
def api_leases():
    leases, err = get_leases()
    if err: return jsonify({"error": err}), 502
    return jsonify([{**l, "type": "dynamic"} for l in leases])


@app.route("/api/devices")
@app.route("/api/all_devices")
def all_devices():
    leases, err1 = get_leases()
    hosts, err2 = read_hosts()
    if err1 or err2: return jsonify({"error": err1 or err2}), 502
    meta = read_json("meta.json", {})
    statics = {s["mac"]: s for s in parse_hosts(hosts)}
    devices, seen = [], set()
    for l in leases:
        st = statics.get(l["mac"]); seen.add(l["mac"])
        devices.append({**l, "is_static": bool(st), "static_ip": st["ip"] if st else "",
                        "static_hostname": st["hostname"] if st else "",
                        "comment": meta.get(l["mac"], {}).get("comment", ""),
                        "type": "static+active" if st else "dynamic"})
    for mac, s in statics.items():
        if mac not in seen:
            devices.append({"mac": mac, "ip": s["ip"], "hostname": s["hostname"], "expires": "",
                            "is_static": True, "static_ip": s["ip"], "static_hostname": s["hostname"],
                            "comment": meta.get(mac, {}).get("comment", ""), "type": "static"})
    return jsonify(devices)


@app.route("/api/static", methods=["GET"])
def get_static():
    hosts, err = read_hosts()
    if err: return jsonify({"error": err}), 502
    meta = read_json("meta.json", {})
    return jsonify([{**s, "comment": meta.get(s["mac"], {}).get("comment", "")} for s in parse_hosts(hosts)])


@app.route("/api/static", methods=["POST"])
@admin_required
def add_static():
    d = request.get_json(silent=True) or {}
    if not d.get("mac") or not d.get("ip"): return jsonify({"error": "mac and ip required"}), 400
    r = upsert([d])
    if "comment" in d and _ok(r):
        set_comment(norm_mac(d["mac"]), d.get("comment", ""))
    return r


@app.route("/api/static/<mac>", methods=["PUT"])
@admin_required
def edit_static(mac):
    """Umbenennen / IP aendern / MAC aendern. Body: ip, hostname, new_mac (optional)."""
    d = request.get_json(silent=True) or {}
    old, new = norm_mac(mac), norm_mac(d.get("new_mac") or mac)
    if not d.get("ip"): return jsonify({"error": "ip required"}), 400
    with _hosts_lock:
        if new != old:
            hosts, err = read_hosts()
            if err: return jsonify({"error": err}), 502
            hosts = [h for h in hosts if not (parse_entry(h) or {}).get("mac") == old]
            if (e := write_hosts(hosts)): return jsonify({"error": e}), 502
        r = upsert([{"mac": new, "ip": d["ip"], "hostname": d.get("hostname", "")}])
    if "comment" in d and _ok(r): set_comment(new, d["comment"])
    return r


@app.route("/api/static/bulk", methods=["POST"])
@admin_required
def bulk_static():
    items = (request.get_json(silent=True) or {}).get("items", [])
    if not items: return jsonify({"error": "items required"}), 400
    return upsert(items)


@app.route("/api/static/<mac>", methods=["DELETE"])
@admin_required
def del_static(mac):
    mac = norm_mac(mac)
    with _hosts_lock:
        hosts, err = read_hosts()
        if err: return jsonify({"error": err}), 502
        new = [h for h in hosts if (parse_entry(h) or {}).get("mac") != mac]
        if len(new) == len(hosts): return jsonify({"error": "Eintrag nicht gefunden"}), 404
        err = write_hosts(new)
        return (jsonify({"error": err}), 502) if err else jsonify({"ok": True})


def _ok(r):
    return (r[0] if isinstance(r, tuple) else r).status_code == 200


def set_comment(mac, comment):
    meta = read_json("meta.json", {})
    comment = str(comment or "").strip()[:120]
    if comment: meta[mac] = {"comment": comment}
    else: meta.pop(mac, None)
    write_json("meta.json", meta)


@app.route("/api/meta/<mac>", methods=["POST"])
@admin_required
def api_meta(mac):
    set_comment(norm_mac(mac), (request.get_json(silent=True) or {}).get("comment", ""))
    return jsonify({"ok": True})


@app.route("/api/free_ips")
def free_ips():
    """Freie IPs: nimmt suggest_start/-end aus den Einstellungen, sonst /24 des Gateways ausserhalb des DHCP-Pools."""
    cfg, st = dhcp_cfg(), get_settings()
    hosts, _ = read_hosts()
    leases, _ = get_leases()
    used = {s["ip"] for s in parse_hosts(hosts or [])} | {l["ip"] for l in leases or []} | {cfg.get("router", "")}
    try:
        if st["suggest_start"] and st["suggest_end"]:
            lo, hi = int(ipaddress.IPv4Address(st["suggest_start"])), int(ipaddress.IPv4Address(st["suggest_end"]))
            skip = None
        else:
            net = ipaddress.IPv4Network(cfg["router"] + "/24", strict=False)
            lo, hi = int(net.network_address) + 1, int(net.broadcast_address) - 1
            skip = (int(ipaddress.IPv4Address(cfg["start"])), int(ipaddress.IPv4Address(cfg["end"])))
    except Exception:
        return jsonify({"error": "Kein Bereich ermittelbar - in Admin > Netzwerk festlegen"}), 400
    n = min(int(request.args.get("count", 10)), 50)
    out = [str(ipaddress.IPv4Address(i)) for i in range(lo, hi + 1)
           if str(ipaddress.IPv4Address(i)) not in used and not (skip and skip[0] <= i <= skip[1])]
    return jsonify(out[:n])


@app.route("/api/lease/renew", methods=["POST"])
@admin_required
def renew_lease():
    mac = (request.get_json(silent=True) or {}).get("mac", "")
    if not mac: return jsonify({"error": "mac required"}), 400
    _, err = ph("delete", f"/dhcp/leases/{norm_mac(mac)}")
    if err: return jsonify({"error": err}), 502
    return jsonify({"ok": True, "msg": "Lease geloescht - Geraet erhaelt bei naechster Anfrage einen neuen"})


@app.route("/api/lease/<mac>", methods=["DELETE"])
@admin_required
def del_lease(mac):
    _, err = ph("delete", f"/dhcp/leases/{norm_mac(mac)}")
    return (jsonify({"error": err}), 502) if err else jsonify({"ok": True})


# ── Backup / Restore ──────────────────────────────────────────────────────────────────────────
@app.route("/api/export")
def export_all():
    hosts, err = read_hosts()
    if err: return jsonify({"error": err}), 502
    return jsonify({"version": 1, "hosts": hosts, "meta": read_json("meta.json", {}), "settings": get_settings()})


@app.route("/api/import", methods=["POST"])
@admin_required
def import_all():
    d = request.get_json(silent=True) or {}
    items = [e for e in map(parse_entry, d.get("hosts", [])) if e]
    if not items: return jsonify({"error": "Keine gueltigen Eintraege"}), 400
    mode = d.get("mode", "merge")
    with _hosts_lock:
        if mode == "replace":
            hosts = [build_entry(e["mac"], e["ip"], e["hostname"].lower(), e["extra"]) for e in items]
            clean, errors, _ = validate([{k: e[k] for k in ("mac", "ip", "hostname")} for e in items], [], [])
            if errors: return jsonify({"error": "; ".join(errors)}), 400
            err = write_hosts(hosts)
            return (jsonify({"error": err}), 502) if err else jsonify({"ok": True, "saved": len(hosts)})
        return upsert([{k: e[k] for k in ("mac", "ip", "hostname")} for e in items])


# ── Konfiguration & Log ─────────────────────────────────────────────────────────────────
@app.route("/api/config", methods=["GET"])
def get_config():
    dhcp = dhcp_cfg()
    dns_data, _ = ph("get", "/config/dns")
    ups = (dns_data or {}).get("config", {}).get("dns", {}).get("upstreams", [])
    return jsonify({"DHCP_START": dhcp.get("start", ""), "DHCP_END": dhcp.get("end", ""),
                    "DHCP_ROUTER": dhcp.get("router", ""), "DHCP_LEASETIME": dhcp.get("leaseTime", ""),
                    "PIHOLE_DNS_1": ups[0] if len(ups) > 0 else "", "PIHOLE_DNS_2": ups[1] if len(ups) > 1 else ""})


@app.route("/api/config", methods=["POST"])
@admin_required
def save_config():
    d = request.get_json(silent=True) or {}
    dhcp = {}
    for key, field in (("DHCP_START", "start"), ("DHCP_END", "end"), ("DHCP_ROUTER", "router")):
        if key in d:
            ip = valid_ip(d[key])
            if not ip: return jsonify({"error": f"{key}: ungueltige IP"}), 400
            dhcp[field] = ip
    if "DHCP_LEASETIME" in d:
        lt = str(d["DHCP_LEASETIME"]).strip()
        if not re.fullmatch(r"\d+[smhdw]?|infinite", lt): return jsonify({"error": "Leasetime z.B. 24h"}), 400
        dhcp["leaseTime"] = lt
    if dhcp:
        _, err = ph("patch", "/config/dhcp", json={"config": {"dhcp": dhcp}})
        if err: return jsonify({"error": err}), 502
    if "PIHOLE_DNS_1" in d or "PIHOLE_DNS_2" in d:
        ups = [u.strip() for u in (d.get("PIHOLE_DNS_1", ""), d.get("PIHOLE_DNS_2", "")) if str(u).strip()]
        if not all(re.fullmatch(r"[0-9a-zA-Z.:#\[\]-]+", u) for u in ups):
            return jsonify({"error": "Ungueltiger DNS-Server"}), 400
        if ups:
            _, err = ph("patch", "/config/dns", json={"config": {"dns": {"upstreams": ups}}})
            if err: return jsonify({"error": err}), 502
    return jsonify({"ok": True})


@app.route("/api/log")
def get_log():
    data, err = ph("get", "/logs/dnsmasq")
    if not err and isinstance(data, dict) and "log" in data:
        lines = [f"{l.get('timestamp','')}  {l.get('message','')}" for l in data["log"]
                 if "DHCP" in l.get("message", "")][-200:]
        return jsonify({"lines": lines or ["[Keine DHCP-Eintraege gefunden]"]})
    data, err = ph("get", "/queries", params={"type": "DHCP", "limit": 200})
    if err: return jsonify({"lines": [f"[Fehler: {err}]"]})
    qs = data.get("queries", []) if isinstance(data, dict) else []
    return jsonify({"lines": [f"{q.get('time','')}  {q.get('type','')}  {q.get('domain','')}  {q.get('client','')}  {q.get('status','')}" for q in qs]
                    or ["[Keine DHCP-Eintraege gefunden]"]})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
