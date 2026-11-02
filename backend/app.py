from flask import Flask, jsonify, request, send_from_directory
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from functools import wraps
from datetime import datetime, timezone
import os
import re
import json
import ipaddress
import logging
import threading
import time
import hmac
import tempfile
import secrets
from collections import Counter

import requests
from requests.exceptions import RequestException

app = Flask(__name__)
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

PIHOLE_URL = os.getenv("PIHOLE_URL", "http://192.168.178.1").rstrip("/")
PIHOLE_PASSWORD = os.getenv("PIHOLE_PASSWORD", "")
FRONTEND_DIR = os.getenv("FRONTEND_DIR", "/app/frontend")
DATA_DIR = os.getenv("DATA_DIR", "/app/data")
ADMIN_PIN = os.getenv("ADMIN_PIN", "")
ALLOW_UNAUTHENTICATED_WRITES = os.getenv("ALLOW_UNAUTHENTICATED_WRITES", "false").strip().lower() in {"1", "true", "yes", "on"}
PIHOLE_TLS_INSECURE = os.getenv("PIHOLE_TLS_INSECURE", "false").strip().lower() in {"1", "true", "yes", "on"}
PIHOLE_CA_BUNDLE = os.getenv("PIHOLE_CA_BUNDLE", "").strip()
TOKEN_MAX_AGE = 12 * 3600
LOGIN_RATE_WINDOW_SECONDS = 60
LOGIN_RATE_MAX_ATTEMPTS = 5

_session_lock = threading.Lock()
_hosts_lock = threading.RLock()
_file_lock = threading.RLock()
_failed_login_lock = threading.Lock()
_sid, _sid_expires = None, 0
_failed_login = {}


# ── Validierung (verhindert u.a. Newline-Injection in dhcp.hosts) ──────────────
MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


DEFAULTS = {
    "title": "hAI.PeeDHCP", "theme": "dark", "accent": "#4f98a3", "density": "comfortable",
    "radius": "md", "font_scale": 100, "mobile_cards": True, "default_view": "overview",
    "refresh_seconds": 0, "date_format": "de", "confirm_delete": True,
    "show_mac": True, "show_expires": True, "show_type": True, "hide_unnamed": False,
    "suggest_start": "", "suggest_end": "",
}
ENUMS = {
    "theme": {"dark", "light", "auto"},
    "density": {"comfortable", "compact"},
    "radius": {"sm", "md", "lg"},
    "date_format": {"de", "iso", "rel"},
    "default_view": {"overview", "all", "leases", "static", "config", "log"},
}


def ensure_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def _path(name):
    ensure_data_dir()
    return os.path.join(DATA_DIR, name)


def _load_or_create_signing_key():
    env_key = os.getenv("SECRET_KEY", "").strip()
    if env_key:
        return env_key

    key_path = _path("signing_secret.txt")
    try:
        with open(key_path, encoding="utf-8") as f:
            key = f.read().strip()
            if key:
                return key
    except FileNotFoundError:
        pass

    key = secrets.token_urlsafe(48)
    tmp_fd, tmp_path = tempfile.mkstemp(dir=DATA_DIR, suffix=".tmp")
    try:
        os.fchmod(tmp_fd, 0o600)
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            f.write(key)
        os.replace(tmp_path, key_path)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
    return key


SECRET_KEY = _load_or_create_signing_key()
_signer = URLSafeTimedSerializer(SECRET_KEY, salt="admin")


if PIHOLE_TLS_INSECURE:
    PIHOLE_VERIFY = False
elif PIHOLE_CA_BUNDLE:
    PIHOLE_VERIFY = PIHOLE_CA_BUNDLE
else:
    PIHOLE_VERIFY = True


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


def sanitize_request_error(err):
    resp = getattr(err, "response", None)
    if resp is None:
        return str(err)
    msg = f"HTTP {resp.status_code}"
    try:
        body = resp.json()
        if isinstance(body, dict):
            detail = body.get("error") or body.get("message")
            if detail:
                msg = f"{msg}: {detail}"
    except ValueError:
        pass
    return msg


# ── Pi-hole Session ──────────────────────────────────────────────────────
def get_sid(force=False):
    global _sid, _sid_expires
    with _session_lock:
        if not force and _sid and time.time() < _sid_expires - 30:
            return _sid
        try:
            r = requests.post(
                f"{PIHOLE_URL}/api/auth",
                json={"password": PIHOLE_PASSWORD},
                timeout=10,
                verify=PIHOLE_VERIFY,
            )
            r.raise_for_status()
            data = r.json()
            sess = data.get("session") if isinstance(data, dict) else None
            sid = (sess or {}).get("sid")
            validity = int((sess or {}).get("validity", 1800))
            if not sid:
                raise ValueError("session.sid fehlt")
            _sid, _sid_expires = sid, time.time() + max(60, validity)
            app.logger.info("PiHole session renewed")
            return _sid
        except Exception as e:
            app.logger.error("PiHole login failed: %s", e)
            _sid = None
            return None


def ph(method, path, **kwargs):
    for attempt in range(2):
        sid = get_sid(force=attempt == 1)
        if not sid:
            return None, "PiHole login failed"
        try:
            r = getattr(requests, method)(
                f"{PIHOLE_URL}/api{path}",
                headers={"X-FTL-SID": sid},
                timeout=10,
                verify=PIHOLE_VERIFY,
                **kwargs,
            )
            if r.status_code == 401 and attempt == 0:
                continue
            r.raise_for_status()
            return (r.json() if r.content else {}), None
        except RequestException as e:
            msg = sanitize_request_error(e)
            app.logger.error("PiHole %s %s: %s", method, path, msg)
            return None, msg
    return None, "Auth failed after retry"


# ── Lokale Daten (Settings, Notizen) ───────────────────────────────────────
def read_json(name, default):
    path = _path(name)
    with _file_lock:
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return default
        except json.JSONDecodeError as e:
            app.logger.error("Ungültige JSON-Datei %s: %s", path, e)
            return default
        except OSError as e:
            app.logger.error("Fehler beim Lesen %s: %s", path, e)
            return default


def write_json(name, data):
    ensure_data_dir()
    with _file_lock:
        fd, tmp = tempfile.mkstemp(dir=DATA_DIR, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            os.replace(tmp, _path(name))
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)


def clean_settings(d):
    out = {}
    for k, default in DEFAULTS.items():
        if k not in d:
            continue
        v = d[k]
        if k in ENUMS:
            if v in ENUMS[k]:
                out[k] = v
        elif k == "accent":
            if isinstance(v, str) and re.fullmatch(r"#[0-9a-fA-F]{6}", v):
                out[k] = v
        elif k == "font_scale":
            try:
                out[k] = max(85, min(130, int(v)))
            except (TypeError, ValueError):
                pass
        elif k == "refresh_seconds":
            try:
                out[k] = 0 if int(v) <= 0 else max(10, min(3600, int(v)))
            except (TypeError, ValueError):
                pass
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
def _client_key():
    fwd = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    return fwd or request.remote_addr or "unknown"


def _rate_limited():
    now = time.time()
    key = _client_key()
    with _failed_login_lock:
        recent = [t for t in _failed_login.get(key, []) if now - t < LOGIN_RATE_WINDOW_SECONDS]
        _failed_login[key] = recent
        return len(recent) >= LOGIN_RATE_MAX_ATTEMPTS


def _record_login_failure():
    now = time.time()
    key = _client_key()
    with _failed_login_lock:
        recent = [t for t in _failed_login.get(key, []) if now - t < LOGIN_RATE_WINDOW_SECONDS]
        recent.append(now)
        _failed_login[key] = recent


def _clear_login_failures():
    key = _client_key()
    with _failed_login_lock:
        _failed_login.pop(key, None)


def is_admin():
    if not ADMIN_PIN:
        return ALLOW_UNAUTHENTICATED_WRITES

    tok = request.headers.get("X-Admin-Token", "")
    if not tok:
        return False
    try:
        payload = _signer.loads(tok, max_age=TOKEN_MAX_AGE)
        return isinstance(payload, dict) and payload.get("role") == "admin"
    except (BadSignature, SignatureExpired):
        return False


def admin_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not is_admin():
            if not ADMIN_PIN and not ALLOW_UNAUTHENTICATED_WRITES:
                return jsonify({
                    "error": "Schreibzugriffe ohne ADMIN_PIN sind deaktiviert. Setze ADMIN_PIN oder ALLOW_UNAUTHENTICATED_WRITES=true.",
                    "auth": False,
                }), 403
            return jsonify({"error": "Admin-Login erforderlich", "auth": True}), 401
        return fn(*a, **kw)

    return wrapper


# ── Statische DHCP-Eintraege (Pi-hole dhcp.hosts) ─────────────────────────────────
def parse_entry(raw):
    parts = [p.strip() for p in str(raw).split(",")]
    mac = norm_mac(parts[0]) if parts else ""
    if not MAC_RE.match(mac) or len(parts) < 2:
        return None
    return {
        "mac": mac,
        "ip": parts[1],
        "hostname": parts[2] if len(parts) > 2 else "",
        "extra": parts[3:],
        "raw": raw,
    }


def parse_hosts(hosts):
    out = []
    for entry in map(parse_entry, hosts):
        if not entry:
            continue
        out.append({"mac": entry["mac"], "ip": entry["ip"], "hostname": entry["hostname"], "comment": ""})
    return out


def build_entry(mac, ip, hostname, extra=()):
    return ",".join([mac, ip, hostname, *extra]).rstrip(",")


def read_hosts():
    data, err = ph("get", "/config/dhcp")
    if err:
        return None, err
    hosts = ((data or {}).get("config", {}).get("dhcp", {}).get("hosts", []))
    if not isinstance(hosts, list):
        return None, "Pi-hole lieferte ein unerwartetes hosts-Format"
    return list(hosts), None


def write_hosts(hosts):
    _, err = ph("patch", "/config/dhcp", json={"config": {"dhcp": {"hosts": hosts}}})
    if err:
        return err
    check, err = read_hosts()
    if err:
        return err
    if [str(h).lower() for h in check] != [str(h).lower() for h in hosts]:
        return "Pi-hole hat die Eintraege nicht wie erwartet uebernommen"
    return None


def get_leases():
    data, err = ph("get", "/dhcp/leases")
    if err:
        return None, err
    raw = data.get("leases", []) if isinstance(data, dict) else data
    if not isinstance(raw, list):
        return None, "Pi-hole lieferte ein unerwartetes Lease-Format"
    leases = []
    for l in raw:
        if not isinstance(l, dict):
            continue
        leases.append(
            {
                "mac": norm_mac(l.get("hwaddr", l.get("mac", ""))),
                "ip": l.get("ip", l.get("address", "")),
                "hostname": "" if l.get("name", l.get("hostname", "")) in ("*", None) else l.get("name", l.get("hostname", "")),
                "expires": l.get("expires", ""),
            }
        )
    return leases, None


def dhcp_cfg():
    data, err = ph("get", "/config/dhcp")
    if err:
        return None, err
    return (data or {}).get("config", {}).get("dhcp", {}), None


def validate(items, hosts, leases, remove_macs=None):
    """items: [{mac,ip,hostname}] -> (clean_items, errors, warnings)"""
    remove_macs = set(remove_macs or [])
    entries = [e for e in map(parse_entry, hosts) if e]
    batch = []
    for i in items:
        batch.append({
            "mac": norm_mac(i.get("mac")),
            "ip": valid_ip(i.get("ip")),
            "hostname": norm_host(i.get("hostname")),
        })

    errors, warns = [], []
    mac_counts = Counter(i["mac"] for i in batch if i["mac"])
    ip_counts = Counter(i["ip"] for i in batch if i["ip"])
    host_counts = Counter(i["hostname"] for i in batch if i["hostname"])

    cfg, cfg_err = dhcp_cfg()
    if cfg_err:
        return [], [cfg_err], []

    lease_ip = {l["ip"]: l["mac"] for l in (leases or []) if l.get("ip")}
    batch_macs = {i["mac"] for i in batch if i["mac"]}
    others = [e for e in entries if e["mac"] not in batch_macs and e["mac"] not in remove_macs]

    clean = []
    for i in batch:
        mac, ip, host = i["mac"], i["ip"], i["hostname"]
        tag = mac or "?"
        if not MAC_RE.match(mac):
            errors.append(f"{tag}: ungueltige MAC")
            continue
        if not ip:
            errors.append(f"{tag}: ungueltige IPv4-Adresse")
            continue
        if host and not HOST_RE.match(host):
            errors.append(f"{tag}: Hostname nur a-z, 0-9, '-' (max. 63 Zeichen)")
            continue
        if ip == cfg.get("router"):
            errors.append(f"{tag}: {ip} ist das Gateway")
            continue
        if mac_counts[mac] > 1:
            errors.append(f"{tag}: MAC mehrfach im Batch")
            continue
        if ip_counts[ip] > 1:
            errors.append(f"{tag}: IP {ip} mehrfach im Batch")
            continue
        if host and host_counts[host] > 1:
            errors.append(f"{tag}: Hostname '{host}' mehrfach im Batch")
            continue
        clash = next((e for e in others if valid_ip(e["ip"]) == ip), None)
        if clash:
            errors.append(f"{tag}: IP {ip} bereits vergeben an {clash['mac']}")
            continue
        if host and any(norm_host(e.get("hostname", "")) == host for e in others):
            errors.append(f"{tag}: Hostname '{host}' bereits vergeben")
            continue
        if lease_ip.get(ip) not in (None, mac):
            warns.append(f"{tag}: {ip} wird aktuell von {lease_ip[ip]} genutzt (Konflikt bis Lease ablaeuft)")
        clean.append({"mac": mac, "ip": ip, "hostname": host})
    return clean, errors, warns


def apply_static_changes(items, remove_macs=None):
    remove_macs = set(remove_macs or [])
    with _hosts_lock:
        hosts, err = read_hosts()
        if err:
            return None, None, err, 502

        leases, lease_err = get_leases()
        if lease_err:
            app.logger.warning("Leases konnten fuer Validierung nicht geladen werden: %s", lease_err)
            leases = []

        clean, errors, warns = validate(items, hosts, leases, remove_macs=remove_macs)
        if errors:
            return None, errors, None, 400

        by_mac = {i["mac"]: i for i in clean}
        out, done = [], set()
        for raw in hosts:
            e = parse_entry(raw)
            if not e:
                out.append(raw)
                continue
            if e["mac"] in remove_macs and e["mac"] not in by_mac:
                continue
            if e["mac"] in by_mac:
                if e["mac"] not in done:
                    i = by_mac[e["mac"]]
                    out.append(build_entry(i["mac"], i["ip"], i["hostname"], e["extra"]))
                    done.add(e["mac"])
            else:
                out.append(raw)

        for mac, i in by_mac.items():
            if mac not in done:
                out.append(build_entry(i["mac"], i["ip"], i["hostname"]))

        err = write_hosts(out)
        if err:
            return None, None, err, 502

        return clean, None, warns, 200


def apply_static_changes_response(items, remove_macs=None):
    clean, errors, result, status = apply_static_changes(items, remove_macs=remove_macs)
    if status != 200:
        if status == 400:
            return jsonify({"error": "; ".join(errors), "errors": errors}), 400
        return jsonify({"error": result}), status
    return jsonify({"ok": True, "saved": len(clean), "warnings": result or []})


def _ok(r):
    return (r[0] if isinstance(r, tuple) else r).status_code == 200


def set_comment(mac, comment):
    comment = str(comment or "").strip()[:120]
    with _file_lock:
        meta = read_json("meta.json", {})
        if comment:
            meta[mac] = {"comment": comment}
        else:
            meta.pop(mac, None)
        write_json("meta.json", meta)


def parse_backup_payload(payload):
    if not isinstance(payload, dict):
        return None, "Ungültiges Backup-Format"

    version = payload.get("version", 1)
    if version not in (1, 2):
        return None, "Nicht unterstützte Backup-Version"

    mode = payload.get("mode", "merge")
    if mode not in ("merge", "replace"):
        return None, "mode muss 'merge' oder 'replace' sein"

    hosts = payload.get("hosts", [])
    if not isinstance(hosts, list):
        return None, "hosts muss ein Array sein"

    meta = payload.get("meta", {})
    if meta is None:
        meta = {}
    if not isinstance(meta, dict):
        return None, "meta muss ein Objekt sein"

    settings = payload.get("settings", {})
    if settings is None:
        settings = {}
    if not isinstance(settings, dict):
        return None, "settings muss ein Objekt sein"

    parsed_items = [e for e in map(parse_entry, hosts) if e]
    invalid_count = len(hosts) - len(parsed_items)
    if invalid_count and hosts:
        return None, f"{invalid_count} hosts-Einträge sind ungültig"

    items = [{k: e[k] for k in ("mac", "ip", "hostname")} for e in parsed_items]
    cleaned_meta = {}
    for mac, obj in meta.items():
        nmac = norm_mac(mac)
        if not MAC_RE.match(nmac):
            continue
        if isinstance(obj, dict):
            c = str(obj.get("comment", "")).strip()[:120]
        else:
            c = str(obj).strip()[:120]
        if c:
            cleaned_meta[nmac] = {"comment": c}

    return {
        "version": version,
        "mode": mode,
        "items": items,
        "hosts": hosts,
        "meta": cleaned_meta,
        "settings": clean_settings(settings),
    }, None


def resolve_lease_ip(identifier):
    raw = str(identifier or "").strip()
    if not raw:
        return None, "mac required", 400

    as_ip = valid_ip(raw)
    if as_ip:
        return as_ip, None, 200

    mac = norm_mac(raw)
    if not MAC_RE.match(mac):
        return None, "ungueltige MAC", 400

    leases, err = get_leases()
    if err:
        return None, err, 502

    match = next((l for l in leases if l.get("mac") == mac), None)
    if not match or not valid_ip(match.get("ip")):
        return None, "Lease nicht gefunden", 404

    return valid_ip(match["ip"]), None, 200


def _derive_auto_suggestion_range(cfg):
    router = valid_ip(cfg.get("router"))
    start = valid_ip(cfg.get("start"))
    end = valid_ip(cfg.get("end"))
    if not all([router, start, end]):
        return None, None, None

    start_i = int(ipaddress.IPv4Address(start))
    end_i = int(ipaddress.IPv4Address(end))
    pool = (min(start_i, end_i), max(start_i, end_i))

    r = ipaddress.IPv4Address(router)
    s = ipaddress.IPv4Address(start)
    e = ipaddress.IPv4Address(end)

    best = None
    for prefix in range(32, 7, -1):
        net = ipaddress.IPv4Network(f"{router}/{prefix}", strict=False)
        if s in net and e in net and r in net:
            best = net
            break
    if best is None:
        return None, None, None

    lo = int(best.network_address) + 1
    hi = int(best.broadcast_address) - 1
    if lo > hi:
        return None, None, None
    return lo, hi, pool


def _is_dhcp_event_line(line):
    s = str(line)
    return "DHCP" in s and any(tag in s for tag in ("DHCPACK", "DHCPOFFER", "DHCPREQUEST", "DHCPDISCOVER", "DHCPRELEASE", "DHCPNAK"))


# ── Routen: Basis ──────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/api/health")
def health():
    _, err = ph("get", "/stats/summary")
    if err:
        return jsonify({"status": "pihole_unreachable", "error": err}), 502
    return jsonify({"status": "ok", "pihole": PIHOLE_URL})


@app.route("/api/livez")
def livez():
    return jsonify({"status": "ok"})


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
    if not ADMIN_PIN:
        if ALLOW_UNAUTHENTICATED_WRITES:
            return jsonify({"ok": True, "token": ""})
        return jsonify({"error": "ADMIN_PIN setzen oder ALLOW_UNAUTHENTICATED_WRITES=true aktivieren"}), 403

    if _rate_limited():
        return jsonify({"error": "Zu viele Fehlversuche. Bitte kurz warten."}), 429

    pin = str((request.get_json(silent=True) or {}).get("pin", ""))
    if not hmac.compare_digest(pin, ADMIN_PIN):
        _record_login_failure()
        time.sleep(1)
        return jsonify({"error": "Falsche PIN"}), 403

    _clear_login_failures()
    return jsonify({"ok": True, "token": _signer.dumps({"role": "admin"})})


# ── Routen: Geraete ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/leases")
def api_leases():
    leases, err = get_leases()
    if err:
        return jsonify({"error": err}), 502
    return jsonify([{**l, "type": "dynamic"} for l in leases])


@app.route("/api/devices")
@app.route("/api/all_devices")
def all_devices():
    leases, err1 = get_leases()
    hosts, err2 = read_hosts()
    if err1 or err2:
        return jsonify({"error": err1 or err2}), 502

    meta = read_json("meta.json", {})
    statics = {s["mac"]: s for s in parse_hosts(hosts)}
    devices, seen = [], set()

    for l in leases:
        st = statics.get(l["mac"])
        seen.add(l["mac"])
        devices.append(
            {
                **l,
                "is_static": bool(st),
                "static_ip": st["ip"] if st else "",
                "static_hostname": st["hostname"] if st else "",
                "comment": meta.get(l["mac"], {}).get("comment", ""),
                "type": "static+active" if st else "dynamic",
            }
        )

    for mac, s in statics.items():
        if mac in seen:
            continue
        devices.append(
            {
                "mac": mac,
                "ip": s["ip"],
                "hostname": s["hostname"],
                "expires": "",
                "is_static": True,
                "static_ip": s["ip"],
                "static_hostname": s["hostname"],
                "comment": meta.get(mac, {}).get("comment", ""),
                "type": "static",
            }
        )
    return jsonify(devices)


@app.route("/api/static", methods=["GET"])
def get_static():
    hosts, err = read_hosts()
    if err:
        return jsonify({"error": err}), 502
    meta = read_json("meta.json", {})
    return jsonify([{**s, "comment": meta.get(s["mac"], {}).get("comment", "")} for s in parse_hosts(hosts)])


@app.route("/api/static", methods=["POST"])
@admin_required
def add_static():
    d = request.get_json(silent=True) or {}
    if not d.get("mac") or not d.get("ip"):
        return jsonify({"error": "mac and ip required"}), 400
    r = apply_static_changes_response([d])
    if "comment" in d and _ok(r):
        set_comment(norm_mac(d["mac"]), d.get("comment", ""))
    return r


@app.route("/api/static/<mac>", methods=["PUT"])
@admin_required
def edit_static(mac):
    """Umbenennen / IP aendern / MAC aendern. Body: ip, hostname, new_mac (optional)."""
    d = request.get_json(silent=True) or {}
    old, new = norm_mac(mac), norm_mac(d.get("new_mac") or mac)
    if not d.get("ip"):
        return jsonify({"error": "ip required"}), 400

    hosts, err = read_hosts()
    if err:
        return jsonify({"error": err}), 502
    if not any((parse_entry(h) or {}).get("mac") == old for h in hosts):
        return jsonify({"error": "Eintrag nicht gefunden"}), 404

    remove = {old} if new != old else set()
    r = apply_static_changes_response([{"mac": new, "ip": d["ip"], "hostname": d.get("hostname", "")}], remove_macs=remove)
    if "comment" in d and _ok(r):
        set_comment(new, d["comment"])
        if new != old:
            set_comment(old, "")
    return r


@app.route("/api/static/bulk", methods=["POST"])
@admin_required
def bulk_static():
    items = (request.get_json(silent=True) or {}).get("items", [])
    if not items:
        return jsonify({"error": "items required"}), 400
    return apply_static_changes_response(items)


@app.route("/api/static/<mac>", methods=["DELETE"])
@admin_required
def del_static(mac):
    mac = norm_mac(mac)
    with _hosts_lock:
        hosts, err = read_hosts()
        if err:
            return jsonify({"error": err}), 502
        new = [h for h in hosts if (parse_entry(h) or {}).get("mac") != mac]
        if len(new) == len(hosts):
            return jsonify({"error": "Eintrag nicht gefunden"}), 404
        err = write_hosts(new)
        if err:
            return jsonify({"error": err}), 502
        set_comment(mac, "")
        return jsonify({"ok": True})


@app.route("/api/meta/<mac>", methods=["POST"])
@admin_required
def api_meta(mac):
    set_comment(norm_mac(mac), (request.get_json(silent=True) or {}).get("comment", ""))
    return jsonify({"ok": True})


@app.route("/api/free_ips")
def free_ips():
    """Freie IP-Vorschlaege auf Basis bekannter Leases/Reservierungen (nicht garantiert frei)."""
    cfg, cfg_err = dhcp_cfg()
    if cfg_err:
        return jsonify({"error": cfg_err}), 502

    st = get_settings()
    hosts, host_err = read_hosts()
    if host_err:
        return jsonify({"error": host_err}), 502

    leases, lease_err = get_leases()
    if lease_err:
        return jsonify({"error": lease_err}), 502

    used = {valid_ip(s["ip"]) for s in parse_hosts(hosts or [])}
    used |= {valid_ip(l["ip"]) for l in leases or []}
    used.add(valid_ip(cfg.get("router", "")))
    used = {ip for ip in used if ip}

    lo = hi = None
    skip = None
    try:
        if st["suggest_start"] and st["suggest_end"]:
            lo = int(ipaddress.IPv4Address(st["suggest_start"]))
            hi = int(ipaddress.IPv4Address(st["suggest_end"]))
        else:
            lo, hi, skip = _derive_auto_suggestion_range(cfg)
        if lo is None or hi is None:
            raise ValueError("range")
    except Exception:
        return jsonify({"error": "Kein Bereich ermittelbar - in Admin > Netzwerk festlegen"}), 400

    if lo > hi:
        lo, hi = hi, lo

    count = min(max(int(request.args.get("count", 10)), 1), 50)
    max_scan = min(max(count * 64, 1024), 65536)
    scanned = 0
    out = []

    for i in range(lo, hi + 1):
        if len(out) >= count or scanned >= max_scan:
            break
        scanned += 1
        if skip and skip[0] <= i <= skip[1]:
            continue
        ip = str(ipaddress.IPv4Address(i))
        if ip in used:
            continue
        out.append(ip)

    return jsonify(out)


@app.route("/api/lease/renew", methods=["POST"])
@admin_required
def renew_lease():
    mac = (request.get_json(silent=True) or {}).get("mac", "")
    ip, err, status = resolve_lease_ip(mac)
    if err:
        return jsonify({"error": err}), status

    _, del_err = ph("delete", f"/dhcp/leases/{ip}")
    if del_err:
        return jsonify({"error": del_err}), 502
    return jsonify({"ok": True, "msg": "Lease zurueckgesetzt - Geraet holt sich bei naechster Anfrage eine neue Adresse"})


@app.route("/api/lease/<mac>", methods=["DELETE"])
@admin_required
def del_lease(mac):
    ip, err, status = resolve_lease_ip(mac)
    if err:
        return jsonify({"error": err}), status
    _, del_err = ph("delete", f"/dhcp/leases/{ip}")
    return (jsonify({"error": del_err}), 502) if del_err else jsonify({"ok": True})


# ── Backup / Restore ──────────────────────────────────────────────────────────────────────────
@app.route("/api/export")
def export_all():
    hosts, err = read_hosts()
    if err:
        return jsonify({"error": err}), 502

    return jsonify({
        "version": 2,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "hosts": hosts,
        "meta": read_json("meta.json", {}),
        "settings": get_settings(),
    })


@app.route("/api/import", methods=["POST"])
@admin_required
def import_all():
    payload = request.get_json(silent=True)
    parsed, err = parse_backup_payload(payload)
    if err:
        return jsonify({"error": err}), 400

    items = parsed["items"]
    mode = parsed["mode"]
    result = {
        "ok": True,
        "partial": False,
        "mode": mode,
        "saved": 0,
        "warnings": [],
        "applied": {"hosts": False, "meta": False, "settings": False},
        "errors": [],
    }

    if mode == "replace":
        hosts_for_write = [build_entry(e["mac"], e["ip"], e["hostname"], e["extra"]) for e in map(parse_entry, parsed["hosts"]) if e]
        clean, errors, warns = validate(items, [], [], remove_macs=set()) if items else ([], [], [])
        if errors:
            return jsonify({"error": "; ".join(errors), "errors": errors}), 400
        if warns:
            result["warnings"].extend(warns)

        err_write = write_hosts(hosts_for_write)
        if err_write:
            result["ok"] = False
            result["errors"].append({"scope": "hosts", "error": err_write})
        else:
            result["applied"]["hosts"] = True
            result["saved"] = len(clean)
    else:
        clean, errors, warns, status = apply_static_changes(items)
        if status == 400:
            return jsonify({"error": "; ".join(errors), "errors": errors}), 400
        if status != 200:
            result["ok"] = False
            result["errors"].append({"scope": "hosts", "error": warns})
        else:
            result["applied"]["hosts"] = True
            result["saved"] = len(clean)
            result["warnings"].extend(warns or [])

    try:
        write_json("meta.json", parsed["meta"])
        result["applied"]["meta"] = True
    except OSError as e:
        result["ok"] = False
        result["errors"].append({"scope": "meta", "error": str(e)})

    merged_settings = get_settings()
    merged_settings.update(parsed["settings"])
    try:
        write_json("settings.json", merged_settings)
        result["applied"]["settings"] = True
    except OSError as e:
        result["ok"] = False
        result["errors"].append({"scope": "settings", "error": str(e)})

    result["partial"] = not result["ok"] and any(result["applied"].values())
    status = 200 if result["ok"] else 502 if result["partial"] else 500
    return jsonify(result), status


# ── Konfiguration & Log ─────────────────────────────────────────────────────────────────
@app.route("/api/config", methods=["GET"])
def get_config():
    dhcp, dhcp_err = dhcp_cfg()
    if dhcp_err:
        return jsonify({"error": dhcp_err}), 502

    dns_data, dns_err = ph("get", "/config/dns")
    if dns_err:
        return jsonify({"error": dns_err}), 502

    ups = (dns_data or {}).get("config", {}).get("dns", {}).get("upstreams", [])
    return jsonify({
        "DHCP_START": dhcp.get("start", ""),
        "DHCP_END": dhcp.get("end", ""),
        "DHCP_ROUTER": dhcp.get("router", ""),
        "DHCP_LEASETIME": dhcp.get("leaseTime", ""),
        "PIHOLE_DNS_1": ups[0] if len(ups) > 0 else "",
        "PIHOLE_DNS_2": ups[1] if len(ups) > 1 else "",
    })


@app.route("/api/config", methods=["POST"])
@admin_required
def save_config():
    d = request.get_json(silent=True) or {}

    dhcp = {}
    for key, field in (("DHCP_START", "start"), ("DHCP_END", "end"), ("DHCP_ROUTER", "router")):
        if key in d:
            ip = valid_ip(d[key])
            if not ip:
                return jsonify({"error": f"{key}: ungueltige IP"}), 400
            dhcp[field] = ip

    if "DHCP_START" in dhcp and "DHCP_END" in dhcp:
        if int(ipaddress.IPv4Address(dhcp["start"])) > int(ipaddress.IPv4Address(dhcp["end"])):
            return jsonify({"error": "DHCP_START muss <= DHCP_END sein"}), 400

    if "DHCP_LEASETIME" in d:
        lt = str(d["DHCP_LEASETIME"]).strip()
        if not re.fullmatch(r"\d+[smhdw]?|infinite", lt):
            return jsonify({"error": "Leasetime z.B. 24h"}), 400
        dhcp["leaseTime"] = lt

    update_dns = "PIHOLE_DNS_1" in d or "PIHOLE_DNS_2" in d
    ups = None
    if update_dns:
        ups = [u.strip() for u in (d.get("PIHOLE_DNS_1", ""), d.get("PIHOLE_DNS_2", "")) if str(u).strip()]
        if not all(re.fullmatch(r"[0-9a-zA-Z.:#\[\]-]+", u) for u in ups):
            return jsonify({"error": "Ungueltiger DNS-Server"}), 400

    errors = []
    applied = {"dhcp": False, "dns": False}

    if dhcp:
        _, err = ph("patch", "/config/dhcp", json={"config": {"dhcp": dhcp}})
        if err:
            errors.append({"scope": "dhcp", "error": err})
        else:
            applied["dhcp"] = True

    if update_dns:
        _, err = ph("patch", "/config/dns", json={"config": {"dns": {"upstreams": ups}}})
        if err:
            errors.append({"scope": "dns", "error": err})
        else:
            applied["dns"] = True

    if errors:
        return jsonify({"ok": False, "partial": any(applied.values()), "applied": applied, "errors": errors}), 502

    return jsonify({"ok": True})


@app.route("/api/log")
def get_log():
    data, err = ph("get", "/logs/dnsmasq")
    if err:
        return jsonify({"error": err}), 502

    raw_lines = []
    if isinstance(data, dict) and isinstance(data.get("log"), list):
        for line in data["log"]:
            if isinstance(line, dict):
                raw_lines.append(f"{line.get('timestamp', '')}  {line.get('message', '')}")
            else:
                raw_lines.append(str(line))
    elif isinstance(data, list):
        raw_lines = [str(line) for line in data]

    lines = [line for line in raw_lines if _is_dhcp_event_line(line)][-200:]
    return jsonify({"lines": lines or ["[Keine DHCP-Eintraege gefunden]"]})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
