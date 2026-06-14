from flask import Flask, jsonify, request, send_from_directory
import os, logging, requests, threading, time
from requests.exceptions import RequestException
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

PIHOLE_URL      = os.getenv("PIHOLE_URL",      "http://192.168.178.1").rstrip("/")
PIHOLE_PASSWORD = os.getenv("PIHOLE_PASSWORD", "")

_session_lock = threading.Lock()
_sid          = None
_sid_expires  = 0


def get_sid():
    """Gibt einen gueltigen Session-Token zurueck, loggt sich bei Bedarf neu ein."""
    global _sid, _sid_expires
    with _session_lock:
        if _sid and time.time() < _sid_expires - 30:
            return _sid
        try:
            r = requests.post(
                f"{PIHOLE_URL}/api/auth",
                json={"password": PIHOLE_PASSWORD},
                timeout=10,
                verify=False,
            )
            r.raise_for_status()
            data = r.json()
            _sid         = data["session"]["sid"]
            validity     = data["session"].get("validity", 1800)
            _sid_expires = time.time() + validity
            app.logger.info("PiHole session renewed")
            return _sid
        except Exception as e:
            app.logger.error(f"PiHole login failed: {e}")
            return None


def ph(method, path, **kwargs):
    """HTTP-Request gegen PiHole v6 API mit automatischer Session."""
    for attempt in range(2):
        sid = get_sid()
        if not sid:
            return None, "PiHole login failed"
        try:
            r = getattr(requests, method)(
                f"{PIHOLE_URL}/api{path}",
                headers={"X-FTL-SID": sid},
                timeout=10,
                verify=False,
                **kwargs,
            )
            if r.status_code == 401 and attempt == 0:
                global _sid
                _sid = None  # Session ungueltig -> neu einloggen
                continue
            r.raise_for_status()
            if r.content:
                return r.json(), None
            return {}, None
        except RequestException as e:
            return None, str(e)
    return None, "Auth failed after retry"


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory("/app/frontend", "index.html")


@app.route("/api/health")
def health():
    data, err = ph("get", "/stats/summary")
    if err:
        return jsonify({"status": "pihole_unreachable", "error": err}), 502
    return jsonify({"status": "ok", "pihole": PIHOLE_URL})


@app.route("/api/leases")
def get_leases():
    data, err = ph("get", "/dhcp/leases")
    if err:
        return jsonify({"error": err}), 502
    leases = data.get("leases", data) if isinstance(data, dict) else data
    return jsonify([{
        "mac":      l.get("hwaddr", l.get("mac", "")),
        "ip":       l.get("ip",     l.get("address", "")),
        "hostname": l.get("name",   l.get("hostname", "*")),
        "expires":  l.get("expires", ""),
        "type":     "dynamic",
    } for l in leases])


# PiHole v6 verwendet /api/dhcp/static_leases (nicht /dhcp/static)
@app.route("/api/static", methods=["GET"])
def get_static():
    data, err = ph("get", "/dhcp/static_leases")
    if err:
        return jsonify({"error": err}), 502
    entries = data.get("static_leases", data.get("staticleases", data.get("static", data))) if isinstance(data, dict) else data
    return jsonify([{
        "mac":      e.get("hwaddr", e.get("mac", "")),
        "ip":       e.get("ip",     e.get("address", "")),
        "hostname": e.get("hostname", e.get("name", "")),
        "comment":  e.get("comment", ""),
    } for e in entries])


@app.route("/api/static", methods=["POST"])
def add_static():
    d = request.json
    if not d.get("mac") or not d.get("ip"):
        return jsonify({"error": "mac and ip required"}), 400
    data, err = ph("post", "/dhcp/static_leases", json={
        "hwaddr":   d["mac"],
        "ip":       d["ip"],
        "hostname": d.get("hostname", ""),
    })
    if err:
        return jsonify({"error": err}), 502
    return jsonify({"ok": True})


@app.route("/api/static/<mac>", methods=["DELETE"])
def del_static(mac):
    _, err = ph("delete", f"/dhcp/static_leases/{mac}")
    if err:
        return jsonify({"error": err}), 502
    return jsonify({"ok": True})


@app.route("/api/config", methods=["GET"])
def get_config():
    data, err = ph("get", "/config")
    if err:
        return jsonify({"error": err}), 502
    cfg  = data.get("config", data) if isinstance(data, dict) else {}
    dhcp = cfg.get("dhcp", {})
    dns  = cfg.get("dns",  {})
    ups  = dns.get("upstreams", [])
    return jsonify({
        "DHCP_START":     dhcp.get("start",     ""),
        "DHCP_END":       dhcp.get("end",       ""),
        "DHCP_ROUTER":    dhcp.get("router",    ""),
        "DHCP_LEASETIME": dhcp.get("leaseTime", ""),
        "PIHOLE_DNS_1":   ups[0] if len(ups) > 0 else "",
        "PIHOLE_DNS_2":   ups[1] if len(ups) > 1 else "",
    })


@app.route("/api/config", methods=["POST"])
def save_config():
    d = request.json
    payload = {"config": {"dhcp": {}}}
    for key, field in [("DHCP_START","start"),("DHCP_END","end"),("DHCP_ROUTER","router"),("DHCP_LEASETIME","leaseTime")]:
        if key in d:
            payload["config"]["dhcp"][field] = d[key]
    _, err = ph("patch", "/config", json=payload)
    if err:
        return jsonify({"error": err}), 502
    return jsonify({"ok": True})


@app.route("/api/log")
def get_log():
    data, err = ph("get", "/queries", params={"type": "DHCP", "limit": 200})
    if err:
        return jsonify({"lines": [f"[Fehler: {err}]"]})
    queries = data.get("queries", []) if isinstance(data, dict) else []
    lines = [
        f"{q.get('time','')}  {q.get('type','')}  {q.get('domain','')}  {q.get('client','')}  {q.get('status','')}"
        for q in queries
    ]
    return jsonify({"lines": lines or ["[Keine DHCP-Eintraege gefunden]"]})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
