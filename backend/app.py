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
    global _sid, _sid_expires
    with _session_lock:
        if _sid and time.time() < _sid_expires - 30:
            return _sid
        try:
            r = requests.post(
                f"{PIHOLE_URL}/api/auth",
                json={"password": PIHOLE_PASSWORD},
                timeout=10, verify=False,
            )
            r.raise_for_status()
            data = r.json()
            _sid         = data["session"]["sid"]
            _sid_expires = time.time() + data["session"].get("validity", 1800)
            app.logger.info("PiHole session renewed")
            return _sid
        except Exception as e:
            app.logger.error(f"PiHole login failed: {e}")
            return None


def ph(method, path, **kwargs):
    for attempt in range(2):
        sid = get_sid()
        if not sid:
            return None, "PiHole login failed"
        try:
            r = getattr(requests, method)(
                f"{PIHOLE_URL}/api{path}",
                headers={"X-FTL-SID": sid},
                timeout=10, verify=False,
                **kwargs,
            )
            if r.status_code == 401 and attempt == 0:
                global _sid
                _sid = None
                continue
            r.raise_for_status()
            return (r.json() if r.content else {}), None
        except RequestException as e:
            return None, str(e)
    return None, "Auth failed after retry"


def parse_hosts(hosts):
    result = []
    for h in hosts:
        parts = h.split(",")
        if len(parts) >= 2:
            result.append({
                "mac":      parts[0].strip(),
                "ip":       parts[1].strip(),
                "hostname": parts[2].strip() if len(parts) > 2 else "",
                "comment":  "",
            })
    return result


# ── Routes ──────────────────────────────────────────────────────────────────

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


@app.route("/api/all_devices")
def all_devices():
    """Kombinierte Liste: aktive Leases + statische Eintraege."""
    leases_data, err1 = ph("get", "/dhcp/leases")
    static_data, err2 = ph("get", "/config/dhcp")

    leases  = leases_data.get("leases", []) if leases_data else []
    hosts   = static_data.get("config", {}).get("dhcp", {}).get("hosts", []) if static_data else []
    statics = parse_hosts(hosts)

    # Index statische Eintraege nach MAC
    static_macs = {s["mac"].lower(): s for s in statics}

    devices = []
    seen_macs = set()

    for l in leases:
        mac = l.get("hwaddr", l.get("mac", ""))
        mac_l = mac.lower()
        seen_macs.add(mac_l)
        st = static_macs.get(mac_l)
        devices.append({
            "mac":      mac,
            "ip":       l.get("ip", l.get("address", "")),
            "hostname": l.get("name", l.get("hostname", "")),
            "expires":  l.get("expires", ""),
            "is_static": st is not None,
            "static_ip": st["ip"] if st else "",
            "type":     "static+active" if st else "dynamic",
        })

    # Statische die gerade nicht aktiv sind
    for s in statics:
        if s["mac"].lower() not in seen_macs:
            devices.append({
                "mac":       s["mac"],
                "ip":        s["ip"],
                "hostname":  s["hostname"],
                "expires":   "",
                "is_static": True,
                "static_ip": s["ip"],
                "type":      "static",
            })

    return jsonify(devices)


@app.route("/api/static", methods=["GET"])
def get_static():
    data, err = ph("get", "/config/dhcp")
    if err:
        return jsonify({"error": err}), 502
    hosts = data.get("config", {}).get("dhcp", {}).get("hosts", [])
    return jsonify(parse_hosts(hosts))


@app.route("/api/static", methods=["POST"])
def add_static():
    d = request.json
    if not d.get("mac") or not d.get("ip"):
        return jsonify({"error": "mac and ip required"}), 400
    data, err = ph("get", "/config/dhcp")
    if err:
        return jsonify({"error": err}), 502
    hosts = data.get("config", {}).get("dhcp", {}).get("hosts", [])
    # Evtl. bestehenden Eintrag fuer diese MAC ersetzen
    hosts = [h for h in hosts if not h.lower().startswith(d["mac"].lower())]
    hosts.append(f"{d['mac']},{d['ip']},{d.get('hostname', '')}")
    _, err = ph("patch", "/config/dhcp", json={"config": {"dhcp": {"hosts": hosts}}})
    if err:
        return jsonify({"error": err}), 502
    return jsonify({"ok": True})


@app.route("/api/static/<mac>", methods=["DELETE"])
def del_static(mac):
    data, err = ph("get", "/config/dhcp")
    if err:
        return jsonify({"error": err}), 502
    hosts = data.get("config", {}).get("dhcp", {}).get("hosts", [])
    hosts = [h for h in hosts if not h.lower().startswith(mac.lower())]
    _, err = ph("patch", "/config/dhcp", json={"config": {"dhcp": {"hosts": hosts}}})
    if err:
        return jsonify({"error": err}), 502
    return jsonify({"ok": True})


@app.route("/api/lease/renew", methods=["POST"])
def renew_lease():
    """Lease verlaengern: Eintrag aus Leases loeschen und neu einloesen lassen."""
    d = request.json
    mac = d.get("mac", "")
    if not mac:
        return jsonify({"error": "mac required"}), 400
    # PiHole v6: DELETE /dhcp/leases/{mac} loescht den Lease -> Geraet holt sich neuen
    _, err = ph("delete", f"/dhcp/leases/{mac}")
    if err:
        return jsonify({"error": err}), 502
    return jsonify({"ok": True, "msg": "Lease geloescht – Geraet erhaelt bei naechster Anfrage neuen Lease"})


@app.route("/api/lease/<mac>", methods=["DELETE"])
def del_lease(mac):
    """Aktiven Lease loeschen."""
    _, err = ph("delete", f"/dhcp/leases/{mac}")
    if err:
        return jsonify({"error": err}), 502
    return jsonify({"ok": True})


@app.route("/api/config", methods=["GET"])
def get_config():
    data, err = ph("get", "/config/dhcp")
    if err:
        return jsonify({"error": err}), 502
    dhcp = data.get("config", {}).get("dhcp", {})
    dns_data, _ = ph("get", "/config/dns")
    dns  = dns_data.get("config", {}).get("dns", {}) if dns_data else {}
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
    _, err = ph("patch", "/config/dhcp", json=payload)
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
