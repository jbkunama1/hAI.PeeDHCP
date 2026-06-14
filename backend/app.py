from flask import Flask, jsonify, request, send_from_directory
import os, logging, requests
from requests.exceptions import RequestException

app = Flask(__name__)
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

PIHOLE_URL = os.getenv("PIHOLE_URL", "http://pihole").rstrip("/")
PIHOLE_API_KEY = os.getenv("PIHOLE_API_KEY", "")


def ph_get(path, params=None):
    """GET gegen die PiHole v6 REST-API."""
    headers = {"X-FTL-SID": PIHOLE_API_KEY} if PIHOLE_API_KEY else {}
    try:
        r = requests.get(
            f"{PIHOLE_URL}/api{path}",
            headers=headers,
            params=params or {},
            timeout=10,
            verify=False,
        )
        r.raise_for_status()
        return r.json(), None
    except RequestException as e:
        app.logger.error(f"PiHole API error {path}: {e}")
        return None, str(e)


def ph_post(path, payload):
    headers = {"X-FTL-SID": PIHOLE_API_KEY} if PIHOLE_API_KEY else {}
    try:
        r = requests.post(
            f"{PIHOLE_URL}/api{path}",
            headers=headers,
            json=payload,
            timeout=10,
            verify=False,
        )
        r.raise_for_status()
        return r.json(), None
    except RequestException as e:
        return None, str(e)


def ph_delete(path):
    headers = {"X-FTL-SID": PIHOLE_API_KEY} if PIHOLE_API_KEY else {}
    try:
        r = requests.delete(
            f"{PIHOLE_URL}/api{path}",
            headers=headers,
            timeout=10,
            verify=False,
        )
        r.raise_for_status()
        return True, None
    except RequestException as e:
        return False, str(e)


# ── Static frontend ────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory("/app/frontend", "index.html")


# ── Health ─────────────────────────────────────────────────────────────────────

@app.route("/api/health")
def health():
    data, err = ph_get("/dns/info")
    if err:
        return jsonify({"status": "pihole_unreachable", "error": err}), 502
    return jsonify({"status": "ok", "pihole": PIHOLE_URL})


# ── Leases ─────────────────────────────────────────────────────────────────────

@app.route("/api/leases")
def get_leases():
    """Aktive DHCP-Leases aus /api/dhcp/leases"""
    data, err = ph_get("/dhcp/leases")
    if err:
        return jsonify({"error": err}), 502
    leases = data.get("leases", data) if isinstance(data, dict) else data
    result = []
    for l in leases:
        result.append({
            "mac":      l.get("hwaddr", l.get("mac", "")),
            "ip":       l.get("ip",     l.get("address", "")),
            "hostname": l.get("name",   l.get("hostname", "")),
            "expires":  l.get("expires", ""),
            "type":     "dynamic",
        })
    return jsonify(result)


# ── Static DHCP entries ────────────────────────────────────────────────────────

@app.route("/api/static", methods=["GET"])
def get_static():
    """Statische DHCP-Eintraege aus /api/dhcp/static"""
    data, err = ph_get("/dhcp/static")
    if err:
        return jsonify({"error": err}), 502
    entries = data.get("staticleases", data.get("static", data)) if isinstance(data, dict) else data
    result = []
    for e in entries:
        result.append({
            "mac":      e.get("hwaddr", e.get("mac", "")),
            "ip":       e.get("ip",     e.get("address", "")),
            "hostname": e.get("hostname", e.get("name", "")),
            "comment":  e.get("comment", ""),
        })
    return jsonify(result)


@app.route("/api/static", methods=["POST"])
def add_static():
    d = request.json
    if not d.get("mac") or not d.get("ip"):
        return jsonify({"error": "mac and ip required"}), 400
    payload = {
        "hwaddr":   d["mac"],
        "ip":       d["ip"],
        "hostname": d.get("hostname", ""),
    }
    data, err = ph_post("/dhcp/static", payload)
    if err:
        return jsonify({"error": err}), 502
    return jsonify({"ok": True})


@app.route("/api/static/<mac>", methods=["DELETE"])
def del_static(mac):
    ok, err = ph_delete(f"/dhcp/static/{mac}")
    if err:
        return jsonify({"error": err}), 502
    return jsonify({"ok": True})


# ── DHCP Config ────────────────────────────────────────────────────────────────

@app.route("/api/config", methods=["GET"])
def get_config():
    """DHCP-Einstellungen aus /api/config"""
    data, err = ph_get("/config")
    if err:
        return jsonify({"error": err}), 502
    cfg = data.get("config", data) if isinstance(data, dict) else {}
    dhcp = cfg.get("dhcp", {})
    dns  = cfg.get("dns",  {})
    return jsonify({
        "DHCP_START":     dhcp.get("start",      ""),
        "DHCP_END":       dhcp.get("end",        ""),
        "DHCP_ROUTER":    dhcp.get("router",     ""),
        "DHCP_LEASETIME": dhcp.get("leaseTime",  ""),
        "PIHOLE_DNS_1":   dns.get("upstreams",   [""])[0] if dns.get("upstreams") else "",
        "PIHOLE_DNS_2":   dns.get("upstreams",   ["",""])[1] if len(dns.get("upstreams", [])) > 1 else "",
        "_raw": cfg,
    })


@app.route("/api/config", methods=["POST"])
def save_config():
    d = request.json
    payload = {"config": {"dhcp": {}}}
    mapping = {
        "DHCP_START":     ("dhcp", "start"),
        "DHCP_END":       ("dhcp", "end"),
        "DHCP_ROUTER":    ("dhcp", "router"),
        "DHCP_LEASETIME": ("dhcp", "leaseTime"),
    }
    for key, (section, field) in mapping.items():
        if key in d:
            payload["config"].setdefault(section, {})[field] = d[key]
    data, err = ph_post("/config", payload)
    if err:
        return jsonify({"error": err}), 502
    return jsonify({"ok": True})


# ── Log ────────────────────────────────────────────────────────────────────────

@app.route("/api/log")
def get_log():
    """DHCP-Queries aus /api/queries"""
    data, err = ph_get("/queries", params={"type": "DHCP", "limit": 200})
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
