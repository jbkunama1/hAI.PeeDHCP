from flask import Flask, jsonify, request, send_from_directory
import re, os, subprocess, logging

app = Flask(__name__)
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

LEASES    = os.getenv("PIHOLE_LEASES",      "/data/leases/dnsmasq.leases")
STATIC    = os.getenv("PIHOLE_STATIC_CONF", "/data/dnsmasq/04-pihole-static-dhcp.conf")
SETUPVARS = os.getenv("PIHOLE_SETUPVARS",   "/data/pihole/setupVars.conf")
LOGFILE   = "/data/pihole.log"

def pihole_reload():
    try:
        subprocess.run(["pihole", "restartdns", "reload"], timeout=15, check=True)
    except Exception as e:
        app.logger.warning(f"reload failed: {e}")

@app.route("/")
def index():
    return send_from_directory("/app/frontend", "index.html")

@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})

@app.route("/api/leases")
def get_leases():
    leases = []
    try:
        with open(LEASES) as f:
            for line in f:
                p = line.strip().split()
                if len(p) >= 4:
                    leases.append({"expires": p[0], "mac": p[1], "ip": p[2], "hostname": p[3]})
    except FileNotFoundError:
        return jsonify({"error": "leases file not found"}), 404
    return jsonify(leases)

@app.route("/api/static", methods=["GET"])
def get_static():
    entries = []
    try:
        with open(STATIC) as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                m = re.match(r"dhcp-host=([^,]+),([^,]+),([^\s,]+)(?:,#(.*))?", line)
                if m:
                    entries.append({"mac": m[1], "ip": m[2], "hostname": m[3], "comment": m[4] or ""})
    except FileNotFoundError:
        return jsonify({"error": "static conf not found"}), 404
    return jsonify(entries)

@app.route("/api/static", methods=["POST"])
def add_static():
    d = request.json
    if not d.get("mac") or not d.get("ip"):
        return jsonify({"error": "mac and ip required"}), 400
    comment = f",#{d['comment']}" if d.get("comment") else ""
    entry = f"dhcp-host={d['mac']},{d['ip']},{d.get('hostname', d['mac'])}{comment}\n"
    with open(STATIC, "a") as f:
        f.write(entry)
    pihole_reload()
    return jsonify({"ok": True})

@app.route("/api/static/<mac>", methods=["DELETE"])
def del_static(mac):
    try:
        with open(STATIC) as f:
            lines = f.readlines()
        with open(STATIC, "w") as f:
            f.writelines(l for l in lines if mac.lower() not in l.lower())
        pihole_reload()
    except FileNotFoundError:
        return jsonify({"error": "static conf not found"}), 404
    return jsonify({"ok": True})

@app.route("/api/config", methods=["GET"])
def get_config():
    cfg = {}
    try:
        with open(SETUPVARS) as f:
            for line in f:
                if "=" in line and not line.startswith("#"):
                    k, _, v = line.strip().partition("=")
                    cfg[k] = v
    except FileNotFoundError:
        return jsonify({"error": "setupVars not found"}), 404
    return jsonify(cfg)

@app.route("/api/config", methods=["POST"])
def save_config():
    d = request.json
    keys = {"DHCP_START", "DHCP_END", "DHCP_ROUTER", "DHCP_LEASETIME", "PIHOLE_DNS_1", "PIHOLE_DNS_2"}
    try:
        with open(SETUPVARS) as f:
            lines = f.readlines()
        updated = []
        found = set()
        for line in lines:
            key = line.split("=")[0] if "=" in line else ""
            if key in keys and key in d:
                updated.append(f"{key}={d[key]}\n")
                found.add(key)
            else:
                updated.append(line)
        for key in keys:
            if key not in found and key in d:
                updated.append(f"{key}={d[key]}\n")
        with open(SETUPVARS, "w") as f:
            f.writelines(updated)
        pihole_reload()
    except FileNotFoundError:
        return jsonify({"error": "setupVars not found"}), 404
    return jsonify({"ok": True})

@app.route("/api/log")
def get_log():
    try:
        with open(LOGFILE) as f:
            lines = f.readlines()[-200:]
        return jsonify({"lines": [l.rstrip() for l in lines if "dhcp" in l.lower()]})
    except FileNotFoundError:
        return jsonify({"lines": ["[Log-Datei nicht gefunden]"]})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
