<div align="center">

# 🌐 hAI.PeeDHCP

**DHCP Admin Dashboard für PiHole v6 – als Portainer Stack**

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](docker-compose.yml)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](backend/app.py)
[![PiHole](https://img.shields.io/badge/PiHole-v6-96060C?style=for-the-badge&logo=pi-hole&logoColor=white)](https://pi-hole.net)
[![TruffleHog](https://img.shields.io/badge/TruffleHog-Scanning-FF6B35?style=for-the-badge&logo=github-actions&logoColor=white)](.github/workflows/trufflehog.yml)
[![GitHub last commit](https://img.shields.io/github/last-commit/jbkunama1/hAI.PeeDHCP?style=for-the-badge)](https://github.com/jbkunama1/hAI.PeeDHCP/commits)

> Eine schlanke, containerisierte Admin-Oberfläche zum Verwalten der PiHole-DHCP-Konfiguration – über die **PiHole v6 REST-API**.
> PiHole bleibt dabei vollständig primär und funktionsfähig. Keine Dateizugriffe, keine Volumes.

**[🌐 Projektseite](https://jbkunama1.github.io/hAI.PeeDHCP)**

</div>

---

## ✨ Features

| Feature | Beschreibung |
|---|---|
| 📊 **Dashboard** | KPI-Cards: aktive Leases, statische Einträge, Pool-Größe, Leasetime |
| 📋 **Aktive Leases** | Echtzeit-Tabelle via PiHole API mit Suchfilter |
| 📌 **Statische Einträge** | MAC → IP Bindungen hinzufügen & löschen |
| ⚙️ **Konfiguration** | DHCP-Pool, Gateway, DNS, Leasetime bearbeiten |
| 📄 **DHCP-Log** | Live-Logansicht mit Farbfilter |
| 🔄 **Auto-Session** | Login per Passwort, Session-Token wird automatisch erneuert |
| 🌙 **Dark/Light Mode** | System-aware Theme, manuell umschaltbar |
| 🐳 **Portainer-Ready** | Einzelner Stack, keine externen Abhängigkeiten, keine Volumes |

---

## 🛡️ Authentifizierung

hAI.PeeDHCP nutzt die **PiHole v6 REST-API** mit automatischem Session-Management:

1. Beim ersten Request loggt sich das Backend mit `PIHOLE_PASSWORD` ein
2. Der Session-Token (`sid`) wird im Speicher gecacht
3. Bei Ablauf wird automatisch ein neuer Token geholt
4. Du musst **nie manuell einen API-Key kopieren**

---

## 🏗️ Architektur

```
┌─────────────────────────────────────────────────────┐
│                    Host (DietPi/Debian)             │
│                                                     │
│  ┌──────────────┐        ┌───────────────────────┐  │
│  │   PiHole v6  │  HTTP  │   hAI.PeeDHCP Stack   │  │
│  │  :80/api/... │◄──────►│  Flask + Gunicorn     │  │
│  │  (primär)    │ REST  │  :8080 → Host :8095  │  │
│  └──────────────┘       └───────────────────────┘  │
└─────────────────────────────────────────────────────┘
         Browser → http://<server-ip>:8095
```

**Keine Volumes** – der Container braucht nur Netzwerkzugriff auf PiHole.

---

## 🚀 Installation

### Voraussetzungen

- Docker & Docker Compose (oder Portainer)
- PiHole **v6** läuft bereits auf demselben oder erreichbaren Host
- Port `8095` frei

### 1️⃣ Repository klonen

```bash
git clone https://github.com/jbkunama1/hAI.PeeDHCP.git
cd hAI.PeeDHCP
```

### 2️⃣ `.env` anlegen

```bash
cp .env.example .env
joe .env   # oder nano/vim
```

Nur zwei Werte müssen gesetzt werden:

```env
PIHOLE_URL=http://192.168.178.1      # IP deines PiHole-Hosts
PIHOLE_PASSWORD=dein-pihole-passwort # PiHole Web-Passwort
```

> 💡 Das Passwort wird **nur einmalig zum Login** verwendet. Der Session-Token wird gecacht und automatisch erneuert.

### 3️⃣ Starten

```bash
docker compose up -d --build
```

### 4️⃣ Dashboard aufrufen

```
http://<server-ip>:8095
```

### Als Portainer Stack

In Portainer → **Stacks → Add Stack → Upload** → `docker-compose.yml`
Environment-Variablen direkt in Portainer als Stack-Env setzen.

---

## 🔧 API-Endpunkte

| Method | Endpoint | PiHole API | Beschreibung |
|---|---|---|---|
| `GET` | `/api/leases` | `/api/dhcp/leases` | Aktive DHCP-Leases |
| `GET` | `/api/static` | `/api/dhcp/static` | Statische Einträge |
| `POST` | `/api/static` | `/api/dhcp/static` | Eintrag hinzufügen |
| `DELETE` | `/api/static/<mac>` | `/api/dhcp/static/<mac>` | Eintrag löschen |
| `GET` | `/api/config` | `/api/config` | DHCP-Konfiguration |
| `POST` | `/api/config` | `/api/config` (PATCH) | Konfiguration speichern |
| `GET` | `/api/log` | `/api/queries` | DHCP-Log |
| `GET` | `/api/health` | `/api/stats/summary` | Health Check |

---

## 📁 Projektstruktur

```
hAI.PeeDHCP/
├── .github/
│   └── workflows/
│       └── trufflehog.yml       # Secret Scanning
├── backend/
│   ├── app.py                   # Flask API + PiHole Session-Manager
│   └── requirements.txt
├── docs/
│   └── index.html               # GitHub Pages Projektseite
├── frontend/
│   └── index.html               # Admin UI
├── .env.example
├── .gitignore
├── docker-compose.yml
├── Dockerfile
├── LICENSE
└── README.md
```

---

## 🔒 Sicherheitshinweise

> ⚠️ **Nie direkt ins Internet exponieren** – nur im LAN oder via VPN.

- `PIHOLE_PASSWORD` als Portainer-Secret oder in `.env` (nie committen)
- Zugriff per Traefik + BasicAuth oder Cloudflare Access absichern
- `.env` ist in `.gitignore` eingetragen

---

## 🛡️ Security Scanning

Automatisches Secret-Scanning mit **TruffleHog** bei jedem Push und Pull Request.

---

## 📄 Lizenz

[MIT License](LICENSE) – Copyright © 2026 jbkunama1

---

<div align="center">
Made with ❤️ by <a href="https://github.com/jbkunama1">@jbkunama1</a> &nbsp;|&nbsp; Part of the <strong>hAI.</strong> project family
</div>
