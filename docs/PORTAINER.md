# Portainer mit GHCR-Image

## Umfang dieses Deployment-Schritts

Der Produktionsstack verwendet ein fertiges Image statt lokaler Builds. Backend und Frontend bleiben funktional unveraendert. Dieser Schritt behebt noch nicht die separat festgestellten Backendfehler. Python 3.11 und die bestehenden Dependency-Pins werden hier bewusst beibehalten; dies ist kein Nachweis aktueller oder schwachstellenfreier Abhaengigkeiten.

## Vor einem bestehenden Deployment

1. Bisherigen Stacktext, Umgebungsvariablen und verwendetes Image samt Digest sichern.
2. Den bisherigen absoluten Hostpfad des nach /app/data gemounteten Verzeichnisses feststellen und extern sichern. Ein neues Docker-Volume uebernimmt dessen Dateien NICHT automatisch.
3. Fuer ein bestandserhaltendes Update DATA_SOURCE auf genau diesen absoluten Hostpfad setzen, zum Beispiel /srv/peedhcp/data. Keine relativen Pfade verwenden. Vorhandene Dateien muessen fuer Container-UID/GID 1000 beschreibbar sein. Berechtigungen nicht pauschal rekursiv auf beliebigen Verzeichnissen aendern.
4. Ohne DATA_SOURCE wird ein neues, stackbezogenes Volume peedhcp_data verwendet. Das ist fuer Neuinstallationen vorgesehen. Den Portainer-Stacknamen bei Updates beibehalten.

## Installation

Erst nach erfolgreichem GHCR-Workflow deployen. In Portainer einen Docker-Standalone-Stack mit dem Inhalt von docker-compose.yml anlegen. Es werden weder ein Repository-Checkout auf dem Host noch eine lokale .env oder ein Frontend-Bind-Mount benoetigt.

Variablen:

| Variable | Bedeutung |
|---|---|
| PIHOLE_URL | Vom Container erreichbare Pi-hole-Basisadresse ohne /api |
| PIHOLE_PASSWORD | Pi-hole-Passwort, nur in Portainer hinterlegen |
| ADMIN_PIN | Eigene Admin-PIN fuer Schreibaktionen |
| SECRET_KEY | Unabhaengiger langer zufaelliger Signaturschluessel; nicht die PIN wiederverwenden |
| APP_PORT | Optional, Standard 8095 |
| IMAGE_TAG | Optional, Standard latest; fuer reproduzierbare Updates sha-<vollstaendiger Commit-SHA> verwenden |
| DATA_SOURCE | Optional, bestehender absoluter Datenpfad statt neuem Volume |
| LOG_LEVEL | Optional, Standard INFO |

Zufaelligen SECRET_KEY beispielsweise lokal mit `openssl rand -hex 32` erzeugen. Geheimnisse nicht in Git committen. Die Oberflaeche ist unter http://SERVER-IP:8095 erreichbar. Nicht ungeschuetzt im Internet veroeffentlichen. Lesende APIs sind im bisherigen Backend weiterhin ohne Login erreichbar und die bisherige Pi-hole-TLS-Zertifikatspruefung ist noch deaktiviert.

Ist das GHCR-Package privat, benoetigt Portainer eine passende GHCR-Registry-Anmeldung mit Leseberechtigung. Alternativ kann der Besitzer die Package-Sichtbarkeit bewusst auf public setzen. Das Repository allein garantiert keine oeffentliche Image-Verfuegbarkeit.

## Tests und Healthcheck

Vor dem Multiarch-Publish prueft CI Compose-Konfiguration, Container-Build, Python-Syntax, pip check, HTTP-Start, Nicht-Root-Betrieb, Schreiben ins Datenvolume und Persistenz ueber einen Container-Neustart. Alle Zugangsdaten sind CI-Dummys; Pi-hole zeigt im Test auf einen nicht erreichbaren Loopback-Port. Dies ist ein Smoke-Test, KEIN vollstaendiger DHCP-Regressionstest. Der ausfuehrbare Smoke-Test laeuft auf AMD64; ARM64 wird anschliessend gebaut, aber nicht gleichwertig zur Laufzeit getestet.

Docker prueft die lokale Startseite. /api/health bleibt der separate Pi-hole-Verbindungstest und kann bei Pi-hole-Ausfall HTTP 502 liefern, ohne die lokale Container-Gesundheit von Pi-hole abhaengig zu machen. Ein gesunder Container beweist keine funktionierenden DHCP-Schreibaktionen.

## Update und Rollback

Aktuelles Image/Digest und Daten sichern. Gewuenschten erfolgreich publizierten IMAGE_TAG setzen, in Portainer Image neu ziehen und Stack aktualisieren. DATA_SOURCE beziehungsweise das vorhandene Volume beibehalten. Fuer Rollback den zuvor notierten Image-Tag verwenden und erneut deployen; Daten nicht loeschen. Bei spaeteren Datenformat-Aenderungen ist ein passendes Backup erforderlich.

Nach Deployment pruefen: Oberflaeche mobil/desktop, Pi-hole-Verbindungsstatus, Leases und statische Eintraege, Admin-Login, Einstellungen/Notizen und deren Persistenz. Schreibende DHCP-Tests nur mit bewusst ausgewaehltem Testgeraet und vorherigem Pi-hole-Backup durchfuehren. Bestehende produktive Leases nicht zum Test loeschen.
