# hAI.PeeDHCP

DHCP-Verwaltungsoberflaeche fuer Pi-hole v6, mit Flask/Gunicorn und bestehender responsiver deutscher Vanilla-JS-Oberflaeche. Bereitstellung als Portainer-Stack mit fertigem GHCR-Image, ohne lokale Builds und ohne externe Datenbank.

## Installation in Portainer

1. Den GitHub-Actions-Workflow `Docker Image (GHCR)` fuer den gewuenschten Commit auf erfolgreichen Abschluss pruefen. Ein Commit allein bestaetigt weder Tests noch ein verfuegbares Image.
2. In Portainer einen Docker-Standalone-Stack mit dem Inhalt von `docker-compose.yml` anlegen.
3. Pflichtvariablen setzen: `PIHOLE_URL`, `PIHOLE_PASSWORD`, `ADMIN_PIN`, `SECRET_KEY`. Die URL ist die vom Container erreichbare Basisadresse ohne `/api`.
4. `SECRET_KEY` lokal beispielsweise mit `openssl rand -hex 32` erzeugen; mindestens 32 Zeichen und nicht die PIN. Keine Geheimnisse in Git speichern.
5. Bei bestehender Installation zuerst Daten/Stack sichern und `DATA_SOURCE` auf den bisherigen absoluten Datenpfad setzen. Erst danach deployen.

Standardadresse: `http://SERVER-IP:8095`. Standardimage: `ghcr.io/jbkunama1/hai.peedhcp:latest`. Builds sind fuer AMD64 und ARM64 konfiguriert. Die automatisierten Laufzeittests sind AMD64-Tests; ein ARM64-Build ist kein gleichwertiger ARM64-Laufzeitnachweis.

| Variable | Vorgabe / Bedeutung |
|---|---|
| PIHOLE_URL | Pflicht; erreichbare Pi-hole-Basisadresse |
| PIHOLE_PASSWORD | Pflicht; Pi-hole-Passwort |
| ADMIN_PIN | Pflicht im Produktionsstack; Schutz fuer Schreibaktionen |
| SECRET_KEY | Pflicht im Stack; mindestens 32 zufaellige Zeichen |
| APP_PORT | 8095 |
| IMAGE_TAG | latest; alternativ sha-<vollstaendiger Commit-SHA> |
| DATA_SOURCE | Bestehender absoluter Hostpfad; sonst neues Volume |
| PIHOLE_TLS_INSECURE | false; true deaktiviert Zertifikatspruefung ausdruecklich |
| PIHOLE_CA_BUNDLE | Optionaler Containerpfad einer zusaetzlich gemounteten CA-Datei |
| REQUIRE_READ_AUTH | false; true schuetzt weitere lesende APIs per Admin-Token |
| LOG_LEVEL | INFO |

`ALLOW_UNAUTHENTICATED_WRITES` ist im Produktionsstack fest auf false gesetzt. Das Backend kann ohne expliziten SECRET_KEY einen zufaelligen Schluessel im Datenverzeichnis erzeugen; der Standardstack verlangt bewusst eine explizite Konfiguration. Ein Schluesselwechsel macht bestehende Login-Tokens ungueltig.

## HTTPS und Zugriffsschutz

Pi-hole-Zertifikate werden standardmaessig geprueft. Fuer eine eigene CA im Stack unter volumes zusaetzlich beispielsweise `/srv/peedhcp/pihole-ca.crt:/run/certs/pihole-ca.crt:ro` eintragen und `PIHOLE_CA_BUNDLE=/run/certs/pihole-ca.crt` setzen. Der Hostpfad muss bereits eine lesbare Datei sein. Nur als bewusste unsichere Ausnahme `PIHOLE_TLS_INSECURE=true` verwenden. Bei HTTP findet keine TLS-Pruefung statt.

Standardmaessig bleibt die Leseansicht ohne Login verfuegbar. Die Anwendung daher nicht ungeschuetzt im Internet veroeffentlichen. Bei `REQUIRE_READ_AUTH=true` bleiben `/api/settings` fuer den UI-Bootstrap und `/api/livez` weiterhin oeffentlich. Der bestehende Frontend-API-Helper sendet einen vorhandenen Admin-Token auch bei GET-Anfragen. Verhalten nach Login und Tokenablauf beim eigenen Test pruefen. Login-Limits verwenden die direkte Client-IP; hinter einem Proxy koennen mehrere Nutzer denselben Grenzwert teilen.

## Bestehende Daten erhalten

Notizen und Einstellungen liegen unter `/app/data`. Ein neues Docker-Volume uebernimmt die bisherigen `./data`-Dateien NICHT automatisch. Fuer ein bestandserhaltendes Update den bisherigen absoluten Hostpfad als DATA_SOURCE verwenden, dessen Inhalt extern sichern und Schreibrechte fuer Container-UID/GID 1000 pruefen. Keine pauschalen rekursiven Berechtigungsaenderungen an fremden Verzeichnissen. Bei Updates Stacknamen und Datenquelle beibehalten.

## Funktionen und Grenzen

- Aktive Leases und einfache statische MAC/IPv4-Zuweisungen gemeinsam anzeigen, suchen und bearbeiten.
- Reservierungen einzeln oder im Batch speichern; MAC-Aenderungen ohne vorzeitiges Loeschen des alten Eintrags. Nicht unterstuetzte Rohformate bleiben erhalten, werden aber nicht vollstaendig als editierbare Geraete dargestellt.
- Lease zuruecksetzen: MAC wird zur aktiven IP aufgeloest und ueber `DELETE /api/dhcp/leases/{ip}` geloescht. Das erzwingt KEINE sofortige Client-Erneuerung; vorhandene UI-Beschriftungen koennen noch Verlaengerung sagen.
- IP-Vorschlaege verwenden die konfigurierte Netmask oder einen expliziten Bereich. Sie bedeuten nur nicht in bekannten Leases/Reservierungen, nicht garantiert unbenutzt. Bei unbekannter Netmask einen Bereich unter Admin > Netzwerk setzen; der alte /24-Hinweis in der UI ist nicht mehr massgeblich.
- Konfiguration wird vor dem Schreiben validiert; DHCP/DNS werden gemeinsam ueber `/api/config` gesendet. Logs stammen nur aus dnsmasq, nicht aus DNS-Querydaten.
- Backup v2 umfasst hosts, Notizen und Einstellungen; v1 bleibt importierbar. Merge erhaelt fremde Notizen. Replace ersetzt Inhalte und nutzt fuer ausgelassene Einstellungen Standardwerte. Explizites `hosts: []` mit Replace leert Reservierungen bewusst.
- Vor Restore wird ein `restore-<Zeitstempel>.json` im Datenverzeichnis angelegt. Checkpoints schuetzen und extern sichern; Aufbewahrung manuell verwalten.

Pi-hole und lokale Dateien bilden keine gemeinsame Transaktion. Bei Timeout oder fehlgeschlagener Schreibkontrolle kann der upstream bereits geaendert sein: neu laden, nicht blind wiederholen. Teilfehler und Restore-Checkpoint beachten. Lokale Locks schuetzen nur den einzelnen Prozess, nicht gleichzeitige externe Pi-hole-Aenderungen oder mehrere Replikate. Einen Gunicorn-Worker beibehalten.

## CI und Uebergabe

Vor GHCR-Publikation sind Compose-Pruefung, Container-Build, pip check, Python-Syntaxpruefung, isolierte unittest-Tests sowie Nicht-Root-/HTTP-/Persistenz-Smoke-Tests konfiguriert. Die Tests verwenden keine produktiven Zugangsdaten und keinen Live-Pi-hole. Das ist keine vollstaendige Browser- oder Live-DHCP-Abnahme.

Die Deployment- und Praxistests fuehrt der Betreiber selbst durch. Vor Update pruefen: erfolgreicher Workflow fuer genau den Commit, veroeffentlichtes GHCR-Tag, Datenbackup, TLS-Konfiguration und Rollback-Image. Bei privatem GHCR-Package eine passende Registry-Anmeldung in Portainer hinterlegen; Repository-Sichtbarkeit garantiert keine Package-Sichtbarkeit.

Nach Deployment: Login, Listen, Logs, Einstellungen/Notizen, Reset und Export pruefen; Neustart und Persistenz pruefen. Restore und DHCP-Schreibaktionen nur mit gesicherten Daten und bewusst ausgewaehltem Testgeraet bzw. Test-Pi-hole testen. Keine produktiven Leases zum Ausprobieren loeschen.

## Update und Rollback

Den erfolgreich publizierten IMAGE_TAG setzen, in Portainer Image neu ziehen und Stack aktualisieren. Fuer reproduzierbare Updates `sha-<vollstaendiger Commit-SHA>` statt latest verwenden. Vorheriges Image/Tag/Digest und Daten sichern. Fuer Rollback vorheriges Image einstellen und Datenquelle beibehalten; bei inkompatiblen Datenformaten passendes Backup wiederherstellen.

Details: [Backend-Migration](docs/BACKEND-MIGRATION.md).

## Lizenz

MIT, siehe LICENSE.
