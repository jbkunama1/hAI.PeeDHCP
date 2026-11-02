# Backend-Modernisierung: Migration und Pruefstatus

Vor Deployment CI abwarten: bestehende Vertragstests und neue Sicherheitstests laufen ohne Netzwerk im Container. Dieser Commit ist kein Nachweis eines erfolgreichen Live-Tests. Es wurden keine produktiven DHCP-Eintraege veraendert. Python-Version, AMD64/ARM64-Build und Portainer-Grundkonfiguration bleiben erhalten. ARM64-Laufzeittests sind weiterhin nicht gleichwertig zu AMD64 belegt.

## Sicherheitskonfiguration

SECRET_KEY muss mindestens 32 Zeichen lang und unabhaengig von ADMIN_PIN sein. Bestehende kurze Schluessel vor Update ersetzen; dadurch werden alte Login-Tokens ungueltig. Ohne SECRET_KEY wird ein zufaelliger Schluessel im persistenten DATA_DIR gespeichert. Ohne ADMIN_PIN sind Schreibaktionen standardmaessig gesperrt. ALLOW_UNAUTHENTICATED_WRITES=true ist nur ein bewusster unsicherer Opt-in. Rate-Limiting verwendet die direkte Clientadresse, nicht ungepruefte Forwarded-Header. Hinter einem Proxy koennen alle Nutzer einen gemeinsamen Grenzwert teilen. Nur einen Gunicorn-Worker verwenden. Locks und Login-Limits sind pro Prozess, nicht fuer mehrere Replikate geeignet.

TLS-Zertifikate werden jetzt geprueft. Fuer selbstsignierte Pi-hole-Zertifikate bevorzugt eine eigene CA einbinden. PIHOLE_CA_BUNDLE ist der lesbare Containerpfad einer gemounteten CA-Datei. Nur als ausdrueckliche unsichere Ausnahme PIHOLE_TLS_INSECURE=true setzen. REQUIRE_READ_AUTH=true schuetzt lesende Daten-APIs zusaetzlich, standardmaessig bleibt die bisherige Leseansicht erhalten. /api/settings und /api/livez sind fuer Bootstrap/Health weiterhin oeffentlich. Frontend und Zugriffsschutz in dieser optionalen Betriebsart vor externer Freigabe testen.

Diese optionalen Variablen muessen im Portainer-Stack unter environment ergaenzt werden; das Hinterlegen als Portainer-Variable allein reicht nicht, solange keine Zuordnung im Compose-Text existiert. CA-Dateien muessen zusaetzlich read-only gemountet werden.

## Daten und Verhalten

Bestehenden Datenpfad und Pi-hole-Konfiguration vor Update sichern. Backup v1 bleibt importierbar. Export v2 enthaelt hosts, meta und settings. Merge erhaelt fremde Notizen, Replace ersetzt Notizen und setzt ausgelassene Einstellungen auf Standardwerte. Ein explizites leeres hosts-Array mit mode=replace leert Reservierungen bewusst; ein fehlendes hosts-Feld wird abgelehnt. Vor jedem Restore wird ein restore-<Zeitstempel>.json im Datenverzeichnis gesichert. Diese Checkpoints enthalten Netzwerkdaten, muessen geschuetzt und regelmaessig extern gesichert/aufgeraeumt werden.

Pi-hole-Schreibvorgaenge und lokale Dateien bilden keine gemeinsame Transaktion. Bei Timeouts oder fehlgeschlagener Schreibkontrolle kann der upstream bereits geaendert sein: Status neu laden, nicht blind wiederholen. Teilfehler werden gemeldet; Checkpoint bei Restore verwenden. Gleichzeitige externe Pi-hole-Konfigurationsaenderungen sind nicht durch den lokalen Prozess-Lock ausgeschlossen.

Lease-Reset loescht per aufgeloester IP. Er erzwingt keine sofortige Client-Erneuerung. Der alte /api/lease/renew-Pfad bleibt kompatibel; bestehende UI-Texte koennen weiterhin eine Verlaengerung suggerieren. IP-Vorschlaege verwenden konfigurierte Netmask oder einen expliziten Bereich, nicht geratenes /24. Sie bedeuten nur nicht in bekannten Leases/Reservierungen, niemals nachweislich unbenutzt. DHCP-Logs werden ausschliesslich aus dnsmasq gelesen; fehlendes DHCP-Logging in Pi-hole aktivieren.

## Abnahme vor produktivem Update

CI-Testergebnisse und GHCR-Image bestaetigen; Volume/Bind-Pfad, Berechtigungen und Rollback-Tag pruefen. Mobil/Desktop, Login, Notizen, Settings, Listen, Logs und Export pruefen. Restore und Reservierungsaenderungen zuerst mit isoliertem Test-Pi-hole und gesicherten Daten testen, einschliesslich ungueltiger Eingaben und upstream-Ausfall. Live-DHCP-Schreibtests nur nach separater Freigabe mit eindeutigem Testgeraet. Kein automatisches Server-Deployment durch diesen Commit.
