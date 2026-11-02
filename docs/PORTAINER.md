# Portainer-Uebergabe

Die aktuelle und verbindliche Anleitung samt Variablen, CA-Mount, Datenuebernahme, Tests und Rollback steht in der [README](../README.md). Aeltere Hinweise auf deaktivierte TLS-Pruefung sind ueberholt: Seit der Backend-Modernisierung ist sie standardmaessig aktiv.

Der Betreiber deployt und testet selbst. Vorher GitHub-Actions-Ergebnis und GHCR-Tag fuer genau den gewuenschten Commit pruefen. Dieser Dokumentationsstand bestaetigt keine erfolgreichen CI- oder Live-Tests.

Fuer Bestandsinstallationen DATA_SOURCE auf den bisherigen absoluten Hostpfad setzen. Ohne diese Angabe wird ein neues, leeres stackbezogenes Volume verwendet; keine automatische Datenmigration.
