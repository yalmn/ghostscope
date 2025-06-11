# GhostScope

GhostScope ist ein Kommandozeilen-Tool zur Schwachstellensuche mithilfe der [Shodan API](https://www.shodan.io/).

## Funktionen

- Durchsucht IP-Bereiche automatisch nach verwundbaren Geräten
- Nutzt die Shodan-API für netzwerkweite Schwachstelleninformationen
- Erkennt CVEs mit CVSS-Werten und End-of-Life (EOL) Informationen
- Erstellt übersichtliche HTML-Berichte
- Optional: Integration mit Nmap zur tieferen Analyse
- Filtert ungültige IP-Adressen automatisch heraus

## Installation

1. Repository klonen

   ```bash
   git clone https://github.com/yalmn/ghostscope.git
   cd ghostscope

2. Abhängigkeiten installieren

   Stelle sicher, dass folgende Pakete auf deinem System installiert sind:

   - libcurl  
   - cJSON  
   - gcc oder ein anderer C-Compiler  
   - make

   Unter Debian/Ubuntu:

   ```bash
   sudo apt update
   sudo apt install libcurl4-openssl-dev libcjson-dev build-essential

3. Projekt bauen
   
    - make

## Nutzung

### API-Key hinterlegen

Erstelle im Projektverzeichnis eine Datei namens `apikey.txt` und füge deinen [Shodan API Key](https://account.shodan.io/) dort ein.

### IP-Ranges definieren

Erstelle eine Datei `iprange.txt` mit IP-Adressen oder CIDR-Ranges, z. B.:
192.168.1.0/24

### Tool ausführen

  ```bash
  ./ghostscope --all (Für weitere Flags --help)

Weitere Optionen:

```bash
./ghostscope --attack   # Erstellt cve-attack-vector.html
```
