# NetworkScanner

A cross-platform Python GUI for network discovery, TCP port scanning, and basic service analysis.

> ⚠️ **Use only on networks and devices you own or are authorized to scan.**

## Features

* Automatic local network discovery
* Fast, Standard, Full and Custom scan profiles
* Concurrent host and port scanning
* TCP service and banner detection
* HTTP/HTTPS and TLS analysis
* Basic OS hints and security assessment
* Scan history stored locally
* Export to CSV, JSON and HTML
* Built with Python standard library only

## Requirements

* Python 3
* Tkinter

No third-party Python packages are required.

## Usage

```bash
python NetworkScanner.py
```

Select a scan profile, start the network scan, and select a discovered device to perform a detailed port scan.

### Scan Profiles

| Profile  | Ports                     |
| -------- | ------------------------- |
| Fast     | Common ports              |
| Standard | Common ports + `1-1024`   |
| Full     | `1-65535`                 |
| Custom   | User-defined ports/ranges |

## Exports

Results can be exported as:

* CSV
* JSON
* HTML

Scan history is stored in `~/.networkscanner_history.json` with up to 50 snapshots.

## Disclaimer

This tool is intended for network administration, inventory and authorized security testing. It is **not a full vulnerability scanner** and should not be used against systems without permission.
