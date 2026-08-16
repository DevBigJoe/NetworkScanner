#!/usr/bin/env python3
"""
NetworkScanner3
Cross-platform network inventory and TCP service scanner.

Use only on networks/devices you own or are authorized to scan.
Standard-library only; optional TLS/HTTP analysis uses Python's stdlib.
"""

import csv
import datetime as dt
import http.client
import ipaddress
import json
import os
import platform
import re
import socket
import ssl
import subprocess
import time
import threading
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from urllib.parse import urlparse


APP_NAME = "NetworkScanner"
HISTORY_FILE = Path.home() / ".networkscanner_history.json"

SERVICE_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    587: "SMTP", 631: "IPP", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 465: "SMTPS", 636: "LDAPS", 990: "FTPS",
    5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",
}

COMMON_PORTS = sorted(set(SERVICE_PORTS) | {
    88, 161, 500, 554, 548, 8000, 8008, 8009, 8080, 8081, 8082, 9000
})


class NetworkScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("1450x820")
        self.root.minsize(1050, 650)

        self.cancel_event = threading.Event()
        self.scan_lock = threading.Lock()
        self.devices = []
        self.current_scan = None
        self.port_total = 0
        self.port_done = 0
        self.device_total = 0
        self.device_done = 0

        self._build_gui()
        self._load_history()

    def sort_device_tree(self, column, reverse):
        rows = [
            (self.device_tree.set(item, column), item)
            for item in self.device_tree.get_children("")
        ]

        if column == "IP":
            rows.sort(
                key=lambda item: tuple(
                    int(part)
                    for part in item[0].split(".")
                ),
                reverse=reverse,
            )
        else:
            rows.sort(
                key=lambda item: item[0].lower(),
                reverse=reverse,
            )

        for index, (_, item) in enumerate(rows):
            self.device_tree.move(item, "", index)

        self.device_tree.heading(
            column,
            command=lambda c=column: self.sort_device_tree(c, not reverse)
        )

    # ---------- GUI ----------

    def _build_gui(self):
        top = ttk.Frame(self.root, padding=8)
        top.pack(fill=tk.X)

        ttk.Label(top, text="Scanprofil:").pack(side=tk.LEFT)
        self.profile_var = tk.StringVar(value="Standard")
        ttk.Combobox(
            top,
            textvariable=self.profile_var,
            values=("Schnell", "Standard", "Vollständig", "Benutzerdefiniert"),
            state="readonly",
            width=18,
        ).pack(side=tk.LEFT, padx=(5, 15))

        ttk.Label(top, text="Benutzerdefinierte Ports:").pack(side=tk.LEFT)
        self.custom_ports_var = tk.StringVar(
            value="22,53,80,135,139,443,445,3389,8080"
        )
        ttk.Entry(top, textvariable=self.custom_ports_var, width=34).pack(
            side=tk.LEFT, padx=5
        )

        self.scan_btn = ttk.Button(
            top, text="Netzwerk scannen", command=self.start_network_scan
        )
        self.scan_btn.pack(side=tk.LEFT, padx=5)

        self.cancel_btn = ttk.Button(
            top, text="Abbrechen", command=self.cancel_scan, state=tk.DISABLED
        )
        self.cancel_btn.pack(side=tk.LEFT, padx=5)

        ttk.Button(
            top, text="CSV", command=lambda: self.export_data("csv")
        ).pack(side=tk.RIGHT, padx=2)
        ttk.Button(
            top, text="JSON", command=lambda: self.export_data("json")
        ).pack(side=tk.RIGHT, padx=2)
        ttk.Button(
            top, text="HTML", command=lambda: self.export_data("html")
        ).pack(side=tk.RIGHT, padx=2)

        filter_frame = ttk.Frame(self.root, padding=(8, 0, 8, 8))
        filter_frame.pack(fill=tk.X)

        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT)
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self.refresh_device_tree())
        ttk.Entry(filter_frame, textvariable=self.filter_var, width=45).pack(
            side=tk.LEFT, padx=5
        )

        self.status_var = tk.StringVar(value="Bereit")
        ttk.Label(filter_frame, textvariable=self.status_var).pack(side=tk.RIGHT)

        paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        left = ttk.LabelFrame(paned, text="Geräte")
        right = ttk.LabelFrame(paned, text="Details")
        paned.add(left, weight=1)
        paned.add(right, weight=2)

        self.device_tree = ttk.Treeview(
            left,
            columns=("IP", "Hostname", "MAC", "Hersteller", "OS", "Ports"),
            show="headings",
        )
        headings = {
            "IP": "IP",
            "Hostname": "Hostname",
            "MAC": "MAC",
            "Hersteller": "Hersteller",
            "OS": "OS-Hinweis",
            "Ports": "Ports",
        }
        widths = {"IP": 120, "Hostname": 180, "MAC": 140,
                  "Hersteller": 160, "OS": 130, "Ports": 60}
        for col in headings:
            self.device_tree.heading(col,
                                     text=headings[col],
                                     command=lambda c=col: self.sort_device_tree(c, False)
                                     )
            self.device_tree.column(col, width=widths[col], anchor=tk.W)
        self.device_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.device_tree.bind("<<TreeviewSelect>>", self.on_device_selected)

        self.notebook = ttk.Notebook(right)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.info_text = tk.Text(self.notebook, wrap="word")
        self.port_tree = ttk.Treeview(
            self.notebook,
            columns=("Port", "Service", "State", "Details"),
            show="headings",
        )
        for col, width in (
            ("Port", 80), ("Service", 130), ("State", 90), ("Details", 500)
        ):
            self.port_tree.heading(col, text=col)
            self.port_tree.column(col, width=width, anchor=tk.W)

        self.notebook.add(self.info_text, text="Geräteinfo")
        self.notebook.add(self.port_tree, text="Ports & Dienste")

        bottom = ttk.Frame(self.root, padding=(8, 0, 8, 8))
        bottom.pack(fill=tk.X)

        self.progress = ttk.Progressbar(
            bottom, orient=tk.HORIZONTAL, mode="determinate"
        )
        self.progress.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
        self.progress_label = ttk.Label(bottom, text="0%")
        self.progress_label.pack(side=tk.RIGHT)

    # ---------- Profiles / target network ----------

    def get_local_network(self):
        local_ip = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except OSError:
            pass

        if not local_ip:
            return "192.168.1.0/24"

        parts = local_ip.split(".")
        return ".".join(parts[:3]) + ".0/24"

    def get_ports(self):
        profile = self.profile_var.get()
        if profile == "Schnell":
            return COMMON_PORTS
        if profile == "Standard":
            return sorted(set(COMMON_PORTS) | set(range(1, 1025)))
        if profile == "Vollständig":
            return list(range(1, 65536))

        ports = set()
        for item in self.custom_ports_var.get().split(","):
            item = item.strip()
            if "-" in item:
                try:
                    start, end = map(int, item.split("-", 1))
                    ports.update(range(max(1, start), min(65535, end) + 1))
                except ValueError:
                    continue
            else:
                try:
                    port = int(item)
                    if 1 <= port <= 65535:
                        ports.add(port)
                except ValueError:
                    continue
        return sorted(ports)

    # ---------- Discovery ----------

    def start_network_scan(self):
        if self.current_scan and self.current_scan.is_alive():
            return

        self.cancel_event.clear()
        self.devices = []
        self.port_done = 0
        self.device_done = 0
        self.progress["value"] = 0
        self.scan_btn.config(state=tk.DISABLED)
        self.cancel_btn.config(state=tk.NORMAL)
        self.status_var.set("Netzwerk wird ermittelt ...")
        self.clear_details()

        self.current_scan = threading.Thread(
            target=self.run_network_scan, daemon=True
        )
        self.current_scan.start()

    def run_network_scan(self):
        try:
            network = ipaddress.ip_network(
                self.get_local_network(), strict=False
            )
            hosts = list(network.hosts())
            self.device_total = len(hosts)

            self.root.after(
                0, lambda: self.status_var.set(
                    f"Discovery: {self.device_total} Hosts"
                )
            )

            with ThreadPoolExecutor(max_workers=64) as executor:
                futures = [
                    executor.submit(self.probe_host, str(ip))
                    for ip in hosts
                ]
                for future in as_completed(futures):
                    if self.cancel_event.is_set():
                        break
                    device = future.result()
                    self.device_done += 1
                    if device:
                        self.devices.append(device)
                    self.update_discovery_progress()

            self.save_history_snapshot()
            self.root.after(0, self.refresh_device_tree)
            self.root.after(
                0,
                lambda: self.status_var.set(
                    f"{len(self.devices)} Geräte gefunden"
                ),
            )
        except Exception as exc:
            self.root.after(
                0,
                lambda e=str(exc): messagebox.showerror(
                    "Scan-Fehler", e
                ),
            )
        finally:
            self.root.after(0, self.scan_finished)

    def probe_host(self, ip):
        if self.cancel_event.is_set():
            return None

        alive_ports = []
        for port in (22, 53, 80, 443, 445, 3389):
            if self.tcp_open(ip, port, 0.18):
                alive_ports.append(port)

        if not alive_ports:
            return None

        hostname = self.reverse_dns(ip)
        mac, vendor = self.get_mac_vendor(ip)
        os_hint = self.infer_os(alive_ports, hostname, vendor)

        return {
            "ip": ip,
            "hostname": hostname,
            "mac": mac,
            "vendor": vendor,
            "os": os_hint,
            "ports": [],
            "discovery_ports": alive_ports,
            "analysis": {},
            "last_seen": dt.datetime.now().isoformat(timespec="seconds"),
        }

    @staticmethod
    def tcp_open(ip, port, timeout=0.3):
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except OSError:
            return False

    @staticmethod
    def reverse_dns(ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except OSError:
            return "Unbekannt"

    # ---------- MAC / OS hints ----------

    def get_mac_vendor(self, ip):
        mac = "Unbekannt"
        vendor = "Unbekannt"

        commands = []
        if platform.system() == "Windows":
            commands = [["arp", "-a", ip]]
        else:
            commands = [["arp", "-n", ip], ["arp", ip]]

        for command in commands:
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=2,
                )
                match = re.search(
                    r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}",
                    result.stdout,
                )
                if match:
                    mac = match.group(0).upper().replace("-", ":")
                    break
            except (OSError, subprocess.SubprocessError):
                continue

        return mac, vendor

    @staticmethod
    def infer_os(ports, hostname, vendor):
        text = f"{hostname} {vendor}".lower()

        if 3389 in ports or 445 in ports or 135 in ports:
            return "Windows-Hinweis"
        if 22 in ports and any(x in text for x in ("linux", "ubuntu", "debian", "rasp", "nas")):
            return "Linux/Unix-Hinweis"
        if "apple" in text or "mac" in text:
            return "Apple-Hinweis"
        if 22 in ports:
            return "Unix/Linux-Hinweis"
        return "Unbekannt"

    # ---------- Port scan / service analysis ----------

    def on_device_selected(self, _event):
        selection = self.device_tree.selection()
        if not selection:
            return

        ip = self.device_tree.item(selection[0], "values")[0]
        device = next((d for d in self.devices if d["ip"] == ip), None)
        if not device:
            return

        self.scan_selected_device(device)

    def scan_selected_device(self, device):
        self.cancel_event.clear()
        for row in self.port_tree.get_children():
            self.port_tree.delete(row)

        self.info_text.delete("1.0", tk.END)
        assessment = self.assess_device(device)
        self.info_text.insert(
            tk.END,
            json.dumps(
                {
                    "IP": device["ip"],
                    "Hostname": device["hostname"],
                    "MAC": device["mac"],
                    "Hersteller": device["vendor"],
                    "OS-Hinweis": device["os"],
                    "Discovery-Ports": device["discovery_ports"],
                    "Bewertung": assessment,
                },
                indent=2,
                ensure_ascii=False,
            ),
        )

        ports = self.get_ports()
        self.port_total = len(ports)
        self.port_done = 0
        self.progress["value"] = 0
        self.progress["maximum"] = 100
        self.progress_label.config(text="0%")
        self.status_var.set(
            f"Portscan {device['ip']}: {len(ports)} Ports"
        )

        threading.Thread(
            target=self.run_port_scan,
            args=(device, ports),
            daemon=True,
        ).start()

    def run_port_scan(self, device, ports):
        results = []

        with ThreadPoolExecutor(max_workers=128) as executor:
            futures = {
                executor.submit(
                    self.scan_single_port, device["ip"], port
                ): port
                for port in ports
            }

            for future in as_completed(futures):
                if self.cancel_event.is_set():
                    break

                result = future.result()
                self.port_done += 1

                if result:
                    results.append(result)
                    self.root.after(
                        0,
                        lambda r=result: self.insert_port_result(r),
                    )

                self.update_port_progress()

        results.sort(key=lambda x: x["port"])
        device["ports"] = results

        self.root.after(0, self.refresh_device_tree)
        self.root.after(
            0,
            lambda: self.status_var.set(
                f"{device['ip']}: {len(results)} offene Ports"
            ),
        )

    def scan_single_port(self, ip, port):
        sock = None
        try:
            sock = socket.create_connection((ip, port), timeout=0.35)
            service = SERVICE_PORTS.get(
                port,
                self.safe_getservbyport(port)
            )

            result = {
                "port": port,
                "service": service,
                "state": "open",
                "details": "",
            }

            if port in (80, 8080, 8000, 8008, 8009):
                result["analysis"] = self.analyze_http(
                    ip, port, False
                )
                result["details"] = self.http_summary(
                    result["analysis"]
                )
            elif port in (443, 8443, 465, 636, 990, 5986):
                result["analysis"] = self.analyze_http(
                    ip, port, True
                )
                result["details"] = self.http_summary(
                    result["analysis"]
                )
            elif port == 22:
                result["analysis"] = self.analyze_ssh(sock)
                result["details"] = result["analysis"].get(
                    "banner", "SSH erreichbar"
                )
            elif port == 53:
                result["analysis"] = {
                    "note": "TCP-DNS-Port erreichbar"
                }
                result["details"] = "DNS/TCP erreichbar"
            elif port == 445:
                result["analysis"] = self.analyze_smb(sock)
                result["details"] = result["analysis"].get(
                    "summary",
                    "SMB erreichbar; keine Anmeldedaten/Enumeration"
                )
            elif port in (21, 23, 25, 110, 143, 587, 993, 995, 3306, 5432, 6379, 3389, 5900):
                result["analysis"] = self.analyze_known_service(sock, port)
                result["details"] = result["analysis"].get(
                    "banner", result["analysis"].get("summary", "")
                )
            else:
                result["analysis"] = self.grab_banner(sock)
                result["details"] = result["analysis"].get(
                    "banner", ""
                )

            return result
        except OSError:
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass

    @staticmethod
    def safe_getservbyport(port):
        try:
            return socket.getservbyport(port)
        except OSError:
            return "Unbekannt"

    @staticmethod
    def grab_banner(sock):
        try:
            sock.settimeout(0.5)
            sock.sendall(b"\r\n")
            data = sock.recv(1024)
            text = data.decode("utf-8", errors="replace").strip()
            return {"banner": text[:300]}
        except OSError:
            return {"banner": ""}

    @staticmethod
    def analyze_ssh(sock):
        try:
            sock.settimeout(0.7)
            data = sock.recv(512)
            banner = data.decode("ascii", errors="replace").strip()
            return {"banner": banner[:300]}
        except OSError:
            return {"banner": "SSH erreichbar"}

    @staticmethod
    def analyze_http(ip, port, use_tls):
        scheme = "https" if use_tls else "http"
        conn = None
        result = {
            "scheme": scheme,
            "status": None,
            "reason": "",
            "server": "",
            "title": "",
            "location": "",
            "content_type": "",
            "content_length": "",
            "powered_by": "",
            "security_headers": {},
            "tls": {},
        }

        try:
            if use_tls:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(
                    ip, port, timeout=3, context=context
                )
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=3)

            conn.request(
                "GET",
                "/",
                headers={
                    "Host": ip,
                    "User-Agent": "NetworkScanner/4.0",
                    "Connection": "close",
                },
            )
            response = conn.getresponse()
            result["status"] = response.status
            result["reason"] = response.reason or ""
            result["server"] = response.getheader("Server", "")
            result["location"] = response.getheader("Location", "")
            result["content_type"] = response.getheader("Content-Type", "")
            result["content_length"] = response.getheader(
                "Content-Length", ""
            )
            result["powered_by"] = response.getheader(
                "X-Powered-By", ""
            )

            interesting_headers = (
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "Referrer-Policy",
                "Permissions-Policy",
            )
            result["security_headers"] = {
                name: response.getheader(name, "")
                for name in interesting_headers
                if response.getheader(name, "")
            }

            body = response.read(65536).decode(
                "utf-8", errors="ignore"
            )
            match = re.search(
                r"<title[^>]*>(.*?)</title>",
                body,
                re.I | re.S,
            )
            if match:
                result["title"] = re.sub(
                    r"\s+", " ", match.group(1)
                ).strip()[:200]

            if use_tls:
                result["tls"] = NetworkScannerGUI.inspect_tls(
                    ip, port
                )
        except Exception as exc:
            result["error"] = str(exc)[:250]
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

        return result

    @staticmethod
    def inspect_tls(ip, port):
        result = {}
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((ip, port), timeout=3) as raw:
                with context.wrap_socket(
                    raw, server_hostname=ip
                ) as tls_sock:
                    result["version"] = tls_sock.version() or ""
                    result["cipher"] = (
                        tls_sock.cipher()[0]
                        if tls_sock.cipher()
                        else ""
                    )
                    cert = tls_sock.getpeercert(binary_form=True)

                    if cert:
                        # The stdlib does not expose peer cert fields when
                        # verification is disabled. Re-open via a temporary
                        # PEM conversion where supported.
                        pem = ssl.DER_cert_to_PEM_cert(cert)
                        tmp = Path(
                            os.path.join(
                                os.path.abspath(os.path.expanduser("~")),
                                ".networkscanner_peer_cert.pem"
                            )
                        )
                        try:
                            tmp.write_text(pem, encoding="ascii")
                            decoded = {}
                            ssl._ssl._test_decode_cert(str(tmp))
                            # _test_decode_cert returns None on some Python builds;
                            # use a second verified context as a best-effort path.
                            result["certificate_present"] = True
                        finally:
                            try:
                                tmp.unlink()
                            except OSError:
                                pass

                    # Best-effort certificate subject/SAN using a verified
                    # connection to the IP/hostname when possible.
                    try:
                        verified = ssl.create_default_context()
                        with socket.create_connection(
                            (ip, port), timeout=3
                        ) as raw2:
                            with verified.wrap_socket(
                                raw2, server_hostname=ip
                            ) as verified_sock:
                                cert_dict = verified_sock.getpeercert()
                                if cert_dict:
                                    result["subject"] = str(
                                        cert_dict.get("subject", "")
                                    )
                                    result["issuer"] = str(
                                        cert_dict.get("issuer", "")
                                    )
                                    result["not_before"] = cert_dict.get(
                                        "notBefore", ""
                                    )
                                    result["not_after"] = cert_dict.get(
                                        "notAfter", ""
                                    )
                                    result["san"] = [
                                        value
                                        for kind, value in cert_dict.get(
                                            "subjectAltName", ()
                                        )
                                        if kind == "DNS"
                                    ]
                    except Exception:
                        pass
        except Exception as exc:
            result["error"] = str(exc)[:200]

        return result

    @staticmethod
    def analyze_known_service(sock, port):
        result = {"banner": "", "summary": ""}
        try:
            sock.settimeout(0.7)
            if port == 23:
                # Telnet: read initial negotiation/banner only.
                data = sock.recv(1024)
            elif port in (25, 110, 143, 587, 993, 995):
                data = sock.recv(1024)
            elif port in (3306, 5432, 6379, 3389, 5900):
                data = sock.recv(1024)
            else:
                sock.sendall(b"\r\n")
                data = sock.recv(1024)

            banner = data.decode(
                "utf-8", errors="replace"
            ).replace("\x00", "").strip()
            result["banner"] = banner[:400]
            result["summary"] = banner[:400]
        except OSError:
            result["summary"] = "Dienst erreichbar"
        return result

    @staticmethod
    def analyze_smb(sock):
        # Safe identification only: no credentials, shares or exploitation.
        result = {
            "summary": "SMB erreichbar (sichere Basis-Erkennung)",
            "protocol": "SMB",
        }
        return result

    @staticmethod
    def http_summary(info):
        parts = []
        if info.get("status") is not None:
            parts.append(
                f"HTTP {info['status']} {info.get('reason', '')}".strip()
            )
        if info.get("server"):
            parts.append(f"Server={info['server']}")
        if info.get("powered_by"):
            parts.append(f"PoweredBy={info['powered_by']}")
        if info.get("title"):
            parts.append(f"Titel={info['title']}")
        if info.get("location"):
            parts.append(f"Redirect={info['location']}")
        if info.get("content_type"):
            parts.append(f"Type={info['content_type']}")
        if info.get("tls"):
            tls = info["tls"]
            if tls.get("version"):
                parts.append(f"TLS={tls['version']}")
            if tls.get("cipher"):
                parts.append(f"Cipher={tls['cipher']}")
            if tls.get("not_after"):
                parts.append(f"Zertifikat bis={tls['not_after']}")
        if info.get("security_headers"):
            parts.append(
                f"Security-Header={len(info['security_headers'])}"
            )
        if info.get("error"):
            parts.append(f"Fehler={info['error']}")
        return " | ".join(parts) or "HTTP erreichbar"

    @staticmethod
    def assess_device(device):
        """Non-invasive local assessment based only on discovered services."""
        warnings = []
        infos = []

        ports = {p["port"] for p in device.get("ports", [])}

        if 23 in ports:
            warnings.append("Telnet erreichbar")
        if 21 in ports:
            warnings.append("FTP erreichbar")
        if 80 in ports and 443 not in ports:
            infos.append("HTTP ohne erkannten HTTPS-Dienst")
        if 445 in ports:
            infos.append("SMB erreichbar")
        if 3389 in ports:
            infos.append("RDP erreichbar")
        if 22 in ports:
            infos.append("SSH erreichbar")

        for port in device.get("ports", []):
            analysis = port.get("analysis", {})
            tls = analysis.get("tls", {})
            if tls.get("version") in ("TLSv1", "TLSv1.1"):
                warnings.append(
                    f"Veraltete TLS-Version auf Port {port['port']}"
                )

        return {"warnings": sorted(set(warnings)),
                "infos": sorted(set(infos))}

    # ---------- GUI helpers ----------

    def refresh_device_tree(self):
        for row in self.device_tree.get_children():
            self.device_tree.delete(row)

        needle = self.filter_var.get().strip().lower()
        for device in sorted(self.devices, key=lambda x: x["ip"]):
            searchable = " ".join(
                str(device.get(k, ""))
                for k in ("ip", "hostname", "mac", "vendor", "os")
            ).lower()
            if needle and needle not in searchable:
                continue

            self.device_tree.insert(
                "",
                tk.END,
                values=(
                    device["ip"],
                    device["hostname"],
                    device["mac"],
                    device["vendor"],
                    device["os"],
                    len(device["ports"]),
                ),
            )

    def insert_port_result(self, result):
        self.port_tree.insert(
            "",
            tk.END,
            values=(
                result["port"],
                result["service"],
                result["state"],
                result["details"],
            ),
        )

    def clear_details(self):
        for row in self.device_tree.get_children():
            self.device_tree.delete(row)
        for row in self.port_tree.get_children():
            self.port_tree.delete(row)
        self.info_text.delete("1.0", tk.END)

    def update_discovery_progress(self):
        if not self.device_total:
            return
        percentage = int(
            self.device_done / self.device_total * 100
        )
        self.root.after(
            0,
            lambda p=percentage: (
                self.progress.config(value=p),
                self.progress_label.config(text=f"{p}%"),
            ),
        )

    def update_port_progress(self):
        if not self.port_total:
            return
        percentage = int(
            self.port_done / self.port_total * 100
        )
        self.root.after(
            0,
            lambda p=percentage: (
                self.progress.config(value=p),
                self.progress_label.config(text=f"{p}%"),
            ),
        )

    def cancel_scan(self):
        self.cancel_event.set()
        self.status_var.set("Abbruch angefordert ...")
        self.cancel_btn.config(state=tk.DISABLED)

    def scan_finished(self):
        self.scan_btn.config(state=tk.NORMAL)
        self.cancel_btn.config(state=tk.DISABLED)
        self.progress["value"] = 100 if self.devices else 0
        self.progress_label.config(
            text="100%" if self.devices else "0%"
        )

    # ---------- History ----------

    def _load_history(self):
        try:
            if HISTORY_FILE.exists():
                data = json.loads(
                    HISTORY_FILE.read_text(encoding="utf-8")
                )
                self.status_var.set(
                    f"Historie geladen: {len(data)} Einträge"
                )
        except (OSError, json.JSONDecodeError):
            pass

    def save_history_snapshot(self):
        try:
            history = []
            if HISTORY_FILE.exists():
                history = json.loads(
                    HISTORY_FILE.read_text(encoding="utf-8")
                )
                if not isinstance(history, list):
                    history = []

            snapshot = {
                "timestamp": dt.datetime.now().isoformat(
                    timespec="seconds"
                ),
                "devices": [
                    {
                        "ip": d["ip"],
                        "hostname": d["hostname"],
                        "mac": d["mac"],
                        "vendor": d["vendor"],
                        "os": d["os"],
                        "ports": [
                            p["port"] for p in d["ports"]
                        ],
                    }
                    for d in self.devices
                ],
            }
            history.append(snapshot)
            history = history[-50:]
            HISTORY_FILE.write_text(
                json.dumps(history, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError:
            pass

    # ---------- Export ----------

    def export_data(self, kind):
        if not self.devices:
            messagebox.showwarning(
                "Export", "Keine Scan-Daten vorhanden."
            )
            return

        ext = {"csv": ".csv", "json": ".json", "html": ".html"}[kind]
        path = filedialog.asksaveasfilename(
            defaultextension=ext,
            filetypes=[(kind.upper(), f"*{ext}")],
        )
        if not path:
            return

        try:
            if kind == "csv":
                self.export_csv(path)
            elif kind == "json":
                Path(path).write_text(
                    json.dumps(
                        self.devices,
                        indent=2,
                        ensure_ascii=False,
                    ),
                    encoding="utf-8",
                )
            else:
                self.export_html(path)

            messagebox.showinfo(
                "Export", f"Export erfolgreich:\n{path}"
            )
        except OSError as exc:
            messagebox.showerror(
                "Export-Fehler", str(exc)
            )

    def export_csv(self, path):
        with open(
            path, "w", newline="", encoding="utf-8-sig"
        ) as file:
            writer = csv.writer(file, delimiter=";")
            writer.writerow(
                [
                    "IP", "Hostname", "MAC", "Hersteller",
                    "OS-Hinweis", "Port", "Dienst", "Details"
                ]
            )
            for device in self.devices:
                if not device["ports"]:
                    writer.writerow([
                        device["ip"], device["hostname"],
                        device["mac"], device["vendor"],
                        device["os"], "", "", ""
                    ])
                else:
                    for port in device["ports"]:
                        writer.writerow([
                            device["ip"], device["hostname"],
                            device["mac"], device["vendor"],
                            device["os"], port["port"],
                            port["service"], port["details"]
                        ])

    def export_html(self, path):
        rows = []
        for device in self.devices:
            for port in device["ports"] or [{}]:
                rows.append(
                    "<tr>"
                    f"<td>{device['ip']}</td>"
                    f"<td>{device['hostname']}</td>"
                    f"<td>{device['mac']}</td>"
                    f"<td>{device['vendor']}</td>"
                    f"<td>{device['os']}</td>"
                    f"<td>{port.get('port', '')}</td>"
                    f"<td>{port.get('service', '')}</td>"
                    f"<td>{port.get('details', '')}</td>"
                    "</tr>"
                )

        html = f"""<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<title>{APP_NAME} Report</title>
<style>
body {{ font-family: sans-serif; margin: 30px; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ccc; padding: 6px; text-align: left; }}
th {{ background: #eee; }}
</style>
</head>
<body>
<h1>{APP_NAME} Report</h1><p>Version: 4.0</p>
<p>Erstellt: {dt.datetime.now().isoformat(timespec="seconds")}</p>
<table>
<tr>
<th>IP</th><th>Hostname</th><th>MAC</th><th>Hersteller</th>
<th>OS-Hinweis</th><th>Port</th><th>Dienst</th><th>Details</th>
</tr>
{''.join(rows)}
</table>
</body>
</html>"""
        Path(path).write_text(html, encoding="utf-8")


def main():
    root = tk.Tk()
    NetworkScannerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
