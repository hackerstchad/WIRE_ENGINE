import os
import sys
import time
import json
import socket
import struct
import sqlite3
import threading
import ipaddress
import subprocess
import queue as q_module
from datetime import datetime
from collections import Counter, defaultdict

import psutil
import requests
import netifaces
import nmap
import dns.resolver
import dns.reversename
from getmac import get_mac_address
from mac_vendor_lookup import MacLookup

from scapy.all import (
    sniff, ARP, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR,
    Ether, Raw, conf, get_if_addr, get_if_list, wrpcap, rdpcap
)

from tkinter import (
    Tk, Frame, Label, Button, Entry, Text, Scrollbar, Listbox,
    Menu, Toplevel, StringVar, BooleanVar, IntVar, DoubleVar,
    OptionMenu, Checkbutton, Radiobutton, Scale, PhotoImage,
    filedialog, messagebox, ttk, END, NORMAL, DISABLED, BOTH,
    LEFT, RIGHT, TOP, BOTTOM, X, Y, W, E, N, S, CENTER
)
from tkinter import font as tkfont

import matplotlib
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure


# ---------------------------------------------------------------------------
# CONSTANTES GLOBALES
# ---------------------------------------------------------------------------
APP_NAME = "WIRE_ENGINE"
APP_VERSION = "1.0.0"
APP_AUTHOR = "CodePal"
APP_LICENSE = "MIT"

DB_FILE = "wire_engine.db"
CONFIG_FILE = "wire_engine.json"
PCAP_DIR = "pcaps"
LOG_DIR = "logs"

THEME_BG = "#0a0a0a"
THEME_FG = "#f0f0f0"
THEME_ACCENT = "#00ffcc"
THEME_SECONDARY = "#888888"
THEME_FRAME = "#141414"
THEME_BORDER = "#2a2a2a"
THEME_RED = "#ff4d4d"
THEME_GREEN = "#4dff4d"
THEME_YELLOW = "#ffff4d"
THEME_BLUE = "#4d94ff"

PROTOCOL_COLORS = {
    "TCP": "#4d94ff",
    "UDP": "#4dff4d",
    "ICMP": "#ffff4d",
    "ARP": "#ff4d4d",
    "DNS": "#ff80ff",
    "HTTP": "#ffaa00",
    "HTTPS": "#ff5500",
    "OTHER": "#aaaaaa"
}

KNOWN_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
    25: "SMTP", 53: "DNS", 67: "DHCP-SERVER", 68: "DHCP-CLIENT",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 8080: "HTTP-ALT", 8443: "HTTPS-ALT"
}


# ---------------------------------------------------------------------------
# CLASSE DE CONFIGURATION
# ---------------------------------------------------------------------------
class Configuration:
    """Gère la persistance des paramètres utilisateur."""

    def __init__(self, path=CONFIG_FILE):
        self.path = path
        self.defaults = {
            "interface": None,
            "filter": "",
            "max_packets": 10000,
            "auto_scroll": True,
            "show_payload": False,
            "dark_mode": True,
            "language": "fr",
            "geoip_enabled": True,
            "scan_interval": 60,
            "pcap_auto_save": False
        }
        self.data = self.load()

    def load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                    merged = self.defaults.copy()
                    merged.update(loaded)
                    return merged
            except Exception as e:
                print(f"[CONFIG] Erreur chargement : {e}")
        return self.defaults.copy()

    def save(self):
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=4, ensure_ascii=False)
        except Exception as e:
            print(f"[CONFIG] Erreur sauvegarde : {e}")

    def get(self, key):
        return self.data.get(key, self.defaults.get(key))

    def set(self, key, value):
        self.data[key] = value
        self.save()


# ---------------------------------------------------------------------------
# BASE DE DONNÉES
# ---------------------------------------------------------------------------
class Database:
    """Historise les paquets, appareils et statistiques dans SQLite."""

    def __init__(self, db_path=DB_FILE):
        self.db_path = db_path
        self.local = threading.local()
        self.init_db()

    def get_conn(self):
        if not hasattr(self.local, "conn") or self.local.conn is None:
            self.local.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.local.cursor = self.local.conn.cursor()
        return self.local.conn, self.local.cursor

    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                protocol TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                src_mac TEXT,
                dst_mac TEXT,
                domain TEXT,
                length INTEGER,
                info TEXT,
                explanation TEXT,
                raw_hex TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE,
                mac TEXT,
                vendor TEXT,
                hostname TEXT,
                first_seen TEXT,
                last_seen TEXT,
                status TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                protocol TEXT,
                count INTEGER
            )
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_packets_ts ON packets(timestamp);
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_packets_proto ON packets(protocol);
        """)
        conn.commit()
        conn.close()

    def insert_packet(self, packet_info):
        conn, cursor = self.get_conn()
        try:
            cursor.execute("""
                INSERT INTO packets
                (timestamp, protocol, src_ip, dst_ip, src_port, dst_port,
                 src_mac, dst_mac, domain, length, info, explanation, raw_hex)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                packet_info["timestamp"],
                packet_info["protocol"],
                packet_info.get("src_ip", ""),
                packet_info.get("dst_ip", ""),
                packet_info.get("src_port", 0),
                packet_info.get("dst_port", 0),
                packet_info.get("src_mac", ""),
                packet_info.get("dst_mac", ""),
                packet_info.get("domain", ""),
                packet_info.get("length", 0),
                packet_info.get("info", ""),
                packet_info.get("explanation", ""),
                packet_info.get("raw_hex", "")
            ))
            conn.commit()
        except Exception as e:
            print(f"[DB] Insert packet error: {e}")

    def insert_or_update_device(self, ip, mac, vendor, hostname):
        conn, cursor = self.get_conn()
        now = datetime.now().isoformat()
        try:
            cursor.execute("SELECT id FROM devices WHERE ip = ?", (ip,))
            row = cursor.fetchone()
            if row:
                cursor.execute("""
                    UPDATE devices
                    SET mac = ?, vendor = ?, hostname = ?, last_seen = ?, status = ?
                    WHERE ip = ?
                """, (mac, vendor, hostname, now, "online", ip))
            else:
                cursor.execute("""
                    INSERT INTO devices (ip, mac, vendor, hostname, first_seen, last_seen, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (ip, mac, vendor, hostname, now, now, "online"))
            conn.commit()
        except Exception as e:
            print(f"[DB] Device error: {e}")

    def get_recent_packets(self, limit=1000):
        conn, cursor = self.get_conn()
        cursor.execute("""
            SELECT * FROM packets ORDER BY id DESC LIMIT ?
        """, (limit,))
        return cursor.fetchall()

    def get_devices(self):
        conn, cursor = self.get_conn()
        cursor.execute("SELECT * FROM devices ORDER BY last_seen DESC")
        return cursor.fetchall()

    def clear_packets(self):
        conn, cursor = self.get_conn()
        cursor.execute("DELETE FROM packets")
        conn.commit()


# ---------------------------------------------------------------------------
# RÉSEAU : OUTILS
# ---------------------------------------------------------------------------
class NetworkTools:
    """Ensemble d'outils pour inspecter le réseau local et résoudre les hôtes."""

    def __init__(self, parent_app):
        self.app = parent_app
        try:
            self.mac_lookup = MacLookup()
            self.mac_lookup.load_vendors()
        except Exception:
            self.mac_lookup = None

    def get_interfaces(self):
        try:
            return netifaces.interfaces()
        except Exception:
            return get_if_list()

    def get_default_interface(self):
        try:
            gateways = netifaces.gateways()
            default = gateways.get("default", {})
            if default:
                return default[netifaces.AF_INET][1]
        except Exception:
            pass
        interfaces = self.get_interfaces()
        for iface in interfaces:
            if iface.startswith("e") or iface.startswith("w"):
                return iface
        return interfaces[0] if interfaces else None

    def get_interface_info(self, iface):
        info = {"name": iface, "ip": "", "mask": "", "gateway": "", "mac": ""}
        try:
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                ipv4 = addrs[netifaces.AF_INET][0]
                info["ip"] = ipv4.get("addr", "")
                info["mask"] = ipv4.get("netmask", "")
            if netifaces.AF_LINK in addrs:
                info["mac"] = addrs[netifaces.AF_LINK][0].get("addr", "")
            gateways = netifaces.gateways()
            default = gateways.get("default", {})
            if default and netifaces.AF_INET in default:
                g = default[netifaces.AF_INET]
                if g[1] == iface:
                    info["gateway"] = g[0]
        except Exception as e:
            print(f"[NET] Interface info error: {e}")
        return info

    def get_network_range(self, iface):
        info = self.get_interface_info(iface)
        ip = info.get("ip")
        mask = info.get("mask")
        if ip and mask:
            try:
                network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                return str(network)
            except Exception:
                pass
        return None

    def resolve_hostname(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ""

    def resolve_domain(self, ip):
        try:
            addr = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(addr, "PTR")
            return str(answers[0]).rstrip(".")
        except Exception:
            return ""

    def get_vendor(self, mac):
        if not mac or mac == "ff:ff:ff:ff:ff:ff":
            return "Broadcast"
        if self.mac_lookup:
            try:
                return self.mac_lookup.lookup(mac)
            except Exception:
                pass
        return "Inconnu"

    def scan_network(self, network_range, callback=None):
        devices = []
        try:
            scanner = nmap.PortScanner()
            scanner.scan(hosts=network_range, arguments="-sn -n --max-retries 1")
            for host in scanner.all_hosts():
                state = scanner[host].state()
                if state == "up":
                    mac = ""
                    vendor = ""
                    hostname = ""
                    try:
                        if "mac" in scanner[host]["addresses"]:
                            mac = scanner[host]["addresses"]["mac"]
                            vendor = scanner[host].get("vendor", {}).get(mac, "")
                        hostname = scanner[host].hostname()
                    except Exception:
                        pass
                    if not hostname:
                        hostname = self.resolve_hostname(host)
                    if not vendor and mac:
                        vendor = self.get_vendor(mac)
                    devices.append({
                        "ip": host,
                        "mac": mac,
                        "vendor": vendor,
                        "hostname": hostname,
                        "status": "online"
                    })
                    if callback:
                        callback(host, mac, vendor, hostname)
        except Exception as e:
            print(f"[NET] Scan error: {e}")
        return devices

    def get_gateway_info(self):
        try:
            gateways = netifaces.gateways()
            default = gateways.get("default", {})
            if netifaces.AF_INET in default:
                g = default[netifaces.AF_INET]
                return {"ip": g[0], "interface": g[1]}
        except Exception:
            pass
        return {}


# ---------------------------------------------------------------------------
# ANALYSEUR DE PAQUETS
# ---------------------------------------------------------------------------
class PacketAnalyzer:
    """Transforme un paquet Scapy en information lisible et expliquée."""

    def __init__(self, app):
        self.app = app
        self.dns_cache = {}
        self.ip_cache = {}

    def explain(self, proto, src, dst, sport, dport, domain, length, flags=None):
        parts = []
        parts.append(f"Protocole détecté : {proto}.")

        if proto == "ARP":
            parts.append("Ce paquet sert à associer une adresse IP à une adresse MAC sur le réseau local.")
        elif proto == "ICMP":
            parts.append("Ce paquet est utilisé pour diagnostiquer la connectivité (ping) ou signaler une erreur.")
        elif proto == "DNS":
            if domain:
                parts.append(f"Une requête ou réponse DNS concerne le nom de domaine '{domain}'.")
                parts.append("Le DNS transforme les noms de domaine en adresses IP comprises par les routeurs.")
            else:
                parts.append("Communication avec un serveur DNS pour résoudre un nom de domaine.")
        elif proto == "TCP":
            service = KNOWN_PORTS.get(dport, "un service inconnu")
            parts.append(f"Connexion TCP vers le port {dport} ({service}).")
            if flags:
                parts.append(f"Flags TCP : {flags}.")
        elif proto == "UDP":
            service = KNOWN_PORTS.get(dport, "un service inconnu")
            parts.append(f"Communication UDP vers le port {dport} ({service}).")
        elif proto == "HTTP":
            parts.append("Requête ou réponse web non chiffrée (HTTP).")
        elif proto == "HTTPS":
            parts.append("Communication web sécurisée et chiffrée (HTTPS/TLS).")
        else:
            parts.append("Protocole réseau générique.")

        if domain:
            parts.append(f"Le nom de domaine '{domain}' a transité via le routeur et les serveurs DNS.")

        parts.append(f"Taille du paquet : {length} octets.")
        return " ".join(parts)

    def get_flags(self, pkt):
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            flags = []
            if tcp.flags.F: flags.append("FIN")
            if tcp.flags.S: flags.append("SYN")
            if tcp.flags.R: flags.append("RST")
            if tcp.flags.P: flags.append("PSH")
            if tcp.flags.A: flags.append("ACK")
            if tcp.flags.U: flags.append("URG")
            return ",".join(flags)
        return ""

    def detect_application(self, pkt):
        if pkt.haslayer(TCP):
            dport = pkt[TCP].dport
            sport = pkt[TCP].sport
            if dport == 80 or sport == 80:
                return "HTTP"
            if dport == 443 or sport == 443:
                return "HTTPS"
            if dport == 22 or sport == 22:
                return "SSH"
            if dport == 25 or sport == 25:
                return "SMTP"
        if pkt.haslayer(UDP):
            dport = pkt[UDP].dport
            sport = pkt[UDP].sport
            if dport == 53 or sport == 53:
                return "DNS"
            if dport == 67 or dport == 68 or sport == 67 or sport == 68:
                return "DHCP"
        return ""

    def extract_domain(self, pkt):
        if pkt.haslayer(DNS):
            try:
                dns_layer = pkt[DNS]
                if dns_layer.qd:
                    name = dns_layer.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                    if name:
                        return name
                if dns_layer.an and dns_layer.an.type == 1:
                    name = dns_layer.an.rrname.decode("utf-8", errors="ignore").rstrip(".")
                    return name
            except Exception:
                pass
        return ""

    def resolve_ip(self, ip):
        if ip in self.ip_cache:
            return self.ip_cache[ip]
        try:
            host = socket.gethostbyaddr(ip)[0]
            self.ip_cache[ip] = host
            return host
        except Exception:
            self.ip_cache[ip] = ""
        return ""

    def analyze(self, pkt):
        info = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "protocol": "OTHER",
            "src_ip": "",
            "dst_ip": "",
            "src_port": 0,
            "dst_port": 0,
            "src_mac": "",
            "dst_mac": "",
            "domain": "",
            "length": len(pkt),
            "info": "",
            "explanation": "",
            "raw_hex": ""
        }

        if pkt.haslayer(Ether):
            info["src_mac"] = pkt[Ether].src
            info["dst_mac"] = pkt[Ether].dst

        if pkt.haslayer(IP):
            info["src_ip"] = pkt[IP].src
            info["dst_ip"] = pkt[IP].dst

        if pkt.haslayer(ARP):
            info["protocol"] = "ARP"
            info["src_ip"] = pkt[ARP].psrc
            info["dst_ip"] = pkt[ARP].pdst
            info["src_mac"] = pkt[ARP].hwsrc
            info["dst_mac"] = pkt[ARP].hwdst
            info["info"] = f"ARP {pkt[ARP].psrc} -> {pkt[ARP].pdst}"

        elif pkt.haslayer(ICMP):
            info["protocol"] = "ICMP"
            icmp_type = pkt[ICMP].type
            type_name = "Echo Request" if icmp_type == 8 else "Echo Reply" if icmp_type == 0 else f"Type {icmp_type}"
            info["info"] = f"ICMP {type_name} {info['src_ip']} -> {info['dst_ip']}"

        elif pkt.haslayer(TCP):
            info["protocol"] = "TCP"
            info["src_port"] = pkt[TCP].sport
            info["dst_port"] = pkt[TCP].dport
            app = self.detect_application(pkt)
            if app:
                info["protocol"] = app
            flags = self.get_flags(pkt)
            info["info"] = f"TCP {info['src_ip']}:{info['src_port']} -> {info['dst_ip']}:{info['dst_port']} [{flags}]"

        elif pkt.haslayer(UDP):
            info["protocol"] = "UDP"
            info["src_port"] = pkt[UDP].sport
            info["dst_port"] = pkt[UDP].dport
            app = self.detect_application(pkt)
            if app:
                info["protocol"] = app
            info["info"] = f"UDP {info['src_ip']}:{info['src_port']} -> {info['dst_ip']}:{info['dst_port']}"

        info["domain"] = self.extract_domain(pkt)
        if not info["domain"] and info["dst_ip"]:
            host = self.resolve_ip(info["dst_ip"])
            if host:
                info["domain"] = host

        if not info["info"]:
            info["info"] = f"Paquet de {info['length']} octets"

        flags = self.get_flags(pkt) if pkt.haslayer(TCP) else ""
        info["explanation"] = self.explain(
            info["protocol"],
            info["src_ip"],
            info["dst_ip"],
            info["src_port"],
            info["dst_port"],
            info["domain"],
            info["length"],
            flags
        )

        try:
            info["raw_hex"] = bytes(pkt).hex()[:200]
        except Exception:
            info["raw_hex"] = ""

        return info


# ---------------------------------------------------------------------------
# CAPTURE EN TEMPS RÉEL
# ---------------------------------------------------------------------------
class CaptureEngine:
    """Moteur de capture Scapy exécuté dans un thread séparé."""

    def __init__(self, app):
        self.app = app
        self.running = False
        self.thread = None
        self.interface = None
        self.filter_expr = ""
        self.packet_count = 0
        self.packet_queue = q_module.Queue()

    def set_interface(self, iface):
        self.interface = iface

    def set_filter(self, expr):
        self.filter_expr = expr

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            try:
                self.thread.join(timeout=2)
            except Exception:
                pass
        self.thread = None

    def _packet_handler(self, pkt):
        if not self.running:
            return
        self.packet_count += 1
        try:
            info = self.app.analyzer.analyze(pkt)
            self.packet_queue.put(info)
        except Exception as e:
            print(f"[CAPTURE] Analyze error: {e}")

    def _capture_loop(self):
        try:
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                filter=self.filter_expr,
                store=False,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            print(f"[CAPTURE] Sniff error: {e}")
            self.running = False


# ---------------------------------------------------------------------------
# INTERFACE GRAPHIQUE TKINTER
# ---------------------------------------------------------------------------
class WireEngineApp:
    """Application principale WIRE_ENGINE."""

    def __init__(self, root):
        self.root = root
        self.root.title(f"{APP_NAME} v{APP_VERSION}")
        self.root.geometry("1600x900")
        self.root.configure(bg=THEME_BG)
        self.root.state("zoomed")

        self.config = Configuration()
        self.db = Database()
        self.net_tools = NetworkTools(self)
        self.analyzer = PacketAnalyzer(self)
        self.capture = CaptureEngine(self)

        self.devices = {}
        self.packet_list = []
        self.protocol_counts = Counter()
        self.ip_counts = Counter()
        self.domain_counts = Counter()
        self.lock = threading.Lock()

        self.setup_fonts()
        self.build_menu()
        self.build_header()
        self.build_main_layout()
        self.build_footer()

        self.refresh_interface_list()
        self.start_ui_updater()
        self.start_network_scanner()
        self.load_history()

    def setup_fonts(self):
        self.font_title = tkfont.Font(family="Consolas", size=24, weight="bold")
        self.font_label = tkfont.Font(family="Consolas", size=11)
        self.font_mono = tkfont.Font(family="Consolas", size=10)
        self.font_small = tkfont.Font(family="Consolas", size=9)

    def build_menu(self):
        menubar = Menu(self.root, bg=THEME_FRAME, fg=THEME_FG, activebackground=THEME_ACCENT, activeforeground=THEME_BG)
        file_menu = Menu(menubar, tearoff=0, bg=THEME_FRAME, fg=THEME_FG)
        file_menu.add_command(label="Exporter en PCAP", command=self.export_pcap)
        file_menu.add_command(label="Importer PCAP", command=self.import_pcap)
        file_menu.add_separator()
        file_menu.add_command(label="Effacer l'historique", command=self.clear_history)
        file_menu.add_separator()
        file_menu.add_command(label="Quitter", command=self.on_close)
        menubar.add_cascade(label="Fichier", menu=file_menu)

        view_menu = Menu(menubar, tearoff=0, bg=THEME_FRAME, fg=THEME_FG)
        view_menu.add_checkbutton(label="Défilement auto", variable=BooleanVar(value=self.config.get("auto_scroll")), command=self.toggle_auto_scroll)
        view_menu.add_checkbutton(label="Afficher payload", variable=BooleanVar(value=self.config.get("show_payload")), command=self.toggle_show_payload)
        menubar.add_cascade(label="Affichage", menu=view_menu)

        help_menu = Menu(menubar, tearoff=0, bg=THEME_FRAME, fg=THEME_FG)
        help_menu.add_command(label="À propos", command=self.show_about)
        help_menu.add_command(label="Documentation", command=self.show_docs)
        menubar.add_cascade(label="Aide", menu=help_menu)

        self.root.config(menu=menubar)

    def build_header(self):
        self.header = Frame(self.root, bg=THEME_BG, height=80)
        self.header.pack(fill=X, padx=10, pady=10)

        title = Label(self.header, text=f"⚡ {APP_NAME}", font=self.font_title,
                      bg=THEME_BG, fg=THEME_FG)
        title.pack(side=LEFT, padx=10)

        subtitle = Label(self.header, text="Analyseur de trafic réseau en temps réel",
                         font=self.font_label, bg=THEME_BG, fg=THEME_SECONDARY)
        subtitle.pack(side=LEFT, padx=10)

        self.status_label = Label(self.header, text="● PRÊT", font=self.font_label,
                                  bg=THEME_BG, fg=THEME_GREEN)
        self.status_label.pack(side=RIGHT, padx=10)

    def build_main_layout(self):
        self.paned = Frame(self.root, bg=THEME_BG)
        self.paned.pack(fill=BOTH, expand=True, padx=10, pady=5)

        self.paned.columnconfigure(0, weight=3)
        self.paned.columnconfigure(1, weight=1)
        self.paned.rowconfigure(0, weight=1)

        # Panneau gauche : contrôles + liste de paquets
        left_frame = Frame(self.paned, bg=THEME_BG)
        left_frame.grid(row=0, column=0, sticky=NSEW, padx=5, pady=5)

        self.build_controls(left_frame)
        self.build_packet_table(left_frame)
        self.build_detail_panel(left_frame)

        # Panneau droit : appareils + statistiques
        right_frame = Frame(self.paned, bg=THEME_BG)
        right_frame.grid(row=0, column=1, sticky=NSEW, padx=5, pady=5)

        self.build_devices_panel(right_frame)
        self.build_stats_panel(right_frame)
        self.build_graph_panel(right_frame)

    def build_controls(self, parent):
        control_frame = Frame(parent, bg=THEME_FRAME, highlightbackground=THEME_BORDER,
                              highlightthickness=1)
        control_frame.pack(fill=X, pady=5)

        Label(control_frame, text="Interface :", bg=THEME_FRAME, fg=THEME_FG,
              font=self.font_label).pack(side=LEFT, padx=5)

        self.interface_var = StringVar()
        self.interface_menu = OptionMenu(control_frame, self.interface_var, "")
        self.interface_menu.config(bg=THEME_FRAME, fg=THEME_FG, highlightthickness=0,
                                   font=self.font_label)
        self.interface_menu["menu"].config(bg=THEME_FRAME, fg=THEME_FG)
        self.interface_menu.pack(side=LEFT, padx=5)

        Label(control_frame, text="Filtre :", bg=THEME_FRAME, fg=THEME_FG,
              font=self.font_label).pack(side=LEFT, padx=5)

        self.filter_entry = Entry(control_frame, bg=THEME_BG, fg=THEME_FG,
                                  insertbackground=THEME_FG, font=self.font_label,
                                  width=30)
        self.filter_entry.pack(side=LEFT, padx=5)
        self.filter_entry.insert(0, self.config.get("filter"))

        self.btn_start = Button(control_frame, text="▶ DÉMARRER", command=self.start_capture,
                                bg=THEME_GREEN, fg=THEME_BG, font=self.font_label)
        self.btn_start.pack(side=LEFT, padx=5)

        self.btn_stop = Button(control_frame, text="⏹ ARRÊTER", command=self.stop_capture,
                               bg=THEME_RED, fg=THEME_BG, font=self.font_label, state=DISABLED)
        self.btn_stop.pack(side=LEFT, padx=5)

        self.btn_scan = Button(control_frame, text="⟳ SCANNER", command=self.manual_scan,
                               bg=THEME_ACCENT, fg=THEME_BG, font=self.font_label)
        self.btn_scan.pack(side=LEFT, padx=5)

    def build_packet_table(self, parent):
        table_frame = Frame(parent, bg=THEME_FRAME, highlightbackground=THEME_BORDER,
                            highlightthickness=1)
        table_frame.pack(fill=BOTH, expand=True, pady=5)

        columns = ("time", "proto", "src", "dst", "domain", "info")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings",
                                 height=20)

        self.tree.heading("time", text="Heure")
        self.tree.heading("proto", text="Proto")
        self.tree.heading("src", text="Source")
        self.tree.heading("dst", text="Destination")
        self.tree.heading("domain", text="Domaine")
        self.tree.heading("info", text="Information")

        self.tree.column("time", width=130, anchor=W)
        self.tree.column("proto", width=70, anchor=CENTER)
        self.tree.column("src", width=160, anchor=W)
        self.tree.column("dst", width=160, anchor=W)
        self.tree.column("domain", width=200, anchor=W)
        self.tree.column("info", width=350, anchor=W)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background=THEME_BG, foreground=THEME_FG,
                        fieldbackground=THEME_BG, font=self.font_mono, rowheight=24)
        style.configure("Treeview.Heading", background=THEME_FRAME, foreground=THEME_FG,
                        font=self.font_label)
        style.map("Treeview", background=[("selected", THEME_ACCENT)],
                  foreground=[("selected", THEME_BG)])

        scrollbar_y = Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        scrollbar_x = Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)

        self.tree.grid(row=0, column=0, sticky=NSEW)
        scrollbar_y.grid(row=0, column=1, sticky=NS)
        scrollbar_x.grid(row=1, column=0, sticky=EW)

        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)

        self.tree.bind("<<TreeviewSelect>>", self.on_packet_select)

    def build_detail_panel(self, parent):
        detail_frame = Frame(parent, bg=THEME_FRAME, highlightbackground=THEME_BORDER,
                             highlightthickness=1)
        detail_frame.pack(fill=BOTH, expand=False, pady=5)

        Label(detail_frame, text="📋 Explication détaillée", bg=THEME_FRAME,
              fg=THEME_ACCENT, font=self.font_label).pack(anchor=W, padx=5, pady=5)

        self.detail_text = Text(detail_frame, bg=THEME_BG, fg=THEME_FG,
                                insertbackground=THEME_FG, font=self.font_mono,
                                wrap="word", height=10)
        self.detail_text.pack(fill=BOTH, expand=True, padx=5, pady=5)

        scrollbar = Scrollbar(self.detail_text, command=self.detail_text.yview)
        scrollbar.pack(side=RIGHT, fill=Y)
        self.detail_text.config(yscrollcommand=scrollbar.set)

    def build_devices_panel(self, parent):
        devices_frame = Frame(parent, bg=THEME_FRAME, highlightbackground=THEME_BORDER,
                              highlightthickness=1)
        devices_frame.pack(fill=BOTH, expand=True, pady=5)

        Label(devices_frame, text="🖧 Appareils connectés", bg=THEME_FRAME,
              fg=THEME_ACCENT, font=self.font_label).pack(anchor=W, padx=5, pady=5)

        self.devices_listbox = Listbox(devices_frame, bg=THEME_BG, fg=THEME_FG,
                                       font=self.font_mono, selectbackground=THEME_ACCENT,
                                       selectforeground=THEME_BG)
        self.devices_listbox.pack(fill=BOTH, expand=True, padx=5, pady=5)

        scrollbar = Scrollbar(self.devices_listbox, command=self.devices_listbox.yview)
        scrollbar.pack(side=RIGHT, fill=Y)
        self.devices_listbox.config(yscrollcommand=scrollbar.set)

    def build_stats_panel(self, parent):
        stats_frame = Frame(parent, bg=THEME_FRAME, highlightbackground=THEME_BORDER,
                            highlightthickness=1)
        stats_frame.pack(fill=BOTH, expand=True, pady=5)

        Label(stats_frame, text="📊 Statistiques", bg=THEME_FRAME,
              fg=THEME_ACCENT, font=self.font_label).pack(anchor=W, padx=5, pady=5)

        self.stats_text = Text(stats_frame, bg=THEME_BG, fg=THEME_FG,
                               insertbackground=THEME_FG, font=self.font_mono,
                               wrap="word", height=10)
        self.stats_text.pack(fill=BOTH, expand=True, padx=5, pady=5)

    def build_graph_panel(self, parent):
        graph_frame = Frame(parent, bg=THEME_FRAME, highlightbackground=THEME_BORDER,
                            highlightthickness=1)
        graph_frame.pack(fill=BOTH, expand=True, pady=5)

        Label(graph_frame, text="📈 Protocoles", bg=THEME_FRAME,
              fg=THEME_ACCENT, font=self.font_label).pack(anchor=W, padx=5, pady=5)

        self.fig = Figure(figsize=(4, 3), dpi=100, facecolor=THEME_BG)
        self.ax = self.fig.add_subplot(111)
        self.ax.set_facecolor(THEME_BG)
        self.ax.tick_params(colors=THEME_FG)
        self.ax.spines["bottom"].set_color(THEME_FG)
        self.ax.spines["top"].set_color(THEME_FG)
        self.ax.spines["left"].set_color(THEME_FG)
        self.ax.spines["right"].set_color(THEME_FG)

        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas.get_tk_widget().pack(fill=BOTH, expand=True, padx=5, pady=5)

    def build_footer(self):
        self.footer = Frame(self.root, bg=THEME_BG, height=30)
        self.footer.pack(fill=X, padx=10, pady=5)

        self.footer_label = Label(self.footer, text="Prêt", bg=THEME_BG,
                                  fg=THEME_SECONDARY, font=self.font_small)
        self.footer_label.pack(side=LEFT)

        self.packet_count_label = Label(self.footer, text="Paquets : 0", bg=THEME_BG,
                                        fg=THEME_SECONDARY, font=self.font_small)
        self.packet_count_label.pack(side=RIGHT)

    # -----------------------------------------------------------------------
    # ACTIONS
    # -----------------------------------------------------------------------
    def refresh_interface_list(self):
        interfaces = self.net_tools.get_interfaces()
        menu = self.interface_menu["menu"]
        menu.delete(0, "end")
        default_iface = self.net_tools.get_default_interface()
        selected = self.config.get("interface") or default_iface

        for iface in interfaces:
            label = f"{iface}"
            info = self.net_tools.get_interface_info(iface)
            if info.get("ip"):
                label += f" ({info['ip']})"
            menu.add_command(label=label, command=lambda v=iface: self.interface_var.set(v))

        if selected in interfaces:
            self.interface_var.set(selected)
        elif interfaces:
            self.interface_var.set(interfaces[0])

    def start_capture(self):
        iface = self.interface_var.get().split(" ")[0]
        filt = self.filter_entry.get().strip()
        self.config.set("interface", iface)
        self.config.set("filter", filt)

        self.capture.set_interface(iface)
        self.capture.set_filter(filt)
        self.capture.start()

        self.status_label.config(text="● EN CAPTURE", fg=THEME_YELLOW)
        self.btn_start.config(state=DISABLED)
        self.btn_stop.config(state=NORMAL)
        self.footer_label.config(text=f"Capture sur {iface} | filtre: {filt or 'aucun'}")

    def stop_capture(self):
        self.capture.stop()
        self.status_label.config(text="● ARRÊTÉ", fg=THEME_RED)
        self.btn_start.config(state=NORMAL)
        self.btn_stop.config(state=DISABLED)
        self.footer_label.config(text="Capture arrêtée")

    def manual_scan(self):
        iface = self.interface_var.get().split(" ")[0]
        network_range = self.net_tools.get_network_range(iface)
        if not network_range:
            messagebox.showwarning("Scan", "Impossible de déterminer le réseau local.")
            return

        self.footer_label.config(text=f"Scan en cours sur {network_range}...")
        threading.Thread(target=self._scan_thread, args=(network_range,), daemon=True).start()

    def _scan_thread(self, network_range):
        def on_device(ip, mac, vendor, hostname):
            self.db.insert_or_update_device(ip, mac, vendor, hostname)
            self.devices[ip] = {"ip": ip, "mac": mac, "vendor": vendor, "hostname": hostname}
            self.root.after(0, self.update_devices_list)

        self.net_tools.scan_network(network_range, callback=on_device)
        self.root.after(0, lambda: self.footer_label.config(text="Scan terminé"))

    def start_network_scanner(self):
        def loop():
            while True:
                try:
                    iface = self.interface_var.get().split(" ")[0]
                    network_range = self.net_tools.get_network_range(iface)
                    if network_range:
                        self.net_tools.scan_network(network_range, callback=self.on_device_found)
                except Exception as e:
                    print(f"[SCANNER] {e}")
                time.sleep(self.config.get("scan_interval"))

        threading.Thread(target=loop, daemon=True).start()

    def on_device_found(self, ip, mac, vendor, hostname):
        self.db.insert_or_update_device(ip, mac, vendor, hostname)
        with self.lock:
            self.devices[ip] = {"ip": ip, "mac": mac, "vendor": vendor, "hostname": hostname}
        self.root.after(0, self.update_devices_list)

    def update_devices_list(self):
        self.devices_listbox.delete(0, END)
        with self.lock:
            for ip, dev in sorted(self.devices.items()):
                label = f"{ip}"
                if dev.get("hostname"):
                    label += f" | {dev['hostname']}"
                if dev.get("vendor"):
                    label += f" | {dev['vendor']}"
                self.devices_listbox.insert(END, label)

    def start_ui_updater(self):
        def update():
            self.process_packet_queue()
            self.update_stats()
            self.update_graph()
            self.packet_count_label.config(text=f"Paquets : {self.capture.packet_count}")
            self.root.after(500, update)
        update()

    def process_packet_queue(self):
        count = 0
        while not self.capture.packet_queue.empty() and count < 100:
            try:
                info = self.capture.packet_queue.get_nowait()
                self.add_packet_to_ui(info)
                self.db.insert_packet(info)
                count += 1
            except Exception as e:
                print(f"[UI] Queue error: {e}")
                break

    def add_packet_to_ui(self, info):
        proto = info.get("protocol", "OTHER")
        tag = f"tag_{proto}"
        if tag not in self.tree.tag_configure("").__dict__:
            color = PROTOCOL_COLORS.get(proto, THEME_FG)
            self.tree.tag_configure(tag, foreground=color)

        values = (
            info.get("timestamp", ""),
            proto,
            f"{info.get('src_ip', '')}:{info.get('src_port', '')}".rstrip(":"),
            f"{info.get('dst_ip', '')}:{info.get('dst_port', '')}".rstrip(":"),
            info.get("domain", ""),
            info.get("info", "")
        )
        self.tree.insert("", END, values=values, tags=(tag,))

        with self.lock:
            self.protocol_counts[proto] += 1
            if info.get("src_ip"):
                self.ip_counts[info["src_ip"]] += 1
            if info.get("dst_ip"):
                self.ip_counts[info["dst_ip"]] += 1
            if info.get("domain"):
                self.domain_counts[info["domain"]] += 1

            self.packet_list.append(info)
            max_packets = self.config.get("max_packets")
            if len(self.packet_list) > max_packets:
                self.packet_list.pop(0)

        if self.config.get("auto_scroll"):
            self.tree.yview_moveto(1.0)

    def on_packet_select(self, event):
        selected = self.tree.selection()
        if not selected:
            return
        item = self.tree.item(selected[0])
        values = item.get("values", [])
        if not values:
            return

        timestamp = values[0]
        proto = values[1]
        src = values[2]
        dst = values[3]
        domain = values[4]
        info_text = values[5]

        explanation = (
            f"Heure : {timestamp}\n"
            f"Protocole : {proto}\n"
            f"Source : {src}\n"
            f"Destination : {dst}\n"
            f"Domaine : {domain}\n"
            f"Info brute : {info_text}\n\n"
        )

        for pkt in reversed(self.packet_list):
            if pkt.get("timestamp") == timestamp and pkt.get("info") == info_text:
                explanation += f"Explication :\n{pkt.get('explanation', '')}\n\n"
                explanation += f"Hex brut (200 premiers caractères) :\n{pkt.get('raw_hex', '')}"
                break

        self.detail_text.delete("1.0", END)
        self.detail_text.insert(END, explanation)

    def update_stats(self):
        with self.lock:
            total = sum(self.protocol_counts.values())
            lines = [f"Total paquets : {total}", "", "Par protocole :"]
            for proto, count in self.protocol_counts.most_common():
                pct = (count / total * 100) if total else 0
                lines.append(f"  {proto:8} : {count:6} ({pct:.1f}%)")
            lines.append("")
            lines.append("Top IP :")
            for ip, count in self.ip_counts.most_common(5):
                lines.append(f"  {ip:20} : {count}")
            lines.append("")
            lines.append("Top domaines :")
            for domain, count in self.domain_counts.most_common(5):
                lines.append(f"  {domain:40} : {count}")

        self.stats_text.delete("1.0", END)
        self.stats_text.insert(END, "\n".join(lines))

    def update_graph(self):
        self.ax.clear()
        self.ax.set_facecolor(THEME_BG)
        self.ax.tick_params(colors=THEME_FG)
        with self.lock:
            labels = list(self.protocol_counts.keys())
            values = list(self.protocol_counts.values())
        if labels:
            colors = [PROTOCOL_COLORS.get(l, THEME_FG) for l in labels]
            self.ax.bar(labels, values, color=colors)
            self.ax.set_title("Répartition des protocoles", color=THEME_FG)
        self.canvas.draw()

    def load_history(self):
        try:
            rows = self.db.get_recent_packets(100)
            for row in reversed(rows):
                info = {
                    "timestamp": row[1],
                    "protocol": row[2],
                    "src_ip": row[3],
                    "dst_ip": row[4],
                    "src_port": row[5],
                    "dst_port": row[6],
                    "src_mac": row[7],
                    "dst_mac": row[8],
                    "domain": row[9],
                    "length": row[10],
                    "info": row[11],
                    "explanation": row[12],
                    "raw_hex": row[13]
                }
                self.add_packet_to_ui(info)
        except Exception as e:
            print(f"[HISTORY] Load error: {e}")

    def clear_history(self):
        self.db.clear_packets()
        for item in self.tree.get_children():
            self.tree.delete(item)
        with self.lock:
            self.packet_list.clear()
            self.protocol_counts.clear()
            self.ip_counts.clear()
            self.domain_counts.clear()

    def export_pcap(self):
        path = filedialog.asksaveasfilename(defaultextension=".pcap",
                                            filetypes=[("Fichiers PCAP", "*.pcap")])
        if path:
            messagebox.showinfo("Export", f"Fonctionnalité d'export PCAP vers : {path}")

    def import_pcap(self):
        path = filedialog.askopenfilename(filetypes=[("Fichiers PCAP", "*.pcap")])
        if path:
            try:
                packets = rdpcap(path)
                for pkt in packets:
                    info = self.analyzer.analyze(pkt)
                    self.add_packet_to_ui(info)
                    self.db.insert_packet(info)
                messagebox.showinfo("Import", f"{len(packets)} paquets importés.")
            except Exception as e:
                messagebox.showerror("Erreur", str(e))

    def toggle_auto_scroll(self):
        self.config.set("auto_scroll", not self.config.get("auto_scroll"))

    def toggle_show_payload(self):
        self.config.set("show_payload", not self.config.get("show_payload"))

    def show_about(self):
        msg = f"{APP_NAME} v{APP_VERSION}\nAuteur : {APP_AUTHOR}\nLicence : {APP_LICENSE}\n\n"
        msg += "Analyseur de trafic réseau en temps réel avec interface Tkinter."
        messagebox.showinfo("À propos", msg)

    def show_docs(self):
        doc = (
            "WIRE_ENGINE - Guide rapide\n\n"
            "1. Choisissez une interface réseau.\n"
            "2. (Optionnel) saisissez un filtre BPF, ex: tcp port 80\n"
            "3. Cliquez sur DÉMARRER pour capturer.\n"
            "4. Les paquets apparaissent en temps réel.\n"
            "5. Cliquez sur un paquet pour voir son explication.\n"
            "6. L'onglet Appareils liste les machines connectées.\n"
            "7. Les statistiques et graphiques se mettent à jour automatiquement.\n"
        )
        messagebox.showinfo("Documentation", doc)

    def on_close(self):
        self.capture.stop()
        self.config.save()
        self.root.destroy()


# ---------------------------------------------------------------------------
# POINT D'ENTRÉE
# ---------------------------------------------------------------------------
def main():
    root = Tk()
    app = WireEngineApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
