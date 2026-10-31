#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WIRE_ENGINE
Auteur : hackes_tchad
Version : 1.0.0
Description :
    Interface avancée de capture et d’analyse réseau en temps réel.
    Capture les paquets transitant par le routeur/localhost, liste les
    appareils connectés, résout les noms de domaine, et affiche une
    introduction pédagogique directement dans l’interface.
"""

# =============================================================================
# IMPORTS
# =============================================================================

import sys
import os
import re
import time
import json
import csv
import socket
import struct
import threading
import subprocess
import ipaddress
import datetime
import argparse
import hashlib
import base64
import random
import string
import platform
import textwrap
import html
import math
import stat
import shutil
import uuid
import warnings
import traceback
import logging
from collections import deque, Counter, defaultdict
from contextlib import suppress
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from typing import (
    Any, Callable, Deque, Dict, Iterable, List, Optional, Set, Tuple, Union
)

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog, scrolledtext, Menu
except ImportError:  # pragma: no cover
    raise ImportError("Tkinter est requis pour l'interface WIRE_ENGINE.")

# ---------------------------------------------------------------------------
# Gestion des dépendances tierces avec messages explicites
# ---------------------------------------------------------------------------

_MISSING = []

# scapy : capture / décodage de paquets
with suppress(ImportError):
    from scapy.all import (
        sniff, get_if_list, get_if_addr, conf, Ether, IP, IPv6, TCP, UDP,
        ICMP, ARP, DNS, DNSQR, DNSRR, Raw, wrpcap, rdpcap, Packet
    )

if 'scapy' not in sys.modules:
    _MISSING.append("scapy>=2.5.0")

# psutil : stats réseau / appareils
with suppress(ImportError):
    import psutil

if 'psutil' not in sys.modules:
    _MISSING.append("psutil>=5.9.0")

# requests : géolocalisation IP
with suppress(ImportError):
    import requests

if 'requests' not in sys.modules:
    _MISSING.append("requests>=2.31.0")

# matplotlib : graphiques temps réel
with suppress(ImportError):
    import matplotlib
    matplotlib.use("TkAgg")
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure

if 'matplotlib' not in sys.modules:
    _MISSING.append("matplotlib>=3.8.0")

# pandas : export / analyse
with suppress(ImportError):
    import pandas as pd

if 'pandas' not in sys.modules:
    _MISSING.append("pandas>=2.0.0")

# numpy : traitement de signaux / stats
with suppress(ImportError):
    import numpy as np

if 'numpy' not in sys.modules:
    _MISSING.append("numpy>=1.24.0")

# netaddr : manipulation d’adresses réseau
with suppress(ImportError):
    import netaddr

if 'netaddr' not in sys.modules:
    _MISSING.append("netaddr>=0.9.0")

if _MISSING:
    print("\n[ERREUR] Modules manquants. Installez-les via :")
    print("pip install " + " ".join(_MISSING))
    sys.exit(1)

# ---------------------------------------------------------------------------
# Configuration globale
# ---------------------------------------------------------------------------

APP_NAME = "WIRE_ENGINE"
APP_AUTHOR = "hackes_tchad"
APP_VERSION = "1.0.0"
APP_LICENSE = "MIT – Usage éducatif uniquement"

DEFAULT_DB_PATH = "wire_engine_captures"
LOG_FILE = "wire_engine.log"
MAX_PACKET_QUEUE = 50_000
MAX_UI_ROWS = 10_000
REFRESH_MS = 500

# Palette monochrome
BG_COLOR = "#0a0a0a"
FG_COLOR = "#f0f0f0"
ACCENT_COLOR = "#00ffcc"
SECONDARY_FG = "#b0b0b0"
GRID_COLOR = "#333333"
ROW_ODD = "#111111"
ROW_EVEN = "#1a1a1a"
HIGHLIGHT = "#00ffcc"
ALERT_COLOR = "#ff5555"
WARN_COLOR = "#ffcc00"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

# =============================================================================
# STRUCTURES DE DONNÉES
# =============================================================================

class Protocol(Enum):
    UNKNOWN = auto()
    ETHERNET = auto()
    ARP = auto()
    IP = auto()
    ICMP = auto()
    TCP = auto()
    UDP = auto()
    DNS = auto()
    HTTP = auto()
    HTTPS = auto()
    DHCP = auto()
    SSDP = auto()
    LLMNR = auto()
    NBNS = auto()
    MDNS = auto()
    OTHER = auto()


@dataclass
class PacketSummary:
    """Résumé compact d’un paquet capturé."""
    idx: int
    timestamp: float
    src_mac: str
    dst_mac: str
    ethertype: str
    src_ip: str
    dst_ip: str
    proto: str
    src_port: Optional[int]
    dst_port: Optional[int]
    length: int
    info: str
    domain: Optional[str] = None
    hostname: Optional[str] = None
    country: Optional[str] = None
    asn: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    raw_summary: str = ""


@dataclass
class Device:
    """Appareil découvert sur le réseau local."""
    ip: str
    mac: str
    hostname: str = ""
    vendor: str = ""
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    packet_count: int = 0
    bytes_total: int = 0
    is_gateway: bool = False
    os_guess: str = ""
    notes: str = ""


@dataclass
class FlowKey:
    """Clé de flux unidirectionnelle."""
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    proto: str


@dataclass
class Flow:
    """Flux réseau agrégé."""
    key: FlowKey
    first_seen: float
    last_seen: float
    packets: int = 0
    bytes_total: int = 0
    domains: Set[str] = field(default_factory=set)
    flags: Counter = field(default_factory=Counter)


# =============================================================================
# UTILITAIRES RÉSEAU
# =============================================================================

class NetworkUtils:
    """Outils réseau transversaux."""

    MAC_OUI_DB: Dict[str, str] = {}
    WELL_KNOWN_PORTS: Dict[int, str] = {}
    COUNTRY_CACHE: Dict[str, Optional[str]] = {}
    HOSTNAME_CACHE: Dict[str, str] = {}

    @classmethod
    def load_oui(cls, path: str = "oui.txt") -> None:
        """Charge une base OUI minimale si présente."""
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if "(base 16)" in line:
                        parts = line.split("(base 16)")
                        if len(parts) == 2:
                            oui = parts[0].strip().replace("-", ":").upper()
                            vendor = parts[1].strip()
                            cls.MAC_OUI_DB[oui] = vendor

    @classmethod
    def load_well_known_ports(cls) -> None:
        """Charge les services standards depuis /etc/services si possible."""
        candidates = ["/etc/services"]
        if platform.system() == "Windows":
            candidates.append(r"C:\Windows\System32\drivers\etc\services")
        for c in candidates:
            if os.path.exists(c):
                with open(c, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.split("#")[0].strip()
                        if not line:
                            continue
                        parts = line.split()
                        if len(parts) >= 2:
                            name = parts[0]
                            port_proto = parts[1]
                            if "/" in port_proto:
                                try:
                                    port = int(port_proto.split("/")[0])
                                    cls.WELL_KNOWN_PORTS[port] = name
                                except ValueError:
                                    pass

    @staticmethod
    def get_default_interface() -> str:
        """Retourne l’interface par défaut détectée par Scapy."""
        try:
            iface = conf.iface
            return str(iface)
        except Exception:
            ifaces = get_if_list()
            for i in ifaces:
                if i != "lo" and "loop" not in i.lower():
                    return i
            return ifaces[0] if ifaces else "eth0"

    @staticmethod
    def get_local_networks() -> List[str]:
        """Liste les réseaux locaux (CIDR) de l’hôte."""
        nets = []
        try:
            for nic, addrs in psutil.net_if_addrs().items():
                for a in addrs:
                    if a.family == socket.AF_INET:
                        try:
                            net = ipaddress.IPv4Network(
                                f"{a.address}/{a.netmask}", strict=False
                            )
                            nets.append(str(net))
                        except Exception:
                            pass
        except Exception as exc:
            logging.warning("get_local_networks: %s", exc)
        return nets or ["127.0.0.0/8"]

    @staticmethod
    def get_gateway() -> Optional[str]:
        """Retourne la passerelle par défaut IPv4."""
        try:
            gws = psutil.net_if_addrs()
            # fallback : parser la route par défaut
            if platform.system() == "Windows":
                result = subprocess.run(
                    ["route", "print", "0.0.0.0"],
                    capture_output=True, text=True, check=False
                )
                for line in result.stdout.splitlines():
                    if "0.0.0.0" in line and "Gateway" not in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            return parts[2]
            else:
                result = subprocess.run(
                    ["ip", "route"], capture_output=True, text=True, check=False
                )
                for line in result.stdout.splitlines():
                    if line.startswith("default"):
                        parts = line.split()
                        if "via" in parts:
                            return parts[parts.index("via") + 1]
        except Exception as exc:
            logging.warning("get_gateway: %s", exc)
        return None

    @classmethod
    def resolve_hostname(cls, ip: str) -> str:
        """Résolution inverse avec cache."""
        if ip in cls.HOSTNAME_CACHE:
            return cls.HOSTNAME_CACHE[ip]
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            cls.HOSTNAME_CACHE[ip] = hostname
            return hostname
        except Exception:
            cls.HOSTNAME_CACHE[ip] = ""
            return ""

    @classmethod
    def resolve_country(cls, ip: str) -> Optional[str]:
        """Géolocalisation approximative via ip-api (gratuit)."""
        if not ip or ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("169.254."):
            return "LAN"
        if ip in cls.COUNTRY_CACHE:
            return cls.COUNTRY_CACHE[ip]
        try:
            resp = requests.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,as",
                timeout=2
            )
            data = resp.json()
            country = data.get("country") or "Inconnu"
            cls.COUNTRY_CACHE[ip] = country
            return country
        except Exception:
            cls.COUNTRY_CACHE[ip] = None
            return None

    @classmethod
    def vendor_from_mac(cls, mac: str) -> str:
        """Devine le constructeur depuis l’OUI."""
        if not mac or mac == "ff:ff:ff:ff:ff:ff":
            return ""
        oui = ":".join(mac.upper().split(":")[:3])
        return cls.MAC_OUI_DB.get(oui, "")

    @staticmethod
    def port_service(port: int, proto: str = "tcp") -> str:
        """Nom de service standard pour un port."""
        try:
            return socket.getservbyport(port, proto)
        except (OSError, ValueError):
            return NetworkUtils.WELL_KNOWN_PORTS.get(port, "")

    @staticmethod
    def format_bytes(num: int) -> str:
        """Taille lisible."""
        for unit in ["o", "Ko", "Mo", "Go", "To"]:
            if abs(num) < 1024.0:
                return f"{num:.2f} {unit}"
            num /= 1024.0
        return f"{num:.2f} Po"

    @staticmethod
    def format_duration(seconds: float) -> str:
        """Durée lisible."""
        return str(datetime.timedelta(seconds=int(seconds)))

    @staticmethod
    def mac_from_bytes(raw: bytes) -> str:
        """Convertit 6 octets en MAC lisible."""
        return ":".join(f"{b:02x}" for b in raw)


# Charger ressources
NetworkUtils.load_well_known_ports()
NetworkUtils.load_oui()


# =============================================================================
# ANALYSEUR DE PAQUETS
# =============================================================================

class PacketAnalyzer:
    """Transforme un paquet Scapy en structures exploitables."""

    DOMAIN_QUEUE: Deque[Tuple[str, str]] = deque(maxlen=MAX_PACKET_QUEUE)
    HOST_UPDATE_CALLBACK: Optional[Callable[[str], None]] = None

    def __init__(self):
        self.counter = 0

    def analyze(self, pkt: Packet) -> Optional[PacketSummary]:
        """Analyse un paquet Scapy et retourne un résumé."""
        self.counter += 1
        idx = self.counter
        ts = time.time()

        src_mac = dst_mac = ""
        ethertype = ""
        src_ip = dst_ip = ""
        proto_name = Protocol.UNKNOWN.name
        src_port = dst_port = None
        length = len(pkt)
        info = ""
        domain: Optional[str] = None
        tags: List[str] = []

        try:
            if Ether in pkt:
                eth = pkt[Ether]
                src_mac = eth.src
                dst_mac = eth.dst
                ethertype = hex(eth.type)
                if eth.type == 0x0806:
                    proto_name = Protocol.ARP.name
                elif eth.type == 0x0800:
                    proto_name = Protocol.IP.name
                elif eth.type == 0x86dd:
                    proto_name = Protocol.IPv6.name

            # ARP
            if ARP in pkt:
                arp = pkt[ARP]
                src_ip = arp.psrc
                dst_ip = arp.pdst
                info = f"ARP {arp.op} {src_ip} -> {dst_ip}"
                proto_name = Protocol.ARP.name
                if arp.hwsrc:
                    src_mac = arp.hwsrc
                tags.append("ARP")

            # IPv4
            if IP in pkt:
                ip = pkt[IP]
                src_ip = ip.src
                dst_ip = ip.dst
                info = f"IPv4 TTL={ip.ttl} ID={ip.id}"
                if TCP in pkt:
                    proto_name = Protocol.TCP.name
                    tcp = pkt[TCP]
                    src_port = tcp.sport
                    dst_port = tcp.dport
                    flags = self._tcp_flags(tcp.flags)
                    info = f"TCP {src_port} -> {dst_port} [{flags}] Seq={tcp.seq} Ack={tcp.ack}"
                    if tcp.flags.S:
                        tags.append("SYN")
                    if tcp.flags.A:
                        tags.append("ACK")
                    if tcp.flags.F:
                        tags.append("FIN")
                    if tcp.flags.R:
                        tags.append("RST")
                    if dst_port == 80 or src_port == 80:
                        proto_name = Protocol.HTTP.name
                        info += " HTTP"
                    elif dst_port == 443 or src_port == 443:
                        proto_name = Protocol.HTTPS.name
                        info += " HTTPS"
                elif UDP in pkt:
                    proto_name = Protocol.UDP.name
                    udp = pkt[UDP]
                    src_port = udp.sport
                    dst_port = udp.dport
                    info = f"UDP {src_port} -> {dst_port} Len={udp.len}"
                    if DNS in pkt:
                        proto_name = Protocol.DNS.name
                        info = self._dns_info(pkt)
                        domain = self._extract_dns_domain(pkt)
                    elif dst_port == 67 or dst_port == 68 or src_port in (67, 68):
                        proto_name = Protocol.DHCP.name
                        info = "DHCP"
                    elif dst_port == 1900 or src_port == 1900:
                        proto_name = Protocol.SSDP.name
                        info = "SSDP"
                    elif dst_port == 5355 or src_port == 5355:
                        proto_name = Protocol.LLMNR.name
                        info = "LLMNR"
                    elif dst_port == 137 or src_port == 137:
                        proto_name = Protocol.NBNS.name
                        info = "NBNS"
                    elif dst_port == 5353 or src_port == 5353:
                        proto_name = Protocol.MDNS.name
                        info = "mDNS"
                elif ICMP in pkt:
                    proto_name = Protocol.ICMP.name
                    icmp = pkt[ICMP]
                    info = f"ICMP type={icmp.type} code={icmp.code}"
                    tags.append("ICMP")

            # IPv6
            if IPv6 in pkt:
                ip6 = pkt[IPv6]
                src_ip = ip6.src
                dst_ip = ip6.dst
                info = f"IPv6 NH={ip6.nh} Hlim={ip6.hlim}"
                if TCP in pkt:
                    proto_name = Protocol.TCP.name
                elif UDP in pkt:
                    proto_name = Protocol.UDP.name

            # Couche Raw / payload
            if Raw in pkt:
                payload = bytes(pkt[Raw].load)
                if proto_name == Protocol.TCP.name and (dst_port == 80 or src_port == 80):
                    try:
                        text = payload[:200].decode("utf-8", errors="ignore")
                        if text.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HTTP/")):
                            first = text.split("\r\n")[0]
                            info = f"HTTP {first[:80]}"
                    except Exception:
                        pass

            if not src_ip:
                src_ip = ""
            if not dst_ip:
                dst_ip = ""

            raw_summary = pkt.summary()

            summary = PacketSummary(
                idx=idx,
                timestamp=ts,
                src_mac=src_mac,
                dst_mac=dst_mac,
                ethertype=ethertype,
                src_ip=src_ip,
                dst_ip=dst_ip,
                proto=proto_name,
                src_port=src_port,
                dst_port=dst_port,
                length=length,
                info=info,
                domain=domain,
                tags=tags,
                raw_summary=raw_summary
            )

            if domain and src_ip:
                PacketAnalyzer.DOMAIN_QUEUE.append((domain, src_ip))
                if PacketAnalyzer.HOST_UPDATE_CALLBACK:
                    PacketAnalyzer.HOST_UPDATE_CALLBACK(domain)

            return summary
        except Exception as exc:
            logging.warning("analyze error: %s", exc)
            return None

    @staticmethod
    @staticmethod
    def _tcp_flags(flags) -> str:
        """Convertit les flags TCP en chaîne lisible (SYN, ACK, FIN, etc.)."""
        letters = []
        if flags.S: letters.append("S")
        if flags.A: letters.append("A")
        if flags.F: letters.append("F")
        if flags.R: letters.append("R")
        if flags.P: letters.append("P")
        if flags.U: letters.append("U")
        return "".join(letters) if letters else "-"
        """Retourne une chaîne de flags TCP lisible."""
        out = []
        if flags.F:
            out.append("FIN")
        if flags.S:
            out.append("SYN")
        if flags.R:
            out.append("RST")
        if flags.P:
            out.append("PSH")
        if flags.A:
            out.append("ACK")
        if flags.U:
            out.append("URG")
        return ",".join(out) if out else "-"

    @staticmethod
    @staticmethod
    def _dns_info(pkt: Packet) -> str:
        """Construit une info textuelle pour un paquet DNS."""
        try:
            dns = pkt[DNS]
            qname = ""
            if dns.qd:
                qname = dns.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
            if dns.qr == 0:
                return f"DNS Query {qname}"
            else:
                answers = []
                if dns.an:
                    for i in range(dns.ancount):
                        rr = dns.an[i]
                        if rr:
                            answers.append(str(rr.rdata))
                return f"DNS Response {qname} -> {', '.join(answers[:3])}"
        except Exception as exc:
            return f"DNS (erreur décodage: {exc})"

    @staticmethod
    def _extract_dns_domain(pkt: Packet) -> Optional[str]:
        """Extrait le nom de domaine d’une requête DNS."""
        try:
            dns = pkt[DNS]
            if dns.qd and dns.qd.qname:
                return dns.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
        except Exception:
            pass
        return None


# =============================================================================
# DÉCOUVERTE DES APPAREILS
# =============================================================================

class DeviceDiscovery:
    """Découvre et enrichit les appareils du réseau local."""

    def __init__(self):
        self._lock = threading.RLock()
        self._devices: Dict[str, Device] = {}
        self._gateway: Optional[str] = NetworkUtils.get_gateway()
        self._last_scan = 0.0
        self._scan_interval = 60.0

    def feed(self, summary: PacketSummary) -> None:
        """Met à jour la table d’appareils à partir d’un paquet."""
        for ip, mac in [(summary.src_ip, summary.src_mac), (summary.dst_ip, summary.dst_mac)]:
            if not ip or not mac:
                continue
            if ip == "0.0.0.0" or ip.startswith("255") or ip.startswith("224"):
                continue
            with self._lock:
                if mac in self._devices:
                    dev = self._devices[mac]
                    if ip not in (dev.ip, ""):
                        dev.ip = ip
                    dev.last_seen = time.time()
                    dev.packet_count += 1
                    dev.bytes_total += summary.length
                else:
                    dev = Device(
                        ip=ip,
                        mac=mac,
                        vendor=NetworkUtils.vendor_from_mac(mac),
                        hostname=NetworkUtils.resolve_hostname(ip),
                        is_gateway=(ip == self._gateway),
                        packet_count=1,
                        bytes_total=summary.length
                    )
                    self._devices[mac] = dev

    def enrich(self) -> None:
        """Enrichit périodiquement via résolution DNS et marquage gateway."""
        now = time.time()
        if now - self._last_scan < self._scan_interval:
            return
        self._last_scan = now
        with self._lock:
            for dev in self._devices.values():
                if not dev.hostname:
                    dev.hostname = NetworkUtils.resolve_hostname(dev.ip)
                dev.is_gateway = (dev.ip == self._gateway)

    def get_devices(self) -> List[Device]:
        """Retourne la liste des appareils triés par activité."""
        with self._lock:
            return sorted(
                self._devices.values(),
                key=lambda d: d.bytes_total,
                reverse=True
            )

    def device_count(self) -> int:
        with self._lock:
            return len(self._devices)


# =============================================================================
# MOTEUR DE CAPTURE
# =============================================================================

class CaptureEngine:
    """Gère la capture Scapy et l’agrégation des données."""

    def __init__(self, interface: Optional[str] = None, bpf_filter: str = ""):
        self.interface = interface or NetworkUtils.get_default_interface()
        self.bpf_filter = bpf_filter
        self._analyzer = PacketAnalyzer()
        self._callbacks: List[Callable[[PacketSummary], None]] = []
        self._queue: Deque[PacketSummary] = deque(maxlen=MAX_PACKET_QUEUE)
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._start_time: Optional[float] = None
        self.device_discovery = DeviceDiscovery()
        self.flows: Dict[Tuple[str, str, Optional[int], Optional[int], str], Flow] = {}
        self.domains: Dict[str, Set[str]] = defaultdict(set)
        self._packet_count = 0
        self._byte_count = 0
        self._last_pps_time = time.time()
        self._pps_window: Deque[float] = deque(maxlen=10)

    def register_callback(self, callback: Callable[[PacketSummary], None]) -> None:
        self._callbacks.append(callback)

    def unregister_callback(self, callback: Callable[[PacketSummary], None]) -> None:
        with suppress(ValueError):
            self._callbacks.remove(callback)

    def _process_packet(self, pkt: Packet) -> None:
        summary = self._analyzer.analyze(pkt)
        if not summary:
            return
        with self._lock:
            self._packet_count += 1
            self._byte_count += summary.length
            self._queue.append(summary)
            self.device_discovery.feed(summary)
            self._update_flows(summary)
            if summary.domain:
                self.domains[summary.domain].add(summary.src_ip)
                self.domains[summary.domain].add(summary.dst_ip)
        for cb in self._callbacks:
            try:
                cb(summary)
            except Exception as exc:
                logging.warning("callback error: %s", exc)

    def _update_flows(self, s: PacketSummary) -> None:
        if not s.src_ip or not s.dst_ip:
            return
        key_tuple = (s.src_ip, s.dst_ip, s.src_port, s.dst_port, s.proto)
        now = time.time()
        flow = self.flows.get(key_tuple)
        if flow is None:
            key = FlowKey(s.src_ip, s.dst_ip, s.src_port, s.dst_port, s.proto)
            flow = Flow(key=key, first_seen=now, last_seen=now)
            self.flows[key_tuple] = flow
        flow.last_seen = now
        flow.packets += 1
        flow.bytes_total += s.length
        if s.domain:
            flow.domains.add(s.domain)
        for tag in s.tags:
            flow.flags[tag] += 1

    def _sniff_loop(self) -> None:
        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter or None,
                prn=self._process_packet,
                stop_filter=lambda p: self._stop_event.is_set(),
                store=False
            )
        except Exception as exc:
            logging.error("sniff error: %s", exc)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._start_time = time.time()
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2.0)

    def get_stats(self) -> Dict[str, Any]:
        now = time.time()
        duration = (self._start_time and (now - self._start_time)) or 0.0
        self._pps_window.append(self._packet_count)
        pps = 0.0
        if len(self._pps_window) >= 2:
            pps = (self._pps_window[-1] - self._pps_window[0]) / max(1.0, now - self._last_pps_time)
        self._last_pps_time = now
        with self._lock:
            return {
                "packets": self._packet_count,
                "bytes": self._byte_count,
                "duration": duration,
                "pps": pps,
                "flows": len(self.flows),
                "devices": self.device_discovery.device_count(),
                "domains": len(self.domains)
            }

    def get_packets(self, limit: int = 1000) -> List[PacketSummary]:
        with self._lock:
            return list(self._queue)[-limit:]

    def export_csv(self, path: str) -> None:
        rows = self.get_packets(MAX_UI_ROWS)
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "idx", "timestamp", "src_mac", "dst_mac", "ethertype",
                "src_ip", "dst_ip", "proto", "src_port", "dst_port",
                "length", "domain", "info"
            ])
            for s in rows:
                writer.writerow([
                    s.idx, s.timestamp, s.src_mac, s.dst_mac, s.ethertype,
                    s.src_ip, s.dst_ip, s.proto, s.src_port, s.dst_port,
                    s.length, s.domain or "", s.info
                ])


# =============================================================================
# COMPOSANTS D’INTERFACE TKINTER
# =============================================================================

class StyledFrame(ttk.Frame):
    """Frame stylisé noir et blanc."""
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.configure(style="Dark.TFrame")


class PacketTree(ttk.Treeview):
    """Tableau des paquets capturés."""

    COLUMNS = (
        "idx", "time", "src", "dst", "proto", "sport", "dport",
        "len", "domain", "info"
    )

    def __init__(self, parent):
        super().__init__(
            parent,
            columns=self.COLUMNS,
            show="headings",
            selectmode="browse",
            style="Dark.Treeview"
        )
        self._setup_columns()
        self.vsb = ttk.Scrollbar(parent, orient="vertical", command=self.yview)
        self.hsb = ttk.Scrollbar(parent, orient="horizontal", command=self.xview)
        self.configure(yscrollcommand=self.vsb.set, xscrollcommand=self.hsb.set)
        self.grid(row=0, column=0, sticky="nsew")
        self.vsb.grid(row=0, column=1, sticky="ns")
        self.hsb.grid(row=1, column=0, sticky="ew")
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=1)
        self._rows: Dict[int, str] = {}
        self._data: Dict[str, PacketSummary] = {}

    def _setup_columns(self):
        widths = {
            "idx": 60, "time": 80, "src": 130, "dst": 130, "proto": 70,
            "sport": 60, "dport": 60, "len": 60, "domain": 180, "info": 350
        }
        texts = {
            "idx": "#", "time": "Temps", "src": "Source", "dst": "Destination",
            "proto": "Proto", "sport": "SPort", "dport": "DPort",
            "len": "Taille", "domain": "Domaine", "info": "Info"
        }
        for col in self.COLUMNS:
            self.heading(col, text=texts[col])
            self.column(col, width=widths[col], anchor="w")

    def insert_packet(self, s: PacketSummary) -> None:
        tag = self._tag_for_proto(s.proto)
        ts = datetime.datetime.fromtimestamp(s.timestamp).strftime("%H:%M:%S.%f")[:-3]
        iid = self.insert(
            "", "end",
            values=(
                s.idx, ts, s.src_ip or s.src_mac, s.dst_ip or s.dst_mac,
                s.proto, s.src_port or "", s.dst_port or "", s.length,
                s.domain or "", s.info[:80]
            ),
            tags=(tag,)
        )
        self._rows[s.idx] = iid
        self._data[iid] = s
        if len(self.get_children()) > MAX_UI_ROWS:
            first = self.get_children()[0]
            del self._data[first]
            self.delete(first)

    def _tag_for_proto(self, proto: str) -> str:
        return {
            Protocol.HTTP.name: "http", Protocol.HTTPS.name: "https",
            Protocol.DNS.name: "dns", Protocol.TCP.name: "tcp",
            Protocol.UDP.name: "udp", Protocol.ARP.name: "arp",
            Protocol.ICMP.name: "icmp", Protocol.DHCP.name: "dhcp"
        }.get(proto, "default")

    def selected_summary(self) -> Optional[PacketSummary]:
        sel = self.selection()
        if sel:
            return self._data.get(sel[0])
        return None


class DeviceTree(ttk.Treeview):
    """Tableau des appareils connectés."""

    COLUMNS = ("ip", "mac", "hostname", "vendor", "packets", "bytes", "gateway", "os")

    def __init__(self, parent):
        super().__init__(
            parent, columns=self.COLUMNS, show="headings", style="Dark.Treeview"
        )
        self._setup_columns()
        self.vsb = ttk.Scrollbar(parent, orient="vertical", command=self.yview)
        self.configure(yscrollcommand=self.vsb.set)
        self.grid(row=0, column=0, sticky="nsew")
        self.vsb.grid(row=0, column=1, sticky="ns")
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=1)
        self._items: Dict[str, str] = {}

    def _setup_columns(self):
        texts = {
            "ip": "IP", "mac": "MAC", "hostname": "Hôte",
            "vendor": "Constructeur", "packets": "Paquets",
            "bytes": "Octets", "gateway": "Passerelle", "os": "OS"
        }
        widths = {
            "ip": 130, "mac": 130, "hostname": 160, "vendor": 160,
            "packets": 70, "bytes": 90, "gateway": 70, "os": 90
        }
        for col in self.COLUMNS:
            self.heading(col, text=texts[col])
            self.column(col, width=widths[col], anchor="w")

    def refresh(self, devices: List[Device]) -> None:
        current = set(self._items.keys())
        seen = set()
        for dev in devices:
            key = dev.mac
            seen.add(key)
            values = (
                dev.ip, dev.mac, dev.hostname, dev.vendor,
                dev.packet_count, NetworkUtils.format_bytes(dev.bytes_total),
                "OUI" if dev.is_gateway else "", dev.os_guess
            )
            if key in self._items:
                self.item(self._items[key], values=values)
            else:
                iid = self.insert("", "end", values=values)
                self._items[key] = iid
        for key in current - seen:
            self.delete(self._items[key])
            del self._items[key]


class DomainTree(ttk.Treeview):
    """Tableau des noms de domaine observés."""

    COLUMNS = ("domain", "ips", "hits", "last_seen")

    def __init__(self, parent):
        super().__init__(
            parent, columns=self.COLUMNS, show="headings", style="Dark.Treeview"
        )
        self._setup_columns()
        self.vsb = ttk.Scrollbar(parent, orient="vertical", command=self.yview)
        self.configure(yscrollcommand=self.vsb.set)
        self.grid(row=0, column=0, sticky="nsew")
        self.vsb.grid(row=0, column=1, sticky="ns")
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=1)
        self._items: Dict[str, str] = {}
        self._hits: Counter = Counter()
        self._last: Dict[str, float] = {}

    def _setup_columns(self):
        self.heading("domain", text="Nom de domaine")
        self.heading("ips", text="IPs")
        self.heading("hits", text="Requêtes")
        self.heading("last_seen", text="Dernier")
        self.column("domain", width=300)
        self.column("ips", width=200)
        self.column("hits", width=80)
        self.column("last_seen", width=120)

    def touch(self, domain: str, ip: str = "") -> None:
        now = time.time()
        self._hits[domain] += 1
        self._last[domain] = now
        if domain not in self._items:
            iid = self.insert("", "end", values=(domain, ip, 1, "à l’instant"))
            self._items[domain] = iid
        else:
            ips = set(self.item(self._items[domain], "values")[1].split(", "))
            if ip:
                ips.add(ip)
            self.item(
                self._items[domain],
                values=(domain, ", ".join(sorted(ips)), self._hits[domain], "à l’instant")
            )


class TrafficChart:
    """Graphique temps réel du trafic."""

    def __init__(self, parent):
        self.fig = Figure(figsize=(6, 2.5), dpi=100, facecolor=BG_COLOR)
        self.ax = self.fig.add_subplot(111, facecolor=BG_COLOR)
        self.ax.set_title("Débit (paquets / seconde)", color=FG_COLOR)
        self.ax.tick_params(colors=FG_COLOR)
        self.ax.spines["bottom"].set_color(GRID_COLOR)
        self.ax.spines["left"].set_color(GRID_COLOR)
        self.line, = self.ax.plot([], [], color=ACCENT_COLOR, linewidth=1.5)
        self.fill = self.ax.fill_between([], [], color=ACCENT_COLOR, alpha=0.2)
        self.times: Deque[float] = deque(maxlen=60)
        self.values: Deque[float] = deque(maxlen=60)
        self.canvas = FigureCanvasTkAgg(self.fig, master=parent)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def update(self, pps: float) -> None:
        now = time.time()
        self.times.append(now)
        self.values.append(pps)
        if len(self.times) < 2:
            return
        x = [(t - self.times[0]) for t in self.times]
        self.line.set_data(x, list(self.values))
        self.ax.set_xlim(0, max(x) if x else 1)
        self.ax.set_ylim(0, max(self.values) * 1.2 or 1)
        # Recréer le remplissage
        if self.fill:
            self.fill.remove()
        self.fill = self.ax.fill_between(x, list(self.values), color=ACCENT_COLOR, alpha=0.2)
        self.canvas.draw_idle()


# =============================================================================
# INTERFACE PRINCIPALE
# =============================================================================

class WireEngineApp:
    """Application WIRE_ENGINE complète."""

    def __init__(self, root: tk.Tk, interface: Optional[str] = None, bpf_filter: str = ""):
        self.root = root
        self.root.title(f"{APP_NAME} v{APP_VERSION} – par {APP_AUTHOR}")
        self.root.configure(bg=BG_COLOR)
        self.root.geometry("1400x900")
        self.root.minsize(1100, 700)

        self.engine = CaptureEngine(interface=interface, bpf_filter=bpf_filter)
        self.engine.register_callback(self._on_packet)
        PacketAnalyzer.HOST_UPDATE_CALLBACK = self._on_domain

        self._setup_styles()
        self._build_menu()
        self._build_ui()
        self._bind_events()

        self.update_queue: Deque[PacketSummary] = deque(maxlen=500)
        self.domain_queue: Deque[str] = deque(maxlen=200)
        self.after_id = None
        self.running = False

    def _setup_styles(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Dark.TFrame", background=BG_COLOR)
        style.configure(
            "Dark.Treeview",
            background=BG_COLOR,
            foreground=FG_COLOR,
            fieldbackground=BG_COLOR,
            rowheight=22,
            bordercolor=GRID_COLOR
        )
        style.configure(
            "Dark.Treeview.Heading",
            background="#1a1a1a",
            foreground=FG_COLOR,
            bordercolor=GRID_COLOR,
            font=("Consolas", 10, "bold")
        )
        style.map(
            "Dark.Treeview",
            background=[("selected", ACCENT_COLOR)],
            foreground=[("selected", "#000000")]
        )
        style.configure(
            "Dark.TButton",
            background="#1a1a1a", foreground=FG_COLOR,
            bordercolor=GRID_COLOR, focusthickness=0,
            font=("Consolas", 10)
        )
        style.map("Dark.TButton", background=[("active", "#333333")])
        style.configure(
            "Dark.TCombobox",
            fieldbackground="#1a1a1a", background="#1a1a1a",
            foreground=FG_COLOR, arrowcolor=FG_COLOR
        )
        style.configure(
            "Dark.TEntry",
            fieldbackground="#1a1a1a", foreground=FG_COLOR,
            insertcolor=FG_COLOR, bordercolor=GRID_COLOR
        )
        style.configure(
            "Dark.TLabel", background=BG_COLOR, foreground=FG_COLOR,
            font=("Consolas", 10)
        )
        style.configure(
            "Accent.TLabel", background=BG_COLOR, foreground=ACCENT_COLOR,
            font=("Consolas", 12, "bold")
        )

    def _build_menu(self) -> None:
        menubar = Menu(self.root, bg=BG_COLOR, fg=FG_COLOR, activebackground=GRID_COLOR)
        file_menu = Menu(menubar, tearoff=0, bg=BG_COLOR, fg=FG_COLOR)
        file_menu.add_command(label="Exporter CSV…", command=self._export_csv)
        file_menu.add_command(label="Quitter", command=self._on_close)
        menubar.add_cascade(label="Fichier", menu=file_menu)

        capture_menu = Menu(menubar, tearoff=0, bg=BG_COLOR, fg=FG_COLOR)
        capture_menu.add_command(label="Démarrer", command=self.start)
        capture_menu.add_command(label="Arrêter", command=self.stop)
        menubar.add_cascade(label="Capture", menu=capture_menu)

        help_menu = Menu(menubar, tearoff=0, bg=BG_COLOR, fg=FG_COLOR)
        help_menu.add_command(label="Introduction", command=self._show_intro)
        help_menu.add_command(label="À propos", command=self._show_about)
        menubar.add_cascade(label="Aide", menu=help_menu)

        self.root.config(menu=menubar)

    def _build_ui(self) -> None:
        main = ttk.Frame(self.root, style="Dark.TFrame")
        main.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        main.grid_rowconfigure(2, weight=3)
        main.grid_rowconfigure(3, weight=2)
        main.grid_columnconfigure(0, weight=1)

        # --- Barre supérieure ---
        top = ttk.Frame(main, style="Dark.TFrame")
        top.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        ttk.Label(top, text=APP_NAME, style="Accent.TLabel").pack(side=tk.LEFT, padx=(0, 12))
        ttk.Label(top, text="Interface :", style="Dark.TLabel").pack(side=tk.LEFT)
        self.iface_var = tk.StringVar(value=self.engine.interface)
        self.iface_combo = ttk.Combobox(
            top, textvariable=self.iface_var, values=get_if_list(),
            width=20, state="readonly", style="Dark.TCombobox"
        )
        self.iface_combo.pack(side=tk.LEFT, padx=(0, 12))
        ttk.Label(top, text="Filtre BPF :", style="Dark.TLabel").pack(side=tk.LEFT)
        self.filter_var = tk.StringVar(value=self.engine.bpf_filter)
        ttk.Entry(top, textvariable=self.filter_var, width=30, style="Dark.TEntry").pack(side=tk.LEFT, padx=(0, 12))
        self.start_btn = ttk.Button(top, text="▶ Démarrer", command=self.start, style="Dark.TButton")
        self.start_btn.pack(side=tk.LEFT, padx=(0, 6))
        self.stop_btn = ttk.Button(top, text="⏹ Arrêter", command=self.stop, state="disabled", style="Dark.TButton")
        self.stop_btn.pack(side=tk.LEFT, padx=(0, 12))
        self.status_label = ttk.Label(top, text="Prêt", style="Dark.TLabel")
        self.status_label.pack(side=tk.LEFT)

        # --- Stats ---
        stats = ttk.Frame(main, style="Dark.TFrame")
        stats.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        self.stat_labels: Dict[str, ttk.Label] = {}
        stat_names = [
            ("packets", "Paquets"), ("bytes", "Octets"), ("duration", "Durée"),
            ("pps", "Paquets/s"), ("flows", "Flux"), ("devices", "Appareils"),
            ("domains", "Domaines")
        ]
        for key, name in stat_names:
            ttk.Label(stats, text=f"{name}:", style="Dark.TLabel").pack(side=tk.LEFT, padx=(8, 2))
            lbl = ttk.Label(stats, text="0", style="Accent.TLabel")
            lbl.pack(side=tk.LEFT, padx=(0, 16))
            self.stat_labels[key] = lbl

        # --- Notebook (onglets) ---
        self.notebook = ttk.Notebook(main)
        self.notebook.grid(row=2, column=0, sticky="nsew", pady=(0, 8))

        # Onglet Paquets
        pkt_frame = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.packet_tree = PacketTree(pkt_frame)
        self.notebook.add(pkt_frame, text="Paquets")

        # Onglet Appareils
        dev_frame = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.device_tree = DeviceTree(dev_frame)
        self.notebook.add(dev_frame, text="Appareils")

        # Onglet Domaines
        dom_frame = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.domain_tree = DomainTree(dom_frame)
        self.notebook.add(dom_frame, text="Noms de domaine")

        # Onglet Flux
        flow_frame = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.flow_tree = ttk.Treeview(
            flow_frame,
            columns=("src", "dst", "proto", "ports", "pkts", "bytes", "domains"),
            show="headings", style="Dark.Treeview"
        )
        for col, txt, w in [
            ("src", "Source", 140), ("dst", "Destination", 140),
            ("proto", "Proto", 70), ("ports", "Ports", 100),
            ("pkts", "Paquets", 80), ("bytes", "Octets", 90),
            ("domains", "Domaines", 250)
        ]:
            self.flow_tree.heading(col, text=txt)
            self.flow_tree.column(col, width=w, anchor="w")
        self.flow_tree.grid(row=0, column=0, sticky="nsew")
        ttk.Scrollbar(flow_frame, orient="vertical", command=self.flow_tree.yview).grid(row=0, column=1, sticky="ns")
        flow_frame.grid_rowconfigure(0, weight=1)
        flow_frame.grid_columnconfigure(0, weight=1)
        self.notebook.add(flow_frame, text="Flux")

        # Onglet Introduction
        intro_frame = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.intro_text = scrolledtext.ScrolledText(
            intro_frame, wrap=tk.WORD, bg=BG_COLOR, fg=FG_COLOR,
            insertbackground=FG_COLOR, font=("Consolas", 11),
            relief=tk.FLAT, borderwidth=0, padx=10, pady=10
        )
        self.intro_text.pack(fill=tk.BOTH, expand=True)
        self.intro_text.insert(tk.END, self._build_intro_text())
        self.intro_text.config(state=tk.DISABLED)
        self.notebook.add(intro_frame, text="Introduction")

        # --- Graphique et log ---
        bottom = ttk.Frame(main, style="Dark.TFrame")
        bottom.grid(row=3, column=0, sticky="nsew")
        bottom.grid_rowconfigure(0, weight=1)
        bottom.grid_columnconfigure(0, weight=1)
        bottom.grid_columnconfigure(1, weight=1)

        chart_frame = ttk.LabelFrame(bottom, text="Débit temps réel", style="Dark.TFrame")
        chart_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 4))
        self.chart = TrafficChart(chart_frame)

        log_frame = ttk.LabelFrame(bottom, text="Journal", style="Dark.TFrame")
        log_frame.grid(row=0, column=1, sticky="nsew", padx=(4, 0))
        self.log_text = scrolledtext.ScrolledText(
            log_frame, wrap=tk.WORD, bg=BG_COLOR, fg=SECONDARY_FG,
            font=("Consolas", 9), state=tk.DISABLED, relief=tk.FLAT
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)

    def _bind_events(self) -> None:
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.packet_tree.bind("<Double-1>", self._show_packet_details)

    # -----------------------------------------------------------------------
    # Textes pédagogiques
    # -----------------------------------------------------------------------

    def _build_intro_text(self) -> str:
        return """
=== WIRE_ENGINE – Introduction pédagogique ===

Qu’est-ce que WIRE_ENGINE ?
--------------------------
WIRE_ENGINE est un analyseur de trafic réseau en temps réel. Il capture les
paquets qui passent par votre carte réseau (routeur/point d’accès selon la
configuration), identifie les appareils connectés et affiche les noms de
domaine consultés.

Comment fonctionne un réseau domestique ?
-----------------------------------------
1. Votre appareil (téléphone, PC, TV…) envoie une requête via le routeur.
2. Le routeur fait suivre cette requête vers Internet via la box.
3. Chaque étape utilise des « paquets » : petits morceaux de données.
4. WIRE_ENGINE lit ces paquets localement grâce à Scapy et les classe.

Les onglets expliqués
---------------------
• Paquets        : liste brute de chaque paquet capturé.
• Appareils      : machines découvertes sur le réseau (IP, MAC, constructeur).
• Noms de domaine : sites/services contactés (Google, YouTube, DNS…).
• Flux           : conversations regroupées entre deux machines.
• Débit temps réel : graphique du nombre de paquets par seconde.

Les protocoles principaux
-------------------------
• IP / IPv6   : adressage des machines.
• TCP         : transport fiable (web, mail, SSH…).
• UDP         : transport rapide (DNS, streaming, jeux…).
• DNS         : traduction nom de domaine → adresse IP.
• ARP         : traduction IP → adresse MAC locale.
• ICMP        : messages de contrôle (ping).
• HTTP / HTTPS : navigation web (HTTPS est chiffré).

Sécurité et légalité
--------------------
• N’utilisez cet outil que sur des réseaux dont vous êtes propriétaire ou
  pour lesquels vous avez une autorisation écrite.
• Le trafic HTTPS est chiffré : WIRE_ENGINE voit l’adresse IP et le SNI/QUIC
  mais pas le contenu des pages.
• En mode moniteur/promiscuité, vous pouvez voir le trafic d’autrui : cela
  est souvent illégal sans autorisation.

Auteur : hackes_tchad
Licence : MIT – usage éducatif uniquement.
"""

    def _show_intro(self) -> None:
        self.notebook.select(4)

    def _show_about(self) -> None:
        messagebox.showinfo(
            "À propos",
            f"{APP_NAME}\nVersion {APP_VERSION}\nAuteur : {APP_AUTHOR}\n\n{APP_LICENSE}"
        )

    # -----------------------------------------------------------------------
    # Actions
    # -----------------------------------------------------------------------

    def start(self) -> None:
        if self.running:
            return
        iface = self.iface_var.get()
        bpf = self.filter_var.get().strip()
        self.engine.interface = iface
        self.engine.bpf_filter = bpf
        self.running = True
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.status_label.config(text="Capture en cours…", foreground=ACCENT_COLOR)
        self.log("Capture démarrée.")
        self.engine.start()
        self._schedule_ui_update()

    def stop(self) -> None:
        self.running = False
        self.engine.stop()
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status_label.config(text="Arrêté", foreground=FG_COLOR)
        self.log("Capture arrêtée.")

    def _on_close(self) -> None:
        self.stop()
        self.root.destroy()

    def _export_csv(self) -> None:
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("Tous fichiers", "*.*")]
        )
        if path:
            try:
                self.engine.export_csv(path)
                self.log(f"Export CSV : {path}")
            except Exception as exc:
                messagebox.showerror("Erreur export", str(exc))

    def _show_packet_details(self, event=None) -> None:
        s = self.packet_tree.selected_summary()
        if not s:
            return
        detail = (
            f"Index : {s.idx}\n"
            f"Timestamp : {s.timestamp}\n"
            f"Source MAC : {s.src_mac}\n"
            f"Destination MAC : {s.dst_mac}\n"
            f"EtherType : {s.ethertype}\n"
            f"Source IP : {s.src_ip}\n"
            f"Destination IP : {s.dst_ip}\n"
            f"Protocole : {s.proto}\n"
            f"Ports : {s.src_port} → {s.dst_port}\n"
            f"Taille : {s.length}\n"
            f"Domaine : {s.domain or ''}\n"
            f"Tags : {', '.join(s.tags)}\n"
            f"Info : {s.info}\n"
            f"Résumé brut : {s.raw_summary}"
        )
        win = tk.Toplevel(self.root, bg=BG_COLOR)
        win.title(f"Détail paquet #{s.idx}")
        win.geometry("700x500")
        txt = scrolledtext.ScrolledText(
            win, wrap=tk.WORD, bg=BG_COLOR, fg=FG_COLOR,
            font=("Consolas", 10), padx=10, pady=10
        )
        txt.pack(fill=tk.BOTH, expand=True)
        txt.insert(tk.END, detail)

    # -----------------------------------------------------------------------
    # Mises à jour UI
    # -----------------------------------------------------------------------

    def _on_packet(self, s: PacketSummary) -> None:
        self.update_queue.append(s)

    def _on_domain(self, domain: str) -> None:
        self.domain_queue.append(domain)

    def _schedule_ui_update(self) -> None:
        if not self.running:
            return
        self._refresh_ui()
        self.after_id = self.root.after(REFRESH_MS, self._schedule_ui_update)

    def _refresh_ui(self) -> None:
        # Paquets
        count = 0
        while self.update_queue and count < 200:
            s = self.update_queue.popleft()
            self.packet_tree.insert_packet(s)
            count += 1

        # Domaines
        while self.domain_queue:
            dom = self.domain_queue.popleft()
            # Chercher une IP liée
            ips = self.engine.domains.get(dom, set())
            self.domain_tree.touch(dom, ", ".join(sorted(ips)[:3]))

        # Appareils
        self.engine.device_discovery.enrich()
        self.device_tree.refresh(self.engine.device_discovery.get_devices())

        # Flux
        self._refresh_flows()

        # Stats
        stats = self.engine.get_stats()
        for key, lbl in self.stat_labels.items():
            value = stats.get(key, 0)
            if key == "bytes":
                lbl.config(text=NetworkUtils.format_bytes(int(value)))
            elif key == "duration":
                lbl.config(text=NetworkUtils.format_duration(value))
            else:
                lbl.config(text=f"{value:,.0f}" if isinstance(value, float) else str(value))

        # Graphique
        self.chart.update(stats.get("pps", 0))

    def _refresh_flows(self) -> None:
        # On rafraîchit partiellement : on reconstruit pour la simplicité
        # car le nombre de flux reste raisonnable en contexte local.
        for item in self.flow_tree.get_children():
            self.flow_tree.delete(item)
        flows = sorted(
            self.engine.flows.values(),
            key=lambda f: f.bytes_total,
            reverse=True
        )[:200]
        for flow in flows:
            ports = f"{flow.key.src_port or ''} → {flow.key.dst_port or ''}"
            self.flow_tree.insert(
                "", "end",
                values=(
                    flow.key.src_ip, flow.key.dst_ip, flow.key.proto,
                    ports, flow.packets, NetworkUtils.format_bytes(flow.bytes_total),
                    ", ".join(sorted(flow.domains))[:80]
                )
            )

    def log(self, msg: str) -> None:
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"[{ts}] {msg}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)


# =============================================================================
# FONCTIONS CLI / DÉMARRAGE
# =============================================================================

def ensure_capture_permissions() -> bool:
    """Vérifie si l’utilisateur peut capturer des paquets."""
    if platform.system() == "Linux" and os.geteuid() != 0:
        print("\n[AVERTISSEMENT] La capture de paquets nécessite souvent les droits root.")
        print("Relancez avec : sudo python3 wire_engine.py\n")
        return False
    return True


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog=APP_NAME.lower(),
        description=f"{APP_NAME} – Analyseur réseau temps réel par {APP_AUTHOR}"
    )
    parser.add_argument("-i", "--interface", help="Interface réseau à écouter")
    parser.add_argument("-f", "--filter", default="", help="Filtre BPF (ex: 'tcp port 80')")
    parser.add_argument("--headless", action="store_true", help="Mode console sans interface")
    return parser.parse_args()


def run_headless(interface: Optional[str], bpf_filter: str) -> None:
    """Mode console : affiche les paquets en continu."""
    engine = CaptureEngine(interface=interface, bpf_filter=bpf_filter)

    def print_packet(s: PacketSummary) -> None:
        ts = datetime.datetime.fromtimestamp(s.timestamp).strftime("%H:%M:%S.%f")[:-3]
        dom = f" [{s.domain}]" if s.domain else ""
        print(f"[{ts}] #{s.idx} {s.proto:6} {s.src_ip:>15}:{s.src_port or '-'} -> "
              f"{s.dst_ip:>15}:{s.dst_port or '-'} {s.length:5}o{dom} {s.info[:60]}")

    engine.register_callback(print_packet)
    engine.start()
    print(f"{APP_NAME} headless démarré. Ctrl+C pour arrêter.")
    try:
        while True:
            time.sleep(1)
            stats = engine.get_stats()
            print(f"--- {stats['packets']} paquets, "
                  f"{NetworkUtils.format_bytes(stats['bytes'])}, "
                  f"{stats['devices']} appareils ---")
    except KeyboardInterrupt:
        engine.stop()
        print("Arrêt.")


def main() -> int:
    args = parse_arguments()
    ensure_capture_permissions()

    if args.headless:
        run_headless(args.interface, args.filter)
        return 0

    root = tk.Tk()
    app = WireEngineApp(root, interface=args.interface, bpf_filter=args.filter)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
