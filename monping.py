"""
This application is developed exclusively for educational and research purposes.
It provides researchers, network analysts and students with a full professional tool
to study internet connectivity patterns, DNS behavior, IP reachability and filtering
dynamics across providers. The software identifies stable endpoints, responsive DNS
resolvers and low latency paths useful in academic studies on digital infrastructure,
censorship circumvention research and global network resilience.

ULTIMATE AI EDITION - Predictive EWMA + Variance + Flap Detection + Dynamic Scaling
+ Anomaly + Trend Analysis + Health Score + Auto-Blacklist + Premium UI/UX
Code by Hosea - https://github.com/Expen1
April 2026
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog, simpledialog
import subprocess
import platform
import threading
import time
import socket
import re
import ipaddress
import random
import concurrent.futures
import json
import csv
import urllib.request
import ssl
from datetime import datetime
import queue
from collections import deque
import heapq

# ====================== ULTIMATE OPTIMIZED CONSTANTS ======================
DEFAULT_TARGETS = [
    "static.cloudflareinsights.com", "security.vercel.com",
    "e7.c.lencr.org", "e8.c.lencr.org", "e9.c.lencr.org",
    "r10.c.lencr.org", "r11.c.lencr.org", "r13.c.lencr.org",
    "stg-e5.c.lencr.org", "stg-e7.c.lencr.org", "stg-e8.c.lencr.org",
    "stg-ye1.c.lencr.org", "stg-r11.c.lencr.org",
    "stg-ye2.c.lencr.org", "stg-yr2.c.lencr.org",
    "yr1.c.lencr.org", "ye2.c.lencr.org",
    "sourceforge.net", "vercel.com", "nextjs.org",
    "letsencrypt.org", "pubmed.ncbi.nlm.nih.gov",
    "link.springer.com", "www.sciencedirect.com",
    "www.python.org", "pypi.org", "react.dev",
    "www.certum.eu", "ubuntu.com", "www.npmjs.com",
    "dns.google", "1.1.1.1", "cloudflare.com", "github.com",
    "archive.org", "wikipedia.org", "wikimedia.org",
]

PROVIDERS = {
    "Cloudflare": [
        "104.16.0.0/20", "104.16.16.0/20", "104.16.32.0/20", "104.16.48.0/20",
        "104.16.64.0/20", "104.16.80.0/20", "104.16.96.0/20", "104.16.112.0/20",
        "104.16.128.0/20", "104.16.144.0/20", "104.16.160.0/20", "104.16.176.0/20",
        "104.16.192.0/20", "104.16.208.0/20", "104.16.224.0/20", "104.16.240.0/20",
        "104.17.0.0/20", "104.17.16.0/20", "104.17.32.0/20", "104.17.48.0/20",
        "104.17.64.0/20", "104.17.80.0/20", "104.17.96.0/20", "104.17.112.0/20",
        "104.17.128.0/20", "104.17.144.0/20", "104.17.160.0/20", "104.17.176.0/20",
        "104.17.192.0/20", "104.17.208.0/20", "104.17.224.0/20", "104.17.240.0/20",
        "104.18.0.0/20", "104.18.16.0/20", "104.18.32.0/20", "104.18.64.0/20",
        "104.18.80.0/20", "104.18.96.0/20", "104.18.112.0/20", "104.18.128.0/20",
        "104.18.144.0/20", "104.18.160.0/20", "104.18.176.0/20", "104.18.192.0/20",
        "104.18.208.0/20", "104.18.224.0/20", "104.18.240.0/20",
        "104.19.0.0/20", "104.19.16.0/20", "104.19.32.0/20", "104.19.48.0/20",
        "104.19.64.0/20", "104.19.80.0/20", "104.19.96.0/20", "104.19.112.0/20",
        "104.19.128.0/20", "104.19.144.0/20", "104.19.160.0/20", "104.19.176.0/20",
        "104.19.192.0/20", "104.19.208.0/20", "104.19.224.0/20", "104.19.240.0/20",
        "104.20.0.0/20", "104.20.16.0/20", "104.20.32.0/20", "104.20.48.0/20",
        "104.21.0.0/20", "104.21.16.0/20", "104.21.32.0/20", "104.21.48.0/20",
        "104.21.64.0/20", "104.21.80.0/20", "104.21.96.0/20", "104.21.112.0/20",
        "104.21.192.0/20", "104.21.208.0/20", "104.21.224.0/20",
        "104.24.0.0/20", "104.24.16.0/20", "104.24.32.0/20", "104.24.48.0/20",
        "104.24.64.0/20", "104.24.80.0/20", "104.24.128.0/20", "104.24.144.0/20",
        "104.24.160.0/20", "104.24.176.0/20", "104.24.192.0/20", "104.24.208.0/20",
        "104.24.224.0/20", "104.24.240.0/20",
        "104.25.0.0/20", "104.25.16.0/20", "104.25.32.0/20", "104.25.48.0/20",
        "104.25.64.0/20", "104.25.80.0/20", "104.25.96.0/20", "104.25.112.0/20",
        "104.25.128.0/20", "104.25.144.0/20", "104.25.160.0/20", "104.25.176.0/20",
        "104.25.192.0/20", "104.25.208.0/20", "104.25.224.0/20", "104.25.240.0/20",
        "104.26.0.0/20", "104.27.0.0/20", "104.27.16.0/20", "104.27.32.0/20",
        "104.27.48.0/20", "104.27.64.0/20", "104.27.80.0/20", "104.27.96.0/20",
        "104.27.112.0/20", "104.27.192.0/20",
        "104.28.0.0/20", "104.28.16.0/20", "104.28.32.0/20", "104.28.48.0/20",
        "104.28.64.0/20", "104.28.80.0/20", "104.28.96.0/20", "104.28.112.0/20",
        "104.28.128.0/20", "104.28.144.0/20", "104.28.160.0/20", "104.28.176.0/20",
        "104.28.192.0/20", "104.28.208.0/20", "104.28.224.0/20", "104.28.240.0/20",
        "104.30.0.0/22", "104.30.4.0/22", "104.30.8.0/22", "104.30.12.0/22",
        "104.30.16.0/20", "104.30.32.0/23", "104.30.128.0/23", "104.30.144.0/21",
        "104.30.160.0/20", "104.30.176.0/20",
        "104.31.0.0/21", "104.31.16.0/23",
        "108.162.192.0/20", "141.101.76.0/23", "141.101.112.0/20", "141.101.114.0/23",
        "141.101.120.0/22", "162.158.0.0/22", "162.158.16.0/22", "162.158.20.0/22",
        "162.158.24.0/23", "162.158.76.0/22", "162.158.84.0/22", "162.158.180.0/22",
        "162.158.208.0/22", "162.158.226.0/23", "162.158.234.0/23", "162.158.240.0/22",
        "162.158.250.0/23", "162.159.0.0/20", "162.159.16.0/20", "162.159.32.0/23",
        "162.159.34.0/23", "162.159.40.0/23", "162.159.42.0/23", "162.159.48.0/20",
        "162.159.64.0/20", "162.159.128.0/19", "162.159.192.0/22", "162.159.240.0/20",
        "172.64.32.0/20", "172.64.36.0/23", "172.64.48.0/20", "172.64.80.0/20",
        "172.64.100.0/23", "172.64.240.0/20", "172.65.0.0/19", "172.65.0.0/20",
        "172.65.16.0/20", "172.65.32.0/20", "172.65.48.0/20", "172.65.64.0/20",
        "172.65.80.0/20", "172.65.96.0/20", "172.65.112.0/20", "172.65.128.0/20",
        "172.65.144.0/20", "172.65.160.0/20", "172.65.176.0/20", "172.65.192.0/20",
        "172.65.208.0/20", "172.65.224.0/20", "172.65.240.0/20", "172.66.0.0/22",
        "172.66.40.0/21", "172.66.128.0/20", "172.66.144.0/20", "172.66.160.0/20",
        "172.66.192.0/20", "172.66.208.0/21", "172.67.64.0/20", "172.67.80.0/20",
        "172.67.96.0/20", "172.67.112.0/20", "172.67.128.0/20", "172.67.144.0/20",
        "172.67.160.0/20", "172.67.176.0/20", "172.67.192.0/20", "172.67.208.0/20",
        "172.67.224.0/20", "172.67.240.0/20", "172.68.60.0/22", "172.68.72.0/23",
        "172.68.180.0/22", "173.245.60.0/23", "188.114.106.0/23", "190.93.240.0/20",
        "190.93.244.0/22", "198.41.132.0/22", "198.41.136.0/22", "198.41.192.0/21",
        "198.41.200.0/21", "198.41.208.0/23", "198.41.214.0/23", "199.27.128.0/22",
        "199.27.134.0/23",
        "static.cloudflareinsights.com", "cloudflare.com"
    ],
    "Amazon AWS": [
        "amazonaws.com", "52.94.198.0/24", "13.32.0.0/11", "3.128.0.0/11",
        "18.160.0.0/11", "52.0.0.0/8"
    ],
    "Google": [
        "google.com", "cloud.google.com", "34.64.0.0/11", "35.184.0.0/13", "130.211.0.0/16"
    ],
    "Microsoft Azure": [
        "microsoft.com", "azure.microsoft.com", "13.64.0.0/11", "40.64.0.0/10"
    ],
    "Major Ranges": [
        "1.0.0.0/24", "1.1.1.0/24", "8.6.112.0/24", "8.6.144.0/24", "8.6.145.0/24",
        "23.227.38.0/23", "23.227.42.0/23", "23.227.48.0/23", "45.250.152.0/22",
        "49.238.236.0/22", "103.219.64.0/22", "131.0.72.0/22", "150.48.128.0/18",
        "152.114.0.0/17", "152.114.128.0/18", "203.168.192.0/20", "204.195.192.0/18",
        "222.167.32.0/22"
    ]
}

MAX_IPS_PER_CIDR = 5
BASE_MAX_WORKERS = 5
CHECK_INTERVAL_SECONDS = 3.5
STEALTH_DELAY_MIN = 0.022
STEALTH_DELAY_MAX = 0.14

COMMON_PORTS = [80, 443, 22, 53, 8080, 8443, 993, 995, 465, 587]

MCI_HAMRAH_DNS = [
    "2.188.21.20", "2.188.21.90", "2.188.21.100", "2.188.21.120",
    "2.188.21.130", "2.188.21.190", "2.188.21.200", "2.188.21.230",
    "2.188.21.240", "2.189.1.1", "2.189.1.12", "2.189.44.44",
    "5.106.18.134", "5.106.18.218", "5.160.13.83", "5.160.119.225",
    "5.160.119.228", "5.160.121.70", "5.160.139.74", "5.160.233.150",
    "5.160.242.48", "80.210.22.217", "80.210.41.48", "80.210.41.221",
    "80.210.44.184", "80.210.44.187", "80.210.48.24", "80.210.52.165",
    "80.210.53.97", "80.210.54.182", "185.159.153.254",
    "2.177.129.246", "2.177.161.64", "2.177.228.177", "2.177.236.183",
    "2.180.31.171", "2.180.43.13", "2.181.0.54", "2.186.229.200",
    "2.188.20.5", "2.188.26.10", "2.188.162.78", "2.188.167.236",
    "2.188.174.222", "2.189.86.98", "2.189.91.202", "2.190.0.142",
    "2.190.233.153", "31.7.78.133", "37.156.12.65", "78.38.24.122",
    "78.38.50.218", "78.38.182.201", "78.39.8.27", "78.39.139.149",
    "80.191.68.247", "80.191.88.90", "80.191.92.188", "109.109.32.10",
    "109.109.32.11", "109.109.32.18", "109.109.32.21", "109.109.32.102",
    "109.109.32.110", "109.109.32.124", "109.109.32.125", "109.109.32.152",
    "109.109.32.155", "109.109.34.118", "178.173.144.224", "217.219.120.82"
]

DEFAULT_DNS_SERVERS = {
    "Irancell": [
        "37.32.4.61", "37.32.121.130", "95.38.102.86", "95.38.132.6",
        "109.230.72.243", "109.230.78.13", "109.230.79.10", "109.230.79.12",
        "109.230.83.155", "109.230.83.243", "109.230.90.86", "109.230.91.226"
    ],
    "MCI (Hamrah e Avval)": MCI_HAMRAH_DNS
}

C = {
    "bg": "#0f0f0f", "bg2": "#1a1a1a", "bg3": "#222222",
    "fg": "#e8e8e8", "fg2": "#888888", "fg3": "#555555",
    "accent": "#3b82f6", "accent_dark": "#1d4ed8", "accent2": "#10b981",
    "green": "#22c55e", "green_bg": "#052e16",
    "red": "#ef4444", "red_bg": "#2d0a0a",
    "yellow": "#f59e0b", "yellow_bg": "#1c1200",
    "header_bg": "#111111"
}

FONT_MONO = ("Consolas", 10)
FONT_SMALL = ("Segoe UI", 9)
FONT_MED = ("Segoe UI", 10)
FONT_BOLD = ("Segoe UI", 10, "bold")
FONT_TITLE = ("Segoe UI", 13, "bold")

# ====================== GLOBAL DATA ======================
target_list = []
status_map = {}
resolved_ips = {}
ping_times = {}
cidr_used_ips = {}
ip_cidr_parent = {}
best_port_map = {}
stability_map = {}
predicted_latency = {}
variance_map = {}
per_target_history = {}
last_check_time = {}
anomaly_flags = {}
flap_count = {}
health_score = {}
trend_map = {}
blacklist = set()

check_history = []
latency_history = deque(maxlen=120)

active_dns_servers = []
dns_target_results = {}

update_queue = queue.Queue()

# ====================== HELPERS ======================
def is_cidr(text):
    return "/" in text and not text.startswith("http")

def is_ip(text):
    try:
        ipaddress.IPv4Address(text)
        return True
    except ipaddress.AddressValueError:
        return False

def pick_random_ip_from_cidr(cidr):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        usable = net.num_addresses - 2
        if usable <= 0:
            return None
        if cidr not in cidr_used_ips:
            cidr_used_ips[cidr] = set()
        used = cidr_used_ips[cidr]
        if len(used) >= usable:
            return None
        for _ in range(200):
            candidate = str(random.choice(list(net.hosts())))
            if candidate not in used:
                used.add(candidate)
                return candidate
        return None
    except ValueError:
        return None

def expand_cidr_targets(cidr, count=MAX_IPS_PER_CIDR):
    ips = []
    for _ in range(count):
        ip = pick_random_ip_from_cidr(cidr)
        if ip:
            ip_cidr_parent[ip] = cidr
            ips.append(ip)
    return ips

def _get_hidden_subprocess_kwargs():
    if platform.system().lower() == "windows":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0
        return {"startupinfo": startupinfo}
    return {}

def ping_host(host, timeout=0.9):
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout)), host]
    try:
        start = time.perf_counter()
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout + 2, **_get_hidden_subprocess_kwargs())
        elapsed = (time.perf_counter() - start) * 1000
        if result.returncode == 0:
            output = result.stdout.decode(errors="ignore")
            rtt = None
            try:
                if system == "windows":
                    match = re.search(r"Average\s*=\s*(\d+)ms", output)
                else:
                    match = re.search(r"time[=<]([\d.]+)\s*ms", output)
                if match:
                    rtt = float(match.group(1))
            except:
                pass
            return True, rtt if rtt is not None else elapsed
        return False, float("inf")
    except Exception:
        return False, float("inf")

def resolve_host(host):
    if is_ip(host):
        return host
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return "unresolved"

def tcp_connect_check(host, port=443, timeout=1.4):
    try:
        start = time.perf_counter()
        with socket.create_connection((host, port), timeout=timeout):
            return True, (time.perf_counter() - start) * 1000
    except Exception:
        return False, float("inf")

def http_check(host, timeout=2.2):
    if not host or host == "unresolved":
        return False, float("inf")
    try:
        start = time.perf_counter()
        url = f"https://{host}" if not host.startswith(("http://", "https://")) else host
        req = urllib.request.Request(url, method="HEAD")
        context = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=timeout, context=context) as _:
            return True, (time.perf_counter() - start) * 1000
    except Exception:
        return False, float("inf")

def run_traceroute(host):
    system = platform.system().lower()
    try:
        if system == "windows":
            cmd = ["tracert", "-d", "-h", "25", host]
        else:
            cmd = ["traceroute", "-q", "1", "-m", "25", host]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20, **_get_hidden_subprocess_kwargs())
        return result.stdout.strip() or "No route data returned."
    except Exception:
        return "Traceroute unavailable."

def initialize_targets(raw_targets):
    global target_list
    target_list.clear()
    status_map.clear()
    resolved_ips.clear()
    ping_times.clear()
    cidr_used_ips.clear()
    ip_cidr_parent.clear()
    best_port_map.clear()
    stability_map.clear()
    predicted_latency.clear()
    variance_map.clear()
    per_target_history.clear()
    last_check_time.clear()
    anomaly_flags.clear()
    flap_count.clear()
    health_score.clear()
    trend_map.clear()
    blacklist.clear()

    for entry in [e.strip() for e in raw_targets if e.strip()]:
        if is_cidr(entry):
            sampled = expand_cidr_targets(entry)
            for ip in sampled:
                target_list.append(ip)
                status_map[ip] = None
                resolved_ips[ip] = ip
                ping_times[ip] = float("inf")
                best_port_map[ip] = "-"
                stability_map[ip] = 50.0
                predicted_latency[ip] = 80.0
                variance_map[ip] = 0.0
                per_target_history[ip] = deque(maxlen=18)
                last_check_time[ip] = time.time()
                anomaly_flags[ip] = False
                flap_count[ip] = 0
                health_score[ip] = 50.0
                trend_map[ip] = "Stable"
        else:
            target_list.append(entry)
            status_map[entry] = None
            resolved_ips[entry] = "resolving..."
            ping_times[entry] = float("inf")
            best_port_map[entry] = "-"
            stability_map[entry] = 50.0
            predicted_latency[entry] = 80.0
            variance_map[entry] = 0.0
            per_target_history[entry] = deque(maxlen=18)
            last_check_time[entry] = time.time()
            anomaly_flags[entry] = False
            flap_count[entry] = 0
            health_score[entry] = 50.0
            trend_map[entry] = "Stable"

def check_single_target(target, stop_event=None):
    if stop_event and stop_event.is_set():
        return

    try:
        if not is_ip(target):
            ip = resolve_host(target)
            resolved_ips[target] = ip
        else:
            ip = target

        if ip == "unresolved":
            status_map[target] = False
            ping_times[target] = float("inf")
            best_port_map[target] = "-"
            per_target_history[target].append(0)
            stability_map[target] = max(0, sum(per_target_history[target]) * 100 / len(per_target_history[target]))
            predicted_latency[target] = 999.0
            variance_map[target] = 0.0
            last_check_time[target] = time.time()
            health_score[target] = 5.0
            trend_map[target] = "Degrading"
            return

        # Layer 1: ICMP
        online, latency = ping_host(ip)
        best_latency = latency if online else float("inf")
        best_port = 0 if online else None

        # Layer 2: Multi-port TCP
        for port in COMMON_PORTS:
            if stop_event and stop_event.is_set():
                return
            p_online, p_latency = tcp_connect_check(ip, port)
            if p_online and p_latency < best_latency:
                best_latency = p_latency
                best_port = port

        # Layer 3: HTTP fallback
        if best_port is None:
            http_online, http_latency = http_check(ip)
            if http_online and http_latency < best_latency:
                best_latency = http_latency
                best_port = 443

        status_map[target] = best_latency != float("inf")
        ping_times[target] = best_latency
        best_port_map[target] = str(best_port) if best_port else "-"

        # Advanced EWMA + Variance + Flap Detection
        history = per_target_history[target]
        history.append(1 if status_map[target] else 0)

        stability_map[target] = max(0, sum(history) * 100 / len(history))

        alpha = 0.32
        if latency != float("inf"):
            predicted_latency[target] = alpha * latency + (1 - alpha) * predicted_latency.get(target, latency)

        if len(history) > 5:
            mean = sum(history) / len(history)
            variance_map[target] = sum((x - mean) ** 2 for x in history) / len(history)
            if variance_map[target] > 0.25:
                flap_count[target] = flap_count.get(target, 0) + 1

        anomaly_flags[target] = stability_map[target] < 40 or flap_count.get(target, 0) > 3

        # PROFESSIONAL HEALTH SCORE + TREND + AUTO-BLACKLIST
        lat_penalty = min(100, predicted_latency[target] / 4.0)
        var_penalty = variance_map[target] * 250
        flap_penalty = flap_count.get(target, 0) * 18
        health_score[target] = round(
            stability_map[target] * 0.55 +
            (100 - lat_penalty) * 0.25 +
            (100 - var_penalty) * 0.12 +
            (100 - flap_penalty) * 0.08
        )
        health_score[target] = max(5, min(100, health_score[target]))

        if len(history) >= 5:
            old_avg = sum(list(history)[-5:-2]) / 3
            new_avg = sum(list(history)[-3:]) / 3
            if new_avg > old_avg + 0.25:
                trend_map[target] = "Improving ↑"
            elif new_avg < old_avg - 0.25:
                trend_map[target] = "Degrading ↓"
            else:
                trend_map[target] = "Stable →"

        if health_score[target] < 28 or flap_count.get(target, 0) > 7:
            blacklist.add(target)
            anomaly_flags[target] = True

        last_check_time[target] = time.time()

    except Exception:
        status_map[target] = False
        ping_times[target] = float("inf")
        best_port_map[target] = "-"
        per_target_history[target].append(0)
        stability_map[target] = max(0, sum(per_target_history[target]) * 100 / len(per_target_history[target]))
        predicted_latency[target] = 999.0
        health_score[target] = 5.0
        trend_map[target] = "Degrading"
        last_check_time[target] = time.time()

def run_checks_once(targets, on_progress=None, stealth=False, stop_event=None):
    active_targets = [t for t in targets if t not in blacklist]
    if not active_targets:
        return

    online_rate = sum(1 for v in status_map.values() if v is True) / max(1, len(status_map))
    current_workers = max(3, int(BASE_MAX_WORKERS * (0.65 if online_rate > 0.88 else 1.0)))

    def priority_score(t):
        lat = predicted_latency.get(t, ping_times.get(t, float("inf")))
        stab = stability_map.get(t, 50.0)
        var = variance_map.get(t, 0.0)
        recency = time.time() - last_check_time.get(t, 0)
        flap_penalty = flap_count.get(t, 0) * 80
        anomaly_bonus = 150 if anomaly_flags.get(t, False) else 0
        return lat * 0.52 + (100 - stab) * 1.4 + var * 45 + max(0, 200 - recency * 9) + flap_penalty - anomaly_bonus

    heap = [(priority_score(t), idx, t) for idx, t in enumerate(active_targets)]
    heapq.heapify(heap)
    sorted_targets = [heapq.heappop(heap)[2] for _ in range(len(heap))]

    with concurrent.futures.ThreadPoolExecutor(max_workers=current_workers) as executor:
        future_map = {executor.submit(check_single_target, t, stop_event): t for t in sorted_targets}
        for future in concurrent.futures.as_completed(future_map):
            target = future_map[future]
            try:
                future.result()
            except Exception:
                status_map[target] = False
                ping_times[target] = float("inf")
                best_port_map[target] = "-"

            if on_progress:
                on_progress(target)

            if stop_event and stop_event.is_set():
                break

            if stealth:
                delay_factor = 0.5 if online_rate > 0.85 else 1.0
                time.sleep(random.uniform(STEALTH_DELAY_MIN * delay_factor, STEALTH_DELAY_MAX * delay_factor))

# ====================== DNS ======================
def check_dns_server(dns_ip, test_host="google.com", timeout=1.8):
    def build_dns_query(hostname):
        tid = random.randint(0, 65535).to_bytes(2, "big")
        header = tid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        question = b""
        for part in hostname.split("."):
            question += bytes([len(part)]) + part.encode()
        question += b"\x00\x00\x01\x00\x01"
        return header + question
    try:
        query = build_dns_query(test_host)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        start = time.perf_counter()
        sock.sendto(query, (dns_ip, 53))
        data, _ = sock.recvfrom(512)
        elapsed = (time.perf_counter() - start) * 1000
        sock.close()
        return len(data) >= 12, elapsed
    except Exception:
        return False, float("inf")

def run_dns_checks(dns_servers, on_progress=None):
    test_hosts = ["google.com", "cloudflare.com", "github.com"]
    def check_one(dns_ip, host):
        online, latency = check_dns_server(dns_ip, host)
        if dns_ip not in dns_target_results:
            dns_target_results[dns_ip] = {}
        dns_target_results[dns_ip][host] = (latency, online)
        if on_progress:
            on_progress(dns_ip, host)
    tasks = [(dns_ip, host) for dns_ip in dns_servers for host in test_hosts]
    with concurrent.futures.ThreadPoolExecutor(max_workers=BASE_MAX_WORKERS) as executor:
        for future in concurrent.futures.as_completed({executor.submit(check_one, *t): t for t in tasks}):
            pass

def get_summary_stats():
    online = sum(1 for v in status_map.values() if v is True)
    offline = sum(1 for v in status_map.values() if v is False)
    pending = sum(1 for v in status_map.values() if v is None)
    return {"online": online, "offline": offline, "pending": pending, "total": len(status_map)}

def get_top_targets(n=8):
    online = [(t, ping_times[t]) for t in target_list if status_map.get(t) is True and ping_times.get(t, float("inf")) < float("inf")]
    return sorted(online, key=lambda x: x[1])[:n]

def get_best_dns():
    best = []
    for dns, results in dns_target_results.items():
        latencies = [v[0] for v in results.values() if v[0] != float("inf")]
        if latencies:
            avg = sum(latencies) / len(latencies)
            provider = next((p for p, ips in DEFAULT_DNS_SERVERS.items() if dns in ips), "Unknown")
            best.append((dns, avg, provider))
    return sorted(best, key=lambda x: x[1])[:6]

def get_bypass_recommendations():
    recs = []
    for t in target_list:
        if t in blacklist:
            continue
        if status_map.get(t) is True and ping_times.get(t, float("inf")) < float("inf"):
            if any(kw in t.lower() for kw in ["cloudflare", "lencr", "vercel", "nextjs"]):
                recs.append((t, ping_times[t], best_port_map.get(t, "-"), round(stability_map.get(t, 50), 1), round(health_score.get(t, 50), 1), trend_map.get(t, "Stable"), anomaly_flags.get(t, False), flap_count.get(t, 0)))
    recs.sort(key=lambda x: x[1])
    return recs[:20]

# ====================== MAIN APP ======================
class NetMonitorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("MonPing")
        self.geometry("1580x1020")
        self.minsize(1320, 880)
        self.configure(bg=C["bg"])
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._check_thread = None
        self._is_running = False
        self._is_paused = False
        self._stealth_mode = tk.BooleanVar(value=True)
        self._setup_styles()
        self._build_menu()
        self._build_ui()
        self._init_data()
        self._process_queue()

    def _setup_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame", background=C["bg"])
        style.configure("TLabel", background=C["bg"], foreground=C["fg"], font=FONT_MED)
        style.configure("Header.TLabel", background=C["header_bg"], foreground=C["accent2"], font=FONT_TITLE)
        style.configure("TButton", background=C["accent"], foreground="#ffffff", font=FONT_BOLD, relief="flat", padding=(22, 11))
        style.map("TButton", background=[("active", C["accent_dark"])])
        style.configure("Treeview", background=C["bg2"], foreground=C["fg"], fieldbackground=C["bg2"], font=FONT_MONO, rowheight=31)
        style.configure("Treeview.Heading", background=C["bg3"], foreground=C["fg2"], font=FONT_BOLD)

    def _build_menu(self):
        menubar = tk.Menu(self)
        self.config(menu=menubar)
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Import Targets...", command=self._import_targets)
        file_menu.add_command(label="Export Targets...", command=self._export_targets)
        file_menu.add_separator()
        file_menu.add_command(label="Export All Data JSON", command=lambda: self._export_research_data("json"))
        file_menu.add_command(label="Export All Data CSV", command=lambda: self._export_research_data("csv"))
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_close)

        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Traceroute Analyzer...", command=self._open_traceroute_tool)
        tools_menu.add_command(label="Quick DNS Lookup...", command=self._open_dns_lookup)
        tools_menu.add_command(label="Clear Blacklist", command=self._clear_blacklist)

        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About MonPing v2", command=self._show_about)
        help_menu.add_command(label="GitHub Repository", command=lambda: messagebox.showinfo("GitHub", "https://github.com/Expen1"))

    def _build_ui(self):
        hdr = tk.Frame(self, bg=C["header_bg"], height=86)
        hdr.pack(fill="x", side="top")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="MONPING", bg=C["header_bg"], fg=C["accent2"], font=FONT_TITLE).pack(side="left", padx=28, pady=24)
        self._lbl_stats = tk.Label(hdr, text="", bg=C["header_bg"], fg=C["fg2"], font=FONT_SMALL)
        self._lbl_stats.pack(side="right", padx=28)

        ctrl = tk.Frame(hdr, bg=C["header_bg"])
        ctrl.pack(side="right", padx=18)
        self._btn_toggle = ttk.Button(ctrl, text="▶ START SCAN", command=self._toggle_monitoring)
        self._btn_toggle.pack(side="left", padx=6)
        self._btn_pause = ttk.Button(ctrl, text="⏸ PAUSE", command=self._toggle_pause)
        self._btn_pause.pack(side="left", padx=6)
        ttk.Checkbutton(ctrl, text="Stealth Mode", variable=self._stealth_mode).pack(side="left", padx=18)

        self._progress = ttk.Progressbar(hdr, mode="indeterminate", length=260)
        self._progress.pack(side="right", padx=18)

        self._notebook = ttk.Notebook(self)
        self._notebook.pack(fill="both", expand=True, padx=14, pady=12)

        self._tab_main = ttk.Frame(self._notebook)
        self._tab_dns = ttk.Frame(self._notebook)
        self._tab_insights = ttk.Frame(self._notebook)
        self._tab_bypass = ttk.Frame(self._notebook)

        self._notebook.add(self._tab_main, text=" Targets ")
        self._notebook.add(self._tab_dns, text=" DNS Servers ")
        self._notebook.add(self._tab_insights, text=" Live Insights ")
        self._notebook.add(self._tab_bypass, text=" Bypass Assistant ")

        self._build_main_tab()
        self._build_dns_tab()
        self._build_insights_tab()
        self._build_bypass_tab()

        status_bar = tk.Frame(self, bg=C["header_bg"], height=38)
        status_bar.pack(fill="x", side="bottom")
        self._lbl_status = tk.Label(status_bar, text="Ready • AI Predictive Engine Active", bg=C["header_bg"], fg=C["fg2"], font=FONT_SMALL)
        self._lbl_status.pack(side="left", padx=24)
        self._lbl_time = tk.Label(status_bar, text="", bg=C["header_bg"], fg=C["fg3"], font=FONT_SMALL)
        self._lbl_time.pack(side="right", padx=24)

    def _build_main_tab(self):
        frame = self._tab_main
        toolbar = tk.Frame(frame, bg=C["bg2"], height=50)
        toolbar.pack(fill="x")
        tk.Label(toolbar, text="Filter:", bg=C["bg2"], fg=C["fg2"]).pack(side="left", padx=(20, 4))
        self._filter_var = tk.StringVar()
        self._filter_var.trace_add("write", lambda *_: self._refresh_tree())
        tk.Entry(toolbar, textvariable=self._filter_var, bg=C["bg3"], fg=C["fg"], relief="flat", font=FONT_SMALL, width=40).pack(side="left", padx=4, pady=10)

        self._sort_var = tk.StringVar(value="status")
        for val, txt in [("status", "Status"), ("name", "Name"), ("ping", "Ping"), ("stability", "Stability"), ("health", "Health")]:
            tk.Radiobutton(toolbar, text=txt, variable=self._sort_var, value=val, bg=C["bg2"], fg=C["fg2"], command=self._refresh_tree).pack(side="left", padx=18)

        tk.Label(toolbar, text=" | Provider:", bg=C["bg2"], fg=C["fg2"]).pack(side="left", padx=(38, 4))
        self._provider_var = tk.StringVar(value="Select Provider")
        self._provider_combo = ttk.Combobox(toolbar, textvariable=self._provider_var, values=["Select Provider"] + list(PROVIDERS.keys()), state="readonly", width=27)
        self._provider_combo.pack(side="left", padx=4, pady=10)
        ttk.Button(toolbar, text="Load", command=self._load_provider_targets).pack(side="left", padx=14)

        cols = ("target", "ip", "status", "ping", "port", "stability", "predicted", "variance", "health", "trend", "provider")
        self._tree = ttk.Treeview(frame, columns=cols, show="headings")
        col_cfg = [
            ("target", "Target", 260, "w"), ("ip", "Resolved IP", 142, "center"),
            ("status", "Status", 88, "center"), ("ping", "Ping ms", 80, "center"),
            ("port", "Best Port", 70, "center"), ("stability", "Stability %", 86, "center"),
            ("predicted", "Pred. ms", 80, "center"), ("variance", "Var", 68, "center"),
            ("health", "Health", 72, "center"), ("trend", "Trend", 92, "center"),
            ("provider", "Source", 170, "w")
        ]
        for cid, heading, w, a in col_cfg:
            self._tree.heading(cid, text=heading)
            self._tree.column(cid, width=w, anchor=a)

        self._tree.tag_configure("online", background=C["green_bg"], foreground=C["green"])
        self._tree.tag_configure("offline", background=C["red_bg"], foreground=C["red"])
        self._tree.tag_configure("pending", background=C["yellow_bg"], foreground=C["yellow"])
        self._tree.tag_configure("anomaly", background="#3a1a1a", foreground="#ff8888")

        vsb = ttk.Scrollbar(frame, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._tree.pack(fill="both", expand=True)

        self._tree.bind("<Button-3>", self._show_context_menu)

    def _build_dns_tab(self):
        frame = self._tab_dns
        toolbar = tk.Frame(frame, bg=C["bg2"], height=42)
        toolbar.pack(fill="x")
        self._dns_provider_var = tk.StringVar(value="All")
        for p in ["All"] + list(DEFAULT_DNS_SERVERS.keys()):
            tk.Radiobutton(toolbar, text=p, variable=self._dns_provider_var, value=p, bg=C["bg2"], fg=C["fg2"], command=self._refresh_dns_tree).pack(side="left", padx=14)
        ttk.Button(toolbar, text="Run DNS Scan Now", command=self._run_dns_check_now).pack(side="right", padx=14)

        dns_cols = ("dns_ip", "provider", "status", "latency")
        self._dns_tree = ttk.Treeview(frame, columns=dns_cols, show="headings")
        dcol_cfg = [
            ("dns_ip", "DNS Server IP", 200, "w"), ("provider", "Provider", 170, "w"),
            ("status", "Status", 110, "center"), ("latency", "Avg Latency ms", 140, "center")
        ]
        for cid, heading, w, a in dcol_cfg:
            self._dns_tree.heading(cid, text=heading)
            self._dns_tree.column(cid, width=w, anchor=a)
        self._dns_tree.tag_configure("online", background=C["green_bg"], foreground=C["green"])
        self._dns_tree.tag_configure("offline", background=C["red_bg"], foreground=C["red"])
        self._dns_tree.tag_configure("pending", background=C["yellow_bg"], foreground=C["yellow"])

        vsb = ttk.Scrollbar(frame, orient="vertical", command=self._dns_tree.yview)
        self._dns_tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._dns_tree.pack(fill="both", expand=True)

    def _build_insights_tab(self):
        frame = self._tab_insights
        tk.Label(frame, text="Live Insights + Predictive Latency Graph", bg=C["bg"], fg=C["accent2"], font=FONT_TITLE).pack(anchor="w", padx=24, pady=18)

        self._insight_frame = tk.Frame(frame, bg=C["bg2"])
        self._insight_frame.pack(fill="both", expand=True, padx=24, pady=8)

        self._top_targets_label = tk.Label(self._insight_frame, text="", bg=C["bg2"], fg=C["fg"], font=FONT_MONO, justify="left", anchor="nw")
        self._top_targets_label.pack(fill="x", padx=16, pady=8)

        self._best_dns_label = tk.Label(self._insight_frame, text="", bg=C["bg2"], fg=C["fg"], font=FONT_MONO, justify="left", anchor="nw")
        self._best_dns_label.pack(fill="x", padx=16, pady=8)

        self._graph_canvas = tk.Canvas(self._insight_frame, bg="#111111", height=198, highlightthickness=0)
        self._graph_canvas.pack(fill="x", padx=16, pady=12)

        ttk.Button(frame, text="Refresh All Insights", command=self._update_insights).pack(pady=10)

    def _build_bypass_tab(self):
        frame = self._tab_bypass
        tk.Label(frame, text=" Bypass Assistant - Predictive Recommendations", bg=C["bg"], fg=C["accent2"], font=FONT_TITLE).pack(anchor="w", padx=24, pady=18)
        self._bypass_text = tk.Label(frame, text="Waiting for first scan...", bg=C["bg2"], fg=C["fg"], font=FONT_MONO, justify="left", anchor="nw")
        self._bypass_text.pack(fill="both", expand=True, padx=24, pady=8)
        btn_frame = tk.Frame(frame, bg=C["bg"])
        btn_frame.pack(pady=12)
        ttk.Button(btn_frame, text="Refresh Recommendations", command=self._update_bypass).pack(side="left", padx=10)
        ttk.Button(btn_frame, text="📋 Copy Top 8", command=self._copy_top_bypass).pack(side="left", padx=10)

    def _init_data(self):
        initialize_targets(DEFAULT_TARGETS)
        global active_dns_servers
        active_dns_servers = [ip for ips in DEFAULT_DNS_SERVERS.values() for ip in ips]
        self._refresh_tree()
        self._refresh_dns_tree()
        self._update_insights()
        self._update_bypass()

    def _process_queue(self):
        try:
            while True:
                func = update_queue.get_nowait()
                func()
        except queue.Empty:
            pass
        self.after(10, self._process_queue)

    def _safe_after(self, func):
        self.after(0, func)

    def _toggle_monitoring(self):
        if self._is_running:
            self._stop_monitoring()
        else:
            self._start_monitoring()

    def _toggle_pause(self):
        self._is_paused = not self._is_paused
        if self._is_paused:
            self._pause_event.set()
            self._btn_pause.config(text="▶ RESUME")
            self._safe_after(lambda: self._lbl_status.config(text="SCAN PAUSED - Engine Suspended", fg=C["yellow"]))
        else:
            self._pause_event.clear()
            self._btn_pause.config(text="⏸ PAUSE")
            self._safe_after(lambda: self._lbl_status.config(text="Predictive Scan Running", fg=C["accent2"]))

    def _start_monitoring(self):
        self._is_running = True
        self._stop_event.clear()
        self._pause_event.clear()
        self._btn_toggle.config(text="⏹ STOP SCAN")
        self._btn_pause.config(state="normal")
        self._progress.start(16)
        self._safe_after(lambda: self._lbl_status.config(text="Predictive Scan Running", fg=C["accent2"]))
        self._check_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._check_thread.start()

    def _stop_monitoring(self):
        self._is_running = False
        self._stop_event.set()
        self._pause_event.clear()
        self._btn_toggle.config(text="▶ START SCAN")
        self._btn_pause.config(state="disabled")
        self._progress.stop()
        self._safe_after(lambda: self._lbl_status.config(text="Scan stopped", fg=C["fg2"]))

    def _monitor_loop(self):
        while not self._stop_event.is_set():
            if self._pause_event.is_set():
                self._safe_after(lambda: self._lbl_status.config(text="PAUSED - Scan Suspended", fg=C["yellow"]))
                self._pause_event.wait()
                self._safe_after(lambda: self._lbl_status.config(text="Predictive Scan Running", fg=C["accent2"]))
                continue

            self._safe_after(lambda: self._lbl_status.config(text="Running Predictive checks...", fg=C["accent2"]))
            stealth = self._stealth_mode.get()
            run_checks_once(
                target_list,
                on_progress=lambda t: self._safe_after(lambda: self._update_row(t)),
                stealth=stealth,
                stop_event=self._stop_event
            )

            check_history.append({"timestamp": datetime.now().isoformat(), "stats": get_summary_stats()})
            if len(check_history) > 150:
                check_history.pop(0)

            valid_pings = [v for v in ping_times.values() if v < float("inf")]
            avg = sum(valid_pings) / len(valid_pings) if valid_pings else 0
            latency_history.append(avg)

            self._safe_after(self._post_check_update)
            self._stop_event.wait(CHECK_INTERVAL_SECONDS)

    def _post_check_update(self):
        self._refresh_tree()
        self._update_insights()
        self._update_bypass()
        self._update_stats()
        now = time.strftime("%H:%M:%S")
        self._lbl_time.config(text=f"Last scan: {now}")

    def _refresh_tree(self):
        filt = self._filter_var.get().lower().strip()
        sort = self._sort_var.get()
        targets = [t for t in target_list if not filt or filt in t.lower() or filt in resolved_ips.get(t, "").lower()]

        if sort == "status":
            targets.sort(key=lambda t: (0 if status_map.get(t) is True else 1 if status_map.get(t) is None else 2, ping_times.get(t, float("inf"))))
        elif sort == "name":
            targets.sort()
        elif sort == "ping":
            targets.sort(key=lambda t: ping_times.get(t, float("inf")))
        elif sort == "stability":
            targets.sort(key=lambda t: stability_map.get(t, 0), reverse=True)
        elif sort == "health":
            targets.sort(key=lambda t: health_score.get(t, 0), reverse=True)

        scroll_pos = self._tree.yview()
        self._tree.delete(*self._tree.get_children())
        for t in targets:
            tag = "anomaly" if anomaly_flags.get(t, False) else self._row_tag(t)
            self._tree.insert("", "end", iid=t, values=self._row_values(t), tags=(tag,))
        self._tree.yview_moveto(scroll_pos[0])

    def _update_row(self, target):
        if self._tree.exists(target):
            tag = "anomaly" if anomaly_flags.get(target, False) else self._row_tag(target)
            self._tree.item(target, values=self._row_values(target), tags=(tag,))

    def _row_values(self, t):
        ip = resolved_ips.get(t, "—")
        status = status_map.get(t)
        ping_ms = ping_times.get(t, float("inf"))
        port = best_port_map.get(t, "-")
        stab = stability_map.get(t, 50.0)
        pred = predicted_latency.get(t, 80.0)
        var = variance_map.get(t, 0.0)
        health = health_score.get(t, 50.0)
        trend = trend_map.get(t, "Stable")
        parent = ip_cidr_parent.get(t, "")
        status_str = "Online" if status is True else "Offline" if status is False else "Pending"
        ping_str = f"{ping_ms:.1f}" if ping_ms != float("inf") else "—"
        stab_str = f"{stab:.0f}%"
        pred_str = f"{pred:.0f}" if pred < 500 else "—"
        var_str = f"{var:.2f}"
        health_str = f"{health:.0f}"
        return (t, ip, status_str, ping_str, port, stab_str, pred_str, var_str, health_str, trend, parent)

    def _row_tag(self, t):
        s = status_map.get(t)
        if s is True: return "online"
        if s is False: return "offline"
        return "pending"

    def _refresh_dns_tree(self):
        provider_filter = self._dns_provider_var.get()
        self._dns_tree.delete(*self._dns_tree.get_children())
        for provider, ips in DEFAULT_DNS_SERVERS.items():
            if provider_filter != "All" and provider != provider_filter:
                continue
            for ip in ips:
                results = dns_target_results.get(ip, {})
                if results:
                    latencies = [v[0] for v in results.values() if v[0] != float("inf")]
                    avg_lat = sum(latencies) / len(latencies) if latencies else float("inf")
                    any_online = any(v[1] for v in results.values())
                    status_str = "Online" if any_online else "Offline"
                    lat_str = f"{avg_lat:.1f}" if avg_lat != float("inf") else "—"
                    tag = "online" if any_online else "offline"
                else:
                    status_str = "Pending"
                    lat_str = "—"
                    tag = "pending"
                self._dns_tree.insert("", "end", values=(ip, provider, status_str, lat_str), tags=(tag,))

    def _run_dns_check_now(self):
        self._safe_after(lambda: self._lbl_status.config(text="Running DNS checks...", fg=C["accent2"]))
        def worker():
            run_dns_checks(active_dns_servers, on_progress=lambda *_: self._safe_after(self._refresh_dns_tree))
            self._safe_after(lambda: self._lbl_status.config(text="DNS scan complete", fg=C["green"]))
        threading.Thread(target=worker, daemon=True).start()

    def _update_stats(self):
        s = get_summary_stats()
        valid_pings = [v for v in ping_times.values() if v < float("inf")]
        avg = sum(valid_pings) / len(valid_pings) if valid_pings else 0
        self._lbl_stats.config(text=f"Online {s['online']} | Offline {s['offline']} | Pending {s['pending']} | Avg {avg:.0f} ms | Blacklisted {len(blacklist)}")

    def _update_insights(self):
        top = get_top_targets(8)
        txt = "Top performing paths:\n"
        for t, ping in top:
            txt += f"  • {t:<38} {ping:.1f} ms   Health {health_score.get(t, 50):.0f}\n"
        self._top_targets_label.config(text=txt)

        best = get_best_dns()
        txt2 = "Recommended DNS resolvers:\n"
        for dns, lat, prov in best:
            txt2 += f"  • {dns:<20} ({prov}) {lat:.1f} ms\n"
        self._best_dns_label.config(text=txt2)

        self._draw_latency_graph()

    def _draw_latency_graph(self):
        self._graph_canvas.delete("all")
        if not latency_history:
            return
        w = self._graph_canvas.winfo_width() or 640
        h = 188
        vals = list(latency_history)
        if not vals:
            return
        max_val = max(vals) * 1.12 or 200
        min_val = min(vals) * 0.88 or 0
        points = []
        for i, val in enumerate(vals):
            x = i * w / (len(vals) - 1)
            y = h - (val - min_val) * h / (max_val - min_val)
            points.append((x, y))
        for i in range(len(points) - 1):
            self._graph_canvas.create_polygon(points[i][0], h, points[i][0], points[i][1], points[i+1][0], points[i+1][1], points[i+1][0], h, fill="#10b98122", outline="")
            self._graph_canvas.create_line(points[i][0], points[i][1], points[i+1][0], points[i+1][1], fill=C["accent2"], width=3.5)
        self._graph_canvas.create_text(18, 16, text=f"Live Latency Trend ({len(vals)} scans) - Min {min(vals):.0f} Max {max(vals):.0f}", fill=C["fg2"], anchor="nw", font=FONT_SMALL)

    def _update_bypass(self):
        recs = get_bypass_recommendations()
        if not recs:
            txt = "Run a full scan to unlock bypass recommendations.\nCloudflare paths with high Health Score + Stable trend are optimal for filtering bypass."
        else:
            txt = "✅ PREDICTED BEST BYPASS PATHS (High Health + Low Flap):\n\n"
            for t, lat, port, stab, health, trend, anomaly, flaps in recs:
                flag = " 🔥 ANOMALY" if anomaly else ""
                flap_txt = f" ({flaps} flaps)" if flaps > 0 else ""
                txt += f"   • {t:<42} {lat:.1f} ms   Port {port}   Health {health}   {trend}   Stability {stab}%{flag}{flap_txt}   ← RECOMMENDED\n"
            txt += "\n💡 Pro Tips for bypassing filtering:\n   • Use highest Health Score paths in your proxy/VPN configs\n   • Combine with recommended DNS from DNS tab\n   • Rotate between Stable/Improving endpoints\n   • Blacklisted paths are auto-removed (low quality)"
        self._bypass_text.config(text=txt)

    def _copy_top_bypass(self):
        recs = get_bypass_recommendations()[:8]
        if not recs:
            return
        text = "MonPing - Top 8 Predictive Bypass Endpoints:\n\n"
        for t, lat, port, stab, health, trend, anomaly, flaps in recs:
            flag = " [ANOMALY]" if anomaly else ""
            flap_txt = f" ({flaps} flaps)" if flaps > 0 else ""
            text += f"{t}  |  {lat:.1f} ms  |  Port {port}  |  Health {health}  |  {trend}  |  Stability {stab}%{flag}{flap_txt}\n"
        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo("Copied", "Top 8 bypass endpoints copied to clipboard!")

    def _load_provider_targets(self):
        prov = self._provider_var.get()
        if prov == "Select Provider" or prov not in PROVIDERS:
            messagebox.showwarning("Provider", "Please select a provider")
            return
        if not messagebox.askyesno("Confirm", f"Add {prov} ranges to current targets?"):
            return
        new_targets = PROVIDERS[prov]
        for entry in [e.strip() for e in new_targets if e.strip()]:
            if entry in target_list:
                continue
            if is_cidr(entry):
                sampled = expand_cidr_targets(entry)
                for ip in sampled:
                    if ip not in target_list:
                        target_list.append(ip)
                        status_map[ip] = None
                        resolved_ips[ip] = ip
                        ping_times[ip] = float("inf")
                        best_port_map[ip] = "-"
                        stability_map[ip] = 50.0
                        predicted_latency[ip] = 80.0
                        variance_map[ip] = 0.0
                        per_target_history[ip] = deque(maxlen=18)
                        last_check_time[ip] = time.time()
                        anomaly_flags[ip] = False
                        flap_count[ip] = 0
                        health_score[ip] = 50.0
                        trend_map[ip] = "Stable"
                        ip_cidr_parent[ip] = entry
            else:
                if entry not in target_list:
                    target_list.append(entry)
                    status_map[entry] = None
                    resolved_ips[entry] = "resolving..."
                    ping_times[entry] = float("inf")
                    best_port_map[entry] = "-"
                    stability_map[entry] = 50.0
                    predicted_latency[entry] = 80.0
                    variance_map[entry] = 0.0
                    per_target_history[entry] = deque(maxlen=18)
                    last_check_time[entry] = time.time()
                    anomaly_flags[entry] = False
                    flap_count[entry] = 0
                    health_score[entry] = 50.0
                    trend_map[entry] = "Stable"
        self._refresh_tree()
        self._update_insights()
        self._update_bypass()
        self._safe_after(lambda: self._lbl_status.config(text=f"{prov} loaded", fg=C["accent2"]))

    def _show_context_menu(self, event):
        iid = self._tree.identify_row(event.y)
        if not iid:
            return
        self._tree.selection_set(iid)
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Traceroute to target", command=lambda: self._run_traceroute_on_target(iid))
        menu.add_command(label="Copy resolved IP", command=lambda: self._copy_ip(iid))
        menu.add_command(label="Blacklist this target", command=lambda: self._blacklist_target(iid))
        menu.add_separator()
        menu.add_command(label="Remove from list", command=lambda: self._remove_target(iid))
        menu.tk_popup(event.x_root, event.y_root)

    def _run_traceroute_on_target(self, target):
        win = tk.Toplevel(self)
        win.title("Traceroute Research Tool")
        win.geometry("880x620")
        win.configure(bg=C["bg"])
        tk.Label(win, text=f"Analyzing path to: {target}", bg=C["bg"], fg=C["fg"]).pack(anchor="w", padx=24, pady=16)
        text = scrolledtext.ScrolledText(win, font=FONT_MONO, bg=C["bg2"], fg=C["fg"], height=28)
        text.pack(fill="both", expand=True, padx=24, pady=16)
        def run_trace():
            text.delete(1.0, tk.END)
            text.insert(tk.END, f"Analyzing path to {target}...\n\n")
            result = run_traceroute(target)
            text.insert(tk.END, result)
        ttk.Button(win, text="Start Traceroute Analysis", command=run_trace).pack(pady=14)
        run_trace()

    def _copy_ip(self, target):
        ip = resolved_ips.get(target, target)
        self.clipboard_clear()
        self.clipboard_append(ip)
        messagebox.showinfo("Copied", f"IP copied: {ip}")

    def _blacklist_target(self, target):
        if target in blacklist:
            return
        blacklist.add(target)
        self._refresh_tree()
        messagebox.showinfo("Blacklisted", f"{target} added to auto-blacklist\n(Low Health / High Flap path removed from future scans)")

    def _remove_target(self, target):
        if target not in target_list:
            return
        target_list.remove(target)
        for d in (status_map, resolved_ips, ping_times, best_port_map, stability_map,
                  predicted_latency, variance_map, per_target_history, last_check_time,
                  anomaly_flags, flap_count, health_score, trend_map):
            d.pop(target, None)
        if target in blacklist:
            blacklist.remove(target)
        self._refresh_tree()

    def _clear_blacklist(self):
        if not blacklist:
            messagebox.showinfo("Blacklist", "Blacklist is already empty")
            return
        if messagebox.askyesno("Clear Blacklist", f"Remove all {len(blacklist)} blacklisted targets and allow them again?"):
            blacklist.clear()
            self._refresh_tree()
            self._update_insights()
            self._update_bypass()
            messagebox.showinfo("Blacklist", "All blacklisted targets cleared")

    def _open_traceroute_tool(self):
        win = tk.Toplevel(self)
        win.title("Traceroute Research Tool")
        win.geometry("880x620")
        win.configure(bg=C["bg"])
        tk.Label(win, text="Enter target for path analysis:", bg=C["bg"], fg=C["fg"]).pack(anchor="w", padx=24, pady=16)
        entry = tk.Entry(win, font=FONT_MONO, bg=C["bg3"], fg=C["fg"], width=76)
        entry.pack(padx=24, fill="x")
        text = scrolledtext.ScrolledText(win, font=FONT_MONO, bg=C["bg2"], fg=C["fg"], height=28)
        text.pack(fill="both", expand=True, padx=24, pady=16)
        def run_trace():
            target = entry.get().strip()
            if not target:
                return
            text.delete(1.0, tk.END)
            text.insert(tk.END, f"Analyzing path to {target}...\n\n")
            result = run_traceroute(target)
            text.insert(tk.END, result)
        ttk.Button(win, text="Start Traceroute Analysis", command=run_trace).pack(pady=14)

    def _open_dns_lookup(self):
        host = simpledialog.askstring("Quick DNS Lookup", "Enter hostname:")
        if host:
            try:
                ip = socket.gethostbyname(host)
                messagebox.showinfo("Result", f"{host} resolves to {ip}")
            except Exception as e:
                messagebox.showerror("Lookup Failed", str(e))

    def _export_research_data(self, fmt):
        try:
            data = {
                "timestamp": datetime.now().isoformat(),
                "targets": {t: {
                    "ip": resolved_ips.get(t), "status": status_map.get(t), "ping": ping_times.get(t),
                    "best_port": best_port_map.get(t), "stability": stability_map.get(t),
                    "predicted_latency": predicted_latency.get(t), "variance": variance_map.get(t),
                    "health": health_score.get(t), "trend": trend_map.get(t), "flaps": flap_count.get(t)
                } for t in target_list},
                "dns": dns_target_results,
                "history": check_history,
                "bypass_recs": get_bypass_recommendations(),
                "blacklist": list(blacklist)
            }
            if fmt == "json":
                path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
                if path:
                    with open(path, "w", encoding="utf-8") as f:
                        json.dump(data, f, indent=2)
            else:
                path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
                if path:
                    with open(path, "w", newline="", encoding="utf-8") as f:
                        writer = csv.writer(f)
                        writer.writerow(["Target", "IP", "Status", "Ping_ms", "Best_Port", "Stability_%", "Predicted_ms", "Variance", "Health", "Trend"])
                        for t in target_list:
                            writer.writerow([t, resolved_ips.get(t), status_map.get(t), ping_times.get(t), best_port_map.get(t), stability_map.get(t), predicted_latency.get(t), variance_map.get(t), health_score.get(t), trend_map.get(t)])
            messagebox.showinfo("Export Complete", f"Data saved as {fmt.upper()}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def _import_targets(self):
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            with open(path, encoding="utf-8") as f:
                lines = f.readlines()
            initialize_targets(lines)
            self._refresh_tree()
            self._update_insights()
            self._update_bypass()

    def _export_targets(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(target_list))

    def _show_about(self):
        messagebox.showinfo(
            "About MonPing ",
            "MonPing   - Predictive Multi-Port Monitoring & Professional Bypass Assistant\n\n"
            "Code by Hosea\n"
            "GitHub: https://github.com/Expen1\n\n"
            "Version: April 2026\n"
            "Health Score • Trend Detection • Auto-Blacklist • Smooth UI for long scans"
        )

    def on_close(self):
        self._stop_monitoring()
        self.destroy()

if __name__ == "__main__":
    app = NetMonitorApp()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()