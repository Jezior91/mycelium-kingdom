"""
🍄 MYCELIUM AGENT v5 — Imperialne Centrum Dowodzenia
Orkiestrator wykrywający i zarządzający wszystkimi królestwami w sieci.

Protokoły odkrywania:
  ✅ ARP / ICMP (ping sweep)
  ✅ mDNS / Bonjour (Apple, Chromecast, Smart Home)
  ✅ NetBIOS (Windows, Samba)
  ✅ SNMP (routery, switche, NAS)
  ✅ UPnP/SSDP (Powerline, smart urządzenia)
  ✅ Bluetooth BLE
  ✅ Port scanning (identyfikacja usług)

Ekspansja:
  ✅ Spore Deployment (SSH → Linux/RPi)
  ✅ Mapa relacji między królestwami
  ✅ Conquest AI (autonomiczna ocena celów)
"""

import json
import os
from datetime import datetime
from typing import List, Dict, Optional

from scanner import scan_network, scan_bluetooth, get_local_ip, scan_powerline_devices
from scanner.mdns import scan_mdns
from scanner.netbios import scan_netbios_broadcast, enrich_with_netbios
from scanner.snmp import scan_snmp_device
from expansion.relations import build_network_graph, find_gateway, measure_latency
from expansion.spore import SporeDeployer, SporeListener


DATA_FILE = os.path.join(os.path.dirname(__file__), "data", "devices.json")
GRAPH_FILE = os.path.join(os.path.dirname(__file__), "data", "graph.json")


class MycelliumAgent:
    """
    🍄 Mycelium — Centrum Imperium.
    Rozrasta grzybnię przez całą sieć elektryczną i WiFi.
    """

    def __init__(self):
        self.devices: Dict[str, Dict] = {}
        self.local_ip = get_local_ip()
        self.graph: dict = {}
        self._load_devices()
        
        # Ekspansja
        self.spore = SporeDeployer(self)
        self.spore_listener = SporeListener(port=47474)
        
        # Lazy import AI
        self._conquest_ai = None

    @property
    def conquest_ai(self):
        if self._conquest_ai is None:
            from ai.conquest_ai import ConquestAI
            self._conquest_ai = ConquestAI(self)
        return self._conquest_ai

    # ═══════════════════════════════════════════════════════════
    # ODKRYWANIE
    # ═══════════════════════════════════════════════════════════

    def discover(self, include_bluetooth: bool = True, bt_duration: float = 5.0,
                 include_mdns: bool = True, include_netbios: bool = True,
                 include_snmp: bool = True, include_powerline: bool = True,
                 quick: bool = False):
        """
        Pełne odkrywanie królestwa.
        quick=True — tylko ARP+ping, pominięcie powolnych protokołów.
        """
        print("🍄 ══════════════════════════════════════════════")
        print("🍄  MYCELIUM v5 — Rozrastam Imperium...")
        print(f"🍄  Centrum dowodzenia: {self.local_ip}")
        print("🍄 ══════════════════════════════════════════════\n")

        found_ips = set()

        # ── 1. ARP + Ping (podstawa) ──────────────────────────
        print("🔍 [1/6] Skanowanie ARP + Ping...")
        net_devices = scan_network()
        for d in net_devices:
            key = d["ip"]
            self._merge_device(key, d)
            found_ips.add(key)
        print(f"  ✅ Sieć: {len(net_devices)} urządzeń")

        if not quick:
            # ── 2. mDNS / Bonjour ────────────────────────────
            if include_mdns:
                print("\n📡 [2/6] mDNS / Bonjour (Apple, Chromecast, Smart Home)...")
                try:
                    mdns_devices = scan_mdns(timeout=3.0)
                    for d in mdns_devices:
                        key = d["ip"]
                        self._merge_device(key, d)
                        found_ips.add(key)
                    print(f"  ✅ mDNS: {len(mdns_devices)} urządzeń")
                except Exception as e:
                    print(f"  ⚠️ mDNS error: {e}")
            
            # ── 3. NetBIOS (Windows) ──────────────────────────
            if include_netbios:
                print("\n🏰 [3/6] NetBIOS / NBNS (Windows, Samba)...")
                try:
                    nb_devices = scan_netbios_broadcast(timeout=2.0)
                    for d in nb_devices:
                        key = d["ip"]
                        self._merge_device(key, d)
                        found_ips.add(key)
                    # Wzbogać istniejące Windows PC o nazwy NetBIOS
                    all_devs = list(self.devices.values())
                    enriched = enrich_with_netbios(all_devs)
                    for d in enriched:
                        key = d.get("ip")
                        if key:
                            self.devices[key] = d
                    print(f"  ✅ NetBIOS: {len(nb_devices)} nowych + enrichment")
                except Exception as e:
                    print(f"  ⚠️ NetBIOS error: {e}")
            
            # ── 4. Powerline / SSDP ───────────────────────────
            if include_powerline:
                print("\n⚡ [4/6] Powerline / SSDP (sieć elektryczna)...")
                try:
                    all_net = list(self.devices.values())
                    pl_devices = scan_powerline_devices(all_net)
                    for d in pl_devices:
                        key = d["ip"]
                        self._merge_device(key, d)
                        found_ips.add(key)
                    print(f"  ✅ Powerline: {len(pl_devices)} adapterów")
                except Exception as e:
                    print(f"  ⚠️ Powerline error: {e}")
            
            # ── 5. SNMP (routery, switche) ────────────────────
            if include_snmp:
                print("\n📊 [5/6] SNMP (routery, switche, NAS)...")
                snmp_count = 0
                snmp_targets = [
                    ip for ip, d in self.devices.items()
                    if d.get("type") in ("router", "nas", "linux_server", "unknown")
                    and d.get("status") == "online"
                ][:10]  # max 10 celów
                
                for ip in snmp_targets:
                    try:
                        snmp_data = scan_snmp_device(ip, timeout=1.0)
                        if snmp_data:
                            self._merge_device(ip, snmp_data)
                            snmp_count += 1
                    except Exception:
                        pass
                print(f"  ✅ SNMP: {snmp_count} urządzeń odpowiedziało")
            
            # ── 6. Bluetooth BLE ──────────────────────────────
            if include_bluetooth:
                print("\n📶 [6/6] Bluetooth BLE...")
                try:
                    bt_devices = scan_bluetooth(duration=bt_duration)
                    for d in bt_devices:
                        key = f"bt:{d['mac']}"
                        self._merge_device(key, d)
                    print(f"  ✅ Bluetooth: {len(bt_devices)} urządzeń")
                except Exception as e:
                    print(f"  ⚠️ Bluetooth: {e}")
        else:
            print("\n  ⏩ Tryb szybki — pominięto mDNS, NetBIOS, SNMP, BLE")

        # ── Buduj mapę relacji ────────────────────────────────
        all_devs = [d for d in self.devices.values() if d.get("ip")]
        gateway = find_gateway(all_devs)
        if gateway:
            print(f"\n🗺️  Brama sieciowa (centrum): {gateway}")
        
        self.graph = build_network_graph(all_devs, gateway)
        self._save_devices()
        self._save_graph()
        self._print_map()
        
        return self.get_all_devices()

    def _merge_device(self, key: str, new_data: dict):
        """Łączy dane urządzenia — nie nadpisuje istniejących wartości."""
        if key not in self.devices:
            self.devices[key] = new_data
        else:
            existing = self.devices[key]
            for k, v in new_data.items():
                if v and not existing.get(k):
                    existing[k] = v
            # Zawsze aktualizuj open_ports i status
            if new_data.get("open_ports"):
                existing_ports = set(existing.get("open_ports", []))
                existing_ports.update(new_data["open_ports"])
                existing["open_ports"] = sorted(existing_ports)
            if new_data.get("status"):
                existing["status"] = new_data["status"]

    # ═══════════════════════════════════════════════════════════
    # MAPA GRZYBNI
    # ═══════════════════════════════════════════════════════════

    def _print_map(self):
        print("\n🍄 ══════════════════════════════════════════════")
        print("🍄  MAPA IMPERIUM")
        print("🍄 ══════════════════════════════════════════════")

        by_category = {}
        for d in self.devices.values():
            cat = d.get("category", "unknown")
            by_category.setdefault(cat, []).append(d)

        category_emojis = {
            "computer": "🖥️",
            "server": "🗼",
            "network": "👑",
            "mobile": "📱",
            "smart_home": "🏡",
            "media": "📺",
            "storage": "💾",
            "peripheral": "🖨️",
            "iot": "⚡",
            "security": "📷",
            "gaming": "🎮",
            "unknown": "🌫️",
        }

        total = 0
        for category, devs in sorted(by_category.items()):
            cat_emoji = category_emojis.get(category, "📦")
            print(f"\n  {cat_emoji} {category.upper()} ({len(devs)})")
            for d in devs:
                emoji = d.get("emoji", "❓")
                kingdom = d.get("kingdom", d.get("name", "?"))
                ip = d.get("ip", d.get("mac", ""))
                ports = d.get("open_ports", [])
                port_str = f"  [{', '.join(map(str, ports[:5]))}]" if ports else ""
                spore = " 🌱" if d.get("spore_active") else ""
                print(f"    {emoji} {kingdom:<30} {ip:<18}{port_str}{spore}")
            total += len(devs)

        print(f"\n🍄 Razem: {total} królestw w Imperium")
        if self.graph.get("edges"):
            print(f"🔗 Relacje: {len(self.graph['edges'])} połączeń")
        print()

    # ═══════════════════════════════════════════════════════════
    # EKSPANSJA — ZARODNIKI
    # ═══════════════════════════════════════════════════════════

    def plant_spore(self, ip: str, username: str, password: str = None,
                    key_path: str = None) -> dict:
        """Wdraża zarodnik Mycelium na autoryzowane urządzenie SSH."""
        return self.spore.deploy(ip, username, password, key_path)

    def harvest_spore(self, ip: str) -> Optional[dict]:
        """Pobiera dane z istniejącego węzła."""
        node = self.spore.get_node_status(ip)
        return node

    def start_listening(self):
        """Uruchamia nasłuch na zarodniki raportujące się same."""
        self.spore_listener.start()

    # ═══════════════════════════════════════════════════════════
    # AKCJE NA KRÓLESTWACH
    # ═══════════════════════════════════════════════════════════

    def execute(self, device_key: str, action: str, params: dict = None) -> Dict:
        """Wykonuje akcję na urządzeniu."""
        device = self.devices.get(device_key)
        if not device:
            return {"error": f"Królestwo {device_key} nie znalezione"}

        available_actions = device.get("actions", ["ping"])
        print(f"🍄 Rozkazuję: {device.get('emoji', '?')} {device.get('kingdom', device_key)} → {action}")
        return self._dispatch_action(device, action, params or {})

    def _dispatch_action(self, device: Dict, action: str, params: Dict) -> Dict:
        import socket
        import subprocess
        import platform

        ip = device.get("ip")

        if action == "ping":
            is_win = platform.system() == "Windows"
            cmd = ["ping", "-n" if is_win else "-c", "1",
                   "-w" if is_win else "-W", "1000" if is_win else "1", ip]
            result = subprocess.run(cmd, capture_output=True, timeout=5)
            return {"status": "online" if result.returncode == 0 else "offline", "ip": ip}

        elif action == "port_scan":
            ports_to_scan = params.get("ports", [22, 23, 80, 443, 445, 3389, 5900, 8080])
            open_ports = []
            for port in ports_to_scan:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.5)
                    if s.connect_ex((ip, port)) == 0:
                        open_ports.append(port)
                    s.close()
                except Exception:
                    pass
            # Zaktualizuj
            if ip in self.devices:
                existing = set(self.devices[ip].get("open_ports", []))
                existing.update(open_ports)
                self.devices[ip]["open_ports"] = sorted(existing)
                self._save_devices()
            return {"open_ports": open_ports, "ip": ip}

        elif action == "http_get":
            import urllib.request
            port = params.get("port", 80)
            path = params.get("path", "/")
            try:
                url = f"http://{ip}:{port}{path}"
                with urllib.request.urlopen(url, timeout=5) as r:
                    body = r.read(2000).decode("utf-8", errors="replace")
                    return {"status": r.status, "url": url, "body_preview": body[:500]}
            except Exception as e:
                return {"error": str(e)}

        elif action == "wake_on_lan":
            mac = device.get("mac", "")
            if not mac or mac == "unknown":
                return {"error": "Brak MAC address — nie można wysłać WOL"}
            try:
                mac_clean = mac.replace(":", "").replace("-", "")
                magic = bytes.fromhex("FF" * 6 + mac_clean * 16)
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.sendto(magic, ("<broadcast>", 9))
                sock.close()
                return {"status": "sent", "mac": mac, "note": "Magic packet wysłany — urządzenie powinno się uruchomić"}
            except Exception as e:
                return {"error": str(e)}

        elif action == "traceroute":
            from expansion.relations import traceroute_to
            hops = traceroute_to(ip)
            return {"hops": hops, "hop_count": len(hops), "destination": ip}

        elif action == "dns_lookup":
            try:
                hostname, _, addrs = socket.gethostbyaddr(ip)
                return {"hostname": hostname, "aliases": _, "addresses": addrs}
            except Exception as e:
                return {"error": str(e)}

        elif action == "banner_grab":
            results = {}
            for port in device.get("open_ports", [])[:5]:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(2.0)
                    s.connect((ip, port))
                    s.send(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                    banner = s.recv(512).decode("utf-8", errors="replace").strip()[:200]
                    results[port] = banner
                    s.close()
                except Exception:
                    pass
            return {"banners": results, "ip": ip}

        elif action == "snmp_query":
            from scanner.snmp import scan_snmp_device
            data = scan_snmp_device(ip, timeout=2.0)
            return data or {"error": "SNMP nie odpowiada"}

        elif action == "plant_spore":
            username = params.get("username", "pi")
            password = params.get("password")
            key_path = params.get("key_path")
            return self.plant_spore(ip, username, password, key_path)

        elif action == "assess":
            return self.conquest_ai.assess_one(ip) or {"error": "Brak danych"}

        elif action == "deep_recon":
            return self.conquest_ai.deep_recon(ip)

        return {"status": "executed", "action": action, "device": device.get("kingdom", ip)}

    # ═══════════════════════════════════════════════════════════
    # GETTERY
    # ═══════════════════════════════════════════════════════════

    def get_all_devices(self) -> List[Dict]:
        return list(self.devices.values())

    def get_device(self, key: str) -> Optional[Dict]:
        return self.devices.get(key)

    def get_by_category(self, category: str) -> List[Dict]:
        return [d for d in self.devices.values() if d.get("category") == category]

    def get_graph(self) -> dict:
        return self.graph

    def get_empire_stats(self) -> dict:
        devices = self.get_all_devices()
        total = len(devices)
        online = sum(1 for d in devices if d.get("status") == "online")
        
        by_cat = {}
        for d in devices:
            cat = d.get("category", "unknown")
            by_cat[cat] = by_cat.get(cat, 0) + 1
        
        discovery_methods = {}
        for d in devices:
            m = d.get("discovery_method", "ARP")
            discovery_methods[m] = discovery_methods.get(m, 0) + 1
        
        return {
            "total_kingdoms": total,
            "active": online,
            "dormant": total - online,
            "spore_nodes": len(self.spore.active_nodes),
            "by_category": by_cat,
            "discovery_methods": discovery_methods,
            "graph_edges": len(self.graph.get("edges", [])),
        }

    # ═══════════════════════════════════════════════════════════
    # PERSYSTENCJA
    # ═══════════════════════════════════════════════════════════

    def _save_devices(self):
        os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            json.dump({
                "updated_at": datetime.now().isoformat(),
                "devices": self.devices,
            }, f, ensure_ascii=False, indent=2)

    def _save_graph(self):
        os.makedirs(os.path.dirname(GRAPH_FILE), exist_ok=True)
        with open(GRAPH_FILE, "w", encoding="utf-8") as f:
            json.dump(self.graph, f, ensure_ascii=False, indent=2)

    def _load_devices(self):
        if os.path.exists(DATA_FILE):
            try:
                with open(DATA_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.devices = data.get("devices", {})
                print(f"🍄 Wczytano {len(self.devices)} królestw z poprzedniej sesji")
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════
# PUNKT STARTOWY
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys
    
    quick = "--quick" in sys.argv
    no_bt = "--no-bt" in sys.argv
    
    agent = MycelliumAgent()
    agent.discover(
        include_bluetooth=not no_bt,
        bt_duration=5.0,
        quick=quick,
    )
