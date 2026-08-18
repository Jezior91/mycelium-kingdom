"""
🍄 MYCELIUM AGENT — Kingdom Definitions v3
Każde urządzenie to Królestwo. Każda sieć to Imperium.
"""

from typing import List

# ─────────────────────────────────────────────
# TYPY KRÓLESTW (Device Types)
# ─────────────────────────────────────────────

KINGDOM_TYPES = {

    # ══════════════ KOMPUTERY ══════════════
    "windows_pc": {
        "name": "Zamek Windows",
        "emoji": "🏰",
        "category": "fortresses",
        "kingdom_class": "Forteca",
        "ports": [135, 139, 445, 3389],
        "ports_required": 1,
        "actions": ["ping", "rdp", "smb_browse", "wol"],
        "description": "Królestwo systemu Windows — potężne i rozbudowane",
        "lore": "Zamek z wysokimi murami i mnóstwem bram. Zdobyć przez RDP lub SMB.",
    },
    "linux_server": {
        "name": "Forteca Linux",
        "emoji": "🗼",
        "category": "fortresses",
        "kingdom_class": "Forteca",
        "ports": [22, 80, 443, 8080],
        "ports_required": 1,
        "actions": ["ping", "ssh", "http_get", "port_scan"],
        "description": "Serwer lub stacja robocza Linux — stabilna i otwarta",
        "lore": "Bastion zbudowany z otwartego kamienia. Brama SSH zawsze czeka.",
    },
    "macos": {
        "name": "Zamek Apple",
        "emoji": "🍎",
        "category": "fortresses",
        "kingdom_class": "Pałac",
        "ports": [548, 5900, 7000, 22],
        "ports_required": 1,
        "actions": ["ping", "ssh", "airplay", "vnc"],
        "description": "Eleganckie królestwo Apple",
        "lore": "Elegancki pałac z zapieczętowanymi bramami. Można wejść przez SSH lub AirPlay.",
    },
    "raspberry_pi": {
        "name": "Twierdza Pi",
        "emoji": "🥧",
        "category": "fortresses",
        "kingdom_class": "Twierdza",
        "ports": [22, 80, 8080, 1883],
        "ports_required": 1,
        "mac_prefixes": ["B8:27:EB", "DC:A6:32", "E4:5F:01"],
        "actions": ["ping", "ssh", "http_get", "gpio_control"],
        "description": "Miniaturowa twierdza — zaskakująco potężna",
        "lore": "Mała twierdza o wielkich możliwościach. SSH otwiera wszystkie komnaty.",
    },

    # ══════════════ SIEĆ / ROUTER ══════════════
    "router": {
        "name": "Cytadela Sieci",
        "emoji": "👑",
        "category": "capital",
        "kingdom_class": "Stolica",
        "ports": [53, 80, 443, 23, 8080, 7547],
        "ports_required": 1,
        "actions": ["ping", "get_clients", "reboot", "traceroute"],
        "description": "Router/AP — serce Imperium, przez który przepływa całe życie",
        "lore": "Tron całego Imperium. Wszystkie drogi prowadzą przez Cytadelę.",
    },
    "nas": {
        "name": "Skarbiec NAS",
        "emoji": "💰",
        "category": "storage",
        "kingdom_class": "Skarbiec",
        "ports": [5000, 5001, 445, 2049],
        "ports_required": 1,
        "mac_prefixes": ["00:11:32", "00:50:43"],
        "actions": ["ping", "smb_browse", "http_get", "get_storage"],
        "description": "Serwer plików NAS — strzeże cennych zasobów",
        "lore": "Ogromny skarbiec pełen cennych danych. Strzeżony przez wiele zamków.",
    },

    # ══════════════ MOBILNE ══════════════
    "android_phone": {
        "name": "Zwiadowca Android",
        "emoji": "🗺️",
        "category": "scouts",
        "kingdom_class": "Zwiadowca",
        "ports": [5555, 8080],
        "ports_required": 1,
        "actions": ["ping", "adb_connect", "port_scan"],
        "description": "Mobilny zwiadowca — zawsze w ruchu",
        "lore": "Lekki i szybki. Przenika przez sieci jak cień.",
    },
    "iphone": {
        "name": "Zwiadowca Apple",
        "emoji": "🗺️",
        "category": "scouts",
        "kingdom_class": "Zwiadowca",
        "ports": [62078, 7000],
        "ports_required": 1,
        "mac_prefixes": ["A4:C3:F0", "3C:22:FB", "F0:98:9D", "18:65:90",
                         "AC:DE:48", "00:CD:FE", "F4:F1:5A", "BC:92:6B"],
        "actions": ["ping", "airplay", "port_scan"],
        "description": "Hermetyczny zwiadowca Apple",
        "lore": "Zapieczętowany na siedem pieczęci. Trudny do zdobycia, lecz potężny.",
    },

    # ══════════════ SMART HOME / IoT ══════════════
    "philips_hue": {
        "name": "Latarnia Hue",
        "emoji": "🕯️",
        "category": "outposts",
        "kingdom_class": "Posterunek",
        "ports": [80, 443, 1900],
        "ports_required": 2,
        "mac_prefixes": ["00:17:88", "EC:B5:FA"],
        "api_base": "http://{ip}/api",
        "actions": ["turn_on", "turn_off", "set_color", "set_brightness"],
        "description": "Most żarówek Philips Hue — zarządza światłem królestwa",
        "lore": "Latarnia oświetlająca zamkowe komnaty. Rozkazy przez REST API.",
    },
    "shelly": {
        "name": "Posterunek Shelly",
        "emoji": "⚙️",
        "category": "outposts",
        "kingdom_class": "Posterunek",
        "ports": [80],
        "ports_required": 1,
        "mac_prefixes": ["98:F4:AB", "C4:5B:BE", "34:AB:95"],
        "api_base": "http://{ip}",
        "actions": ["turn_on", "turn_off", "get_power", "get_temperature"],
        "description": "Inteligentne gniazdko/przekaźnik Shelly",
        "lore": "Mały, ale sprytny posterunek. Zarządza przepływem energii.",
    },
    "smart_tv": {
        "name": "Koloseum TV",
        "emoji": "🏟️",
        "category": "outposts",
        "kingdom_class": "Teatr",
        "ports": [8001, 8002, 7676, 1925, 55000],
        "ports_required": 1,
        "mac_prefixes": ["00:12:FB", "8C:77:12", "F4:7B:5E", "78:BD:BC"],
        "actions": ["turn_on", "turn_off", "send_key", "get_status"],
        "description": "Smart TV — centrum rozrywki Imperium",
        "lore": "Koloseum pełne widowisk. Władane przez pilota.",
    },
    "sonos": {
        "name": "Bard Sonos",
        "emoji": "🎵",
        "category": "outposts",
        "kingdom_class": "Bard",
        "ports": [1400, 1443],
        "ports_required": 1,
        "mac_prefixes": ["00:0E:58", "78:28:CA", "94:9F:3E"],
        "actions": ["play", "pause", "set_volume", "get_status"],
        "description": "Głośnik Sonos — muzykant Imperium",
        "lore": "Wędrowny bard przechodzący przez wszystkie komnaty.",
    },
    "ip_camera": {
        "name": "Strażnica Kamera",
        "emoji": "👁️",
        "category": "security",
        "kingdom_class": "Strażnica",
        "ports": [554, 8554, 80],
        "ports_required": 1,
        "actions": ["get_snapshot", "get_stream", "port_scan"],
        "description": "Kamera IP — oko Imperium",
        "lore": "Wszystkowidzące oko na wieży. Nigdy nie śpi.",
    },
    "mqtt_broker": {
        "name": "Kurier MQTT",
        "emoji": "📯",
        "category": "outposts",
        "kingdom_class": "Kurier",
        "ports": [1883, 8883],
        "ports_required": 1,
        "actions": ["subscribe", "publish", "get_topics"],
        "description": "Broker MQTT — posłaniec między królestwami",
        "lore": "Szybki kurier dostarczający wiadomości w całym Imperium.",
    },

    # ══════════════ SIEĆ ELEKTRYCZNA ══════════════
    "powerline": {
        "name": "Tunel Elektryczny",
        "emoji": "⚡",
        "category": "powerline",
        "kingdom_class": "Tunel",
        "ports": [80, 443],
        "ports_required": 0,
        "actions": ["ping", "http_get", "port_scan"],
        "description": "Adapter Powerline — sekretne tunele w ścianach",
        "lore": "Ukryte przejście w murach. Łączy królestwa przez sieć elektryczną.",
    },

    # ══════════════ PERYFERIA ══════════════
    "printer": {
        "name": "Kuźnia Druku",
        "emoji": "🔨",
        "category": "workshops",
        "kingdom_class": "Kuźnia",
        "ports": [9100, 631, 515],
        "ports_required": 1,
        "actions": ["ping", "get_status", "print_test"],
        "description": "Drukarka sieciowa — rzemieślnik Imperium",
        "lore": "Kuźnia tworząca dokumenty. Słyszy rozkazy przez port 9100.",
    },
    "voip_phone": {
        "name": "Posłaniec VoIP",
        "emoji": "📜",
        "category": "workshops",
        "kingdom_class": "Posłaniec",
        "ports": [5060, 5061],
        "ports_required": 1,
        "actions": ["ping", "port_scan"],
        "description": "Telefon VoIP/SIP",
        "lore": "Dyplomata przekazujący głosowe depesze między królestwami.",
    },

    # ══════════════ BLUETOOTH ══════════════
    "bt_headphones": {
        "name": "Szept BT",
        "emoji": "🎧",
        "category": "bluetooth",
        "kingdom_class": "Szept",
        "actions": ["connect", "disconnect", "set_volume"],
        "description": "Słuchawki Bluetooth",
        "lore": "Cichy doradca szepczący wprost do ucha króla.",
    },
    "bt_speaker": {
        "name": "Herold BT",
        "emoji": "📢",
        "category": "bluetooth",
        "kingdom_class": "Herold",
        "actions": ["connect", "disconnect", "set_volume"],
        "description": "Głośnik Bluetooth",
        "lore": "Głośny herold ogłaszający dekrety królewskie.",
    },
    "bt_sensor": {
        "name": "Wyrocznia BLE",
        "emoji": "🔮",
        "category": "bluetooth",
        "kingdom_class": "Wyrocznia",
        "actions": ["read_data", "subscribe_notifications"],
        "description": "Czujnik BLE",
        "lore": "Mystyczna wyrocznia zbierająca dane o środowisku.",
    },

    # ══════════════ NIEZNANE ══════════════
    "unknown": {
        "name": "Terra Incognita",
        "emoji": "🌫️",
        "category": "unknown",
        "kingdom_class": "Nieznane",
        "ports": [],
        "actions": ["ping", "port_scan"],
        "description": "Nieznane królestwo — wymaga rozpoznania",
        "lore": "Ziemia za mapą. Wyślij zwiadowców by odkryć co kryje.",
    },
}

# ─────────────────────────────────────────────
# KATEGORIE KRÓLESTW
# ─────────────────────────────────────────────

KINGDOM_CATEGORIES = {
    "capital":    {"name": "Stolice",             "emoji": "👑", "color": "#f5c518"},
    "fortresses": {"name": "Fortece",             "emoji": "🏰", "color": "#58a6ff"},
    "storage":    {"name": "Skarbce",             "emoji": "💰", "color": "#e3b341"},
    "scouts":     {"name": "Zwiadowcy",           "emoji": "🗺️", "color": "#56d364"},
    "outposts":   {"name": "Posterunki",          "emoji": "🏮", "color": "#f0883e"},
    "security":   {"name": "Strażnice",           "emoji": "👁️", "color": "#ff6b6b"},
    "powerline":  {"name": "Tunele Elektryczne",  "emoji": "⚡", "color": "#a78bfa"},
    "workshops":  {"name": "Warsztaty",           "emoji": "🔨", "color": "#8b949e"},
    "bluetooth":  {"name": "Duchy BT",            "emoji": "🎵", "color": "#79c0ff"},
    "unknown":    {"name": "Terra Incognita",     "emoji": "🌫️", "color": "#6e7681"},
}

# ─────────────────────────────────────────────
# MAC OUI → typ królestwa
# ─────────────────────────────────────────────

MAC_VENDOR_MAP = {
    "A4:C3:F0": "iphone",       "3C:22:FB": "iphone",
    "F0:98:9D": "iphone",       "18:65:90": "iphone",
    "AC:DE:48": "macos",        "00:CD:FE": "macos",
    "F4:F1:5A": "iphone",       "BC:92:6B": "iphone",
    "B8:27:EB": "raspberry_pi", "DC:A6:32": "raspberry_pi",
    "E4:5F:01": "raspberry_pi",
    "00:17:88": "philips_hue",  "EC:B5:FA": "philips_hue",
    "98:F4:AB": "shelly",       "C4:5B:BE": "shelly",
    "34:AB:95": "shelly",
    "00:0E:58": "sonos",        "78:28:CA": "sonos",
    "94:9F:3E": "sonos",
    "00:11:32": "nas",
    "00:50:43": "nas",
    "00:12:FB": "smart_tv",     "8C:77:12": "smart_tv",
    "F4:7B:5E": "smart_tv",     "78:BD:BC": "smart_tv",
    "28:6C:07": "android_phone","64:CC:2E": "android_phone",
    # Powerline adapters
    "00:1F:9F": "powerline",    # TP-Link Powerline
    "B0:48:7A": "powerline",    # TP-Link
    "E8:DE:27": "powerline",    # devolo
    "78:9F:70": "powerline",    # devolo
    "00:0D:E9": "powerline",    # Netgear Powerline
    "08:60:6E": "powerline",    # ZyXEL Powerline
}

# ─────────────────────────────────────────────
# HOSTNAME → typ królestwa
# ─────────────────────────────────────────────

HOSTNAME_HINTS = {
    "raspberrypi": "raspberry_pi", "pi": "raspberry_pi",
    "synology":    "nas",          "qnap": "nas",
    "router":      "router",       "gateway": "router",
    "fritzbox":    "router",       "fritz": "router",
    "openwrt":     "router",       "dlink": "router",
    "camera":      "ip_camera",    "cam": "ip_camera",
    "hue":         "philips_hue",
    "shelly":      "shelly",
    "sonos":       "sonos",
    "android":     "android_phone","samsung": "smart_tv",
    "iphone":      "iphone",       "ipad": "iphone",
    "macbook":     "macos",        "imac": "macos",
    "printer":     "printer",      "hp": "printer",
    "canon":       "printer",      "epson": "printer",
    "powerline":   "powerline",    "devolo": "powerline",
    "dlan":        "powerline",    "plc": "powerline",
}


# ─────────────────────────────────────────────
# FUNKCJE IDENTYFIKACJI
# ─────────────────────────────────────────────

def identify_by_mac(mac: str) -> str:
    if not mac or mac in ("—", "unknown", ""):
        return "unknown"
    prefix = mac.upper()[:8]
    return MAC_VENDOR_MAP.get(prefix, "unknown")


def identify_by_hostname(hostname: str) -> str:
    if not hostname:
        return "unknown"
    h = hostname.lower()
    for keyword, dtype in HOSTNAME_HINTS.items():
        if keyword in h:
            return dtype
    return "unknown"


def identify_by_ports(open_ports: List[int], os_hint: str = "unknown") -> str:
    if not open_ports:
        return "unknown"

    port_set = set(open_ports)
    scores = {}

    skip = {"unknown", "bt_headphones", "bt_speaker", "bt_sensor",
            "bt_keyboard", "bt_mouse"}

    for device_type, info in KINGDOM_TYPES.items():
        if device_type in skip:
            continue
        device_ports = set(info.get("ports", []))
        required = info.get("ports_required", 1)
        if not device_ports or required == 0:
            continue
        overlap = len(port_set & device_ports)
        if overlap >= required:
            score = overlap / len(device_ports)
            if os_hint == "windows" and device_type == "windows_pc":
                score += 0.5
            elif os_hint == "linux" and device_type in ("linux_server", "raspberry_pi"):
                score += 0.3
            scores[device_type] = score

    if scores:
        best = max(scores, key=scores.get)
        if scores[best] > 0.1:
            return best
    return "unknown"


def get_kingdom_info(device_type: str) -> dict:
    return KINGDOM_TYPES.get(device_type, KINGDOM_TYPES["unknown"])


# backward compat
DEVICE_TYPES = KINGDOM_TYPES
