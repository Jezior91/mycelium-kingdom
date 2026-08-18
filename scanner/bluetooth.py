"""
🍄 MYCELIUM AGENT — Bluetooth Scanner v2
Skanuje urządzenia Bluetooth / BLE w pobliżu.
Działa gracefully bez adaptera BT.
"""

import asyncio
import sys
from datetime import datetime
from typing import List, Dict


BT_DEVICE_HINTS = {
    "airpods":    ("bt_headphones", "🎧", "Apple AirPods"),
    "headphones": ("bt_headphones", "🎧", "Słuchawki BT"),
    "headset":    ("bt_headphones", "🎧", "Zestaw słuchawkowy"),
    "buds":       ("bt_headphones", "🎧", "Słuchawki dokanałowe"),
    "wh-":        ("bt_headphones", "🎧", "Słuchawki Sony"),
    "speaker":    ("bt_speaker",    "🔈", "Głośnik BT"),
    "jbl":        ("bt_speaker",    "🔈", "Głośnik JBL"),
    "bose":       ("bt_speaker",    "🔈", "Głośnik Bose"),
    "sonos":      ("bt_speaker",    "🔈", "Głośnik Sonos"),
    "sensor":     ("bt_sensor",     "📊", "Czujnik BLE"),
    "temp":       ("bt_sensor",     "📊", "Czujnik temperatury"),
    "mi ":        ("bt_sensor",     "📊", "Urządzenie Xiaomi"),
    "watch":      ("bt_sensor",     "⌚", "Smartwatch"),
    "band":       ("bt_sensor",     "⌚", "Opaska fitness"),
    "keyboard":   ("bt_keyboard",   "⌨️",  "Klawiatura BT"),
    "mouse":      ("bt_mouse",      "🖱️",  "Mysz BT"),
    "phone":      ("android_phone", "📱", "Telefon"),
    "iphone":     ("iphone",        "📱", "iPhone"),
    "samsung":    ("android_phone", "📱", "Telefon Samsung"),
    "galaxy":     ("android_phone", "📱", "Samsung Galaxy"),
}


def identify_bt_device(name: str) -> tuple:
    """Identyfikuje typ urządzenia BT na podstawie nazwy."""
    if not name:
        return ("bt_unknown", "📶", "Urządzenie Bluetooth")
    n = name.lower()
    for keyword, info in BT_DEVICE_HINTS.items():
        if keyword in n:
            return info
    return ("bt_unknown", "📶", "Urządzenie Bluetooth")


def _rssi_to_strength(rssi: int) -> str:
    if rssi >= -50:  return "🟢 Bardzo blisko"
    elif rssi >= -65: return "🟡 Blisko"
    elif rssi >= -80: return "🟠 Dalej"
    else:             return "🔴 Daleko"


async def _async_scan(duration: float) -> List[Dict]:
    """Asynchroniczne skanowanie BLE."""
    try:
        from bleak import BleakScanner
    except ImportError:
        return []

    devices = []
    discovered = await BleakScanner.discover(timeout=duration)
    for d in discovered:
        dtype, emoji, label = identify_bt_device(d.name or "")
        rssi = getattr(d, 'rssi', -99)
        devices.append({
            "mac": d.address,
            "name": d.name or "Nieznane",
            "rssi": rssi,
            "device_type": dtype,
            "emoji": emoji,
            "label": label,
            "category": "bluetooth",
            "discovered_at": datetime.now().isoformat(),
            "status": "nearby",
            "signal_strength": _rssi_to_strength(rssi),
        })
    return devices


def check_bluetooth_available() -> tuple:
    """Sprawdza dostępność Bluetooth. Zwraca (available: bool, reason: str)."""
    try:
        from bleak import BleakScanner
    except ImportError:
        return False, "Moduł 'bleak' nie jest zainstalowany (pip install bleak)"

    import subprocess
    try:
        result = subprocess.run(
            ["hciconfig"], capture_output=True, text=True, timeout=3
        )
        if result.returncode != 0 or not result.stdout.strip():
            return False, "Brak adaptera Bluetooth (hciconfig)"
    except FileNotFoundError:
        # hciconfig nie istnieje — sprawdzamy przez /sys
        import os
        if not os.path.exists("/sys/class/bluetooth"):
            return False, "Brak adaptera Bluetooth w systemie"
        bt_devices = os.listdir("/sys/class/bluetooth")
        if not bt_devices:
            return False, "Brak adaptera Bluetooth w /sys/class/bluetooth"
    except Exception as e:
        return False, f"Nie można sprawdzić BT: {e}"

    return True, "ok"


def scan_bluetooth(duration: float = 5.0) -> List[Dict]:
    """
    🍄 Skanuje urządzenia Bluetooth w pobliżu.
    Bezpieczne — jeśli BT niedostępny, zwraca [] z komunikatem.
    """
    available, reason = check_bluetooth_available()

    if not available:
        print(f"📶 Bluetooth: niedostępny ({reason})")
        print("   → Uruchom na komputerze z adapterem BT aby skanować urządzenia BLE")
        return []

    print(f"📶 Bluetooth: skanuję przez {duration}s...")

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        devices = loop.run_until_complete(_async_scan(duration))
        loop.close()

        if devices:
            print(f"📶 Bluetooth: znaleziono {len(devices)} urządzeń")
            for d in devices:
                print(f"  {d['emoji']} {d['name']:<30} {d['mac']}  {d['signal_strength']}")
        else:
            print("📶 Bluetooth: brak urządzeń w pobliżu")

        return devices

    except Exception as e:
        print(f"📶 Bluetooth: błąd skanowania — {e}")
        return []
