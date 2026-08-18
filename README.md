# 🍄 Mycelium Agent

> Agent który rozrasta się przez Twoją sieć jak grzybnia — odkrywa każde urządzenie i tworzy z nimi połączenia.

---

## ⚡ Szybki start

```bash
# 1. Zainstaluj zależności
pip install -r requirements.txt

# 2. Uruchom agenta (tryb terminalowy)
python agent.py

# 3. LUB uruchom web dashboard
python web/app.py
# → otwórz http://localhost:5000
```

---

## 🔍 Co odkrywa

### Sieć lokalna (LAN)
| Urządzenie | Jak identyfikuje |
|---|---|
| 💻 Komputery Windows | Porty SMB (445), RDP (3389) |
| 🐧 Serwery Linux | Port SSH (22) |
| 🍎 Mac / Apple | AFP (548), AirPlay (7000) |
| 🥧 Raspberry Pi | Prefiks MAC B8:27:EB |
| 💡 Philips Hue | Prefiks MAC 00:17:88 |
| 🔌 Shelly | Prefiks MAC 98:F4:AB |
| 🔊 Sonos | Prefiks MAC 00:0E:58 |
| 📺 Smart TV | Porty 8001, 8002 (Samsung) |
| 📷 Kamera IP | RTSP (554) |
| 💾 NAS | SMB + port 5000 (Synology) |
| 📡 Router | DNS (53), HTTP (80) |
| 🖨️ Drukarka | IPP (631), RAW (9100) |

### Bluetooth BLE
| Urządzenie | Jak identyfikuje |
|---|---|
| 🎧 Słuchawki | Nazwa zawiera "airpods", "headphones", "buds" |
| 🔈 Głośnik | Nazwa zawiera "speaker", "jbl", "bose" |
| 📊 Czujnik | Nazwa zawiera "sensor", "temp", "mi" |
| ⌚ Smartwatch | Nazwa zawiera "watch", "band" |
| 📱 Telefon | Nazwa zawiera "phone", "samsung", "iphone" |

---

## 🛠️ Struktura

```
mycelium/
├── agent.py              # 🧠 Główny orkiestrator
├── scanner/
│   ├── network.py        # 🌐 Skaner sieci lokalnej
│   ├── bluetooth.py      # 📶 Skaner Bluetooth BLE
│   └── device_types.py   # 📋 Baza definicji urządzeń
├── web/
│   ├── app.py            # 🌐 Web dashboard (Flask)
│   └── templates/
│       └── index.html    # UI
├── data/
│   └── devices.json      # 💾 Zapisane urządzenia
└── requirements.txt
```

---

## ⚙️ Wymagania systemowe

- Python 3.9+
- Linux / macOS / Windows
- Na Linux: uprawnienia do `arp` i `ping` (zazwyczaj bez sudo)
- Bluetooth: adapter BT w komputerze + `bleak`

---

## 📡 API (web dashboard)

| Endpoint | Metoda | Opis |
|---|---|---|
| `GET /api/devices` | GET | Lista wszystkich urządzeń |
| `POST /api/scan` | POST | Uruchom skanowanie |
| `POST /api/execute` | POST | Wykonaj akcję na urządzeniu |
| `GET /api/stats` | GET | Statystyki grzybni |

---

*🍄 Mycelium Agent — jak Ophiocordyceps, ale dla Twoich własnych urządzeń*
