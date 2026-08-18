"""
🍄 MYCELIUM — Web API v6 (Kingdom Empire Dashboard)
REST endpoints dla dashboardu imperialne.
"""

import json
import os
import subprocess
import sys
import threading
from datetime import datetime
from flask import Flask, jsonify, render_template, request
from flask_cors import CORS

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from agent import MycelliumAgent

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})
agent = MycelliumAgent()
scan_lock = threading.Lock()
scan_running = False
last_scan_time = None


# ═══════════════════════════════════════════════════════════
# DASHBOARD
# ═══════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template("index.html")


# ═══════════════════════════════════════════════════════════
# KINGDOMS (Urządzenia)
# ═══════════════════════════════════════════════════════════

@app.route("/api/kingdoms")
def get_kingdoms():
    devices = agent.get_all_devices()
    category = request.args.get("category")
    if category:
        devices = [d for d in devices if d.get("category") == category]
    return jsonify({"kingdoms": devices, "total": len(devices)})


@app.route("/api/kingdoms/<path:ip>")
def get_kingdom(ip):
    device = agent.get_device(ip)
    if not device:
        return jsonify({"error": "Królestwo nie znalezione"}), 404
    return jsonify(device)


@app.route("/api/stats")
def get_stats():
    stats = agent.get_empire_stats()
    stats["last_scan"] = last_scan_time
    stats["scan_running"] = scan_running
    return jsonify(stats)


# ═══════════════════════════════════════════════════════════
# ODKRYWANIE
# ═══════════════════════════════════════════════════════════

@app.route("/api/discover", methods=["POST"])
def start_discover():
    global scan_running, last_scan_time
    if scan_running:
        return jsonify({"error": "Skan już w toku", "running": True})

    quick = request.json.get("quick", False) if request.json else False

    def run_scan():
        global scan_running, last_scan_time
        with scan_lock:
            scan_running = True
            try:
                agent.discover(
                    include_bluetooth=True,
                    bt_duration=5.0,
                    include_mdns=True,
                    include_netbios=True,
                    include_snmp=True,
                    include_powerline=True,
                    quick=quick,
                )
                last_scan_time = datetime.now().isoformat()
            except Exception as e:
                print(f"Scan error: {e}")
            finally:
                scan_running = False

    t = threading.Thread(target=run_scan, daemon=True)
    t.start()
    return jsonify({"status": "started", "quick": quick})


@app.route("/api/discover/status")
def discover_status():
    return jsonify({
        "running": scan_running,
        "last_scan": last_scan_time,
        "total": len(agent.devices),
    })


# ═══════════════════════════════════════════════════════════
# AKCJE NA KRÓLESTWACH
# ═══════════════════════════════════════════════════════════

@app.route("/api/kingdoms/<path:ip>/action", methods=["POST"])
def kingdom_action(ip):
    data = request.json or {}
    action = data.get("action", "ping")
    params = data.get("params", {})
    result = agent.execute(ip, action, params)
    return jsonify(result)


@app.route("/api/kingdoms/<path:ip>/recon", methods=["POST"])
def kingdom_recon(ip):
    """Głęboki zwiad — full port scan + banner grab + ocena."""
    result = agent.conquest_ai.deep_recon(ip)
    return jsonify(result)


@app.route("/api/kingdoms/<path:ip>/assess")
def kingdom_assess(ip):
    """Pełna ocena królestwa przez AI."""
    result = agent.conquest_ai.assess_one(ip)
    if not result:
        return jsonify({"error": "Nie można ocenić"}), 404
    return jsonify(result)


# ═══════════════════════════════════════════════════════════
# MAPA RELACJI
# ═══════════════════════════════════════════════════════════

@app.route("/api/graph")
def get_graph():
    graph = agent.get_graph()
    if not graph:
        from expansion.relations import build_network_graph, find_gateway
        devices = [d for d in agent.get_all_devices() if d.get("ip")]
        gateway = find_gateway(devices)
        graph = build_network_graph(devices, gateway)
    return jsonify(graph)


# ═══════════════════════════════════════════════════════════
# ZARODNIKI (Spore Nodes)
# ═══════════════════════════════════════════════════════════

@app.route("/api/spores")
def get_spores():
    nodes = agent.spore.get_all_nodes()
    return jsonify({"nodes": nodes, "total": len(nodes)})


@app.route("/api/spores/deploy", methods=["POST"])
def deploy_spore():
    data = request.json or {}
    ip = data.get("ip")
    username = data.get("username", "pi")
    password = data.get("password")
    key_path = data.get("key_path")
    
    if not ip:
        return jsonify({"error": "Brak IP"}), 400
    
    def do_deploy():
        return agent.plant_spore(ip, username, password, key_path)
    
    t = threading.Thread(target=do_deploy, daemon=True)
    t.start()
    return jsonify({"status": "deploying", "ip": ip, "note": "Zarodnik w drodze..."})


@app.route("/api/spores/<path:ip>")
def get_spore(ip):
    node = agent.harvest_spore(ip)
    if not node:
        return jsonify({"error": "Węzeł nieaktywny"}), 404
    return jsonify(node)


@app.route("/api/spores/log")
def get_spore_log():
    return jsonify({"log": agent.spore.deployment_log[-50:]})


# ═══════════════════════════════════════════════════════════
# CONQUEST AI
# ═══════════════════════════════════════════════════════════

@app.route("/api/conquest/targets")
def get_targets():
    limit = int(request.args.get("limit", 5))
    targets = agent.conquest_ai.get_top_targets(limit)
    return jsonify({"targets": targets})


@app.route("/api/conquest/summary")
def get_conquest_summary():
    return jsonify(agent.conquest_ai.get_summary())


@app.route("/api/conquest/log")
def get_conquest_log():
    limit = int(request.args.get("limit", 50))
    return jsonify({"log": agent.conquest_ai.get_log(limit)})


@app.route("/api/conquest/auto", methods=["POST"])
def toggle_auto_conquest():
    data = request.json or {}
    action = data.get("action", "start")
    interval = data.get("interval_minutes", 10)
    
    if action == "start":
        agent.conquest_ai.start_auto_conquest(interval_minutes=interval)
        return jsonify({"status": "started", "interval_minutes": interval})
    else:
        agent.conquest_ai.stop_auto_conquest()
        return jsonify({"status": "stopped"})


@app.route("/api/spectrum")
def spectrum():
    """HackRF spectrum sweep — zwraca dane widmowe jako lista {freq_mhz, dbm}."""
    try:
        fmin = request.args.get("fmin", "5800")   # MHz
        fmax = request.args.get("fmax", "6000")   # MHz
        lna  = request.args.get("lna",  "40")
        vga  = request.args.get("vga",  "40")
        bw   = request.args.get("bw",   "1000000") # Hz, bin width

        cmd = ["hackrf_sweep",
               "-f", f"{fmin}:{fmax}",
               "-l", lna, "-g", vga,
               "-w", bw,
               "-1"]                              # jeden przebieg

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if result.returncode != 0 and not result.stdout.strip():
            return jsonify({"ok": False,
                            "error": result.stderr.strip() or "hackrf_sweep error"})

        points = []
        for line in result.stdout.strip().splitlines():
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 7:
                continue
            try:
                hz_low  = float(parts[2])
                hz_bin  = float(parts[4])
                dbs     = [float(x) for x in parts[6:] if x]
                freq    = hz_low
                for db in dbs:
                    points.append({"freq": round(freq / 1e6, 4), "dbm": round(db, 2)})
                    freq += hz_bin
            except (ValueError, IndexError):
                continue

        return jsonify({"ok": True,
                        "device": "HackRF One",
                        "fmin": fmin, "fmax": fmax,
                        "points": points,
                        "timestamp": datetime.now().isoformat()})

    except FileNotFoundError:
        return jsonify({"ok": False,
                        "error": "hackrf_sweep nie znaleziono — zainstaluj: sudo apt install hackrf"})
    except subprocess.TimeoutExpired:
        return jsonify({"ok": False, "error": "Timeout — HackRF nie odpowiada lub jest zajęty"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


# ─── Spectrum Peaks — save & retrieve ────────────────────────────────────────
PEAKS_FILE = os.path.join(DATA_DIR, "spectrum_peaks.json")

@app.route("/api/spectrum/peaks", methods=["GET", "POST"])
def spectrum_peaks():
    if request.method == "POST":
        entry = request.get_json(force=True)
        history = []
        if os.path.exists(PEAKS_FILE):
            try:
                with open(PEAKS_FILE) as f:
                    history = json.load(f)
            except Exception:
                history = []
        history.append(entry)
        history = history[-100:]          # keep last 100 scans
        with open(PEAKS_FILE, "w") as f:
            json.dump(history, f, indent=2)
        return jsonify({"ok": True, "saved": len(entry.get("peaks", []))})
    else:
        if not os.path.exists(PEAKS_FILE):
            return jsonify({"ok": True, "history": []})
        with open(PEAKS_FILE) as f:
            history = json.load(f)
        return jsonify({"ok": True, "history": history})


# ─── Spectrum Transmit — CW carrier via HackRF ───────────────────────────────
@app.route("/api/spectrum/transmit", methods=["POST"])
def spectrum_transmit():
    """Nadaj CW (carrier wave) na podanej częstotliwości przez HackRF One."""
    data     = request.get_json(force=True)
    freq_mhz = float(data.get("freq_mhz", 0))
    seconds  = min(10.0, max(0.1, float(data.get("seconds", 1))))

    if not (1 <= freq_mhz <= 6800):
        return jsonify({"ok": False, "error": "Częstotliwość poza zakresem HackRF (1–6800 MHz)"})

    freq_hz = int(freq_mhz * 1e6)
    samples = int(2e6 * seconds)          # 2 Msps × czas
    # generate IQ: constant carrier = DC (I=127, Q=127 in uint8)
    iq_bytes = bytes([127, 127]) * samples

    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
        tmp.write(iq_bytes)
        tmp_path = tmp.name

    try:
        cmd = [
            "hackrf_transfer",
            "-t", tmp_path,
            "-f", str(freq_hz),
            "-s", "2000000",       # 2 Msps
            "-a", "1",             # amp enable
            "-x", "20",            # TX VGA gain (dBm, 0–47)
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=seconds + 10)
        os.unlink(tmp_path)
        if result.returncode != 0:
            return jsonify({"ok": False, "error": result.stderr.strip() or "hackrf_transfer error"})
        return jsonify({
            "ok": True,
            "freq_mhz": freq_mhz,
            "seconds": seconds,
            "message": f"📡 Nadano CW na {freq_mhz:.3f} MHz przez {seconds}s"
        })
    except FileNotFoundError:
        os.unlink(tmp_path)
        return jsonify({"ok": False, "error": "hackrf_transfer nie znaleziono — zainstaluj HackRF tools"})
    except subprocess.TimeoutExpired:
        os.unlink(tmp_path)
        return jsonify({"ok": False, "error": "Timeout nadawania"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


# ─── NEXUS ────────────────────────────────────────────────────────────────────
import sys as _sys
_sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

_nexus_events = []
_nexus_openai_key = os.environ.get('OPENAI_API_KEY','')

try:
    from nexus import DeviceDetector, ModuleRegistry, DataBus, generate_module_ai, generate_module_template, fingerprint_identify
    _detector = DeviceDetector()
    _registry = ModuleRegistry()
    _databus = DataBus()
    _active_devices = {}

    def _on_connect(dev):
        fp = fingerprint_identify(dev.vid or '', dev.pid or '', dev.name)
        info = {'device_id':dev.device_id,'name':dev.name,'display_name':fp.display_name,
                'vid':dev.vid,'pid':dev.pid,'port':dev.port,'device_type':dev.device_type,
                'device_class':fp.device_class,'capabilities':fp.capabilities,
                'icon':fp.icon,'needs_generation':fp.needs_generation,
                'suggested_module':fp.suggested_module,
                'module_available': fp.suggested_module is not None and _registry.get_module(fp.suggested_module) is not None}
        _active_devices[dev.device_id] = info
        _nexus_events.append({'type':'connect','device':info,'ts':time.time()})
        if len(_nexus_events) > 100: _nexus_events.pop(0)

    def _on_disconnect(dev):
        _active_devices.pop(dev.device_id, None)
        _nexus_events.append({'type':'disconnect','device_id':dev.device_id,'ts':time.time()})

    _detector.on_connect(_on_connect)
    _detector.on_disconnect(_on_disconnect)
    _detector.start()
    NEXUS_OK = True
except Exception as _ne:
    NEXUS_OK = False
    _active_devices = {}

@app.route('/api/nexus/devices')
def nexus_devices():
    if not NEXUS_OK:
        return jsonify({'error':'Nexus unavailable','devices':[]})
    devs = []
    for dev in _detector.scan_once():
        fp = fingerprint_identify(dev.vid or '', dev.pid or '', dev.name)
        devs.append({'device_id':dev.device_id,'name':dev.name,'display_name':fp.display_name,
                     'icon':fp.icon,'vid':dev.vid,'pid':dev.pid,'port':dev.port,
                     'device_type':dev.device_type,'device_class':fp.device_class,
                     'capabilities':fp.capabilities,'needs_generation':fp.needs_generation,
                     'suggested_module':fp.suggested_module,
                     'module_available': fp.suggested_module is not None and _registry.get_module(fp.suggested_module) is not None})
    return jsonify({'devices':devs,'count':len(devs)})

@app.route('/api/nexus/events')
def nexus_events():
    return jsonify({'events':_nexus_events[-20:]})

@app.route('/api/nexus/data/<device_id>')
def nexus_data(device_id):
    if not NEXUS_OK: return jsonify({'error':'Nexus unavailable'})
    return jsonify({'device_id':device_id,'latest':_databus.get_latest(device_id),'history':_databus.get_history(device_id)})

@app.route('/api/nexus/scan', methods=['POST'])
def nexus_scan():
    """POST alias for scan — returns devices list same as GET /devices."""
    if not NEXUS_OK:
        return jsonify({'error':'Nexus unavailable','devices':[]})
    devs = []
    try:
        for dev in _detector.scan_once():
            fp = fingerprint_identify(dev.vid or '', dev.pid or '', dev.name)
            devs.append({
                'device_id': dev.device_id,
                'name': fp.display_name or dev.name,
                'icon': fp.icon,
                'vid': dev.vid, 'pid': dev.pid,
                'path': dev.port,
                'description': fp.device_class,
                'module': fp.suggested_module,
                'needs_generation': fp.needs_generation
            })
    except Exception as e:
        return jsonify({'error': str(e), 'devices': []})
    return jsonify({'devices': devs, 'count': len(devs)})

@app.route('/api/nexus/generate', methods=['POST'])
def nexus_generate():
    if not NEXUS_OK: return jsonify({'error':'Nexus unavailable'}), 503
    data = request.get_json() or {}
    # Support both old format (device_info) and new frontend format (vid, pid, name, openai_key)
    if 'device_info' in data:
        dev_info = data['device_info']
    else:
        dev_info = {'vid': data.get('vid',''), 'pid': data.get('pid',''), 'name': data.get('name','unknown')}
    key = data.get('openai_key') or data.get('api_key') or _nexus_openai_key
    if key:
        code = generate_module_ai(dev_info, key)
        ai_used = code is not None
    else:
        code = None; ai_used = False
    if not code:
        code = generate_module_template(dev_info)
    mname = ''.join(c if c.isalnum() else '_' for c in dev_info.get('name','unknown').lower())[:20]
    path = _registry.save_generated(mname, code)
    return jsonify({'status':'ok','module_name':mname,'path':path,'ai_used':ai_used,'code':code})

@app.route('/api/nexus/config', methods=['POST'])
def nexus_config():
    global _nexus_openai_key
    data = request.get_json() or {}
    if 'openai_key' in data:
        _nexus_openai_key = data['openai_key']
        return jsonify({'status':'ok'})
    return jsonify({'error':'missing openai_key'}), 400

@app.route('/api/nexus/modules')
def nexus_modules():
    if not NEXUS_OK: return jsonify({'modules':[]})
    return jsonify({'modules':_registry.list_modules()})

# ── AUTOMATIONS ──────────────────────────────────────────────
try:
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    from automations import engine as auto_engine, load_automations as _load_autos
    auto_engine.start()
    AUTO_OK = True
except Exception as _ae:
    AUTO_OK = False
    print(f"[automations] not available: {_ae}")

@app.route('/api/automations', methods=['GET'])
def get_automations():
    if not AUTO_OK:
        return jsonify([])
    return jsonify(_load_autos())

@app.route('/api/automations', methods=['POST'])
def create_automation():
    if not AUTO_OK:
        return jsonify({'error': 'automations not available'}), 503
    data = request.json or {}
    result = auto_engine.add(data)
    return jsonify(result)

@app.route('/api/automations/<aid>', methods=['DELETE'])
def delete_automation(aid):
    if AUTO_OK:
        auto_engine.delete(aid)
    return jsonify({'ok': True})

@app.route('/api/automations/<aid>/toggle', methods=['POST'])
def toggle_automation(aid):
    if not AUTO_OK:
        return jsonify({'error': 'not available'}), 503
    result = auto_engine.toggle(aid)
    return jsonify(result or {})

# ── PORT SCANNER ─────────────────────────────────────────────
try:
    from scanner.ports import scan_host as _scan_ports
    PORTS_OK = True
except Exception as _pe:
    PORTS_OK = False
    print(f"[ports] not available: {_pe}")

@app.route('/api/scan/ports', methods=['POST'])
def port_scan():
    if not PORTS_OK:
        return jsonify({'error': 'port scanner not available'}), 503
    data = request.json or {}
    ip = data.get('ip', '').strip()
    if not ip:
        return jsonify({'error': 'ip required'}), 400
    result = _scan_ports(ip)
    return jsonify(result)

if __name__ == "__main__":
    print("🍄 Mycelium Dashboard: http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
