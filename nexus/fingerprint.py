"""Device Fingerprinter — identifies devices from VID/PID and name patterns."""
from dataclasses import dataclass
from typing import Optional, List

@dataclass
class DeviceFingerprint:
    device_class: str
    display_name: str
    capabilities: List[str]
    suggested_module: Optional[str]
    icon: str
    needs_generation: bool

VID_PID_DB = {
    ('1D50','6089'): DeviceFingerprint('sdr','HackRF One',['spectrum','transmit','receive'],'hackrf','📡',False),
    ('1D50','604B'): DeviceFingerprint('sdr','HackRF Jawbreaker',['spectrum','transmit'],'hackrf','📡',False),
    ('0BDA','2838'): DeviceFingerprint('sdr','RTL-SDR v1',['spectrum','receive','fm_radio','adsb'],'rtlsdr','📻',False),
    ('0BDA','2832'): DeviceFingerprint('sdr','RTL-SDR v2',['spectrum','receive','fm_radio'],'rtlsdr','📻',False),
    ('1A86','7523'): DeviceFingerprint('microcontroller','Arduino CH340',['serial','sensors','gpio'],'arduino','🔧',False),
    ('0403','6001'): DeviceFingerprint('microcontroller','FTDI USB-Serial',['serial','sensors'],'arduino','🔧',False),
    ('10C4','EA60'): DeviceFingerprint('microcontroller','CP2102 (ESP32)',['serial','sensors','wifi'],'arduino','🔧',False),
    ('067B','2303'): DeviceFingerprint('microcontroller','PL2303 Serial',['serial','sensors'],'arduino','🔧',False),
    ('1546','01A7'): DeviceFingerprint('gps','u-blox GPS',['location','nmea','time'],'gps','🛰️',False),
    ('1546','01A8'): DeviceFingerprint('gps','u-blox GPS 8',['location','nmea','time'],'gps','🛰️',False),
    ('2341','0043'): DeviceFingerprint('microcontroller','Arduino Uno',['serial','sensors','gpio'],'arduino','🔧',False),
    ('2341','8036'): DeviceFingerprint('microcontroller','Arduino Leonardo',['serial','sensors'],'arduino','🔧',False),
    ('0483','5740'): DeviceFingerprint('microcontroller','STM32 USB',['serial','sensors'],'arduino','🔧',False),
    ('0D8C','0014'): DeviceFingerprint('audio','USB Audio',['audio_fft','microphone'],'audio','🎙️',True),
}

NAME_PATTERNS = [
    (['hackrf','jawbreaker'], DeviceFingerprint('sdr','HackRF (by name)',['spectrum','transmit'],'hackrf','📡',False)),
    (['rtl-sdr','rtl2838','rtl28xxu','bulk-in'], DeviceFingerprint('sdr','RTL-SDR (by name)',['spectrum','receive'],'rtlsdr','📻',False)),
    (['arduino','genuino'], DeviceFingerprint('microcontroller','Arduino (by name)',['serial','sensors'],'arduino','🔧',False)),
    (['esp32','esp8266','nodemcu'], DeviceFingerprint('microcontroller','ESP module',['serial','sensors','wifi'],'arduino','🔧',False)),
    (['gps','u-blox','nmea','globalsat'], DeviceFingerprint('gps','GPS Device',['location','nmea'],'gps','🛰️',False)),
    (['multimeter','ut61','ut71','fluke','dmm'], DeviceFingerprint('measurement','Digital Multimeter',['voltage','current','resistance'],'multimeter','⚡',True)),
    (['oscilloscope','dso','hantek','rigol'], DeviceFingerprint('measurement','Oscilloscope',['waveform','frequency'],'oscilloscope','📊',True)),
    (['logic analyzer','saleae'], DeviceFingerprint('measurement','Logic Analyzer',['digital','protocol'],'logic_analyzer','🔍',True)),
    (['temperature','thermometer'], DeviceFingerprint('sensor','Temperature Sensor',['temperature'],'temp_sensor','🌡️',True)),
    (['power meter','wattmeter','energy'], DeviceFingerprint('measurement','Power Meter',['power','energy','voltage'],'power_meter','⚡',True)),
    (['spectrometer','spectro'], DeviceFingerprint('measurement','Spectrometer',['optical_spectrum','wavelength'],'spectrometer','🌈',True)),
    (['geiger','radiation'], DeviceFingerprint('sensor','Geiger Counter',['radiation','cpm'],'geiger','☢️',True)),
]


def identify(vid: str, pid: str, name: str) -> DeviceFingerprint:
    if vid and pid:
        key = (vid.upper(), pid.upper())
        if key in VID_PID_DB:
            return VID_PID_DB[key]
    name_lower = (name or '').lower()
    for patterns, fp in NAME_PATTERNS:
        if any(p in name_lower for p in patterns):
            return fp
    return DeviceFingerprint('unknown', name or 'Unknown Device', [], None, '🔌', True)
