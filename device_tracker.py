"""Network scanner integration for Home Assistant.

Discovers devices in the local network using Nmap and reports
MAC address, IP, vendor, and optional hostname.
"""

import  logging
from homeassistant.components.device_tracker import ScannerEntity
from .core import scan_red

_LOGGER = logging.getLogger(__name__)

SCAN_INTERVAL = 60

async def async_setup_scanner(hass, config, async_add_entities, discovery_info=None):
    async_add_entities([RedScanner(hass)])

class RedScanner(ScannerEntity):

    def __init__(self, hass):
        self.hass = hass
        self._devices = {}

    def scan_devices(self):
        _LOGGER.debug("scan_devices ejecutado")
        devices = scan_red("192.168.0.0/24")
        _LOGGER.debug("Resultado scan: %s", devices)
        self._devices = devices
        return list(devices.keys())

    def get_device_name(self, device):
        data = self._devices.get(device, {})
        return ( data.get("hostname") or data.get("vendor") or f"Device_{device[-5:]}" )