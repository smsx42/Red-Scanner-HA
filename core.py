import subprocess
import re
from typing import Dict

NMAP_CMD = ["nmap", "-sn", "-PR"]

def scan_red(cidr_ip) -> Dict[str, dict]:

    devices = {}
    print("Escaneando red...")

    try:
        process = subprocess.run(
            NMAP_CMD + [cidr_ip],
            capture_output=True,
            text=True,
            check=False
        )
    except():
        print("Error al escanear la red con Nmap.")

    for line in process.stdout.splitlines():
        

        if line.startswith("Nmap scan report for"):
            current_device = {}

            match = re.search(
                r"Nmap scan report for (.+?) \((\d+\.\d+\.\d+\.\d+)\)",
                line
            )

            if match:
                current_device["hostname"] = match.group(1)
                current_device["ip"] = match.group(2)
            else:
                current_device["ip"] = line.split()[-1]
                current_device["hostname"] = None

        elif "MAC Address:" in line and "ip" in current_device:
            match = re.search(
                r"MAC Address: ([0-9A-F:]{17}) \((.+)\)",
                line
            )
            if match:
                mac = match.group(1)
                vendor = match.group(2)
                devices[mac] = {
                    "ip": current_device["ip"],
                    "vendor": vendor,
                    "hostname": current_device["hostname"]
                }
            
    return devices     

devices = scan_red("192.168.0.1/24")

for mac, data in devices.items():
    print(mac, data)


        

