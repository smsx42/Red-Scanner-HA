from scapy.all import ARP, Ether, srp
import ipaddress
from mac_vendor_lookup import MacLookup
from config import IP_RANGE

def red_scan(ip_range) : 

    print("Escaneado la red...")

    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="FF:FF:FF:FF:FF:FF")
    arp_request_broadcast =  broadcast/arp_request
    result = srp(arp_request_broadcast, timeout=3, verbose=0)[0]
    devices = []

    mac_lookup = MacLookup()
    mac_lookup.update_vendors()

    for sent, received in result:
       
        mac = received.hwsrc

        try:
            vendor = mac_lookup.lookup(received.hwsrc)
        except:
            vendor = "Unkown"

        devices.append({
            "ip": received.psrc,
            "mac": mac,
            "vendor": vendor
        })

    sorted_devices_ip = sorted(devices, key=lambda device: ipaddress.IPv4Address(device["ip"]))
    
    for device in sorted_devices_ip:
        print(f"IP: {device['ip']}  MAC: {device['mac']} Vendor: {device['vendor']}")


red_scan(IP_RANGE)

    