
import os
import time
from scapy.all import ARP, Ether, srp
import nmap

def scan_network(ip_range):
    # Create an ARP request packet to broadcast across the network
    arp_request = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp_request

    # Send the packet and receive the response
    result_list = srp(packet, timeout=2, verbose=False)[0]

    devices = []
    for sent, received in result_list:
        # Append the IP and MAC address of each device to the list
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

def identify_routers(devices):
    nm = nmap.PortScanner()
    routers = []
    for device in devices:
        try:
            nm.scan(hosts=device['ip'], arguments='-O')
            if nm[device['ip']].get('osclass'):
                os_class = nm[device['ip']]['osclass'][0]['type']
                if 'router' in os_class.lower():
                    routers.append(device)
        except Exception as e:
            print(f"Error scanning {device['ip']}: {e}")
    return routers

def main():
    ip_range = "192.168.1.0/24"  # Change this to your network range
    while True:
        print("Scanning network for devices...")
        devices = scan_network(ip_range)
        routers = identify_routers(devices)

        print("\nDevices identified as potential routers:")
        for router in routers:
            print(f"IP: {router['ip']}, MAC: {router['mac']}")

        time.sleep(60)  # Wait for 1 minute before scanning again

if __name__ == "__main__":
    main()
