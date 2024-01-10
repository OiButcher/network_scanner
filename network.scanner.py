# Import necessary modules from Scapy
from scapy.all import ARP, Ether, IP, TCP, srp

# Function to perform ARP scan
def arp_scan(ip):
    # Create an ARP request packet
    arp_request = ARP(pdst=ip)
    # Create an Ethernet frame
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    # Combine Ethernet frame and ARP request packet
    packet = ether/arp_request

    # Send the packet and capture the response
    result = srp(packet, timeout=3, verbose=0)[0]

    # Extract and print information from the response
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

# Example usage
target_ip = "192.168.1.1/24"  # Replace with your target IP range
arp_result = arp_scan(target_ip)
print("Devices on the network:")
for device in arp_result:
    print(f"IP: {device['ip']}, MAC: {device['mac']}")
