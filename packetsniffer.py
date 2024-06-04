from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP


def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        # Determine protocol
        if proto == 6:  # TCP
            protocol = 'TCP'
        elif proto == 17:  # UDP
            protocol = 'UDP'
        else:
            protocol = 'Other'

        # Get payload data if TCP or UDP
        if protocol in ('TCP', 'UDP'):
            payload = bytes(packet[protocol].payload)
        else:
            payload = b''

        print(f'Source IP: {ip_src} | Destination IP: {ip_dst} | Protocol: {protocol}')
        print(f'Payload Data: {payload}\n')


# Capture packets on the default network interface
sniff(prn=packet_callback, store=0)
