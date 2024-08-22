# PRODIGY_cs_05








Network Packet Analyzer
from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"Protocol: TCP")
            print(f"Source Port: {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")

        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print(f"Protocol: UDP")
            print(f"Source Port: {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")

        # Display payload data if present
        if packet.payload:
            payload = bytes(packet.payload)
            print(f"Payload: {payload[:50]}...")  # Print the first 50 bytes of the payload

        print("-" * 50)

def start_sniffing(interface=None):
    print(f"Starting packet capture on interface: {interface}")
    sniff(iface=interface, prn=packet_callback, store=0)

interface = "wlan0"
start_sniffing(interface)
