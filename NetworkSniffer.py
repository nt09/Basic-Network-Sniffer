from scapy.all import *

def analyzer(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        mac_src = packet.src
        mac_dst = packet.dst
        
        if TCP in packet:
            print("----------------TCP Segment---------------")
            print(f'IP addres s: {ip_src}:{packet[TCP].sport} -> {ip_dst}:{packet[TCP].dport}')
            print(f'MAC address: {mac_src} -> {mac_dst}')
            print(f'Packet Size: {len(packet[TCP])}')
            if Raw in packet:
                print(f'Packet Data: {packet[Raw].load}')
        
        elif UDP in packet:
            print("----------------UDP Datagram---------------")
            print(f'IP address : {ip_src}:{packet[UDP].sport} -> {ip_dst}:{packet[UDP].dport}')
            print(f'MAC address: {mac_src} -> {mac_dst}')
            print(f'Packet Size: {len(packet[UDP])}')
            if Raw in packet:
                print(f'Packet Data: {packet[Raw].load}')
        
        elif ICMP in packet:
            print("----------------ICMP Packet----------------")
            print(f'IP address : {ip_src} -> {ip_dst}')
            print(f'MAC address: {mac_src} -> {mac_dst}')
            print(f'Packet Size: {len(packet[ICMP])}')
            if Raw in packet:
                print(f'Packet Data: {packet[Raw].load}')

sniff(iface="eth0", prn=analyzer)

