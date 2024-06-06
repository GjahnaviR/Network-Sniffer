import time
import argparse
from scapy.all import *
from prettytable import PrettyTable

def analyze(packet):
    output_table = PrettyTable()
    output_table.field_names = ["Timestamp", "Packet Type", "Source", "Destination", "Protocol", "Details"]

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    if ARP in packet:
        arp_pkt = packet[ARP]
        src_mac = arp_pkt.hwsrc
        src_ip = arp_pkt.psrc
        dst_mac = arp_pkt.hwdst
        dst_ip = arp_pkt.pdst
        output_table.add_row([timestamp, "ARP", f"{src_mac} ({src_ip})", f"{dst_mac} ({dst_ip})", "N/A", "N/A"])
    elif IP in packet:
        ip_pkt = packet[IP]
        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst
        protocol = ip_pkt.proto

        if TCP in packet:
            tcp_pkt = packet[TCP]
            src_port = tcp_pkt.sport
            dst_port = tcp_pkt.dport
            pkt_type = "TCP"
        elif UDP in packet:
            udp_pkt = packet[UDP]
            src_port = udp_pkt.sport
            dst_port = udp_pkt.dport
            pkt_type = "UDP"
        elif ICMP in packet:
            pkt_type = "ICMP"
            src_port = dst_port = "N/A"
        else:
            pkt_type = "IP"
            src_port = dst_port = "N/A"

        src_ip_port = f"{src_ip}:{src_port}"
        dst_ip_port = f"{dst_ip}:{dst_port}"
        if pkt_type != "ICMP":
            details = f"Protocol: {protocol}"
        else:
            details = f"Type: {packet[ICMP].type}, Code: {packet[ICMP].code}"

        output_table.add_row([timestamp, pkt_type, src_ip_port, dst_ip_port, protocol, details])

    print(output_table)

def sniffing(count=None):
    if count is None:
        count = 99999999  
    try:
        sniff(prn=analyze, count=count)
    except KeyboardInterrupt: 
        pass  

parser = argparse.ArgumentParser(description="Network Sniffer")
parser.add_argument("-c", "--count", type=int, help="Number of packets to capture")
args = parser.parse_args()

sniffing(count=args.count)
