from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        
        # Determine the protocol name
        protocol_name = "Other"
        if proto == 6:
            protocol_name = "TCP"
        elif proto == 17:
            protocol_name = "UDP"

        print(f"\n[+] New Packet: {ip_src} -> {ip_dst} | Protocol: {protocol_name}")

        # Check for Payload (Raw data)
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"[*] Payload: {payload[:50]}...") # Show first 50 chars of data

def main():
    print("Starting Packet Sniffer... Press Ctrl+C to stop.")
    # Sniff packets; 'store=0' prevents memory buildup
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()