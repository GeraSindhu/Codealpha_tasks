from scapy.all import sniff, IP, TCP, UDP, Raw

# Function to process captured packets
def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        payload = packet[Raw].load if Raw in packet else "No Payload"
        
        print(f"Source: {src_ip} --> Destination: {dst_ip} | Protocol: {proto}")
        if payload:
            print(f"Payload: {payload}\n")

# Start sniffing on the active network interface
print("Sniffing network traffic... Press Ctrl+C to stop.")
sniff(prn=packet_callback, filter="ip", store=False)

