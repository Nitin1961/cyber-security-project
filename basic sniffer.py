import socket
import struct

# Create a raw socket and bind it to the public interface
def create_sniffer():
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    return sniffer

# Function to parse Ethernet header
def parse_ethernet_header(data):
    dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
    return {
        'destination_mac': format_mac(dest_mac),
        'source_mac': format_mac(src_mac),
        'protocol': proto,
        'payload': data[14:]
    }

# Helper to format MAC address
def format_mac(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr))

# Start capturing packets
def sniff():
    sniffer = create_sniffer()
    print("Sniffer started. Press Ctrl+C to stop.")
    try:
        while True:
            raw_data, addr = sniffer.recvfrom(65536)
            eth = parse_ethernet_header(raw_data)
            print(f"Ethernet Frame: {eth['source_mac']} -> {eth['destination_mac']} | Protocol: {eth['protocol']}")
    except KeyboardInterrupt:
        print("\nSniffer stopped.")

if __name__ == "__main__":
    sniff()
