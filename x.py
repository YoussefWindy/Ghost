from scapy.all import sniff, IP, TCP, Raw, conf, get_if_list, get_if_hwaddr

def simple_packet_callback(packet):
    if packet.haslayer(IP):
        print(f"IP Packet: {packet[IP].src} -> {packet[IP].dst}")
        if packet.haslayer(TCP):
            print(f"TCP Packet: {packet[TCP].sport} -> {packet[TCP].dport}")
            if packet.haslayer(Raw):
                print(f"Raw Payload: {packet[Raw].load}")

def main():
    print("Starting simple packet sniffing...")
    # List all interfaces to help select the right one
    interfaces = get_if_list()
    print("Available interfaces:")
    for iface in interfaces:
        print(f"{iface}: {get_if_hwaddr(iface)}")

    # Specify the interface (e.g., "Ethernet" or "Wi-Fi")
    # Replace YOUR_INTERFACE_IDENTIFIER with the correct identifier
    for i in conf.ifaces:
        conf.iface = i
        mac = get_if_hwaddr(f"\\Device\\NPF_{i}")
        print(f"MAC address of {i}: {mac}")

    #sniff(prn=simple_packet_callback, store=0, filter="tcp", iface=iface)

if __name__ == "__main__":
    main()
