import logging
from scapy.all import sniff, IP, TCP, Raw
from pymongo import MongoClient
import socket
import os

# Set up logging
logging.basicConfig(filename='network_monitor.log', level=logging.INFO, format='%(asctime)s %(message)s')

# MongoDB setup
connection_string = os.getenv("MONGODB_CONNECTION_STRING")
#print(connection_string)
if not connection_string:
    raise EnvironmentError("MONGODB_CONNECTION_STRING environment variable not set.")
client = MongoClient(connection_string)
try:
    # Check the MongoDB connection
    client.admin.command('ping')
    logging.info("MongoDB connection successful.")
except Exception as e:
    logging.error(f"Error connecting to MongoDB: {e}")
    raise
db = client["network_monitor"]
collection = db["web_traffic"]

def resolve_ip(ip):
    """Resolve IP to domain name"""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ip

def extract_http_info(packet):
    """Extract HTTP host and URL from packet"""
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        try:
            if b'HTTP' in payload:
                headers = payload.split(b'\r\n')
                host = None
                url = None
                for header in headers:
                    if b'Host:' in header:
                        host = header.split(b' ')[1].decode()
                    elif b'GET ' in header or b'POST ' in header:
                        url = header.split(b' ')[1].decode()
                if host and url:
                    logging.info(f"HTTP info extracted: http://{host}{url}")
                    return f"http://{host}{url}"
        except Exception as e:
            logging.error(f"Error extracting HTTP info: {e}")
    return None

def extract_https_info(packet):
    """Extract HTTPS domain from packet (SNI)"""
    if packet.haslayer(TCP):
        payload = bytes(packet[TCP].payload)
        if payload.startswith(b'\x16\x03'):
            if payload[5:6] == b'\x01':  # ClientHello
                server_name = None
                try:
                    extensions_length = int.from_bytes(payload[43:45], "big")
                    extensions = payload[45:45 + extensions_length]
                    while extensions:
                        ext_type = int.from_bytes(extensions[:2], "big")
                        ext_length = int.from_bytes(extensions[2:4], "big")
                        if ext_type == 0x00:
                            server_name = extensions[9:9 + int.from_bytes(extensions[7:9], "big")].decode()
                            logging.info(f"HTTPS SNI extracted: {server_name}")
                            break
                        extensions = extensions[4 + ext_length:]
                except Exception as e:
                    logging.error(f"Error extracting HTTPS info: {e}")
                return server_name
    return None

def packet_callback(packet):
    """Callback function to process packets"""
    if packet.haslayer(IP):
        domain = None
        if packet.haslayer(TCP):
            dst_ip = packet[IP].dst
            src_ip = packet[IP].src
            timestamp = packet.time
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                logging.info("HTTP packet detected")
                domain = extract_http_info(packet)
            elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                logging.info("HTTPS packet detected")
                domain = extract_https_info(packet)
            if domain:
                data = {
                    "domain": domain,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "timestamp": timestamp
                }
                # Log
                logging.info(f"Domain: {domain}, Source IP: {src_ip}, Destination IP: {dst_ip}")
                # Insert to MongoDB
                try:
                    collection.insert_one(data)
                    logging.info(f"Data inserted to MongoDB: {data}")
                except Exception as e:
                    logging.error(f"Error inserting to MongoDB: {e}")

# Start sniffing and monitoring
def main():
    logging.info("Starting packet sniffing...")
    # List all interfaces to help select the right one
    #sniff(prn=packet_callback, store=0, filter="tcp")
    # Specify the interface (e.g., "Ethernet" or "Wi-Fi")
    interface = '\\Device\\NPF_{...}'   # Change this to the correct interface name
    logging.info(f"Using interface: {interface}")
    sniff(prn=packet_callback, store=0, filter="tcp", iface=interface)

if __name__ == "__main__":
    main()
