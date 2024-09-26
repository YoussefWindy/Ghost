import logging
from pymongo import MongoClient, errors
from scapy.all import sniff, IP, TCP, Raw
import os
import struct

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# MongoDB setup
connection_string = os.getenv("MONGODB_CONNECTION_STRING")
#print(connection_string)
if not connection_string:
    raise EnvironmentError("MONGODB_CONNECTION_STRING environment variable not set.")
def connect_to_mongodb():
    try:
        client = MongoClient(connection_string)
        db = client["network_monitor"]
        collection = db["web_traffic"]
        logging.info("MongoDB connection successful.")
        return collection
    except errors.ConnectionError as e:
        logging.error(f"Could not connect to MongoDB: {e}")
        return None

'''
def packet_callback(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        try:
            if packet.haslayer(HTTPRequest):
                http_layer = packet.getlayer(HTTPRequest)
                ip_layer = packet.getlayer(IP)
                
                packet_data = {
                    "src_ip": ip_layer.src,
                    "dst_ip": ip_layer.dst,
                    "method": http_layer.Method.decode(),
                    "host": http_layer.Host.decode(),
                    "path": http_layer.Path.decode()
                }
                logging.info(f"HTTP packet detected: {packet_data}")
                
                # Insert into MongoDB
                collection.insert_one(packet_data)
                logging.info("Packet data inserted into MongoDB")
            elif packet.dport == 443 or packet.sport == 443:
                logging.info("HTTPS packet detected")
        except Exception as e:
            logging.error(f"Error processing packet: {e}")

def start_sniffing(interface):
    logging.info(f"Starting packet sniffing on interface: {interface}")
    try:
        sniff(iface=interface, prn=packet_callback, store=0)
    except Exception as e:
        logging.error(f"Error starting packet sniffing: {e}")
'''

# Extract SNI from TLS Client Hello
def extract_sni(tls_data):
    try:
        # TLS handshake starts with 0x16 (Handshake), followed by version (2 bytes), then length (2 bytes)
        if tls_data[0] == 0x16 and tls_data[1:3] in [b'\x03\x00', b'\x03\x01', b'\x03\x02', b'\x03\x03']:
            handshake_data = tls_data[5:]
            # Check if it's a Client Hello (first byte should be 0x01)
            if handshake_data[0] == 0x01:
                session_id_length = handshake_data[38]
                cipher_suites_length = struct.unpack('!H', handshake_data[39 + session_id_length:41 + session_id_length])[0]
                offset = 41 + session_id_length + cipher_suites_length + 2
                extensions_length = struct.unpack('!H', handshake_data[offset - 2:offset])[0]
                extensions_data = handshake_data[offset:offset + extensions_length]
                
                # Parse extensions to find SNI
                while len(extensions_data) > 0:
                    ext_type = struct.unpack('!H', extensions_data[:2])[0]
                    ext_length = struct.unpack('!H', extensions_data[2:4])[0]
                    if ext_type == 0x00:  # SNI extension
                        sni_length = struct.unpack('!H', extensions_data[7:9])[0]
                        sni = extensions_data[9:9 + sni_length].decode()
                        return sni
                    extensions_data = extensions_data[4 + ext_length:]
    except Exception as e:
        logging.error(f"Error parsing TLS data: {e}")
    return None

# Packet processing callback function
def packet_callback(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = bytes(packet[Raw].load)
        logging.info(f"Packet captured: {packet.summary()}")

        sni = extract_sni(payload)
        if sni:
            logging.info(f"SNI detected: {sni}")
            packet_info = {
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'src_port': packet[TCP].sport,
                'dst_port': packet[TCP].dport,
                'sni': sni
            }
            collection.insert_one(packet_info)
        else:
            logging.info("SNI not found in packet.")

if __name__ == "__main__":
    logging.info("Connecting to MongoDB...")
    collection = connect_to_mongodb()
    
    if collection is None:
        logging.error("Could not connect to MongoDB. Exiting...")
    else:
        # Start sniffing for HTTPS packets
        interface = "\\Device\\NPF_{...}"
        logging.info(f"Starting packet sniffing on interface: {interface}")
        sniff(iface=interface, filter="tcp port 443", prn=packet_callback, store=0)
