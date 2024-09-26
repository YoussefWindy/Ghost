#import logging
from scapy.all import sniff, IP, TCP
import psutil
import socket
from pymongo import MongoClient
import time
import os

# Set up logging
#logging.basicConfig(filename='network_monitor.log', level=logging.INFO, format='%(asctime)s %(message)s')

# MongoDB setup
connection_string = os.getenv("MONGODB_CONNECTION_STRING")
#print(connection_string)
client = MongoClient(connection_string)
db = client["network_monitor"]
collection = db["web_traffic"]

def resolve_ip(ip):
    """Resolve IP to domain name"""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ip

def monitor_connections():
    """Monitor active network connections"""
    connections = psutil.net_connections(kind='inet')
    for conn in connections:
        if conn.status == 'ESTABLISHED':
            src_ip = conn.laddr.ip
            dst_ip = conn.raddr.ip
            domain = resolve_ip(dst_ip)
            timestamp = time.time()
            data = {
                "domain": domain,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "timestamp": timestamp
            }
            # Log to file
           # logging.info(f"Domain: {domain}, Source IP: {src_ip}, Destination IP: {dst_ip}")
            # Insert to MongoDB
            if dst_ip != "[redacted]":
                collection.insert_one(data)

def packet_callback(packet):
    """Callback function to process packets"""
    if packet.haslayer(IP) and packet.haslayer(TCP):
        dst_ip = packet[IP].dst
        domain = resolve_ip(dst_ip)
        src_ip = packet[IP].src
        timestamp = packet.time
        data = {
            "domain": domain,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "timestamp": timestamp
        }
        # Log to file
       # logging.info(f"Domain: {domain}, Source IP: {src_ip}, Destination IP: {dst_ip}")
        # Insert to MongoDB
        if dst_ip != "[redacted]":
            collection.insert_one(data)

# Start sniffing and monitoring
def main():
    while True:
        monitor_connections()
        sniff(prn=packet_callback, store=0, filter="tcp", timeout=10)

if __name__ == "__main__":
    main()
