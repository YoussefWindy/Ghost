import pyshark
import logging
from pymongo import MongoClient
import os
from datetime import datetime
import time

# Set up logging

# SETUP MARKER #0

debug = False
if debug: logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# MongoDB connection

# SETUP MARKER #1

connection_string = os.getenv("MONGODB_CONNECTION_STRING")
if not connection_string:
    raise EnvironmentError("MONGODB_CONNECTION_STRING environment variable not set.")
client = MongoClient(connection_string)
try:
    # Check the MongoDB connection
    client.admin.command('ping')
    if debug: logging.info("MongoDB connection successful.")
except Exception as e:
    if debug: logging.error(f"Error connecting to MongoDB: {e}")
    raise
db = client["network_monitor"]
collection = db[datetime.now().strftime('%Y-%m-%d')]

# List of known non-browsing www domains

# SETUP MARKER #2

stupid_domains = {
    "brave.com", "bing.com", "google.com", "gstatic.com", "duckduckgo.com"
}

# List of known non-browsing domains

# SETUP MARKER #3

excluded_domains = {
    "spotify.com", "microsoft.com", "office.com", "adobe.com", "gog.com",
    "mcafee.com", "microsoftonline.com", "oculus.com", "msedge.net",
    "doubleclick.net", "googleapis.com", "windows.com", "nvidia.com",
    "github.com", "epicgames.com", "unity3d.com", "cloudflare.com", "azure.com",
    "ubi.com", "akamai.com", "exp-tas.com", "ubisoft.com",
    "scorecardresearch.com", "trafficmanager.net", "googleusercontent.com", "unity.com",
    "azureedge.net", "parsec.app", "dell.com", "gamepass.com", "duosecurity.com", "xboxlive.com",
    "msn.com", "scorecardresearch.com", "avcdn.net", "steelseries.com", "coinglass.com",
    "akamaihd.net", "steamstatic.com", "akamai.net", "protechts.net", "whatsapp.net",
    "overwolf.com", "ea.com", "discord.gg", "amplitude.com", "githubusercontent.com"
}

def worthy(domain, domain_parts):
    return domain not in stupid_domains and (domain not in excluded_domains or domain_parts[0] == "www")

def capture_sni(packet):
    try:
        if hasattr(packet, 'tls') and hasattr(packet.tls, 'handshake_extensions_server_name'):
            sni = packet.tls.handshake_extensions_server_name
            domain_parts = sni.split('.')
            domain = '.'.join(domain_parts[-2:]) if len(domain_parts) > 1 else sni

            # Check if the domain is in the excluded list
            if worthy(domain, domain_parts):
                # You can change how you want to log the data as you like, here I'm logging the domain, SNI, and timestamp
                t = datetime.now()
                timezone = -5 # change this to your timezone offset
                timestamp = f"{t.day}/{t.month}/{t.year} {t.hour + timezone}:{t.minute}:{t.second}"
                data = {
                    "_id": f"{domain}-{time.time()}",
                    "time": timestamp,
                    "domain": domain,
                    "sni": sni
                }
                # Log
                if debug: logging.info(f"Domain: {domain} - SNI: {sni}")
                # Insert to MongoDB
                try:
                    collection.insert_one(data)
                    if debug: logging.info("Data inserted to MongoDB")
                except Exception as e:
                    if debug: logging.error(f"Error inserting to MongoDB: {e}")
    except AttributeError:
        if debug: logging.error("Error processing packet")
        pass

# Start sniffing and monitoring
def main():
    if debug: logging.info("Starting packet sniffing...")
    # SETUP MARKER #4
    interface = '\\Device\\NPF_{...}' # Insert here
    if debug: logging.info(f"Using interface: {interface}")
    capture = pyshark.LiveCapture(interface=interface, display_filter='tls.handshake')
    capture.sniff(timeout=10)

    for packet in capture.sniff_continuously():
        capture_sni(packet)

if __name__ == "__main__":
    main()
