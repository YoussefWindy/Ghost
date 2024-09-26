import pyshark

# List of known non-browsing domains
excluded_domains = {
    "spotify.com", "microsoft.com", "office.com", "adobe.com", "bing.com",
    "mcafee.com", "brave.com", "microsoftonline.com", "oculus.com", "msedge.net",
    "doubleclick.net", "googleapis.com", "gstatic.com", "windows.com",
    "api.github.com", "epicgames.com", "unity3d.com", "cloudflare.com",
    "duckduckgo.com", "cloud.unity3d.com", "ubiservices.ubi.com", "akamai.com",
    "scorecardresearch.com", "trafficmanager.net", "googleusercontent.com",
    "applicationinsights.azure.com", "azureedge.net", "hub-proxy.unity3d.com",
    "data.microsoft.com", "msn.com", "scorecardresearch.com", "avcdn.net", 
    "akamaihd.net", "steamstatic.com", "akamai.net", "protechts.net", "steamstore-a.akamaihd.net",
    "overwolf.com", "ea.com", "discord.gg", "amplitude.com", "cloudstorage.gog.com"
}

# List of explicitly included domains for testing purposes
included_domains = {"youtube.com"}

def capture_sni(packet):
    try:
        if hasattr(packet, 'tls') and hasattr(packet.tls, 'handshake_extensions_server_name'):
            sni = packet.tls.handshake_extensions_server_name
            domain_parts = sni.split('.')
            domain = '.'.join(domain_parts[-2:]) if len(domain_parts) > 1 else sni

            # Check if the domain is in the excluded list
            if domain not in excluded_domains or domain in included_domains:
                print(f"SNI found: {sni}")
    except AttributeError:
        pass

try:
    capture = pyshark.LiveCapture(interface='\\Device\\NPF_{...}', display_filter='tls.handshake')
    capture.sniff(timeout=10)

    for packet in capture.sniff_continuously():
        capture_sni(packet)
except KeyboardInterrupt:
    capture.close()
    print("Capture stopped by user")
finally:
    capture.close()
    print("Capture closed")
