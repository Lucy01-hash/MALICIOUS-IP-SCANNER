from scapy.all import sniff, IP, TCP
import requests
import logging
import json
from termcolor import colored

# Replace 'your_virustotal_api_key' with your actual VirusTotal API key
VIRUSTOTAL_API_KEY = 'c287c53bfc8d826d070658f458852f580582b08cfdfd9202cdf28e78499eaefb'
VIRUSTOTAL_URL = 'https://www.virustotal.com/vtapi/v2/ip-address/report'

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Set to store seen (IP, port) pairs
seen_pairs = set()

# Function to check if an IP is malicious using VirusTotal API
def check_ip_virustotal(ip):
    params = {
        'apikey': VIRUSTOTAL_API_KEY,
        'ip': ip
    }
    try:
        response = requests.get(VIRUSTOTAL_URL, params=params)
        response.raise_for_status()  # Raise an HTTPError for bad responses
        data = response.json()
        # Check the response for malicious reports
        if 'detected_urls' in data and len(data['detected_urls']) > 0:
            return True
        return False
    except requests.exceptions.RequestException as e:
        logging.error(f"Error checking IP {ip} with VirusTotal: {e}")
        return False
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON response for IP {ip}: {e}")
        return False

# Callback function for each captured packet
def packet_callback(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_dst = packet[IP].dst
        port_dst = packet[TCP].dport
        pair = (ip_dst, port_dst)
        if pair not in seen_pairs:
            seen_pairs.add(pair)
            logging.info(f'Outgoing IP: {ip_dst}, Destination Port: {port_dst}')
            
            # Check if the IP is malicious
            is_malicious = check_ip_virustotal(ip_dst)
            if is_malicious:
                logging.info(colored(f'IP {ip_dst} is malicious!', 'red'))
            else:
                logging.info(f'IP {ip_dst} is not malicious.')

# Start sniffing outgoing packets
logging.info("Starting packet capture. Press Ctrl+C to stop.")
try:
    sniff(filter="tcp", prn=packet_callback, store=0)
except KeyboardInterrupt:
    logging.info("Packet capture stopped by user.")
except Exception as e:
    logging.error(f"An error occurred during packet capture: {e}")
