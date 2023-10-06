from scapy.all import sniff, IP, TCP
import socket
import threading
import sys
import time
from collections import defaultdict

# ANSI escape codes for text formatting
HIGHLIGHT = "\033[1;31m"  # Red text
RESET = "\033[0m"  # Reset text formatting

def get_machine_ip():
    # Get the machine's own IP address
    hostname = socket.gethostname()
    machine_ip = socket.gethostbyname(hostname)
    return machine_ip

# Initialize the high-risk counter and high-risk IP as global variables
high_risk_counter = 0
high_risk_ip = None

def analyze_packet(packet, machine_ip, os_detection_attempts, ignored_ips):
    global high_risk_counter, high_risk_ip  # Declare high_risk_counter and high_risk_ip as global

    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        ttl = packet[IP].ttl

        # Check if the source IP address is in the ignored list
        if src_ip in ignored_ips:
            return

        # Check for common TTL values associated with specific OS types
        if ttl == 64:
            os_type = "Linux/Unix"
        elif ttl == 128:
            os_type = "Windows"
        else:
            os_type = "Unknown"

        # Create a unique key for the source IP
        key = f"{src_ip} ({os_type})"

        # Update the counter for the source IP
        os_detection_attempts[key] += 1

        # Check if the detection threshold is reached within a 1-second window
        now = time.time()

        if os_detection_attempts[key] >= 200:
            print(f"{HIGHLIGHT}High-risk note: OS detection threshold exceeded for {key}!{RESET}")
            high_risk_counter += 1
            high_risk_ip = src_ip  # Set the high-risk IP

        # Display IP addresses and their counts, including high-risk count
        display_counts(os_detection_attempts, high_risk_counter, high_risk_ip, ignored_ips)

def display_counts(os_detection_attempts, high_risk_counter, high_risk_ip, ignored_ips):
    # Clear the terminal
    sys.stdout.write("\033c")

    # Filter out ignored IPs from the counts
    filtered_counts = {key: count for key, count in os_detection_attempts.items() if key.split()[0] not in ignored_ips}

    # Print the counts for IP addresses and high-risk events
    print("IP Addresses (Count):")
    for key, count in filtered_counts.items():
        print(f"{key}: {count}")

    # Print the high-risk count and IP address
    print(f"{HIGHLIGHT}High-Risk Count: {high_risk_counter}")
    if high_risk_ip:
        print(f"High-Risk IP Address: {high_risk_ip}{RESET}")

def capture_packets(interface, machine_ip, os_detection_attempts, ignored_ips):
    print("Monitoring network packets for OS detection attempts...")

    # Start the thread for continuous count display
    display_thread = threading.Thread(target=display_counts, args=(os_detection_attempts, high_risk_counter, high_risk_ip, ignored_ips))
    display_thread.daemon = True
    display_thread.start()

    try:
        # Adjust the filter parameter to capture specific packets if needed
        sniff(iface=interface, prn=lambda pkt: analyze_packet(pkt, machine_ip, os_detection_attempts, ignored_ips), filter="ip")
    except KeyboardInterrupt:
        print("\nCapture stopped.")

if __name__ == "__main__":
    # Specify the network interface to capture packets (e.g., "Ethernet", "Wi-Fi")
    interface = "Ethernet"  # Replace with the name of your network interface

    # Get the machine's own IP address
    machine_ip = get_machine_ip()

    # Dictionary to store IP addresses and their last detection timestamps
    ignored_ips = ["192.168.0.99", "192.168.0.135"]  # Add more IP addresses as needed

    # Initialize a defaultdict to store OS detection attempts
    os_detection_attempts = defaultdict(int)

    capture_packets(interface, machine_ip, os_detection_attempts, ignored_ips)
