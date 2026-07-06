"""
Packet Sniffer Skeleton
-----------------------
Objective:
    Build a simple packet sniffer using Python's socket module.

Instructions:
    Fill in each TODO section. Do NOT replace the entire program.
    Complete the missing code as you progress through the project.

Note:
    Running raw sockets usually requires Administrator (Windows)
    or root (Linux/macOS) privileges.
"""
from collections import defaultdict
import time

import socket
import struct
import datetime


ip_counter = defaultdict(int)
ip_last_seen = {}
total_packets = 0

# ==========================================================
# Helper Functions
# ==========================================================

def get_current_time():
    """
    Return the current timestamp.
    TODO:
        Return the current date/time as a formatted string.
    """

    current_datetime = datetime.datetime.now()
    formatted_string = current_datetime.strftime("%A, $B %d, %Y %I:%M %p")
    
    return formatted_string


# ==========================================================
# IP Header
# ==========================================================

def parse_ip_header(packet):
    """
    Extract information from the IPv4 header.

    TODO:
        Extract:
            - Version
            - Header Length
            - TTL
            - Protocol
            - Source IP
            - Destination IP

    Returns:
        Dictionary containing the parsed information.
    """

    ip_info = {
        "version": None,
        "header_length": None,
        "ttl": None,
        "protocol": None,
        "source_ip": None,
        "destination_ip": None
    }

    # TODO:
    # 1. Slice the first 20 bytes
    # 2. Unpack using struct.unpack()
    # 3. Fill in the dictionary

    # 1.
    ip_header = packet[:20]

    # 2.
    header_format = "!BBHHHBBH4s4s"
    ip_header = struct.unpack(header_format, ip_header)

    # 3.
    # 3a Extacting
    version = ip_header[0] >> 4
    header_length = (ip_header[0] & 0x0F) * 4
    ttl = ip_header[5]
    protocol = ip_header[6]

    # 3b Conversion
    source_ip = socket.inet_ntoa(ip_header[8])
    destination_ip = socket.inet_ntoa(ip_header[9])

    # 3c Fill
    ip_info["version"] = version
    ip_info["header_length"] = header_length
    ip_info["ttl"] = ttl
    ip_info["protocol"] = protocol
    ip_info["source_ip"] = source_ip
    ip_info["destination_ip"] = destination_ip


    return ip_info


# ==========================================================
# TCP Header
# ==========================================================

def parse_tcp_header(packet, ip_header_length):
    """
    Parse a TCP packet.

    TODO:
        Extract:
            - Source Port
            - Destination Port
            - Sequence Number
            - Acknowledgement Number
            - Flags

    Returns:
        Dictionary
    """

    tcp_info = {
        "source_port": None,
        "destination_port": None,
        "sequence": None,
        "acknowledgement": None,
        "flags": None
    }

    # TODO:
    # 1. Calculate TCP header location
    # Google search: "to calculate TCP header you must calculate the dynamic length of the preceding IP header and add it to any prior encapsulation offsets"
    tcp_header_start = ip_header_length    

    # TODO:
    # 2. Slice TCP header
    tcp_header = packet[tcp_header_start:tcp_header_start + 20]

    # TODO:
    # 3. Unpack header
    header_format = "!HHLLBBHHH"
    tcp_header = struct.unpack(header_format, tcp_header)

    # TODO:
    # 4. Store values in dictionary
    tcp_info["source_port"] = tcp_header[0]
    tcp_info["destination_port"] = tcp_header[1]
    tcp_info["sequence"] = tcp_header[2]
    tcp_info["acknowledgement"] = tcp_header[3]
    tcp_info["flags"] = tcp_header[5]

    return tcp_info


# ==========================================================
# UDP Header
# ==========================================================

def parse_udp_header(packet, ip_header_length):
    """
    Parse a UDP packet.

    TODO:
        Extract:
            - Source Port
            - Destination Port
            - Length
    """

    udp_info = {
        "source_port": None,
        "destination_port": None,
        "length": None
    }

    # TODO
    # 1. Calculate where the UDP starts
    udp_header_start = ip_header_length

    # 2. Slice the header
    udp_header = packet[udp_header_start:udp_header_start + 8]

    # 3. Unpack the header
    header_format = "!HHHH"
    udp_header = struct.unpack(header_format, udp_header)

    # 4. Store values in dictionary
    udp_info["source_port"] = udp_header[0]
    udp_info["destination_port"] = udp_header[1]
    udp_info["length"] = udp_header[2]

    return udp_info


# ==========================================================
# ICMP Header
# ==========================================================

def parse_icmp_header(packet, ip_header_length):
    """
    Parse an ICMP packet.

    TODO:
        Extract:
            - Type
            - Code
    """

    icmp_info = {
        "type": None,
        "code": None
    }

    # TODO
    # 1. Calculate where the ICMP starts
    icmp_header_start = ip_header_length

    # 2. Slice the header
    icmp_header = packet[icmp_header_start: icmp_header_start + 2]

    # 3. Unpack the header
    header_format = "!BB"
    icmp_header = struct.unpack(header_format, icmp_header)

    # 4. Store values in dictionary
    icmp_info["type"] = icmp_header[0]
    icmp_info["code"] = icmp_header[1]

    return icmp_info


# ==========================================================
# Suspicious Activity Detection
# ==========================================================

def detect_suspicious_activity(ip_info):
    """
    Analyze captured packets.

    Ideas:
        - Count packets from same IP
        - Detect repeated requests
        - Detect uncommon protocols
        - Detect excessive traffic

    Returns:
        True or False
    """

    # TODO
    # 1. Global info
    global total_packets
    ip = ip_info["source_ip"]
    protocol = ip_info["protocol"]
    now = time.time()

    # 2. Count packets from same IP
    ip_counter[ip] += 1
    if ip_counter[ip] > 50:
        return True

    # 3. Detect repeated requests
    if ip in ip_last_seen:
        if now - ip_last_seen[ip] < 0.1:
            return True
    ip_last_seen[ip] = now

    # 4. Detect uncommon protocols
    if protocol not in [1, 6, 17]:
        return True

    # 5. Detect excessive traffic
    total_packets += 1
    if total_packets > 500:
        return True

    return False


# ==========================================================
# Packet Display
# ==========================================================

def print_packet(ip_info,
                 tcp_info=None,
                 udp_info=None,
                 icmp_info=None):
    """
    Display packet information in a readable format.
    """

    print("=" * 60)

    # TODO:
    # Print timestamp

    # TODO:
    # Print protocol

    # TODO:
    # Print source/destination IP

    # TODO:
    # Print TCP/UDP/ICMP information

    print("=" * 60)


# ==========================================================
# Main Packet Sniffer
# ==========================================================

def start_sniffer():
    """
    Create a raw socket and continuously capture packets.
    """

    # --------------------------------------------
    # TODO:
    # Create raw socket
    # --------------------------------------------

    # Example:
    # sniffer = socket.socket(...)

    # --------------------------------------------
    # TODO:
    # Configure socket
    # --------------------------------------------

    print("Packet sniffer started...\n")

    while True:

        # ----------------------------------------
        # TODO:
        # Receive packet
        # ----------------------------------------

        # packet = ...

        # ----------------------------------------
        # TODO:
        # Parse IP header
        # ----------------------------------------

        ip_info = None

        # ----------------------------------------
        # TODO:
        # Determine protocol
        # ----------------------------------------

        tcp_info = None
        udp_info = None
        icmp_info = None

        # Example:
        #
        # if protocol == TCP:
        #     tcp_info = ...
        #
        # elif protocol == UDP:
        #     udp_info = ...
        #
        # elif protocol == ICMP:
        #     icmp_info = ...

        # ----------------------------------------
        # TODO:
        # Print packet information
        # ----------------------------------------

        # ----------------------------------------
        # TODO:
        # Check for suspicious activity
        # ----------------------------------------

        if False:
            print("\n*** WARNING: Suspicious Activity Detected ***\n")


# ==========================================================
# Program Entry Point
# ==========================================================

def main():
    """
    Start the packet sniffer.
    """

    try:
        start_sniffer()

    except KeyboardInterrupt:
        print("\nStopping packet sniffer...")

    except PermissionError:
        print("\nAdministrator/root privileges are required.")

    except Exception as error:
        print("\nUnexpected Error:")
        print(error)


if __name__ == "__main__":
    main()