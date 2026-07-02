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

import socket
import struct
import datetime


# ==========================================================
# Helper Functions
# ==========================================================

def get_current_time():
    """
    Return the current timestamp.
    TODO:
        Return the current date/time as a formatted string.
    """
    pass


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
    # Calculate TCP header location

    # TODO:
    # Slice TCP header

    # TODO:
    # Unpack header

    # TODO:
    # Store values in dictionary

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