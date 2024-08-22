#!/usr/local/bin/python
#-*- coding:utf-8 -*-


VERSION: str = '1.0'
"""
ARP Scanner - A simple ARP scanner that scans the network for devices and their MAC addresses
Copyright © 2024 Daniel Hoffman (Aka. Z)
GitHub: Zeta-0x00

@Author Daniel Hofman (Aka. Z)
@License: GPL v3
@version {}
""".format(VERSION)

#region imports
import logging
logging.getLogger(name="scapy.runtime").setLevel(level=logging.ERROR)
import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
from termcolor import colored
import scapy.all as scapy # type: ignore
from types import FrameType
import time
import argparse
import signal
import sys
#endregion

#region signals
signal.signal(signalnum=signal.SIGINT, handler=lambda sig, frame: (print(f"\n{colored('[X]', 'red')} Keyboard Interrupt detected. \n\t{colored('Exiting...', 'red')}"), sys.exit(0)))
#endregion


def get_arguments() -> str:
    """Get the arguments from the user
    Returns:
        str: The target IP
    """
    parser:argparse.ArgumentParser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP")
    args: argparse.Namespace = parser.parse_args()
    return args.target

def scan(target: str) -> str:
    """Scan the network for the target IP
    Args:
        target (str): The target IP
    Returns:
        str: The data of the target IP
    """
    arp_packet:scapy.layers.l2.ARP = scapy.ARP(pdst=target)
    broadcast_packet:scapy.layers.l2.Ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # Appending the ARP packet to the broadcast packet to send it to all devices in the network
    arp_packet = broadcast_packet/arp_packet # type scapy.layers.l2.Ether
    answared: scapy.plist.SndRcvList
    answared, _ = scapy.srp(arp_packet, timeout=5, verbose=False)
    tmp: str = colored('IP\t\t\tMAC Address','cyan') + "\n" + colored(f"{'-'*41}\n", 'yellow') + "".join([response[1].psrc + "\t\t" + response[1].hwsrc + "\n" for response in answared]) 
    return tmp

def print_banner() -> None:
    """Print the banner"""
    banner: str = colored("""
      ▄▄▄· ▄▄▄   ▄▄▄·    .▄▄ ·  ▄▄·  ▄▄▄·  ▐ ▄  ▐ ▄ ▄▄▄ .▄▄▄  
    ▐█ ▀█ ▀▄ █·▐█ ▄█    ▐█ ▀. ▐█ ▌▪▐█ ▀█ •█▌▐█•█▌▐█▀▄.▀·▀▄ █·
    ▄█▀▀█ ▐▀▀▄  ██▀·    ▄▀▀▀█▄██ ▄▄▄█▀▀█ ▐█▐▐▌▐█▐▐▌▐▀▀▪▄▐▀▀▄ 
    ▐█ ▪▐▌▐█•█▌▐█▪·•    ▐█▄▪▐█▐███▌▐█ ▪▐▌██▐█▌██▐█▌▐█▄▄▌▐█•█▌
    ▀  ▀ .▀  ▀.▀        ▀▀▀▀ ·▀▀▀  ▀  ▀ ▀▀ █▪▀▀ █▪ ▀▀▀ .▀  ▀
    """, 'red')
    print(banner)
    print(f"{colored('ARP Scanner', 'magenta')}\n{colored('Author: Daniel Hoffman (Aka. Z)', 'magenta')}\n{colored('Version: 1.0', 'magenta')}\n{colored('Github: Zeta-0x00', 'magenta')}\n")

def main() -> None:
    """Main function"""
    target: str = get_arguments()
    print_banner()
    data: str = scan(target=target)
    print(data)

if __name__ == "__main__":
    main()

