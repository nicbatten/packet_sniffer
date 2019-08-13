#!/usr/bin/env python

import scapy.all as scapy

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
#prn calls back the process_sniffed_packet function

def process_sniffed_packet(packet):
    print(packet)

sniff ("eth0")
