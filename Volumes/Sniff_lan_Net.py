#!/usr/bin/env python3

import time as _time
import os as _os
import sys as _sys
from struct import Struct as _Struct
from ipaddress import IPv4Address as _IPv4Address
import socket as _socket

#declaring global variables
tcp_header_unpack = _Struct('!2H2LB').unpack_from                                   # converting in readable form uing struct
udp_header_unpack = _Struct('!4H').unpack_from                                      #unpacking in readable form uing struct
_write_err = _sys.stdout.write
_fast_time = _time.time
count=0
from scapy.all import *

class extract:

    def __init__(self, data):                                                       #init function
        self.timestamp = _fast_time()
        self.protocol  = 0
        self._name = self.__class__.__name__
        self._dlen = len(data)
        self.destination_mac = data[:6].hex()
        self.source_mac = data[6:12].hex()
        self._data   = data[14:]

    def __str__(self):                                                             #dunder method to display the sniffed data
        return '\n'.join([
            f'{"="*32}',
            f'{" "*8}Sniffed Packet from Network',
            f'{"="*32}',
            f'{" "*8}ETHERNET',
            f'{"-"*32}',
            f' source mac address: {self.source_mac}',
            f'destination mac address: {self.destination_mac}',
            f'{"-"*32}',
            f'{" "*8}IP',
            f'{"-"*32}',
            f'header-length: {self.header_len}',
            f'protocol: {self.protocol}',
            f'source-ip: {self.source_ip}',
            f'destination-ip: {self.destination_ip}',
            f'{"-"*32}',
            f'{" "*8}PORT UTILISED',
            f'{"-"*32}',
            f'source-port: {self.source_port}',
            f'destination-port: {self.destination_port}',
            f'{"-"*32}',
            f'{" "*8}DATA',
            f'{"-"*32}',
            f'{self.payload}'
        ])

    def _ip(self):
        data = self._data
        self.source_ip = _IPv4Address(data[12:16])                                      #slicing of data and picking the correct slice of data
        self.destination_ip = _IPv4Address(data[16:20])                                      #builtin library IPV4Address
        self.header_len = (data[0] & 15) * 4
        self.protocol  = data[9]
        self.ip_header = data[:self.header_len]
        self._data = data[self.header_len:]                                          # detaching ip header from payload

    def _tcp(self):
        data = self._data
        tcp_header = tcp_header_unpack(data)
        self.source_port   = tcp_header[0]
        self.destination_port   = tcp_header[1]
        self.sequence_number = tcp_header[2]
        self.acknowledgement_number = tcp_header[3]
        header_len = (tcp_header[4] >> 4 & 15) * 4
        self.proto_header = data[:header_len]
        self.payload = data[header_len:]
    
    # udp header 8 bytes
    def _udp(self):                                                                 #how we actually want to store the packet - using a class in python
        data = self._data
        udp_header = udp_header_unpack(data)
        self.source_port = udp_header[0]
        self.destination_port = udp_header[1]
        self.udp_length  = udp_header[2]
        self.udp_check  = udp_header[3]
        self.proto_header = data[:8]
        self.payload = data[8:]
    
    def parse(self):
        self._ip()
        if (self.protocol == 6):
            self._tcp()
        elif (self.protocol == 17):
            self._udp()
        else:
            _write_err('Unprocessed as not a tcp/udp packet!\n')

def parse(data):
    try:
        packet = extract(data)                                                      #initialising class and putting the data into packet
        packet.parse()                                                              #calling function parse with the packet
        print(packet)
    except:
        pass

def listen_forever(intf):
    sock = _socket.socket(_socket.AF_PACKET, _socket.SOCK_RAW)                      #creates the socket 
    try:
        sock.bind((intf, 3))                                                        #binding it on the interface
    except OSError:
        _sys.exit(f'cannot bind interface: {intf}! exiting for now...')
    else:
        _write_err(f'now listening on {intf}!')
    while True:                                                                     #loop over a socket recieve 
        try:
            data = sock.recv(2048)                                                  #socket recieve function for 2000bytes (a blocking call)
        except OSError:
            pass

        else:
            parse(data)

def insideLan(pkt, count=0):
   print("Lan's Source IP:", pkt[IP].src)
   print(" Lan's Destination IP:", pkt[IP].dst)
   print(" Lan's Protocol:", pkt[IP].proto)
   print("\n")


if __name__ == '__main__':
    if _os.geteuid():
        _sys.exit('Please run the file from root! exiting...')
    opt=input("Enter 1 for sniffing the lan and 2 for sniffing the network of system: ")
    if opt=='1':
        pkt = sniff(iface='br-4819de56e6aa', filter='ip',prn=insideLan)
    else:
        listen_forever('enp0s1')                                                          #interface we are using eth0 for containers and enp0s1 for VM