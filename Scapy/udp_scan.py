#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

dst_ip = "127.0.0.1"
src_port = RandShort()
dst_timeout=10

def udp_scan(dst_ip,dst_timeout):
    for dst_port in range(1, 65535):
        try:
            print("Testando porta %s" % dst_port)
            udp_scan_resp = sr1(IP(dst=dst_ip)/UDP(dport=dst_port), timeout=dst_timeout)
            print("Teste")
            if (str(type(udp_scan_resp)) == "<type 'NoneType'>"):
                retrans = []
                for count in range(0, 3):
                    retrans.append(sr1(IP(dst=dst_ip)/UDP(dport=dst_port), timeout=dst_timeout))
                for item in retrans:
                    if (str(type(item))!="<type 'NoneType'>"):
                        udp_scan(dst_ip, dst_port, dst_timeout)
                        return("Open|Filtered")
                    elif (udp_scan_resp.haslayer(UDP)):
                        return("Open")
                    elif(udp_scan_resp.haslayer(ICMP)):
                        if(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code)==3):
                            return("Closed")
                        elif(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code) in [1, 2, 9, 10, 13]):
                            return("Filtered")
        except KeyInterrupt:
            print("[*] Abortando tarefa.")
            break


udp_scan(dst_ip,dst_timeout)