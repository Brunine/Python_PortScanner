# Stealth Scan
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


def stealth_scan():
    dst_ip = options.host
    src_port = RandShort()
    print("[*] Começando Stealth Scan em %s" % dst_ip)
    for portas in range(1, 65535):
        conf.verb = 0
        stealth_scan_resp = sr1(IP(dst=dst_ip) / TCP(sport=src_port, dport=portas, flags="S"), timeout=10)
        if (str(type(stealth_scan_resp)) == "<type 'NoneType'>"):
            print("[*] Porta %s filtrada." % portas)
        elif (stealth_scan_resp.haslayer(TCP)):
            if (stealth_scan_resp.getlayer(TCP).flags == 0x12):
                send_rst = sr(IP(dst=dst_ip) / TCP(sport=src_port, dport=portas, flags="R"), timeout=10)
                print("[*] Porta %s aberta." % portas)
        elif (stealth_scan_resp.haslayer(ICMP)):
            if (int(stealth_scan_resp.getlayer(ICMP).type) == 3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                print("[*] Porta %s filtrada." % portas)


if options.stealth and options.host:
    stealth_scan()
elif options.stealth and not options.host:
    print("[*] Insira o IP ou DNS com o '-h' ou '--host'.")