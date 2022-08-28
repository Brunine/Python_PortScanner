# NULL Scan
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

dst_ip = "172.20.0.10"
src_port = RandShort()

conf.verb = 0
for portas in range(1, 65535):
    null_scan_resp = sr1(IP(dst=dst_ip) / TCP(dport=portas, flags=""), timeout=10)
    if (str(type(null_scan_resp)) == "<type 'NoneType'>"):
        print("Open|Filtered %s" % portas)
    elif (null_scan_resp and null_scan_resp.haslayer(TCP)):
        if (null_scan_resp and null_scan_resp.haslayer(ICMP)):
            if (int(null_scan_resp.getlayer(ICMP).type) == 3 and int(null_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                print("Filtered %s" % portas)