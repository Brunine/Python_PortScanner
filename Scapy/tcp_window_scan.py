import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

dst_ip = "192.168.15.2"
src_port = RandShort()
dst_port=135

window_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port, flags="A"), timeout=10)
if (str(type(window_scan_resp)) == "<type 'NoneType'>"):
    print("No response")
elif(window_scan_resp.haslayer(TCP)):
    if(window_scan_resp.getlayer(TCP).window == 0):
        print("Closed")
    elif(window_scan_resp.getlayer(TCP).window > 0):
        print("Open")