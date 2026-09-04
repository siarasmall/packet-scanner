#!/usr/bin/python3

from scapy.all import *
import argparse

incidentNum = 0

def packetcallback(packet):
    try:
        if packet.haslayer(Raw):
            payload = packet[Raw].load
        else:
            payload = "Empty payload"
        # NULL scan
        if TCP in packet:
            if packet[TCP].flags == 0:
                raise_alert("NULL scan", packet[IP].src, "TCP", payload)
        # FIN scan
            if packet[TCP].flags.F == 1:
                raise_alert("FIN scan", packet[IP].src, "TCP", payload)
        # Xmas scan
            if packet[TCP].flags == 0x29 or packet[TCP].flags == 0xFF:
                raise_alert("Xmas scan", packet[IP].src, "TCP", payload)  
        for pkt in packet:
            # Someone scanning for Server Message Block (SMB) protocol
            if pkt.haslayer(TCP) or packet.haslayer(UDP):
                if pkt.haslayer(Raw):
                    payload = pkt[Raw].load
                else:
                    payload = "Empty payload"
                if pkt.sport in [137, 138, 139, 445]  or pkt.dport in [137, 138, 139, 445] :
                    raise_alert("SMB scan", pkt[IP].src, pkt.sport, payload)
                # Someone scanning for Remote Desktop Protocol (RDP)
                if pkt.sport == 3389 or pkt.dport == 3389:
                    raise_alert("RDP scan", pkt[IP].src, pkt.sport, payload)
                # Someone scanning for Virtual Network Computing (VNC) instance(s)
                if pkt.sport in [5900, 5901, 5902, 5903] or pkt.dport in [5900, 5901, 5902, 5903]:
                    raise_alert("VNC scan", pkt[IP].src, pkt.sport, payload)
                if pkt.haslayer(Raw):
                    data = pkt[Raw].load.decode('utf-8', 'ignore')
                    if any(keyword in pkt[Raw].load.decode('utf-8', 'ignore') for keyword in ["SMB", "NETBIOS"]):
                        raise_alert("SMB scan", pkt[IP].src, pkt.sport, pkt[Raw].load)
                    # Usernames and passwords sent in-the-clear via IMAP
                    if 'LOGIN' in data:
                        credentials = data.split('LOGIN ')[1].split('\r\n')[0]
                        raise_alert("Usernames and passwords sent in-the-clear", pkt[IP].src, "IMAP", credentials)
                    # Usernames and passwords sent in-the-clear via FTP
                    if 'USER ' in data and 'PASS ' in data: 
                        credentials = data.split('LOGIN ')[1].split('\r\n')[0]
                        raise_alert("Usernames and passwords sent in-the-clear", pkt[IP].src, "FTP", credentials)
                    # Usernames and passwords sent in-the-clear via HTTP Basic Authentication
                    if 'Authorization: Basic' in data:
                        credentials = data.split('LOGIN ')[1].split('\r\n')[0]
                        raise_alert("Usernames and passwords sent in-the-clear", pkt[IP].src, "HTTP", credentials)
                    # Someone scanning for Remote Desktop Protocol (RDP)
                    if any(keyword in data for keyword in ["RDP", "MS-TSGU"]):
                        raise_alert("RDP scan", pkt[IP].src, pkt.sport, pkt[Raw].load)
                    # Nikto scan
                    if b'User-Agent: Mozilla/5.00 (Nikto' in pkt[Raw].load:
                        raise_alert("Nikto scan", pkt[IP].src, "HTTP", pkt[Raw].load)
    except Exception as e:
        # Uncomment the below and comment out `pass` for debugging, find error(s)
        # print(e)
        pass

def raise_alert(incident, sourceIP, protocol, payload):
    global incidentNum
    print(f"{incidentNum}: {incident} is detected from {sourceIP} ({protocol}) ({payload})!")
    incidentNum += 1

# DO NOT MODIFY THE CODE BELOW
parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
    try:
        print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
        sniff(offline=args.pcapfile, prn=packetcallback)    
    except:
        print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
    print("Sniffing on %(interface)s... " % {"interface" : args.interface})
    try:
        sniff(iface=args.interface, prn=packetcallback)
    except:
        print("Sorry, can\'t read network traffic. Are you root?")  