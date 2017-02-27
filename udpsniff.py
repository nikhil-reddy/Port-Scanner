#! /usr/bin/env python

from scapy.all import *

openports= []
closeports= []


ans,unans=sr(IP(dst="10.10.111.1")/UDP(dport=(0,100)), inter=0.5, retry=10,timeout=1)
	

print "Closed ports"
ans.filter(lambda(s,r):ICMP in r).make_table(lambda(s,r):
	(s.dst,s.dport,"close"))

print "Open ports"
for x in unans:
	print str(x[UDP].dport) + "  open"



