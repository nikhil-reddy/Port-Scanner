#! /usr/bin/env python

from scapy.all import *
ans,unans=sr(IP(dst="10.10.111.1")/TCP(dport=(0,100),flags="S"))
print ("Open Ports:")
ans.filter(lambda(s,r):TCP in r and r[TCP].flags&2).make_table(lambda(s,r):
	(s.dst,s.dport,"open"))
print ("Closed Ports:")
ans.filter(lambda(s,r):TCP in r and not r[TCP].flags&2).make_table(lambda(s,r):
	(s.dst,s.dport,"closed"))
unans.nsummary(lambda(s,r): r.sprintf("%TCP.sport% is filtered." ))


