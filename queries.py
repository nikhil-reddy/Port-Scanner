#! /usr/bin/env python

from scapy.all import *

localiface = 'eth0'
localmac = get_if_hwaddr(localiface)
rawmac = '02:1d:07:00:01:36'
localmacraw = rawmac.replace(':','').decode('hex')

//port 53
answer= sr1(IP(dst="10.10.111.1")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="www.target.com")),verbose =0)

print answer[DNS].summary()


//port 67
ans,unans = sr(IP(dst="10.10.111.1")/UDP(sport=68,dport=67)/BOOTP(chaddr=localmacraw,xid=RandInt())/DHCP(options =[('message-type','discover'),'end']))

print ans.summary()
print unans.summary()


//port 68
ans,unans = sr(IP(dst="10.10.111.1")/UDP(sport=67,dport=68)/BOOTP(chaddr=localmacraw,xid=RandInt())/DHCP(options =[('message-type','open'),'end']))

print ans.summary()
print unans.summary()




