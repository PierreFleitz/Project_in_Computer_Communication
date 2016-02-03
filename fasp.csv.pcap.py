#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Purpose: To parse pcap output 
#
#
# Output: outputs a spreadsheet in CSV form
#
# Author: Gerald Q. Maguire Jr.
# 2015.08.18
#
#
import dpkt
import pcapy
import socket

client_ip = socket.inet_aton('130.237.209.248')
server_ip = socket.inet_aton('198.23.89.123')

def client_or_server(host_ip):
    if (client_ip == host_ip):
        return 'c'
    elif (server_ip == host_ip):
        return 's'
    else:
        return 'x'

def if_client(host_ip):
    if (client_ip == host_ip):
        return True
    else:
        return False



f = open('dump20150818a-ascp-198.23.89.123.dump')
pcap = dpkt.pcap.Reader(f)

number_source_packets=0

count=0
for ts, buf in pcap:
#    print "time=" + str(ts)
    eth = dpkt.ethernet.Ethernet(buf)
    #check whether IP packets: to consider only IP packets 
    if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
            continue
            #skip if it is not an IP packets 

    ip=eth.data

    if ip.p==dpkt.ip.IP_PROTO_TCP: #Check for TCP packets
           TCP=ip.data 
           #ADD TCP packets Analysis code here
#           print "found TCP packet"
#           print "%s TCP from %s:%s to %s:%s len=%s" % (ts, socket.inet_ntoa(ip.src), TCP.sport, socket.inet_ntoa(ip.dst), TCP.dport, len(TCP.data))
           print "%s TCP from %s:%s to %s:%s len=%s" % (ts, client_or_server(ip.src), TCP.sport, client_or_server(ip.dst), TCP.dport, len(TCP.data))
    elif ip.p==dpkt.ip.IP_PROTO_UDP: #Check for UDP packets
           UDP=ip.data 
           #UDP packets Analysis code here
#           print "found UDP packet"
#           print "%s UDP from %s:%s to %s:%s len=%s" % (ts, socket.inet_ntoa(ip.src), UDP.sport, socket.inet_ntoa(ip.dst), UDP.dport, UDP.ulen)
           print "%s UDP from %s:%s to %s:%s len=%s" % (ts, client_or_server(ip.src), UDP.sport, client_or_server(ip.dst), UDP.dport, UDP.ulen)
           if if_client(ip.src):
               print "%s number_source_packets=%s" % (ts, number_source_packets)
               number_source_packets=0
           else:
               number_source_packets=number_source_packets+1
#    print eth
#    ip = eth.data
#    print dpkt.ip.dst
#    print dir(eth)

#    udp = ip.data


#    if (count > 100):
#        break
#    else:
#        count=count+1
