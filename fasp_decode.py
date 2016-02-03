#!/usr/bin/python

counter=0
ipcounter=0
tcpcounter=0
udpcounter=0

filename='fasp.csv.pcap'
uuid = 'a9063e44-f785-4bca-8e71-3eaa20a64b32'
uuid_hex = '61393036336534342d663738352d346263612d386537312d336561613230613634623332'
server_source_port = 33001

import pcap
import dpkt
import socket
import datetime
import binascii
import struct
import string

def ip_to_str(ip_address):
    s = list()
    for i in range(4):
#        print ord(ip_address[i])
        s.append( str(ord(ip_address[i])) )
    r = ".".join(s)    
    return r

#
# Convert a network mac address into a string
#
def eth_ntoa(buffer):
    macaddr = ''
    for intval in struct.unpack('BBBBBB', buffer):
        if intval > 15:
            replacestr = '0x'
        else:
            replacestr = 'x'
        macaddr = ''.join([macaddr, hex(intval).replace(replacestr, '')])
    return macaddr

def add_colons_to_mac( mac_addr_s ) :
    """This function accepts a 12 hex digit string and converts it to a colon separated string"""
    s = list()
    for i in range(12/2) : 	# mac_addr should always be 12 chars, we work in groups of 2 chars
        s.append( mac_addr_s[i*2:i*2+2] )
    r = ":".join(s)		# I know this looks strange, refer to http://docs.python.org/library/stdtypes.html#sequence-types-str-unicode-list-tuple-bytearray-buffer-xrange
    return r

def mac_addr(a):
#    print binascii.hexlify(a)
    return add_colons_to_mac(binascii.hexlify(a) )
    
pc=pcap.pcap(filename)

count=1

pc.setfilter('src host 198.23.89.123 or dst host 198.23.89.123')
for timestamp, buf in pc:

    # Print out the timestamp in UTC
    print 'Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp))

    # Unpack the Ethernet frame (mac src/dst, ethertype)
    eth = dpkt.ethernet.Ethernet(buf)
    print 'Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type

    # Make sure the Ethernet frame contains an IP packet
    # EtherType (IP, ARP, PPPoE, IP6... see http://en.wikipedia.org/wiki/EtherType)
    if eth.type != dpkt.ethernet.ETH_TYPE_IP:
        print 'Non IP Packet type not supported %s\n' % eth.data.__class__.__name__
        continue

    # Now unpack the data within the Ethernet frame (the IP packet)
    # Pulling out src, dst, length, fragment info, TTL, and Protocol
    ip = eth.data

    # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
    do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
    more_fragments = bool(ip.off & dpkt.ip.IP_MF)
    fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

    print "do_not_fragment ", do_not_fragment
    print "more_fragments ", more_fragments 
    print "fragment_offset ", fragment_offset

#          (ip_to_str(ip.src), ip_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset)
    # Print out the info
    print 'IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % \
          (socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset)

    if (ip.p == dpkt.ip.IP_PROTO_UDP):
        udp = ip.data
        print "UDP ports ", udp.sport, "->", udp.dport, "len=", udp.ulen
        if (server_source_port == udp.sport):
            direction = "S->C"
        else:
             direction = "C->S"
#        h1=binascii.hexlify(udp.data[0:67])
        h1=binascii.hexlify(udp.data[0:99])
        print direction, h1.replace(uuid_hex, '<<uuid>>', 1)
#        print "h1[0:4]=", h1[0:4]
        if (h1[0:4].find('0818') == 0):
            print "Block transfer #", h1[4:16]

    if (ip.p == dpkt.ip.IP_PROTO_TCP):
        tcp = ip.data
        try:
            d_service = socket.getservbyport(tcp.dport, 'tcp')
        except socket.error:
            d_service = tcp.dport

        try:
            s_service = socket.getservbyport(tcp.sport, 'tcp')
        except socket.error:
            s_service = tcp.sport

        print "TCP ports ", s_service, "->",  d_service

        fin_flag = ( tcp.flags & dpkt.tcp.TH_FIN ) != 0
        syn_flag = ( tcp.flags & dpkt.tcp.TH_SYN ) != 0
        rst_flag = ( tcp.flags & dpkt.tcp.TH_RST ) != 0
        psh_flag = ( tcp.flags & dpkt.tcp.TH_PUSH) != 0
        ack_flag = ( tcp.flags & dpkt.tcp.TH_ACK ) != 0
        urg_flag = ( tcp.flags & dpkt.tcp.TH_URG ) != 0
        ece_flag = ( tcp.flags & dpkt.tcp.TH_ECE ) != 0
        cwr_flag = ( tcp.flags & dpkt.tcp.TH_CWR ) != 0
# The flags string is really for debugging
        flags = (
            ( "C" if cwr_flag else " " ) +
            ( "E" if ece_flag else " " ) +
            ( "U" if urg_flag else " " ) +
            ( "A" if ack_flag else " " ) +
            ( "P" if psh_flag else " " ) +
            ( "R" if rst_flag else " " ) +
            ( "S" if syn_flag else " " ) +
            ( "F" if fin_flag else " " ) )
        print "flags: ", flags, "\n"

    count=count+1
    if (count > 1000):
        exit()

