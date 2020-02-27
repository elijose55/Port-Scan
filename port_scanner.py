#!/usr/bin/env python
import socket
import subprocess
import sys
from datetime import datetime

import argparse
from scapy.all import *
from tabulate import tabulate
from ipaddress import ip_network, ip_address
import sys

from ping3 import ping, verbose_ping

def parseNumList(string):
    try:
        m = string.split('-')
        if not m:
            raise ArgumentTypeError("'" + string + "' is not a range of number. Expected forms like '0-65535' or '5000'.")

        if(len(m) == 2):
            start = m[0]
            end = m[1]
        elif(len(m) == 1):
            start = m[0]
            end = start
        return list(range(int(start,10), int(end,10)+1))
    except:
        raise ArgumentTypeError("'" + string + "' is not a range of number. Expected forms like '0-65535' or '5000'.")


def udp_scan(portList, remoteServer):
    try:
        openPorts = []
        found = False
        for port in portList:
            try:
                port_service = socket.getservbyport(port, 'udp')
            except:
                port_service = 'Unknown'
                pass
            try:
                pkt = sr1(IP(dst=remoteServer)/UDP(sport=port, dport=port), timeout=2, verbose = 0)
                if pkt == None:
                    openPorts.append((str(port)+'/udp', "open / filtered", port_service))
                    found = True
                else:
                    if pkt.haslayer(ICMP):
                        pass

                    elif pkt.haslayer(UDP):
                        openPorts.append((str(port)+'/udp', "open / filtered", port_service))
                        found = True

            except Exception as e:
                print(e)
                sys.exit()

    except KeyboardInterrupt:
        print("You pressed Ctrl+C")
        sys.exit()

    except Exception as e:
        print(e)
        sys.exit()


    # Checking the time again
    t2 = datetime.now()

    # Calculates the difference of time, to see how long it took to run the script
    total =  t2 - t1

    return openPorts, total, found


def tcp_scan(portList, remoteServer):
    try:
        openPorts = []
        found = False
        for port in portList:
            try:
                port_service = socket.getservbyport(port, 'tcp')
            except:
                port_service = 'Unknown'
                pass
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex((remoteServer, port))

                if result == 0:
                    openPorts.append((str(port)+'/tcp', "open", port_service))
                    found = True
                sock.close()

            except socket.error:
                print("**Couldn't connect to port:", port)
                continue

    except KeyboardInterrupt:
        print("You pressed Ctrl+C")
        sys.exit()

    except socket.gaierror:
        print('Hostname could not be resolved. Exiting')
        sys.exit()

    # Checking the time again
    t2 = datetime.now()

    # Calculates the difference of time, to see how long it took to run the script
    total =  t2 - t1

    return openPorts, total, found 


def fast_scan(addr, port):
    socket_obj = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    socket.setdefaulttimeout(0.01)
    result = socket_obj.connect_ex((addr,port))
    socket_obj.close()
    if result == 0:
        return True
    else:
        return False

def ip_range(addr):
    a = ip_network(addr)
    return [ip.exploded for ip in a]


parser = argparse.ArgumentParser(description='Simple Port Scanner by Eli')

parser.add_argument('target',
                       metavar='target',
                       type=str,
                       help='Specify target host to be scanned')

parser.add_argument('-tcp', dest='tcp', action='store_true', default=True,
                    help='Flag to select TCP Protocol (default = tcp)')

parser.add_argument('-udp', dest='udp', action='store_true',
                    help='Flag to select UDP Protocol (default = tcp)')

parser.add_argument('-port', type=parseNumList, default='0-65535',
                    help='Port range to scan (default = 0-65535). Expected forms like 0-65535 or 5000')

parser.add_argument('-net', dest='net', action='store_true', default=False,
                    help='Flag to perfom network scan using ping (default = False)')

parser.add_argument('-net2', dest='net', action='store_true', default=False,
                    help='Flag to perfom network scan using TCP port scan (default = False)')


args = parser.parse_args()
target = args.target
portList = args.port

if(not args.net):
    remoteServerIP  = socket.gethostbyname(target)

    # Print a nice banner with information on which host we are about to scan
    print("-" * 60)
    print("Please wait, scanning remote host", target)
    print("-" * 60)

    # Check what time the scan started
    t1 = datetime.now()


    if(args.udp):
        openPorts, total, found = udp_scan(portList, target)

    elif(args.tcp):
        openPorts, total, found = tcp_scan(portList, remoteServerIP)


    if(not found):
        print("No open ports found.")
    else:
        print(tabulate(openPorts, headers=["PORT", "STATE", "SERVICE"]))

    print("\n")
    print('Scanning Completed in: {0} seconds' .format(total.total_seconds()))

else:

    # Print a nice banner with information on which host we are about to scan
    print("-" * 60)
    print("Please wait, scanning network:", target)
    print("-" * 60)

    # Check what time the scan started
    t1 = datetime.now()

    addr_list = ip_range(target)
    active_addr = []

    portList = [20, 53, 110, 143, 445, 548, 631, 21, 22, 23, 25, 80, 111, 443, 631, 993, 995, 135, 137, 138, 139, 49152, 62078, 1723, 8080, 5000, 8000]

    
    

    if(args.net):
        for addr in addr_list[1:-1]:
            r = ping(addr, timeout=0.05)
            if (r != None and r != False):
                active_addr.append(str(addr))
    elif(args.net2):
        for addr in addr_list:
            for port in portList:
                    if(fast_scan(addr, port)):
                        active_addr.append(str(addr))
                        print(addr)
                        break



    

    # Checking the time again
    t2 = datetime.now()

    # Calculates the difference of time, to see how long it took to run the script
    total =  t2 - t1
    for a in active_addr:
        print(a)
    print('Scanning Completed in: {0} seconds' .format(total.total_seconds()))


