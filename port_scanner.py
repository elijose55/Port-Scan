#!/usr/bin/env python
import socket
import subprocess
import sys
from datetime import datetime

import argparse
from scapy.all import *
from tabulate import tabulate

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


args = parser.parse_args()

remoteServer = args.target
remoteServerIP  = socket.gethostbyname(remoteServer)

portList = args.port

# Print a nice banner with information on which host we are about to scan
print("-" * 60)
print("Please wait, scanning remote host", remoteServer)
print("-" * 60)

# Check what time the scan started
t1 = datetime.now()


if(args.udp):
    try:
        openPorts = []
        found = False
        for port in portList:
            print(tabulate(openPorts, headers=["PORT", "STATE", "SERVICE"]))
            try:

                pkt = sr1(IP(dst=remoteServer)/UDP(sport=port, dport=port), timeout=10)

                if pkt == None:
                    openPorts.append((str(port)+'/udp', "open / filtered", ""))
                    found = True
                else:
                    if pkt.haslayer(ICMP):
                        pass

                    elif pkt.haslayer(UDP):
                        openPorts.append((str(port)+'/udp', "open / filtered", ""))
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

    if(not found):
        print("No open ports found.")
    else:
        print(tabulate(openPorts, headers=["PORT", "STATE", "SERVICE"]))

    print("\n")
    print('UDP Scanning Completed in: {0} seconds' .format(total.total_seconds()))



elif(args.tcp):
    try:
        openPorts = []
        found = False
        for port in portList:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex((remoteServerIP, port))

                if result == 0:
                    openPorts.append((str(port)+'/tcp', "open", socket.getservbyport(port)))
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

    if(not found):
        print("No open ports found.")
    else:
        print(tabulate(openPorts, headers=["PORT", "STATE", "SERVICE"]))

    print("\n")
    print('TCP Scanning Completed in: {0} seconds' .format(total.total_seconds()))