# Port-Scan
Simple port scanner built using Python, Scapy and Socket. Perfoms TCP and UDP port scan and network scanning using both ping and TCP.

### Requirements

	Python 3+
	Scapy
	Socket
	Ping3

## Usage

	sudo python3 port_scanner.py [-h] [-tcp] [-udp] [-port PORT] [-net] [-net2] target
	
## Example

Scans the network using Ping.
	
	sudo python3 port_scanner.py 192.168.0.0/24 -net



Scans the network using TCP
	
	sudo python3 port_scanner.py 192.168.0.0/24 -net


Scans the target (192.168.0.23) UDP ports from 0 to 50
	
	sudo python3 port_scanner.py 192.168.0.23 -udp -port 0-50


Scans the target (192.168.0.23) TCP ports from 0 to 65535

	sudo python3 port_scanner.py 192.168.0.23



Scans the target (192.168.0.23) TCP port 21

	sudo python3 port_scanner.py 192.168.0.23 -port 21
