'''
Jesus Linares
Brandon Deen
Mariana Flores
Geoff Lyle

To do:
Sniff TCP, UDP, and another protocol.
Sniff more than one packet. Continuously sniffy packets.
Add a begin prompt with directions.
Add an exit key stroke.

Description:
This application processes packets in the local network and displays
	the supported protocol's header.
The header is displayed in the same format(s) wireshark displays them.
More features are to come.
'''

import socket, sys
from struct import *

# Constants for each header length.
constIPHeaderLength = 20

# The public network interface.
HOST = socket.gethostbyname(socket.gethostname())

# Create a raw socket and bind it to the public interface.
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
s.bind((HOST, 0))

# Include IP headers
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# Receive all packages
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# We must recieve the packets in the network.
# Packet will be a tuple, for our purpose we must only use the first 
# 	element in the tuple.
packet = s.recvfrom(65565)
packet = packet[0]

# The IP header is 20 bytes, this means we need make ipHeader a list of 
#	packet's elements 0 up to 20.	
ipHeader = packet[:constIPHeaderLength]

# We must unpack the header because it originally in hex.
# The regular expression helps unpack the header.
# ! signifies we are unpacking a network endian.
# B signifies we are unpacking an integer of size 1 byte.
# H signifies we are unpacking an integer of size 2 bytes.
# 4s signifies we are unpacking a string of size 4 bytes.
ipHeaderUnpacked = unpack('!BBHHHBBH4s4s' , ipHeader)

# Our first B is 1 byte and contains the version and header length.
# Both are 4 bits each, so we must split ipHeaderUnpacked[0] in "half".
ipVersionAndHeaderLength = ipHeaderUnpacked[0]
ipVersion = ipVersionAndHeaderLength >> 4
ipHeaderLength = ipVersionAndHeaderLength & 0xF

# Our second B is 1 byte and contains the service type.
ipDSCPAndECN = ipHeaderUnpacked[1]
ipDSCP = ipDSCPAndECN >> 2
ipECN = ipDSCPAndECN & 0xB

# Our first H is 2 bytes and contains the total length.
ipTotalLength = ipHeaderUnpacked[2]

# Our second H is 2 bytes and contains the total length.
ipIdentification = ipHeaderUnpacked[3]

# Our third H is 2 bytes and contains the flags and fragment offset.
# Flags is 3 bits and fragment offset is 13 bits.
# So we must split ipHeaderUnpacked[4].
ipFlagsAndFragmentOffset = ipHeaderUnpacked[4]
ipFlags = ipFlagsAndFragmentOffset >> 13
ipFragmentOffset = ipFlagsAndFragmentOffset & 0x102B36211C7

# Our third B is 1 byte and contains the time to live.
ipTimeToLive = ipHeaderUnpacked[5]

# Our fourth B is 1 byte and contains the protocol.
ipProtocol = ipHeaderUnpacked[6]

# Our fourth H is 2 bytes and contains the header checksum.
ipHeaderChecksum = ipHeaderUnpacked[7]

# Our first 4s is 4 bytes and contains the source address.
ipSourceAddress = socket.inet_ntoa(ipHeaderUnpacked[8]);

# Our second 4s is 4 bytes and contains the dest address.
ipDestAddress = socket.inet_ntoa(ipHeaderUnpacked[9]);

# Print IP Header
# Some segments of the header are switched back to hex form because that
# 	is the format wireshark has it.
print('\nIP' + 
	'\nVersion: ' + str(ipVersion) +
	'\nHeader Length: ' + str(ipHeaderLength) + ' words' +
	'\nDifferentiated Services Code Point: ' + 
		str(format(ipDSCP, '#04X')) +
	'\nExplicit Congestion Notification: ' +
		str(format(ipECN, '#04X')) +
	'\nTotal Length: ' + str(ipTotalLength) + ' bytes' + 
	'\nIdentification: ' + str(format(ipIdentification, '#04X')) +
		' , ' + str(ipIdentification) +
	'\nFlags: ' + str(format(ipFlags, '#04X')) +
	'\nFragment Offset: ' + str(ipFragmentOffset) +
		' eight-byte blocks' +
	'\nTime to Live: ' + str(ipTimeToLive) + ' seconds' +
	'\nProtocol: ' +str(ipProtocol) +
	'\nHeader Checksum: ' +str(format(ipHeaderChecksum, '#04X')) +
	'\nSource Address: ' + str(ipSourceAddress) +
	'\nDestination Address: ' + str(ipDestAddress))
	
# disabled promiscuous mode
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)


