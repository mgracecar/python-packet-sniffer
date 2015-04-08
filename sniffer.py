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

# Ask the user if they would like to begin the sniffer or not.
decision = raw_input('Hello, would you like to sniff the network? Y or N: ')

# Y runs the rest of the application.
# N exits the application.
if (decision == 'Y') or (decision == 'y'):
	print('Sniffing...\n')
	pass
elif (decision == 'N') or (decision == 'n'):
	print('Goodbye.')
	sys.exit()

# Constants for each header length.
constIPHeaderLength = 20
constTCPHeaderLength = 20
constUDPHeaderLength = 8

# Counter to limit how much the while loop runs.
counter = 0

# The public network interface.
HOST = socket.gethostbyname(socket.gethostname())

# Create a raw socket and bind it to the public interface.
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
s.bind((HOST, 0))

# Include IP headers.
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# Receive all packages.
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# While loop is coupled with counter and runs until counter reaches its limit.
while True:
	
	# Recieve the packets in the network.
	# Packet will be a tuple, use the first element in the tuple.
	packet = s.recvfrom(65565)
	packet = packet[0]

	# The IP header is 20 bytes, make ipHeader a list of packet's elements 0 up to 20.	
	ipHeader = packet[:constIPHeaderLength]

	# Unpack the header because it originally in hex.
	# The regular expression helps unpack the header.
	# ! signifies we are unpacking a network endian.
	# B signifies we are unpacking an integer of size 1 byte.
	# H signifies we are unpacking an integer of size 2 bytes.
	# 4s signifies we are unpacking a string of size 4 bytes.
	ipHeaderUnpacked = unpack('!BBHHHBBH4s4s' , ipHeader)

	# Do the protocol first in order to continue or to find another packet that is supported.
	# Our fourth B is 1 byte and contains the protocol.
	ipProtocol = ipHeaderUnpacked[6]
	
	# If the protocol is not supported, continue to the beginning of the while loop
	#	and sniff another packet.
	# If the protocol is supported, the resume to unpack the IP Header and
	#	unpack the corresponding protocol's header.
	if (int(ipProtocol) != 8) and (int(ipProtocol) != 17):
		continue
	
	# The first B is 1 byte and contains the version and header length.
	# Both are 4 bits each, split ipHeaderUnpacked[0] in "half".
	ipVersionAndHeaderLength = ipHeaderUnpacked[0]
	ipVersion = ipVersionAndHeaderLength >> 4
	ipHeaderLength = ipVersionAndHeaderLength & 0xF

	# The second B is 1 byte and contains the service type.
	ipDSCPAndECN = ipHeaderUnpacked[1]
	ipDSCP = ipDSCPAndECN >> 2
	ipECN = ipDSCPAndECN & 0xB

	# The first H is 2 bytes and contains the total length.
	ipTotalLength = ipHeaderUnpacked[2]

	# The second H is 2 bytes and contains the total length.
	ipIdentification = ipHeaderUnpacked[3]

	# The third H is 2 bytes and contains the flags and fragment offset.
	# Flags is 3 bits and fragment offset is 13 bits.
	# Split ipHeaderUnpacked[4].
	ipFlagsAndFragmentOffset = ipHeaderUnpacked[4]
	ipFlags = ipFlagsAndFragmentOffset >> 13
	ipFragmentOffset = ipFlagsAndFragmentOffset & 0x102B36211C7

	# The third B is 1 byte and contains the time to live.
	ipTimeToLive = ipHeaderUnpacked[5]

	# The fourth H is 2 bytes and contains the header checksum.
	ipHeaderChecksum = ipHeaderUnpacked[7]

	# The first 4s is 4 bytes and contains the source address.
	ipSourceAddress = socket.inet_ntoa(ipHeaderUnpacked[8]);

	# The second 4s is 4 bytes and contains the dest address.
	ipDestAddress = socket.inet_ntoa(ipHeaderUnpacked[9]);

	# If the protocol is 17, meaning UDP, then unpack UDP.
	if ipProtocol == 17:
		
		# The UDP header is the 8 bytes after the IP Header ends.
		udpHeader = packet[constIPHeaderLength:constIPHeaderLength + constUDPHeaderLength]

		# Unpack the header because it originally in hex.
		# The regular expression helps unpack the header.
		# ! signifies we are unpacking a network endian.
		# H signifies we are unpacking an integer of size 2 bytes.
		udpHeader = unpack('!HHHH' , udpHeader)
		 
		# The first H is 2 bytes and contains the source port.
		udpSourcePort = udpHeader[0]
		
		# The second H is 2 bytes and contains the destination port.
		udpDestPort = udpHeader[1]
		
		# The third H is 2 bytes and contains the packet length.
		udpLength = udpHeader[2]
		
		# The fourth H is 2 bytes and contains the header checksum.
		udpChecksum = udpHeader[3]
					
	# Increment the counter by one because a packet has been sniffed.
	counter = counter + 1
	
	# Print IP Header
	# Some segments of the header are switched back to hex form because that
	# 	is the format wireshark has it.
	print('IP' + 
		'\nVersion: ' + str(ipVersion) +
		'\nHeader Length: ' + str(ipHeaderLength) + ' words' +
		'\nDifferentiated Services Code Point: ' + str(format(ipDSCP, '#04X')) +
		'\nExplicit Congestion Notification: ' + str(format(ipECN, '#04X')) +
		'\nTotal Length: ' + str(ipTotalLength) + ' bytes' + 
		'\nIdentification: ' + str(format(ipIdentification, '#04X')) + ' , ' + str(ipIdentification) +
		'\nFlags: ' + str(format(ipFlags, '#04X')) +
		'\nFragment Offset: ' + str(ipFragmentOffset) + ' eight-byte blocks' +
		'\nTime to Live: ' + str(ipTimeToLive) + ' seconds' +
		'\nProtocol: ' +str(ipProtocol) +
		'\nHeader Checksum: ' +str(format(ipHeaderChecksum, '#04X')) +
		'\nSource Address: ' + str(ipSourceAddress) +
		'\nDestination Address: ' + str(ipDestAddress))
	
	# Spacing.
	print('\n')
	
	print('UDP' +
		'\nSource Port: ' + str(udpSourcePort) +
		'\nDestination Port: ' + str(udpDestPort) +
		'\nLength: ' + str(udpLength) + ' bytes' +
		'\nChecksum: ' + str(format(udpChecksum, '#04X')))

	# Packet separator.
	print('\n----------------------------------------\n')
		
	# Once the counter reaches its limit, ask to sniff the network again.	
	if counter == 5:
		
		# Ask to sniff the network again.	
		again = raw_input('Would you like to sniff the network again? Y or N: ')

		# Y runs the rest of the application.
		# N exits the application.
		if (again == 'Y') or (again == 'y'):
			counter = 0
			print('Sniffing...\n')
			pass
		elif (again == 'N') or (again == 'n'):
			s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
			s.close
			print('Goodbye.')
			sys.exit()
		
# Disable promiscuous mode.
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
s.close()

# Exit the application.
sys.exit()
