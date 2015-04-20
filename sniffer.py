'''
Jesus Linares
Brandon Deen
Mariana Flores
Geoff Lyle

To do:
Add exceptions for error control.

Description:
This Windows application processes packets in the local network and displays
	the supported protocol's header.
The header is displayed in the same format(s) wireshark displays them.
More features are to come.
'''

import socket, sys, time
from struct import *

# Constants for each header length.
constIPHeaderLength = 20
constTCPHeaderLength = 20
constUDPHeaderLength = 8
constICMPHeaderLength = 8
	
def ip(packet):
	# The IP header is 20 bytes, make ipHeader a list of packet's elements 0 up to 20.	
	ipHeader = packet[:constIPHeaderLength]

	# Unpack the header because it originally in hex.
	# The regular expression helps unpack the header.
	# ! signifies we are unpacking a network endian.
	# B signifies we are unpacking an integer of size 1 byte.
	# H signifies we are unpacking an integer of size 2 bytes.
	# 4s signifies we are unpacking a string of size 4 bytes.
	ipHeaderUnpacked = unpack('!BBHHHBBH4s4s' , ipHeader)
	
	# The first B is 1 byte and contains the version and header length.
	# Both are 4 bits each, split ipHeaderUnpacked[0] in "half".
	ipVersionAndHeaderLength = ipHeaderUnpacked[0]
	ipVersion = ipVersionAndHeaderLength >> 4
	ipHeaderLength = ipVersionAndHeaderLength & 0xF

	# The second B is 1 byte and contains the service type and ECN.
	ipDSCPAndECN = ipHeaderUnpacked[1]
	ipDSCP = ipDSCPAndECN >> 2
	ipECN = ipDSCPAndECN & 0x3

	# The first H is 2 bytes and contains the total length.
	ipTotalLength = ipHeaderUnpacked[2]

	# The second H is 2 bytes and contains the total length.
	ipIdentification = ipHeaderUnpacked[3]

	# The third H is 2 bytes and contains the flags and fragment offset.
	# Flags is 3 bits and fragment offset is 13 bits.
	# Split ipHeaderUnpacked[4].
	ipFlagsAndFragmentOffset = ipHeaderUnpacked[4]
	ipFlags = ipFlagsAndFragmentOffset >> 13
	ipFragmentOffset = ipFlagsAndFragmentOffset & 0x1FFF

	# The third B is 1 byte and contains the time to live.
	ipTimeToLive = ipHeaderUnpacked[5]
	
	# Our fourth B is 1 byte and contains the protocol.
	ipProtocol = ipHeaderUnpacked[6]
	
	# The fourth H is 2 bytes and contains the header checksum.
	ipHeaderChecksum = ipHeaderUnpacked[7]

	# The first 4s is 4 bytes and contains the source address.
	ipSourceAddress = socket.inet_ntoa(ipHeaderUnpacked[8]);

	# The second 4s is 4 bytes and contains the dest address.
	ipDestAddress = socket.inet_ntoa(ipHeaderUnpacked[9]);

	# Print IP Header
	# Some segments of the header are switched back to hex form because that
	# 	is the format wireshark has it.
	print('IP' + 
		'\nVersion: ' + str(ipVersion) +
		'\nHeader Length: ' + str(ipHeaderLength) + ' 32-bit words' +
		'\nDifferentiated Services Code Point: ' + format(ipDSCP, '#04X') + ' , ' + str(ipDSCP) +
		'\nExplicit Congestion Notification: ' + format(ipECN, '#04X') + ' , ' + str(ipECN) +
		'\nTotal Length: ' + str(ipTotalLength) + ' bytes' + 
		'\nIdentification: ' + format(ipIdentification, '#04X') + ' , ' + str(ipIdentification) +
		'\nFlags: ' + format(ipFlags, '#04X') + ' , ' + str(ipFlags) +
		'\nFragment Offset: ' + str(ipFragmentOffset) + ' eight-byte blocks' +
		'\nTime to Live: ' + str(ipTimeToLive) + ' seconds' +
		'\nProtocol: ' + str(ipProtocol) +
		'\nHeader Checksum: ' + format(ipHeaderChecksum, '#04X') + 
		'\nSource Address: ' + str(ipSourceAddress) +
		'\nDestination Address: ' + str(ipDestAddress))
	
	# Spacing between IP header and the protocol's header.
	print('\n')
	
	return ipProtocol

def icmp(packet):
	# The ICMP header is the 8 bytes after the IP Header ends.
	icmpHeader = packet[constIPHeaderLength:constIPHeaderLength + constICMPHeaderLength]

	# Unpack the header because it originally in hex.
	# The regular expression helps unpack the header.
	# ! signifies we are unpacking a network endian.
	# B signifies we are unpacking an integer of size 1 byte.
	# H signifies we are unpacking an integer of size 2 bytes.
	# L signifies we are unpacking a long of size 4 bytes.
	icmpHeaderUnpacked = unpack('!BBHL', icmpHeader)

	# The first B is 1 byte and contains the type.
	icmpType = icmpHeaderUnpacked[0]

	# The second B is 1 byte and contains the code.
	icmpCode = icmpHeaderUnpacked[1]

	# The first H is 2 bytes and contains the checksum.
	icmpChecksum = icmpHeaderUnpacked[2]

	# Check if the type is 1 or 8, if so, unpack the identifier and sequence number.
	if (icmpType == 0) or (icmpType == 8):
		# The first L is 4 bytes and contains the rest of the header.
		icmpIdentifier = icmpHeaderUnpacked[3] >> 16
		icmpSeqNumber = icmpHeaderUnpacked[3] & 0xFFFF
		
		# Print ICMP Header
		# Some segments of the header are switched back to hex form because that
		# 	is the format wireshark has it.
		print('ICMP' +
			'\nType: ' + str(icmpType) +
			'\nCode: ' + str(icmpCode) + 
			'\nChecksum: ' + format(icmpChecksum, '#04X') + 
			'\nIdentifier: ' + str(icmpIdentifier) +
			'\nSequence Number: ' + str(icmpSeqNumber))
	# If not, just print out everything but othe last L.
	else:
		print('ICMP' +
			'\nType: ' + str(icmpType) +
			'\nCode: ' + str(icmpCode) + 
			'\nChecksum: ' + format(icmpChecksum, '#04X'))
			
	# Separator to separate each packet.
	print('\n----------------------------------------\n')

def tcp(packet):
	# The TCP header is the 20 bytes after the IP Header ends.
	tcpHeader = packet[constIPHeaderLength:constIPHeaderLength + constTCPHeaderLength]

	# Unpack the header because it originally in hex.
	# The regular expression helps unpack the header.
	# ! signifies we are unpacking a network endian.
	# H signifies we are unpacking an integer of size 2 bytes.
	# L signifies we are unpacking a long of size 4 bytes.
	# B signifies we are unpacking an integer of size 1 byte.
	tcpHeaderUnpacked = unpack('!HHLLBBHHH', tcpHeader)
	
	# The first H is 2 bytes and contains the source port.
	tcpSourcePort = tcpHeaderUnpacked[0]
	
	# The second H is 2 bytes and contains the destination port.
	tcpDestPort = tcpHeaderUnpacked[1]

	# The first L is 2 bytes and contains the sequence number.
	tcpSeqNumber = tcpHeaderUnpacked[2]
	
	# The second L is 4 bytes and contains the acknowledgement number.
	tcpAckNumber = tcpHeaderUnpacked[3]
	
	# The first B is 1 byte and contains the data offset, reserved bits, and NS flag.
	# Split tcpHeaderUnpacked[4]
	tcpDataOffsetAndReserved = tcpHeaderUnpacked[4]
	tcpDataOffset = tcpDataOffsetAndReserved >> 4
	tcpReserved = (tcpDataOffsetAndReserved >> 1) & 0x7
	tcpNSFlag = tcpDataOffsetAndReserved & 0x1
	
	# The second B is 1 byte and contains the rest of the flags.
	# Split tcpHeaderUnpacked[5].
	tcpRestOfFLags = tcpHeaderUnpacked[5]
	tcpCWRFlag = tcpRestOfFLags >> 7
	tcpECEFlag = (tcpRestOfFLags >> 6) & 0x1
	tcpURGFlag = (tcpRestOfFLags >> 5) & 0x1
	tcpACKFlag = (tcpRestOfFLags >> 4) & 0x1
	tcpPSHFlag = (tcpRestOfFLags >> 3) & 0x1
	tcpRSTFlag = (tcpRestOfFLags >> 2) & 0x1
	tcpSYNFlag = (tcpRestOfFLags >> 1) & 0x1
	tcpFINFlag = tcpRestOfFLags & 0x1
	
	# The third H is 2 bytes and contains the window size.
	tcpWindowSize = tcpHeaderUnpacked[6]
	
	# The fourth H is 2 byte and conntains the checksum.
	tcpChecksum = tcpHeaderUnpacked[7]
	
	# The fifth H is 2 bytes and constains the urgent pointer.
	tcpUrgentPointer = tcpHeaderUnpacked[8]
	
	# Print TCP Header
	# Some segments of the header are switched back to hex form because that
	# 	is the format wireshark has it.
	print('TCP' +
	'\nSource Port: ' + str(tcpSourcePort) +
	'\nDestination Port: ' + str(tcpDestPort) +
	'\nSequence Number: ' + str(tcpSeqNumber) +
	'\nAcknowledgment Number: ' + str(tcpAckNumber) +
	'\nData Offset: ' + str(tcpDataOffset) + ' 32-bit words' +
	'\nReserved: ' + format(tcpReserved, '03b') + '. .... ....'
	'\nNS Flag:  ' + '...' + format(tcpNSFlag, '01b') + ' .... ....' +
	'\nCWR Flag: ' + '.... ' + format(tcpCWRFlag, '01b') + '... ....' +
	'\nECE Flag: ' + '.... .' + format(tcpECEFlag, '01b') + '.. ....' +
	'\nURG Flag: ' + '.... ..' + format(tcpURGFlag, '01b') + '. ....' +
	'\nACK Flag: ' + '.... ...' + format(tcpACKFlag, '01b') + ' ....' +
	'\nPSH Flag: ' + '.... .... ' + format(tcpPSHFlag, '01b') + '...' +
	'\nRST Flag: ' + '.... .... .' + format(tcpRSTFlag, '01b') + '..' +
	'\nSYN Flag: ' + '.... .... ..' + format(tcpSYNFlag, '01b') + '.' +
	'\nFIN Flag: ' + '.... .... ...' + format(tcpFINFlag, '01b') +
	'\nWindow Size: ' + str(tcpWindowSize) + ' bytes' +
	'\nUrgent Pointer: ' + str(tcpUrgentPointer) +
	'\nChecksum: ' + format(tcpChecksum, '#04X'))
	
	# Separator to separate each packet.
	print('\n----------------------------------------\n')

def udp(packet):
	# The UDP header is the 8 bytes after the IP Header ends.
	udpHeader = packet[constIPHeaderLength:constIPHeaderLength	 + constUDPHeaderLength]

	# Unpack the header because it originally in hex.
	# The regular expression helps unpack the header.
	# ! signifies we are unpacking a network endian.
	# H signifies we are unpacking an integer of size 2 bytes.
	udpHeaderUnpacked = unpack('!HHHH', udpHeader)
	 
	# The first H is 2 bytes and contains the source port.
	udpSourcePort = udpHeaderUnpacked[0]
	
	# The second H is 2 bytes and contains the destination port.
	udpDestPort = udpHeaderUnpacked[1]
	
	# The third H is 2 bytes and contains the packet length.
	udpLength = udpHeaderUnpacked[2]
	
	# The fourth H is 2 bytes and contains the header checksum.
	udpChecksum = udpHeaderUnpacked[3]
	
	# Print UDP Header
	print('UDP' +
	'\nSource Port: ' + str(udpSourcePort) +
	'\nDestination Port: ' + str(udpDestPort) +
	'\nLength: ' + str(udpLength) + ' bytes' +
	'\nChecksum: ' + format(udpChecksum, '#04X'))
	
	# Separator to separate each packet.
	print('\n----------------------------------------\n')

def sniff():
	# Ask the user if they would like to begin the sniffer or not.
	decision = raw_input('Hello, would you like to sniff the network? Y/N: ')

	# Y runs the rest of the application.
	if (decision == 'Y') or (decision == 'y'):
		print('Sniffing, press Ctrl+c to cancel...\n')
		pass
	# N exits the application.
	elif (decision == 'N') or (decision == 'n'):
		print('Goodbye.')
		time.sleep(2)
		sys.exit()

	# The public network interface.
	HOST = socket.gethostbyname(socket.gethostname())

	try:
		# Create a raw socket and bind it to the public interface.
		sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
		sock.bind((HOST, 0))

		# Include IP headers
		sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

		# Receive all packages.
		sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
	
		while True:	
			# Recieve the packets in the network.
			# Packet will be a tuple, use the first element in the tuple.
			packet = sock.recvfrom(65565)
			packet = packet[0]
			
			# Unpack the IP information.
			ipProtocol = ip(packet)
			
			# If the protocol is 1, meaning ICMP, then unpack the ICMP information.
			if ipProtocol == 1:
				icmp(packet)
			# If the protocol is 6, meaning TCP, then unpack the TCP information.
			elif ipProtocol == 6:
				tcp(packet)
			# If the protocol is 17, meaning UDP, then unpack the UDP information.
			elif ipProtocol == 17:
				udp(packet)
		
	except socket.error, msg:
		print('Socket could not be created.\nError code: ' + str(msg[0]) + '\nMessage:' + msg[1])
	except KeyboardInterrupt:
		print "Sniffing stopped."
        
	# Disable promiscuous mode.
	sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
	sock.close()

	# Exit the application.
	print('Goodbye.')
	time.sleep(2)
	sys.exit()       

def main():
	sniff()

if __name__ == "__main__":
	main()
'''
- Fix bitwise operation bugs, was giving wrong output.
- Split protocol operations into separate functions/methods
- Continuously sniff packets until user presses Ctrl+c
- Add trys and excepts for socket errors and keyboard interrupts
- Display more protocol information
'''
