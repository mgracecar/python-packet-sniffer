'''
Jesus Linares
Brandon Deen
Mariana Flores
Geoff Lyle

Description:
This Linux and Windows application processes packets in the local network and displays
	the supported protocol's header and data.
Linux has support for link layer whereas Windows has support for network layer.
The header is displayed in the same format(s) wireshark displays them.
'''

import socket, sys, time, platform
from struct import *

# Constants for each header length.
constEthHeaderLength = 14
constARPLength = 28
constIPHeaderLength = 20
constTCPHeaderLength = 20
constUDPHeaderLength = 8
constICMPHeaderLength = 8

# Lists of unpacked packets.
allList = []
arpList = []
icmpList = []
tcpList = []
udpList = []

def eth(packet, begin, end):
	# Get Ethernet header using begin and end.
	ethHeader = packet[begin:end]

	# Unpack the header because it originally in hex.
	# The regular expression helps unpack the header.
	# ! signifies we are unpacking a network endian.
	# 6s signifies we are unpacking a string of size 6 bytes.
	# H signifies we are unpacking an integer of size 2 bytes.
	ethHeaderUnpacked = unpack('!6s6sH', ethHeader)
		
	# The first 6s is 6 bytes and contains the destination address.
	ethDestAddress = ethHeaderUnpacked[0]
	
	# The second 6s is 6 bytes and contains the source address.
	ethSourceAddress = ethHeaderUnpacked[1]
	
	# The first H is 2 bytes and contains the packet length.
	ethType = socket.ntohs(ethHeaderUnpacked[2])
	
	# Properly unpack and format the destination address.
	ethDestAddress = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(ethDestAddress[0]), ord(ethDestAddress[1]), ord(ethDestAddress[2]), ord(ethDestAddress[3]), ord(ethDestAddress[4]), ord(ethDestAddress[5]))
	
	# Properly unpack and format the source address.
	ethSourceAddress = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(ethSourceAddress[0]), ord(ethSourceAddress[1]), ord(ethSourceAddress[2]), ord(ethSourceAddress[3]), ord(ethSourceAddress[4]), ord(ethSourceAddress[5]))
	
	# Print Ethernet Header
	print('\n********************\n** Ethernet (MAC) **\n********************' +
	'\nDestination Address: ' + str(ethDestAddress) +
	'\nSource Address: ' + str(ethSourceAddress) +
	'\nEtherType: ' + str(ethType))
	
	return ethType
	
def arp(packet, begin, end):
	# Get ARP header using begin and end.
	arpHeader = packet[begin:end]
	
	# Unpack the header because it originally in hex.
	# The regular expression helps unpack the header.
	# ! signifies we are unpacking a network endian.
	# H signifies we are unpacking an integer of size 2 bytes.
	# B signifies we are unpacking an integer of size 1 byte.
	# 6s signifies we are unpacking a string of size 6 bytes.
	# 4s signifies we are unpacking a string of size 4 bytes.
	arpHeaderUnpacked = unpack("!HHBBH6s4s6s4s", arpHeader)
	
	# The first H is 2 bytes and contains the hardware type.
	arpHardwareType = socket.ntohs(arpHeaderUnpacked[0])
	
	# The second H is 2 bytes and contains the protocol type.
	arpProtocolType = socket.ntohs(arpHeaderUnpacked[1])
	
	# The first B is 1 byte and contains the hardware address length.
	arpHardAddressLength = arpHeaderUnpacked[2]
	
	# The second B is 1 byte and contains the protocol address length.
	arpProtAddressLength = arpHeaderUnpacked[3]
	
	# The third H is 2 bytes and contains the operation.
	arpOperation = arpHeaderUnpacked[4]

	# The first 6s is 6 bytes and contains the sender hardware address.
	arpSenderHardAddress = arpHeaderUnpacked[5]
	
	# The first 4s is 4 bytes and contains the sender protocol address.
	arpSenderProtAddress = socket.inet_ntoa(arpHeaderUnpacked[6])
	
	# The second 6s is 6 bytes and contains the target hardware address.
	arpTargetHardAddress = arpHeaderUnpacked[7]
	
	# The second 4s is 4 bytes and contains the target protocol address.
	arpTargetProtAddress = socket.inet_ntoa(arpHeaderUnpacked[8])
	
	# Properly unpack and format the source MAC address.
	arpSenderHardAddress = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(arpSenderHardAddress[0]), ord(arpSenderHardAddress[1]), ord(arpSenderHardAddress[2]), ord(arpSenderHardAddress[3]), ord(arpSenderHardAddress[4]), ord(arpSenderHardAddress[5]))
	
	# Properly unpack and format the destination MAC address.
	arpTargetHardAddress = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(arpTargetHardAddress[0]), ord(arpTargetHardAddress[1]), ord(arpTargetHardAddress[2]), ord(arpTargetHardAddress[3]), ord(arpTargetHardAddress[4]), ord(arpTargetHardAddress[5]))
	
	# Print Arp Header
	print('\n*******************\n******* ARP *******\n*******************' +
		'\nHardware Type: ' + str(arpHardwareType) +
		'\nProtocol Type: ' + str(arpProtocolType) +
		'\nHardware Address Length: ' + str(arpHardAddressLength) +
		'\nProtocol Address Length: ' + str(arpProtAddressLength) +
		'\nOperation: ' + str(arpOperation) + 
		'\nSender Hardware Address: ' + str(arpSenderHardAddress) +
		'\nSender Protocol Address: ' + str(arpSenderProtAddress) +
		'\nTarget Hardware Address: ' + str(arpTargetHardAddress) +
		'\nTarget Protocol Address: ' + str(arpTargetProtAddress))

def ip(packet, begin, end):
	# Get IP header using begin and end.	
	ipHeader = packet[begin:end]

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
	print('\n********************\n******** IP ********\n********************' + 
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
	
	return ipProtocol

def icmp(packet, begin, end):
	# Get ICMP header using begin and end.
	icmpHeader = packet[begin:end]

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
		print('\n********************\n******* ICMP *******\n********************' +
			'\nType: ' + str(icmpType) +
			'\nCode: ' + str(icmpCode) + 
			'\nChecksum: ' + format(icmpChecksum, '#04X') + 
			'\nIdentifier: ' + str(icmpIdentifier) +
			'\nSequence Number: ' + str(icmpSeqNumber))
	# If not, just print out everything but the last L.
	else:
		print('\n********************\n******* ICMP *******\n********************' +
			'\nType: ' + str(icmpType) +
			'\nCode: ' + str(icmpCode) + 
			'\nChecksum: ' + format(icmpChecksum, '#04X'))
	
def tcp(packet, begin, end):
	# Get TCP header using begin and end.
	tcpHeader = packet[begin:end]

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
	print('\n*******************\n******* TCP *******\n*******************' +
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

def udp(packet, begin, end):
	# Get UDP header using begin and end.
	udpHeader = packet[begin:end]

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
	print('\n*******************\n******* UDP *******\n*******************' +
	'\nSource Port: ' + str(udpSourcePort) +
	'\nDestination Port: ' + str(udpDestPort) +
	'\nLength: ' + str(udpLength) + ' bytes' +
	'\nChecksum: ' + format(udpChecksum, '#04X'))
	
def linuxUnpack(packet, sniff):
	# Unpack the Ethernet (MAC) information.
	begin = 0
	end = constEthHeaderLength
	ethProtocol = eth(packet, begin, end)

	# Find if the Ethernet frame is ARP or IP.
	begin = constEthHeaderLength
	protocol = ''
	if ethProtocol == 1544:
		# Unpack the ARP information.
		end = begin + constARPLength
		arp(packet, begin, end)
		protocol = 'arp'
	elif ethProtocol == 8:
		# Unpack the IP information.
		end = begin + constIPHeaderLength
		ipProtocol = ip(packet, begin, end)
		
		# If the protocol is 1, meaning ICMP, then unpack the ICMP information.
		# If the protocol is 6, meaning TCP, then unpack the TCP information.
		# If the protocol is 17, meaning UDP, then unpack the UDP information.
		begin = constEthHeaderLength + constIPHeaderLength
		if ipProtocol == 1:
			end = begin + constICMPHeaderLength
			icmp(packet, begin, end)
			protocol = 'icmp'
		elif ipProtocol == 6:
			end = begin + constTCPHeaderLength
			tcp(packet, begin, end)
			protocol = 'tcp'
		elif ipProtocol == 17:
			end = begin + constUDPHeaderLength
			udp(packet, begin, end)
			protocol = 'udp'
			
	# Separator	
	print('\n----------------------------------------')	
		
	# If the sniff key is 0, save the packets accordingly.
	# If sniff key is not 0, do not save the packets.
	if sniff == 0:
		if protocol == 'arp':
			allList.append(packet)
			arpList.append(packet)
		elif protocol == 'icmp':
			allList.append(packet)
			icmpList.append(packet)				
		elif protocol == 'tcp':
			allList.append(packet)
			tcpList.append(packet)				
		elif protocol == 'udp':
			allList.append(packet)
			udpList.append(packet)

def windowsUnpack(packet, sniff):
	# Unpack the IP information.
	begin = 0
	end = constIPHeaderLength
	ipProtocol = ip(packet, begin, end)
	
	# If the protocol is 1, meaning ICMP, then unpack the ICMP information.
	# If the protocol is 6, meaning TCP, then unpack the TCP information.
	# If the protocol is 17, meaning UDP, then unpack the UDP information.
	begin = constIPHeaderLength
	protocol = ''
	if ipProtocol == 1:
		end = begin + constICMPHeaderLength
		icmp(packet, begin, end)
		protocol = 'icmp'
	elif ipProtocol == 6:
		end = begin + constTCPHeaderLength
		tcp(packet, begin, end)
		protocol = 'tcp'
	elif ipProtocol == 17:
		end = begin + constUDPHeaderLength
		udp(packet, begin, end)
		protocol = 'udp'
		
	# Separator	
	print('\n----------------------------------------')	
	
	# If the sniff key is 0, save the packets accordingly.
	# If sniff key is not 0, do not save the packets.
	if sniff == 0:
		if protocol == 'icmp':
			icmpList.append(packet)				
		elif protocol == 'tcp':
			tcpList.append(packet)				
		elif protocol == 'udp':
			udpList.append(packet)
		allList.append(packet)

def linuxFilter():
	while True:
		# Display filtering options.
		# Repeated if incorrect input.
		decision = raw_input('All: 0\nARP: 1\nICMP: 2\nTCP: 3\nUDP: 4\nCancel: C\nSelection: ')
			
		# Separator
		print('')

		# Filter based on input, if input is not supported, notify user.
		# If no protocols of certain type were filtered, notify user.
		# If user chooses cancel option, break while loop.
		if decision == '0':
			length = len(allList)
			if length > 0:
				for i in range(length):
					packet = allList[i]
					linuxUnpack(packet, sniff)
			else:
				print('No protocols of this type were sniffed.')
		elif decision == '1':
			length = len(arpList)
			if length > 0:
				for i in range(length):
					packet = arpList[i]
					linuxUnpack(packet, sniff)
			else:
				print('No protocols of this type were sniffed.')
		elif decision == '2':
			length = len(icmpList)
			if length > 0:
				for i in range(length):
					packet = icmpList[i]
					linuxUnpack(packet, sniff)
			else:
				print('No protocols of this type were sniffed.')
		elif decision == '3':
			length = len(tcpList)
			if length > 0:
				for i in range(length):
					packet = tcpList[i]
					linuxUnpack(packet, sniff)
			else:
				print('No protocols of this type were sniffed.')
		elif decision == '4':
			length = len(udpList)
			if length > 0:
				for i in range(length):
					packet = udpList[i]
					linuxUnpack(packet, sniff)
			else:
				print('No protocols of this type were sniffed.')
		elif (decision == 'C') or (decision == 'c'):
			print('Filtering stopped...')
			break
		else:
			print('Unsupported input, try again...')

def windowsFilter():
	while True:
		# Display filtering options.
		# Repeated if incorrect input.
		decision = raw_input('All: 0\nICMP: 2\nTCP: 3\nUDP: 4\nCancel: C\nSelection: ')
					
		# Separator
		print('')
	
		# Filter based on input, if input is not supported, notify user.
		# If no protocols of certain type were filtered, notify user.
		# If user chooses cancel option, break while loop.
		if decision == '0':
			length = len(allList)
			if length > 0:
				for i in range(length):
					packet = allList[i]
					windowsUnpack(packet, sniff)
			else:
				print('No protocols of this type were sniffed.')
		elif decision == '2':
			length = len(icmpList)
			if length > 0:
				for i in range(length):
					packet = icmpList[i]
					windowsUnpack(packet, sniff)
			else:
				print('No protocols of this type were sniffed.')
		elif decision == '3':
			length = len(tcpList)
			if length > 0:
				for i in range(length):
					packet = tcpList[i]
					windowsUnpack(packet, sniff)
			else:
				print('No protocols of this type were sniffed.')
		elif decision == '4':
			length = len(udpList)
			if length > 0:
				for i in range(length):
					packet = udpList[i]
					windowsUnpack(packet, sniff)
			else:
				print('No protocols of this type were sniffed.')
		elif (decision == 'C') or (decision == 'c'):
			print('Filtering stopped...')
			break
		else:
			print('Unsupported input, try again...')

def startSniff():
	while True:
		# Ask the user if they would like to begin the sniffer or not.
		decision = raw_input('Hello, would you like to sniff the network? Y/N: ')
		
		# Y runs the rest of the application.
		# N exits the application.
		if (decision == 'Y') or (decision == 'y'):
			print('Sniffing, press Ctrl+c to cancel...')
			break
		elif (decision == 'N') or (decision == 'n'):
			close()
		else:
			print('Unsupported input...')
	

def startFilter():
	while True:
		# Ask the user if they would like to filter the packets or not.
		decision = raw_input('Would you like to filter the sniffed packets by protocol? Y/N: ')

		# Y runs the rest of the application.
		# N exits the application.
		if (decision == 'Y') or (decision == 'y'):
			print('Select a protocol...')
			break
		elif (decision == 'N') or (decision == 'n'):
			close()
		else:
			print('Unsupported input...')

def close():
	# Exit the application.
	print('Goodbye.')
	time.sleep(1)
	sys.exit()

def sniff():
	try:
		# Ask the user to begin.
		startSniff()
	except KeyboardInterrupt:
		print('\nApplication cancelled')
		close()
		
	try:
		# Know what platform the application is running on.
		os = platform.system()
	
		# A sniff key of 0 means the application is sniffing and packets must be saved.
		sniff = 0
		
		# If Linux, set up the raw socket the Linux way.
		# If Windows, set up the raw socket the Windows way.
		# If not Linux or Windows, close the application.
		if os == 'Linux':
			# Create the raw socket.
			sock = socket.socket(socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
			
			# Sniff packets. Will loop until user presses Ctrl+c.
			while True:	
				# Recieve the packets in the network.
				# Packet will be a tuple, use the first element in the tuple.
				packet = sock.recvfrom(65565)
				packet = packet[0]				
				
				linuxUnpack(packet, sniff)
				
			# Close the socket.
			sock.close()
		elif os == 'Windows':
			# The public network interface.
			HOST = socket.gethostbyname(socket.gethostname())

			# Create a raw socket and bind it to the public interface.
			sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
			sock.bind((HOST, 0))

			# Include IP headers
			sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

			# Receive all packages.
			sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
			
			# Sniff packets. Will loop until user presses Ctrl+c.
			while True:	
				# Recieve the packets in the network.
				# Packet will be a tuple, use the first element in the tuple.
				packet = sock.recvfrom(65565)
				packet = packet[0]
					
				windowsUnpack(packet, sniff)	
				
			# Disable promiscuous mode.	
			sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
			
			# Close the socket.
			sock.close()
		else:
			print('The OS you are running is not supported.')
			close()   				
	except socket.error, msg:
		print('Socket could not be created. \nError code: ' + str(msg[0]) + '\nMessage: ' + msg[1])
		close()
	except KeyboardInterrupt:
		print "\nSniffing stopped."
	
	try:
		# Ask the user to filter.
		startFilter()

		# A sniff key of 1 means the application is not sniffing and packets must not be saved.
		sniff = 1
	
		# If Linux, filter Linux's supported protocols.
		# If Windows, filter Window's supported protocols.
		if os == 'Linux':
			linuxFilter()
		elif os == 'Windows':
			windowsFilter()
	except KeyboardInterrupt:
		print "\nApplication cancelled."
		close()
	
	close()  

def main():
	sniff()

if __name__ == "__main__":
	main()
