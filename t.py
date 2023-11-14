from scapy.all import sniff, IP, TCP, send, Raw

def modify_packet(packet):
    # Check if the packet is a TCP packet and has source port 8080
	if TCP in packet and packet[TCP].sport == 9000:
		print("Original packet: ", packet[TCP].payload)
		# Modify first byte in packet's payload to 0xff
		packet[TCP].payload = Raw(b'\xff' + packet[TCP].payload[1:])
		print("Modified packet: ", packet[TCP].payload)
		# Send the modified packet
		send(packet, verbose=0)


# Replace 'your_interface' with the actual network interface name (e.g., 'eth0', 'wlan0')
network_interface = 'lo'

# Start sniffing for packets in real time, filter by source port
sniff(iface=network_interface, filter="tcp and src port 8080", prn=modify_packet, store=0)
