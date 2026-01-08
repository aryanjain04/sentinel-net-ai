from scapy.all import IP, TCP, UDP, wrpcap


packets = []


for i in range(5):
    pkt = IP(src="192.168.1.10", dst="10.0.0.5") / TCP(sport=1234+i, dport=80, flags="S")
    packets.append(pkt)


for i in range(5):
    pkt = IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=53, dport=53)
    packets.append(pkt)


wrpcap("sample.pcap", packets)
print("Successfully created sample.pcap with 10 packets.")