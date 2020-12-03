import dpkt
import datetime
import socket
import virustotal
import operator

counter = 0
icmpcounter = 0
tcpcounter = 0
udpcounter = 0
arpcounter = 0
all_path = []
src_list = []
filename = 'test.pcap'

for ts, pkt in dpkt.pcap.Reader(open(filename, 'rb')):
    counter += 1
    eth = dpkt.ethernet.Ethernet(pkt)
    if eth.type != dpkt.ethernet.ETH_TYPE_IP:
        continue

    ip = eth.data

    all_path.append("src: "+socket.inet_ntoa(ip.src)+" -> dst: "+socket.inet_ntoa(ip.dst))
    src_list.append(socket.inet_ntoa(ip.src))
    if ip.p == dpkt.ip.IP_PROTO_TCP:
        tcpcounter += 1

    if ip.p == dpkt.ip.IP_PROTO_UDP:
        udpcounter += 1

    if ip.p == dpkt.arp:
        arpcounter += 1

    if ip.p == dpkt.ip.IP_PROTO_ICMP and len(pkt)>1050:
        icmpcounter += 1
        if icmpcounter == 1:
            stime = ts

        else:
            ltime = ts

path_dict = {}
for path in set(all_path):
    path_dict[path] = all_path.count(path)

src_list = list(set(src_list))
path_dict = sorted(path_dict.items(), key=operator.itemgetter(1) ,reverse=True)

print("Total number of packets in the pcap file: ", counter)
print("Total number of tcp packets:", tcpcounter)
print("Total number of udp packets:", udpcounter)
print("Total number of icmp packets: ", icmpcounter)
print("icmp flooding 시작 시간:",str(datetime.datetime.utcfromtimestamp(stime)))
print("icmp flooding 종료 시간:",str(datetime.datetime.utcfromtimestamp(ltime)))
print("duration:",(datetime.datetime.utcfromtimestamp(ltime)-datetime.datetime.utcfromtimestamp(stime)).seconds)
print("cps:", icmpcounter/(datetime.datetime.utcfromtimestamp(ltime)-datetime.datetime.utcfromtimestamp(stime)).seconds)
print("------------------------------------------------")

for i in path_dict:
    print(i[0], " 횟수:", i[1])


ip = path_dict[0][0]
for i in src_list:
    if ip.find(i) != -1:
        virustotal.open_web(i)
