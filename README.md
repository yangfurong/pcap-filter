# Pcap-filter For MPTCP measurement
---
##Function:
This tool is used to pre-process MPTCP pcap file, including:
* Filtering packets that don't belong to this MPTCP connection;
* Truncating pcap file that only include packets from MPCAP-SYN to MP-FIN (exclude MP-FIN).

##Build
./build.sh
./configure

##Usage:
pcap-filter -f input-file -o output-file

##Test Env:
Ubuntu14.04 + Linux-3.18.20 (mptcp v0.90)
gcc 4.8.4
