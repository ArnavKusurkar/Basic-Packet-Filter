# Basic-Packet-Filter
This code sets up a basic packet capture using libpcap in C. It opens a live capture session on network interface en0, compiles a filter to capture all IP packets ("ip"), installs the filter, and then enters a loop to capture and handle packets using the packet_handler function.
