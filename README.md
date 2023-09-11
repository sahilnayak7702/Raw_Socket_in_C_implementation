Raw Socket in C Implementation
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
This project demonstrates the implementation of a raw socket in C. A raw socket is a type of socket that allows the user to read and write packets at the network layer, bypassing the operating system's networking stack. This can be useful for applications that need to perform low-level network operations, such as packet sniffing or packet injection.
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Authors: Sahil Nayak: 20110119, Chhavi Gautam: 20110046

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
How to implement the repository in your system

1. Install the following dependencies:
   
   libpcap - https://github.com/the-tcpdump-group/libpcap/blob/master/INSTALL.md
   
   gcc - sudo apt install GCC.
   
3. Clone the repository:
   
   git clone https://github.com/sahilnayak7702/Raw_Socket_in_C_implementation.git


4. Compile the C file:
   
   gcc -o pcap_parser pcap_parser.c -lpcap


5. Run the C file:
   
   ./pcap_parser <file_name>.pcap

6. Run .pcap file:

   sudo tcpreplay -i <network_interface> --mbps=<speed> <path_to_pcap_file>

   Disconnect from your wired ethernet connection in your VM, if possible, while replaying the packets using tcpreplay.

8. For reverse DNS lookup run the vi file(dig shell script):

   vi <file_name>


*************************************************************************************************************************************************************

## Further Reading

* [Raw Socket](https://en.wikipedia.org/wiki/Raw_socket)
* [libpcap](https://www.tcpdump.org/)
* [Raw Socket Operations]([https://www.tcpdump.org/](https://docs.google.com/document/d/1z42olU6x9EOZqK7pLIESQqhDs2aKFl18PKx0jgIr390/edit#heading=h.h41uezhi9kbk)https://docs.google.com/document/d/1z42olU6x9EOZqK7pLIESQqhDs2aKFl18PKx0jgIr390/edit#heading=h.h41uezhi9kbk)
