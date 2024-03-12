#include <rte_mbuf_core.h>

#include "headers.h"
#include <stdio.h>

const int PORT_IGNORE_PACKET = -1; // Packet is dropped
const int PORT_BROADCAST = 3;      // Packet is sent to all ports except incoming one
const int PORT_TO_HOST = 2;        // Packet is sent to port 2 (towards host)
const int PORT_RING_FORWARD = 1;   // Packet is sent to port 1 if recieved on port 0 and vice versa

const int CONFIGURED_IP = 8;     // Last decimal of IPv4 address, e.g. 10.0.0.4

// #define LOG printf
#define LOG

void push_batch(int port, struct rte_mbuf* batch[BURST_SIZE], size_t num_rx);

/**
 * Prints out the given IP address to the LOG
 * @param addr The IP address, where each decimal is packet as a byte in the 32bit integer. Can be obtained e.g. via ip_hdr->src_addr
 */
void print_ip(unsigned int ip)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;   
    LOG("%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);        
}

/**
 * Prints out the given MAC address to the LOG.
 * @param addr The MAC address as byte array, with fixed length of 6. Can be obtained e.g. via eth_hdr->src_addr.addr_bytes
 */
void print_mac(uint8_t addr[])
{
  LOG("%02x:%02x:%02x:%02x:%02x:%02x",
  (unsigned char) addr[0],
  (unsigned char) addr[1],
  (unsigned char) addr[2],
  (unsigned char) addr[3],
  (unsigned char) addr[4],
  (unsigned char) addr[5]);
}

/**
 * Moves the pointer p by n bytes.
 * E.g if you want to get the ICMP header and have the start of the IPv4 Header:
 * <code>
 *   size_t size_of_ipv4_header = sizeof(struct rte_ipv4_hdr);
 *   void* next_header = move_pointer_by_n_bytes(pointerToFirstByteInIPv4Header,
 * size_of_ipv4_header); struct rte_icmp_hdr* = (struct rte_icmp_hdr*)
 * next_header;
 * </code>
 *
 * @param p the original pointer
 * @param num_bytes number of bytes the pointer should move forward
 * @return the new address
 */
void *move_pointer_by_n_bytes(void *p, size_t num_bytes) {
  return ((char *)p) + num_bytes;
}


int run_ipv4(int inPort, char* pointerToFirstByteInIPv4Header) {
	struct rte_ipv4_hdr* ipHeader = (struct rte_ipv4_hdr*) pointerToFirstByteInIPv4Header;
	rte_be32_t dst_addr = __bswap_32(ipHeader->dst_addr);
	
	void* tcpFrame = move_pointer_by_n_bytes(pointerToFirstByteInIPv4Header, sizeof(struct rte_ipv4_hdr));
	struct rte_tcp_hdr* header = (struct rte_tcp_hdr*) tcpFrame;
	
	rte_be32_t cmp_dst_addr = dst_addr - 0xa000000;
	
	if (cmp_dst_addr == CONFIGURED_IP) {
		return 2;
	} else if (inPort == 2) {
		return PORT_BROADCAST;
	} else if (inPort == 0) {
		return 1;
	} else if (inPort == 1) {
		return 0;
	}
}

/**
 * @brief Receives a batch of packets from the interfaces
 * @param port the source port the packets came from
 * @param batch the packets
 * @param num_rx number of packets in batch
 */
void push_batch(int port, struct rte_mbuf* batch[BURST_SIZE], size_t num_rx)
{
  for(unsigned int i=0; i<num_rx; ++i) {
    struct rte_ether_hdr* eth_hdr = rte_pktmbuf_mtod(batch[i], struct rte_ether_hdr*);
    
    // TODO: Implement your forwarding logic here
    int dst_port = PORT_IGNORE_PACKET;
    dst_port = -1;
    if(__bswap_16(eth_hdr->ether_type) == RTE_ETHER_TYPE_IPV4) {
  
    		dst_port = run_ipv4(port, ((char*)eth_hdr + sizeof(struct rte_ether_hdr)));
    		if (dst_port == PORT_BROADCAST) {
    			int portid;
	    		rte_mbuf_refcnt_set(batch[i], 2);
	    		RTE_ETH_FOREACH_DEV(portid) {
	    			if (portid != port) {
	    				rte_eth_tx_burst(portid, 0, &batch[i], 1);
	    			}
	    		}
	    		break;
    		}
    		rte_eth_tx_burst(dst_port, 0, &batch[i], 1);
    }		
    else if(__bswap_16(eth_hdr->ether_type) == RTE_ETHER_TYPE_ARP){    	
    		int portid;
    		rte_mbuf_refcnt_set(batch[i], 2);
    		RTE_ETH_FOREACH_DEV(portid) {
    			if (portid != port) {
    				rte_eth_tx_burst(portid, 0, &batch[i], 1);
    			}
    		}
    }
    }
  
}


