/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

 /*check if the length meet the minimum require*/
  if (len >= sizeof(sr_ethernet_hdr_t))
  {
	  if (ethertype(packet) == ethertype_ip)   /*handle ip packet*/;
	  {
		  handle_ip_packet(sr, packet, len, interface);
	  }
	  else if (ethertype(packet) == ethertype_arp)	 /*handle arp packet*/;
	  {
		  handle_arp_packet(sr, packet, len, interface);
	  }	  
  }

}

void handle_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface){
	/*locate the ip header*/;
	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	/*check if the length meet the minimum require*/
	if (ip_hdr->ip_len < 20)
		return;
	/*verify ip header checksum*/
	uint16 Tip_sum = ip_hdr->sum;
	ip_hdr->sum = 0;
	uint16 Nip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
	if (Nip_sum != Tip_sum)
		return;
	ip_hdr->sum = Tip_sum;
	
	/*check if the destined IP is one of the router's interface*/
	if (sr_get_intf_ip(sr, ip_hdr->ip_dst)){
	/*the packet is destined to the router
	  check whether the packet is a ICMP*/
		if ((ip_hdr->ip_p) == ip_protocol_icmp){
			/*chec if the length meet the minimum require*/
			int minsize_icmp = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
			if (len < minsize_icmp)
				return;
			/*verify ICMP header checksum*/
			sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
			uint16_t Oicmp_sum = icmp_hdr->icmp_sum;
			icmp_hdr->icmp_sum = 0;
			uint16_t Nicmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4));
			icmp_hdr->icmp_sum = Oicmp_sum;
			if (Oicmp_sum != Nicmp_sum)
				return;
			/*send ICMP message back to sender*/
			send_icmp_msg(sr, packet, len, (uint8_t)0, (uint8_t)0);
			}
		else if (1){  /*the packet is tcp or udp, drop it and send ICMP message, type 3, code */
			send_icmp_msg(sr, packet, len, (uint8_t)3, (uint8_t)3);
			}
			
	}
	else{
	/*forward the packet*/
		sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

		/* Decrement TTL and check if TTL bigger than 0*/
		ip_hdr->ip_ttl--;
		if (ip_hdr->ip_ttl <= 0)
		{
			send_icmp_msg(sr, packet, len, (uint8_t)11, (uint8_t)0);
			return;
		}
		
		/*recalculate IP checksum*/
		ip_hdr->sum = 0;
		ip_hdr->sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
		
		struct sr_rt *routetable = longest_matching_prefix_ip(sr, ip_hdr->ip_dst);
		if (!routetable)  /*there is a non-existent route to the destination IP*/
		{
			send_icmp_msg(sr, packet, len, (uint8_t)3, (uint8_t)0);
			return;
		}

		struct sr_if *sending_intf = sr_get_interface(sr, routetable->interface);
		
		/*check ARP cache*/
		struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, routetable->gw.s_addr);
		if (entry == NULL)
			queue_arp_request(sr, packet, len, sending_intf, routetable->gw.s_addr);
		else
			send_packet(sr, packet, len, sending_intf, entry);

	
	}
	
}

/*send ICMP message*/
void send_icmp_msg(struct sr_instance *sr, uint8_t *packet, unsigned int len, uint8_t type, uint8_t code){
	sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	

	/*find the longest prefix match of the IP address*/
	struct sr_rt *routetable = longest_matching_prefix(sr, ip_hdr->ip_src);
	/*get the interface of the route table*/
	struct sr_if *sending_intf = sr_get_interface(sr, routetable->interface);
	
	if (type == 0){   /*the ICMP message is a echo reply*/
		sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
		/*set the ICMP information*/
		icmp_hdr->icmp_type = type; /*echo tpye*/
		icmp_hdr->icmp_code = code;

		icmp_hdr->icmp_sum = 0;
		icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4));
		
		/*set the IP header information*/
		uint32_t temp = ip_hdr->ip_src; /*swap the source and destination address*/
		ip_hdr->ip_src = ip_hdr->ip_dst;
		ip_hdr->ip_dst = temp;

		ip_hdr->ip_sum = 0;/*calculate the IP header's checksum*/
		ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
	
		/*send the ICMP packet*/
		/*check the whether the MAC address in the cache*/
		struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, routetable->gw.s_addr);
		if (entry == NULL)
			queue_arp_request(sr, packet, len, sending_intf, route->gw.s_addr);
		else
			send_packet(sr, packet, len, sending_intf, entry);


	}
	else if ((type == 3) || (type == 11)){     /*Destination unreachable or Time exceeded*/
		
		uint8_t *new_packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));  /*create a new packet*/
		int new_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
		sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *)new_packet;
		sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
		sr_icmp_t3_hdr_t *new_icmp_hdr = (sr_icmp_t3_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t) + (ip_hdr->ip_hl * 4));

		/*init ethernet header*/
		new_eth_hdr->ether_type = htons(ethertype_ip);
		
		/* Init IP header*/
		new_ip_hdr->ip_v = 4;
		new_ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) / 4; 
		new_ip_hdr->ip_tos = 0;
		new_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
		new_ip_hdr->ip_id = 0;
		new_ip_hdr->ip_off = htons(IP_DF);
		new_ip_hdr->ip_ttl = 255;
		new_ip_hdr->ip_p = ip_protocol_icmp;
		new_ip_hdr->ip_sum = 0;
		new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));
		new_ip_hdr->ip_dst = ip_hdr->ip_src; /*send the packet to where it comes from*/
		if (code == 3) /* Port unreachable*/
		new_ip_hdr->ip_src = ip_hdr->ip_dst;
		else new_ip_hdr->ip_src = sending_intf->ip;

		/*init ICMP header*/
		new_icmp_hdr->icmp_type = type;
		new_icmp_hdr->icmp_code = code;
		new_icmp_hdr->unused = 0;
		new_icmp_hdr->next_mtu = 0; 
		memcpy(new_icmp_hdr->data, ip_hdr, 28); /*ip header and 8 data bytes*/

		new_icmp_hdr->icmp_sum = 0;
		new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

		/*send the ICMP packet*/
		struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, routetable->gw.s_addr);
		if (entry == NULL)
			queue_arp_request(sr, new_packet, new_len, sending_intf, routetable->gw.s_addr);
		else
			send_packet(sr, new_packet, new_len, sending_intf, entry);
		
	}

}


/*set ethernet header and send packet*/
void send_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *interface, struct sr_arpentry *entry){

		sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
		memcpy(eth_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN); 
		memcpy(eth_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);     
		sr_send_packet(sr, packet, len, interface->name);
		free£¨packet£©;
	}

}
/*queue the arp request */
void queue_arp_request(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *interface, uint32_t dest_ip){
	struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, dest_ip, packet, len, interface->name);
	handle_arpreq(sr, req);
	free(packet);
}

void handle_arp_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface){
	sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

	/*check if the router send to the router
	struct sr_if *dest = sr_get_interface_ip(sr, arp_hdr->ar_tip);
	if (!dest)
	{
		return;
	}*/

	if (ntohs(arp_hdr->ar_op) == arp_op_request) {
			/*get the interface of where it from*/
			struct sr_if *intf = sr_get_interface(sr, interface);

			/*copy the request to a new reply packet*/
			uint8_t *arp_rep = malloc(len);
			memcpy(arp_rep, packet, len);

			/* Update ethernet header */
			sr_ethernet_hdr_t *arprep_eth_hdr = (sr_ethernet_hdr_t *)arp_rep;
			memcpy(arprep_eth_hdr->ether_dhost, arprep_eth_hdr->ether_shost, ETHER_ADDR_LEN);
			memcpy(arprep_eth_hdr->ether_shost, intf->addr, ETHER_ADDR_LEN);

			/* Update ARP header */
			sr_arp_hdr_t *arprep_arp_hdr = (sr_arp_hdr_t *)(arp_rep + sizeof(sr_ethernet_hdr_t));
			arprep_arp_hdr->ar_op = htons(arp_op_reply);                     
			memcpy(arprep_arp_hdr->ar_sha, intf->addr, ETHER_ADDR_LEN);
			arprep_arp_hdr->ar_sip = intf->ip;
			memcpy(arprep_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN); 
			arprep_arp_hdr->ar_tip = arp_hdr->ar_sip;                        

			sr_send_packet(sr, arp_rep, len, interface->name);
			free(packet);
		}
		else if (ntohs(arp_hdr->ar_op) == arp_op_reply){
			/*find the request of the arp reply and update the entry*/
			struct sr_arpreq *req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
			if (req == 0)
				return;
			/*find the first packet*/
			struct sr_packet *packet = req->packets;
			/*send all the packet waiting for the arp reply out*/
			struct sr_if *packet_intf = NULL;
			sr_ethernet_hdr_t *eth_hdr = NULL;
			/*send all the packets requesting the MAC address out*/
			while (packet){
				packet_intf = sr_get_interface(sr, packet->iface);
				eth_hdr = (sr_ethernet_hdr_t *)(packet->buf);
				memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
				memcpy(eth_hdr->ether_shost, packet_intf->addr, ETHER_ADDR_LEN);
				sr_send_packet(sr, packet->buf, packet->len, packet->iface);
				packet = packet->next;
				}
			/*request finish*/
			sr_arpreq_destroy(&sr->cache, req);
			


		}
	}


struct sr_rt *longest_matching_prefix_ip(struct sr_instance *sr, uint32_t ip)
{
	struct sr_rt *matching_rt = NULL;

	struct sr_rt *routetable = sr->routing_table;
	while (routetable)
	{
		if ((routetable->dest.s_addr & routetable->mask.s_addr) == (ip & routetable->mask.s_addr))
		{
			if (matching_rt == NULL)
				matching_rt = routetable;
			else if (routetable->mask.s_addr > matching_rt->mask.s_addr)
				matching_rt = routetable;
		}

		routetable = routetable->next;
	}
	return matching_rt;
}

int sr_get_intf_ip(struct sr_instance *sr, uint32_t ip)
{

	struct sr_if *intf_walker = sr->if_list;
	while (intf_walker)
	{
		if (intf_walker->ip == ip)
		{
			return 1;
		}

		intf_walker = intf_walker->next;
	}

	return 0;
}

void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req){
	time_t now = time(NULL);
	/* every second, check the arp request*/
	if (difftime(now, req->sent) > 1.0){
		/* it the request has been sent than 5 times*/
		if (req->times_sent >= 5){
			/* Send ICMP message back to sender */
			struct sr_packet *packet = req->packets;
			sr_ethernet_hdr_t *packet_ehdr;
			while (packet)
			{
				packet_ehdr = (sr_ethernet_hdr_t *)(packet->buf);
				send_icmp_msg(sr, packet->buf, packet->len, (uint8_t)3, (uint8_t)1);
				packet = packet->next;
			}
			sr_arpreq_destroy(&sr->cache, req);
		}
		/* arp request sent less than 5 times*/
		else{
			/*build a arp request*/
			int len_arp = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
			uint8_t *arp_packet = malloc(len_arp);
			/*set ethernet header */
			sr_ethernet_hdr_t *arp_pkt_ehdr = (sr_ethernet_hdr_t *)arp_packet;
			arp_pkt_ehdr->ether_type = htons(ethertype_arp);
			memset(arp_pkt_ehdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
			arp_pkt_ehdr->ether_type = htons(ethertype_arp);
			/*broadcast arp message to every interface*/
			struct sr_if *curr_intf = sr->if_list;
			while (curr_intf != NULL) {
				memcpy(arp_pkt_ehdr->ether_shost, (uint8_t *)curr_intf->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
				/* Init ARP header */
				sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(arp_packet + sizeof(sr_ethernet_hdr_t));
				arp_hdr->ar_hrd = htons(1);/*1*/
				arp_hdr->ar_pro = htons(2048);/*0x0800*/
				arp_hdr->ar_hln = 6;/*48bits*/
				arp_hdr->ar_pln = 4;/*32bits*/
				arp_hdr->ar_op = htons(arp_op_request);
				memcpy(arp_hdr->ar_sha, curr_intf->addr, ETHER_ADDR_LEN);
				memset(arp_hdr->ar_tha, 0xff, ETHER_ADDR_LEN);
				arp_hdr->ar_sip = curr_intf->ip;
				arp_hdr->ar_tip = req->ip;

				/*send packet*/
				sr_send_packet(sr, arp_packet, len_arp, curr_intf->name);
				
				curr_intf = curr_intf->next;
			}
			free(arp_packet);
			/*reset request*/
			req->sent = now;
			req->times_sent++;
		}

	}
}