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
#include <string.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_nat.h"

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

	/*printf("*** -> Received packet of length %d \n", len);*/

	/*check if the length meet the minimum require*/
	if (len >= sizeof(sr_ethernet_hdr_t))
	{
		if (ethertype(packet) == ethertype_ip)   /*handle ip packet*/
		{
			/*printf("*** -> Received packet ip packet \n");*/
			if(sr->nat == NULL){
			handle_ip_packet(sr, packet, len, interface);
			}else{
			nat_handle_packet(sr, packet, len, interface);
			}

		}
		else if (ethertype(packet) == ethertype_arp)	 /*handle arp packet*/
		{
			/*printf("*** -> Received packet arp packet \n");*/
			handle_arp_packet(sr, packet, len, interface);
		}
	}
	else{/*waste time*/
		printf("****** -> Received packet doesn't meet minimum length requirement \n");
	}

}

void handle_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface){
	/*locate the ip header*/;
	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	/*check if the length meet the minimum require*/
	if (ip_hdr->ip_len < 20)
		return;
	/*verify ip header checksum*/
	uint16_t Tip_sum = ip_hdr->ip_sum;
	ip_hdr->ip_sum = 0;
	uint16_t Nip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
	if (Nip_sum != Tip_sum)
		return;
	ip_hdr->ip_sum = Tip_sum;

	/*check if the destined IP is one of the router's interface*/
	if (sr_get_intf_ip(sr, ip_hdr->ip_dst)){

	/*the packet is destined to the router
	  check whether the packet is a ICMP*/
		if ((ip_hdr->ip_p) == ip_protocol_icmp){

			/*chec if the length meet the minimum require*/
			int minsize_icmp = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
			if (len < minsize_icmp){

				return;
			}

			/*verify ICMP header checksum*/
			sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
			uint16_t Oicmp_sum = icmp_hdr->icmp_sum;
			icmp_hdr->icmp_sum = 0;
			uint16_t Nicmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4));
			icmp_hdr->icmp_sum = Oicmp_sum;
			if (Oicmp_sum != Nicmp_sum){
				return;
			}

			/*send ICMP echo message back to sender*/
			icmp_echo_reply(sr, packet, len, interface);
			}
		else if (1){  /*the packet is tcp or udp, drop it and send ICMP message, type 3, code */
			handle_icmp_error((uint8_t)3, (uint8_t)3, sr, packet, len, interface);
			}

	}
	else{
	/*forward the packet*/

		sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

		/* Decrement TTL and check if TTL bigger than 0*/
		ip_hdr->ip_ttl--;
		if (ip_hdr->ip_ttl <= 0)
		{/*send IMCP message time exceeded*/
			handle_icmp_error((uint8_t)11, (uint8_t)0, sr, packet, len, interface);
			return;
		}

		/*recalculate IP checksum*/
		ip_hdr->ip_sum = 0;
		ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
		/*find the longest prefix ip*/
		struct sr_rt *routetable = matching_prefix_ip(sr, ip_hdr->ip_dst);
		if (!routetable)  /*there is a non-existent route to the destination IP*/
		{
			handle_icmp_error((uint8_t)3, (uint8_t)0, sr, packet, len, interface);
			return;
		}

		struct sr_if *sending_intf = sr_get_interface(sr, routetable->interface);
		struct sr_if *intf = sr_get_interface(sr, interface);
		/*check ARP cache*/
		struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, routetable->gw.s_addr);
		if (entry == NULL)
			queue_arp_request(sr, packet, len, intf, routetable->gw.s_addr);
		else
			set_eth_send_packet(sr, packet, len, sending_intf, entry);
	}

}

/*nat mode handle ip packet*/
void nat_handle_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface){
	/*locate the ip header*/;
	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	/*check if the length meet the minimum require*/
	if (ip_hdr->ip_len < 20)
		return;
	/*verify ip header checksum*/
	uint16_t Tip_sum = ip_hdr->ip_sum;
	ip_hdr->ip_sum = 0;
	uint16_t Nip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
	if (Nip_sum != Tip_sum)
		return;
	ip_hdr->ip_sum = Tip_sum;

    /*get two interface of the router*/
    struct sr_if *ext_intf = sr_get_interface(sr, "eth2");
    struct sr_if *int_intf = sr_get_interface(sr, "eth1");

    /*build a new mapping pointer*/
    struct sr_nat_mapping *mapping = NULL;
	/*check if it's a outbound message or inbound message*/
	if(!strncmp(interface, "eth1", sr_IFACE_NAMELEN)){/*it's a outbound message*/
        /*check if the destined IP is one of the router's interface*/
        if (sr_get_intf_ip(sr, ip_hdr->ip_dst)){
            /*the packet is destined to the router
            check whether the packet is a ICMP*/
            if ((ip_hdr->ip_p) == ip_protocol_icmp){

                /*chec if the length meet the minimum require*/
                int minsize_icmp = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
                if (len < minsize_icmp){

                    return;
                }

                /*verify ICMP header checksum*/
                sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
                uint16_t Oicmp_sum = icmp_hdr->icmp_sum;
                icmp_hdr->icmp_sum = 0;
                uint16_t Nicmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4));
                icmp_hdr->icmp_sum = Oicmp_sum;
                if (Oicmp_sum != Nicmp_sum){
                    return;
                }
                if(icmp_hdr->icmp_type == 8)
                    /*send ICMP echo message back to sender*/
                    icmp_echo_reply(sr, packet, len, interface);
                else
                     handle_icmp_error((uint8_t)3, (uint8_t)3, sr, packet, len, interface);
			}
            else if (1){  /*the packet is tcp or udp, drop it and send ICMP message, type 3, code */
                handle_icmp_error((uint8_t)3, (uint8_t)3, sr, packet, len, interface);
			}

        }else{/*the destination is not my router*/

            if((ip_hdr->ip_p) == ip_protocol_icmp){
                /*locate icmp header*/
                sr_nat_icmp_hdr_t *icmp_hdr = (sr_nat_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
                /*find the mapping*/
                mapping = sr_nat_lookup_internal(&(sr->nat), ip_hdr->ip_src, icmp_hdr->icmp_id, nat_mapping_icmp);
                if(!mapping){
                    mapping = sr_nat_insert_mapping(&(sr->nat), ip_hdr->ip_src, icmp_hdr->icmp_id, nat_mapping_icmp);
                    mapping->ip_ext = ext_intf->ip;
                    mapping->last_updated = time(NULL);/*edit can delete*/

                }
                /*translate icmp id*/
                icmp_hdr->icmp_id = mapping->aux_ext;
                icmp_hdr->icmp_sum = 0;
                icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));/*edit size of */
            }else if((ip_hdr->ip_p) == nat_mapping_tcp){
                /*locate the tcp header*/
                sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
                /*find the mapping*/
                mapping = sr_nat_lookup_internal(&(sr->nat), ip_hdr->ip_src, ntohs(tcp_hdr->source_port), nat_mapping_tcp);
                if (!mapping){
                    mapping = sr_nat_insert_mapping(&(sr->nat), ip_hdr->ip_src, ntohs(tcp_hdr->source_port), nat_mapping_tcp);
                    mapping->ip_ext = ext_intf->ip;
                    mapping->last_updated = time(NULL);/*edit*/
                }
                /*get connection and check the state*/
                nat_state_transfer_outbound(&(sr->nat), mapping, ip_hdr, tcp_hdr);

                /*translate tcp port*/
                 tcp_hdr->source_port = htons(mapping->aux_ext);

                tcp_hdr->checksum = 0;
                tcp_hdr->checksum = tcp_cksum(packet, len);
            }
            ip_hdr->ip_src = ext_intf->ip;
            ip_hdr->ip_sum = 0;
            ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
        }
	}
	else{/*it's a inbound message*/
        if (sr_get_intf_ip(sr, ip_hdr->ip_dst)){/*it must be send to the router*/
            if(ip_hdr->ip_p == ip_protocol_icmp){
                sr_nat_icmp_hdr_t *icmp_hdr = (sr_nat_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

                mapping = sr_nat_lookup_external(&(sr->nat), icmp_hdr->icmp_id, nat_mapping_icmp);
                    if (!mapping)
                    {
                      /* no icmp mapping in list, drop the packet*/
                        return;
                    }

                    /* Update ICMP header with mapping's internal ID */
                    icmp_hdr->icmp_id = mapping->aux_int;
                    icmp_hdr->icmp_sum = 0;
                    icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

            }else if(ip_hdr->ip_p == ip_protocol_tcp){
                sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
                 /*check if the port number meet the minimum require*/
                 if (ntohs(tcp_hdr->destination_port) < 1024){
                        handle_icmp_error((uint8_t)3, (uint8_t)3, sr, packet, len, interface);
                        return;
                }
                 mapping = sr_nat_lookup_external(&(sr->nat), ntohs(tcp_hdr->destination_port), nat_mapping_tcp);
                 if (!mapping){
                    /* no tcp mapping in list, drop the packet*/
                    return;
                }
                nat_state_transfer_inbound(&(sr->nat), mapping, ip_hdr, tcp_hdr);

                tcp_hdr->destination_port = htons(mapping->aux_int);
                tcp_hdr->checksum = 0;
                tcp_hdr->checksum = tcp_cksum(packet, len);
            }
            ip_hdr->ip_dst = mapping->ip_int;
            ip_hdr->ip_sum = 0;
            ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
        }
	}
    if (mapping)
    {
        /* Decrement TTL and check if TTL bigger than 0*/
		ip_hdr->ip_ttl--;
		if (ip_hdr->ip_ttl <= 0)
		{/*send IMCP message time exceeded*/
			handle_icmp_error((uint8_t)11, (uint8_t)0, sr, packet, len, interface);
			return;
		}

		/*recalculate IP checksum*/
		ip_hdr->ip_sum = 0;
		ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
		/*find the longest prefix ip*/
		struct sr_rt *routetable = matching_prefix_ip(sr, ip_hdr->ip_dst);
		if (!routetable)  /*there is a non-existent route to the destination IP*/
		{
			handle_icmp_error((uint8_t)3, (uint8_t)0, sr, packet, len, interface);
			return;
		}

		struct sr_if *sending_intf = sr_get_interface(sr, routetable->interface);
		struct sr_if *intf = sr_get_interface(sr, interface);
		/*check ARP cache*/
		struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, routetable->gw.s_addr);
		if (entry == NULL)
			queue_arp_request(sr, packet, len, intf, routetable->gw.s_addr);
		else
			set_eth_send_packet(sr, packet, len, sending_intf, entry);

    }
}

void handle_arp_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface){
	sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));


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

		sr_send_packet(sr, arp_rep, len, interface);
		/*free(packet);*/
	}
	else if (ntohs(arp_hdr->ar_op) == arp_op_reply){
		/*find the request of the arp reply and update the entry*/
		struct sr_arpreq *req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
		if (req == 0)
			return;

		struct sr_rt *routetable = matching_prefix_ip(sr, req->ip);
		/*send all the packet waiting for the arp reply out*/
		struct sr_if *packet_intf = sr_get_interface(sr, routetable->interface);
		clean_req(sr, packet, req, len, packet_intf);
	}
}

/*send all the packets in ARP request queue out*/
void clean_req(struct sr_instance *sr, uint8_t *packet, struct sr_arpreq *req, unsigned int len, struct sr_if *packet_intf){
	sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	sr_ethernet_hdr_t *eth_hdr = NULL;
	struct sr_packet *qu_packet = req->packets;
	/*send all the packets requesting the MAC address out*/
	while (qu_packet){
		eth_hdr = (sr_ethernet_hdr_t *)(qu_packet->buf);
		memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
		memcpy(eth_hdr->ether_shost, packet_intf->addr, ETHER_ADDR_LEN);
		sr_send_packet(sr, qu_packet->buf, qu_packet->len, packet_intf->name);
		qu_packet = qu_packet->next;
	}
	/*request finish*/
	sr_arpreq_destroy(&sr->cache, req);
}

/*send back the ICMP echo reply*/
void icmp_echo_reply(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface){
	sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	/*find the longest prefix match of the IP address*/
	struct sr_rt *routetable = matching_prefix_ip(sr, ip_hdr->ip_src);
	/*get the interface of the route table*/
	struct sr_if *sending_intf = sr_get_interface(sr, routetable->interface);
	struct sr_if *intf = sr_get_interface(sr, interface);
	sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
	/*set the ICMP information*/
	icmp_hdr->icmp_type = (uint8_t)0; /*echo tpye*/
	icmp_hdr->icmp_code = (uint8_t)0;

	icmp_hdr->icmp_sum = 0;
	icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4));

	/*set the IP header information*/
	uint32_t temp = ip_hdr->ip_src; /*swap the source and destination address*/
	ip_hdr->ip_src = ip_hdr->ip_dst;
	ip_hdr->ip_dst = temp;

	ip_hdr->ip_sum = 0;/*calculate the IP header's checksum*/
	ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

	/*send the ICMP packet*/
	/*printf("*** -> Sending ICMP echo reply \n");*/
	/*check the whether the MAC address in the cache*/
	struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, routetable->gw.s_addr);
	if (entry == NULL)
		queue_arp_request(sr, packet, len, intf, routetable->gw.s_addr);
	else
		set_eth_send_packet(sr, packet, len, sending_intf, entry);

}
/*send ICMP error message*/
void handle_icmp_error(uint8_t type, uint8_t code, struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface){
	sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));


	/*find the longest prefix match of the IP address*/
	struct sr_rt *routetable = matching_prefix_ip(sr, ip_hdr->ip_src);
	/*get the interface of where the packet from*/
	struct sr_if *intf = sr_get_interface(sr, interface);


	/*printf("*** -> Sending ICMP type %d, code %d\n", type,code);*/
	uint8_t *new_packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));  /*create a new packet*/
	int new_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
	sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *)new_packet;
	sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
	sr_icmp_t3_hdr_t *new_icmp_hdr = (sr_icmp_t3_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t) + (ip_hdr->ip_hl * 4));


	/*init ethernet header*/
	new_eth_hdr->ether_type = htons(ethertype_ip);
	memcpy(new_eth_hdr->ether_shost, intf->addr, ETHER_ADDR_LEN);
	memcpy(new_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);

	/* Init IP header*/
	new_ip_hdr->ip_v = 4;
	new_ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) / 4;
	new_ip_hdr->ip_tos = 0;
	new_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
	new_ip_hdr->ip_id = htons(0);
	new_ip_hdr->ip_off = htons(IP_DF);
	new_ip_hdr->ip_ttl = 255;
	new_ip_hdr->ip_p = ip_protocol_icmp;
	new_ip_hdr->ip_dst = ip_hdr->ip_src; /*send the packet to where it comes from*/
	if (code == 3){
		new_ip_hdr->ip_src = ip_hdr->ip_dst;
	}
	else {
		new_ip_hdr->ip_src = intf->ip;
	}
	new_ip_hdr->ip_sum = 0;
	new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));

	/*init ICMP header*/
	new_icmp_hdr->icmp_type = type;
	new_icmp_hdr->icmp_code = code;
	new_icmp_hdr->unused = 0;
	new_icmp_hdr->next_mtu = 0;
	memcpy(new_icmp_hdr->data, ip_hdr, 28); /*ip header and 8 data bytes*/

	new_icmp_hdr->icmp_sum = 0;
	new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

	/*send the ICMP packet*/

	sr_send_packet(sr, new_packet, new_len, interface);

	/*struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, routetable->gw.s_addr);
	if (entry == NULL)
	{
		printf("*** -> Sending ARP before send ICMP back");
		queue_arp_request(sr, new_packet, new_len, sending_intf, routetable->gw.s_addr);
	}
	else
		send_packet(sr, new_packet, new_len, sending_intf, entry);*/

	}


/*set ethernet header and send packet*/
void set_eth_send_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *interface, struct sr_arpentry *entry){

		sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
		memcpy(eth_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
		memcpy(eth_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
		sr_send_packet(sr, packet, len, interface->name);
		/*free(packet);*/
	}

/*queue the arp request */
void queue_arp_request(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *interface, uint32_t dest_ip){
	struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, dest_ip, packet, len, interface->name);
	handle_arpreq(sr, req);
	/*free(packet);*/
}


/*find longest matching prefix ip*/
struct sr_rt *matching_prefix_ip(struct sr_instance *sr, uint32_t ip)
{
	struct sr_rt *matching_rt = NULL;

	struct sr_rt *routetable = sr->routing_table;
	while (routetable)
	{
		if (routetable->dest.s_addr  == (ip & routetable->mask.s_addr))
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

/*find whether the ip is one of the router's interface's ip*/
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
	if (difftime(now, req->sent) >= 1.0){
		/* it the request has been sent than 5 times*/
		if (req->times_sent >= 5){
			/* Send ICMP message back to sender */
			struct sr_packet *packet = req->packets;
			char *interface = packet->iface;

			/*sr_ethernet_hdr_t *packet_ehdr;*/
			while (packet)
			{
				/*packet_ehdr = (sr_ethernet_hdr_t *)(packet->buf);*/
				handle_icmp_error((uint8_t)3, (uint8_t)1, sr, packet->buf, packet->len, interface);
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
			/*free(arp_packet);*/
			/*reset request*/
			req->sent = now;
			req->times_sent++;
		}

	}
}
