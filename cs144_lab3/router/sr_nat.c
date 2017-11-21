#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include "sr_router.h"
#include "sr_utils.h"

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  nat->syn_packet = NULL;
  nat->tcp_port_number = 1024;
  nat->icmp_identifier_number = 1024;
  /* Initialize any variables here */

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */
    struct sr_nat_mapping *mapping = nat->mappings;

    while (mapping)
    {
        struct sr_nat_mapping *prev  = mapping;
        mapping = mapping->next;
        free(prev);
    }
    struct sr_nat_syn_queue *queue_packet = nat->syn_packet;
    while (queue_packet)
    {
        struct sr_nat_syn_queue *prevq  = queue_packet;
        queue_packet = queue_packet->next;
        free(prevq);
    }


  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    /* handle periodic tasks here */
    /*clean timeout mappings*/
    struct sr_nat_mapping *mapping = nat->mappings;

    /*check all the mapping*/
    while(mapping){
        /*copy the next pointer, in case we delete the current mapping*/
        struct sr_nat_mapping *temp = mapping->next;
        /*if it's a tcp mapping, check the connection states*/
        if(mapping->type == nat_mapping_tcp){
            struct sr_nat_connection *connection = mapping->conns;
            /*go through all the connections*/
            while(connection){
                /*tcp in establish state*/
                if (((connection->state == Estblsh)||
                    (connection->state == FinWt1)||
                    (connection->state == FinWt2)||
                    (connection->state == ClosWt))&&
                    (difftime(curtime, connection->last_updated)> nat->tcp_established_idle_timeout)){
                    /*copy the next pointer, in case we delete the current connection*/
                    struct sr_nat_connection *next = connection->next;
                    /*delete the connection*/
                    sr_nat_destroy_connection(mapping, connection);
                    connection = next;
                }else if(((connection->state == Listen)||/*tcp connection in other state*/
                         (connection->state == SynSent)||
                         (connection->state == SynRcvd)||
                         (connection->state == Closing)||
                         (connection->state == LastAck)||
                         (connection->state == TimeWt)||
                         (connection->state == Closed))&&
                         (difftime(curtime, connection->last_updated) > nat->tcp_transitory_idle_timeout)){
                            struct sr_nat_connection *next = connection->next;
                            /*delete the connection*/
                            sr_nat_destroy_connection(mapping, connection);
                            connection = next;
                         }
            }
            /*if there is no connection in the mapping left, we delete this mapping*/
            if(mapping->conns == NULL){
                sr_nat_delete_mapping(nat, mapping);
            }

        }
        else if(mapping->type == nat_mapping_icmp){
          /*if this mapping is a icmp type, check if the time interval greater than icmp_query_timeout, clean the mapping entry*/
            if (difftime(curtime, mapping->last_updated) > nat->icmp_query_timeout){
                sr_nat_delete_mapping(nat, mapping);
            }
        }

        mapping = temp;
    }

    /*check all the pack queue in syn_queue*/
    struct sr_nat_syn_queue *syn = nat->syn_packet;
    struct sr_nat_syn_queue *pre = NULL;
    while(syn){
        struct sr_nat_syn_queue *syn_next = syn->next;
        if(difftime(curtime, syn->last_updated) > 6){
            /*send icmp error message back to sender*/
            nat_icmp_error(nat->sr, syn->packet, syn->interface);
            /*delete is packet*/
            if(pre == NULL){
                nat->syn_packet = syn_next;
            }else{
                pre->next = syn_next;
            }
            free(syn);
        }
        syn = syn_next;
    }



    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

    pthread_mutex_lock(&(nat->lock));

    /* handle lookup here, malloc and assign to copy */
    struct sr_nat_mapping *copy = NULL;
    struct sr_nat_mapping *mapping_walker = nat->mappings;
    while (mapping_walker)
    {
        if (mapping_walker->type == type && mapping_walker->aux_ext == aux_ext)
        {
            break;
        }
        mapping_walker = mapping_walker->next;
    }
    copy = (sr_nat_mapping_t *)malloc(sizeof(sr_nat_mapping_t));
    memcpy(copy, mapping_walker, sizeof(sr_nat_mapping_t));


    pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

    pthread_mutex_lock(&(nat->lock));

    /* handle lookup here, malloc and assign to copy. */
    struct sr_nat_mapping *copy = NULL;
    struct sr_nat_mapping *mapping_walker = nat->mappings;
    while (mapping_walker)
    {
        if (mapping_walker->type == type && mapping_walker->aux_ext == aux_ext && mapping_walker->ip_int == ip_int)
        {
            break;
        }
        mapping_walker = mapping_walker->next;
    }
    copy = (sr_nat_mapping_t *)malloc(sizeof(sr_nat_mapping_t));
    memcpy(copy, mapping_walker, sizeof(sr_nat_mapping_t));


    pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

    pthread_mutex_lock(&(nat->lock));

    /* handle insert here, create a mapping, and then return a copy of it */
    struct sr_nat_mapping *mapping = NULL;
    struct sr_nat_mapping *new_mapping = NULL;
    new_mapping = ( sr_nat_mapping_t *)malloc(sizeof(sr_nat_mapping_t));
    /*allocate port number to new mapping*/
     if(type == nat_mapping_icmp){
            new_mapping->aux_ext = nat->icmp_identifier_number;
            if (nat->icmp_identifier_number >= 4048){
                nat->icmp_identifier_number = 1024;
            }else {
                nat->icmp_identifier_number++;
            }

    }else if(type == nat_mapping_tcp){
            new_mapping->aux_ext = nat->tcp_port_number;
            if (nat->tcp_port_number >= 4048){
                nat->tcp_port_number = 1024;
            }else{
                nat->tcp_port_number++;
            }
    }
    /*init mapping setting*/
    new_mapping->type = type;
    new_mapping->ip_int = ip_int;
    new_mapping->ip_ext = 0;
    new_mapping->aux_int = aux_int;
    new_mapping->last_updated = time(NULL);
    new_mapping->conns = NULL;
    /*put it in the head of mapping list*/
    new_mapping->next = nat->mappings;
    nat->mappings = new_mapping;

    mapping= (sr_nat_mapping_t *)malloc(sizeof(sr_nat_mapping_t));
    memcpy(mapping, new_mapping, sizeof(sr_nat_mapping_t));

    pthread_mutex_unlock(&(nat->lock));
  return mapping;
}

/*remove mapping entry and all its connections*/
void sr_nat_delete_mapping(struct sr_nat *nat, struct sr_nat_mapping *Mapping)
{
    /*pthread_mutex_lock(&(nat->lock));*/

    struct sr_nat_mapping *mapwalker = nat->mappings, *prev = NULL;
    while(mapwalker){
          /*find the target mapping entry*/
         if (mapwalker == Mapping){
            if (prev){
               prev->next = mapwalker->next;
            }
            else{
                nat->mappings = mapwalker->next
            }
            break;
         }
         prev = mapwalker;
         mapwalker = mapwalker->next;
      }

      while (Mapping->conns != NULL)
      {
         struct sr_nat_connection * con_walker = Mapping->conns;
         Mapping->conns = con_walker->next;

         free(con_walker);
      }

      free(Mapping);

      /*pthread_mutex_unlock(&(nat->lock));*/
}

/*add a new connection to a mapping*/
void sr_nat_add_connection(struct sr_nat_mapping *mapping, struct sr_ip_hdr *ip_hdr){
    sr_nat_connection_t *connection = (sr_nat_connection_t *)malloc(sizeof(sr_nat_connection_t));
    memset(connection, 0, sizeof(sr_nat_connection_t));

    connection->ip = ip_hdr->ip_src;
    connection->state = Closed;
    connection->last_updated = time(NULL);

    connection->next = mapping->conns;
    mapping->conns = connection;

}

/*in a mapping find a connection*/
struct sr_nat_connection *sr_nat_search_conn(struct sr_nat_mapping *mapping, struct sr_ip_hdr *ip_hdr)
{

    struct sr_nat_connection *connection = mapping->conns;
    while (connection){
        if (connection->ip == ip_hdr->ip_src){
            break;
        }

        connection = connection->next;
    }
    return connection;

}


/*clean a connection in mapping*/
void sr_nat_destroy_connection(struct sr_nat_mapping *Mapping, struct sr_nat_connection *connection)
{
   struct sr_nat_connection *con_walker = Mapping->conns, *prev = NULL;
      while(con_walker){
         if (con_walker == connection){
            if (prev){
                prev->next = con_walker->next;
            }
            else{
               Mapping->conns = con_walker->next;
            }

            break;
         }
         prev = con_walker;
         con_walk = con_walker->next;
      }

      free(connection);
}

/*send icmp type 3, code 3, back to sender*/
void nat_icmp_error(struct sr_instance *sr, uint8_t *packet, char *interface){
	sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

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
	new_ip_hdr->ip_src = ip_hdr->ip_dst;
	new_ip_hdr->ip_sum = 0;
	new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));

	/*init ICMP header*/
	new_icmp_hdr->icmp_type = 3;
	new_icmp_hdr->icmp_code = 3;
	new_icmp_hdr->unused = 0;
	new_icmp_hdr->next_mtu = 0;
	memcpy(new_icmp_hdr->data, ip_hdr, 28); /*ip header and 8 data bytes*/

	new_icmp_hdr->icmp_sum = 0;
	new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

	/*send the ICMP packet*/

	sr_send_packet(sr, new_packet, new_len, interface);

	}
/*when receive a tcp packet, check its connection state*/
void nat_state_transfer_outbound(struct sr_nat *nat, struct sr_nat_mapping *mapping, struct sr_ip_hdr *ip_hdr, struct sr_tcp_hdr *tcp_hdr){
    pthread_mutex_lock(&(nat->lock));

    struct sr_nat_connection *connection = sr_nat_search_conn(mapping, ip_hdr);
    if (!connection){
        sr_nat_add_connection(mapping, ip_hdr);
        connection = mapping->conns;
    }

    switch (connection->state){
        case Estblsh:{
        /* ESTAB -> CLOSED (ACK of FIN) */
        if (tcp_hdr->fin && tcp_hdr->ack){
        connection->client_seq_num = ntohl(tcp_hdr->seq_num);
        connection->state = Closed;
        }
        break;
        }

        case Closed:{
        /* CLOSED -> SYN_SENT */
        if (!tcp_hdr->ack && tcp_hdr->syn && ntohl(tcp_hdr->ack_num) == 0){
        connection->client_seq_num = ntohl(tcp_hdr->seq_num);
        connection->state = SynSent;
        }
        break;
        }

        case SynRcvd:{
        /* SYN_RCVD -> ESTAB (ACK of SYN) */
        if (!tcp_hdr->syn && ntohl(tcp_hdr->seq_num) == connection->client_seq_num + 1 && ntohl(tcp_hdr->ack_num) == connection->server_seq_num + 1){
        connection->client_seq_num = ntohl(tcp_hdr->seq_num);
        connection->state = Estblsh;
        }
        /*add_incoming_syn(&sr->nat, ip_hdr->ip_src, tcp_hdr->src_port, packet, len);*/
        break;
        }

        default:{
        break;
        }
    }

    pthread_mutex_unlock(&(nat->lock));

}

void nat_state_transfer_inbound(struct sr_nat *nat, struct sr_nat_mapping *mapping, struct sr_ip_hdr *ip_hdr, struct sr_tcp_hdr *tcp_hdr){
    pthread_mutex_lock(&(nat->lock));

    struct sr_nat_connection *connection = sr_nat_search_conn(mapping, ip_hdr);
    if (!connection){
        sr_nat_add_connection(mapping, ip_hdr);
        connection = mapping->conns;
    }

    switch (connection->state){
        case SynSent:
        {
            /* SYN_SENT -> SYN_RECV */
            if (tcp_hdr->syn)
            {
                if (tcp_hdr->ack && ntohl(tcp_hdr->ack_num) == connection->client_seq_num + 1)
                {
                    /* Simultaneous open */
                    connection->server_seq_num = ntohl(tcp_hdr->seq_num);
                    connection->state = SynRcvd;
                }
                else if (!tcp_hdr->ack && ntohl(tcp_hdr->ack_num) == 0)
                {
                    /* SYN + initial seq num of 0 */
                    connection->server_seq_num = ntohl(tcp_hdr->seq_num);
                    connection->state = SynRcvd;
                }

                /*add_incoming_syn(&sr->nat, ip_hdr->ip_src, tcp_hdr->src_port, packet, len);*/
            }
            break;
        }

        case SynRcvd:
        {
            /*add_incoming_syn(&sr->nat, ip_hdr->ip_src, tcp_hdr->src_port, packet, len);*/
            break;
        }

        default:
        {
            break;
        }
    }

    pthread_mutex_unlock(&(nat->lock));


}
