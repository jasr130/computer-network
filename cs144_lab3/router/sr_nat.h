
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>
#include "sr_protocol.h"

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
  /* nat_mapping_udp, */
} sr_nat_mapping_type;

/*tcp state*/
typedef enum
{
   Listen,
   SynSent,
   SynRcvd,
   Estblsh,
   FinWt1,
   FinWt2,
   ClosWt,
   Closing,
   LastAck,
   TimeWt,
   Closed
} sr_tcp_state_t;

struct sr_nat_connection {
  /* add TCP connection state data members here */
    uint32_t ip;
    sr_tcp_state_t state;
    uint32_t client_seq_num;
    uint32_t server_seq_num;
    time_t last_updated;
  struct sr_nat_connection *next;};
typedef struct sr_nat_connection sr_nat_connection_t;

struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
};
typedef struct sr_nat_mapping sr_nat_mapping_t;

struct sr_nat_syn_queue{
    uint8_t *packet;
    char *interface;
    time_t last_updated;
    struct sr_nat_syn_queue* next;
};
typedef struct sr_nat_syn_queue sr_nat_syn_queue_t;

struct sr_nat {
  /* add any fields here */
  struct sr_nat_mapping *mappings;
  struct sr_nat_syn_queue *syn_packet;

  int icmp_query_timeout;
  int tcp_established_idle_timeout;
  int tcp_transitory_idle_timeout;
  struct sr_instance *sr;

  uint16_t tcp_port_number;
  uint16_t icmp_identifier_number;

  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;
};
typedef struct sr_nat sr_nat_t;


int   sr_nat_init(struct sr_nat *nat);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

void sr_nat_delete_mapping(struct sr_nat *nat, struct sr_nat_mapping *Mapping);
void sr_nat_add_connection(struct sr_nat_mapping *mapping, struct sr_ip_hdr *ip_hdr);
struct sr_nat_connection *sr_nat_search_conn(struct sr_nat_mapping *mapping, struct sr_ip_hdr *ip_hdr);
void sr_nat_destroy_connection(struct sr_nat_mapping *Mapping, struct sr_nat_connection *connection);
void nat_icmp_error(struct sr_instance *sr, uint8_t *packet, char *interface);
void nat_state_transfer_outbound(struct sr_nat *nat, struct sr_nat_mapping *mapping, struct sr_ip_hdr *ip_hdr, struct sr_tcp_hdr *tcp_hdr);
void nat_state_transfer_inbound(struct sr_nat *nat, struct sr_nat_mapping *mapping, struct sr_ip_hdr *ip_hdr, struct sr_tcp_hdr *tcp_hdr);

#endif
