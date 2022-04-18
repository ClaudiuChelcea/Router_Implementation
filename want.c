#include "queue.h"
#include "skel.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

typedef enum {
	FAILURE = -1,
	FALSE = 0,
	TRUE = 1
} bool;

// Strings are equal
#define STRING_EQ 0

// Verify condition
#define DIE_NEW(assertion,message)                               						\
if(assertion == TRUE) {										 							\
	fprintf(stderr, "Error at line %d in file %s!\n", __LINE__, __FILE__);				\
	perror(message);																	\
	exit(errno);																		\
}

// Allocate a pointer safe
#define SAFE_ALLOC(pointer,alloc_type,count,size)                                       \
if(strcmp(alloc_type, "malloc") == STRING_EQ) {											\
	*pointer = malloc(count * size);													\
	if(*pointer == NULL) {																\
		DIE_NEW(TRUE, "Couldn't allocate pointer!");									\
	}																					\
} else if (strcmp(alloc_type, "calloc") == STRING_EQ) {									\
	*pointer = calloc(count, size);														\
	if(*pointer == NULL) {																\
		DIE_NEW(TRUE, "Couldn't allocate pointer!");									\
	}																					\
} else {																				\
	DIE_NEW(TRUE, "Couldn't allocate pointer due to unrecognized alloc type!");			\
}																						\

#define MAX_ENTRIES 1L<<17
#define MAX_ARP_CACHE 1L	<<7

typedef struct route_table_entry route_table_entry;
typedef route_table_entry RTE;
typedef struct arp_entry arp_entry;
typedef arp_entry ARPE;
typedef struct ether_header ethhdr;
typedef struct iphdr iphdr;
typedef struct arp_header arphdr;
typedef struct icmphdr icmphdr;

// Route table and length
typedef struct RT_STRUCT {
	RTE* rtable;
	int rtable_len;
} RT_STRUCT;

// ARP table and length
typedef struct ARP_STRUCT {
	ARPE* arp_table;
	int arp_table_len;
} ARP_STRUCT;

// Used for qsort sorting
static inline int cmp_fct_sort(const void *a, const void *b) {
	// If prefixes are equal, return masks' difference
	// Otherwise return the prefixes' difference
	int diff = (uint32_t) ((RTE *)b)->prefix - (uint32_t) ((RTE *)a)->prefix;
	if(!diff) {
		return (uint32_t)  ((RTE *)b)->mask - (uint32_t)  ((RTE *)a)->mask;
	} else {
		return diff;
	}
}

// Create and return the routing table
static inline RT_STRUCT get_rtable(char* argv_1) {
	RT_STRUCT route_table = {NULL, 0};
	SAFE_ALLOC(&route_table.rtable, "calloc", MAX_ENTRIES, sizeof(RTE));
	route_table.rtable_len = read_rtable(argv_1, route_table.rtable);
	return route_table;
}

// Create and return the ARP table
static inline ARP_STRUCT get_arptable() {
	ARP_STRUCT arp_table = {NULL, 0};
	SAFE_ALLOC(&arp_table.arp_table, "calloc", MAX_ARP_CACHE, sizeof(ARPE));
	return arp_table;
}

// Increase checksum
static inline uint16_t add1_checksum(uint16_t checksum, int16_t ttl)
{
	int add = -(ttl - ~ttl);
	return (uint16_t) checksum + add;
}

// Check new checksum is correct
static inline int validate_checksum(iphdr *ip_hdr) {
	uint32_t start = ip_hdr->check;
    ip_hdr->check = 0;
    ip_hdr->check = ip_checksum((uint8_t*) ip_hdr, sizeof(iphdr));
    
    if (start == ip_hdr->check) {
        return TRUE;
    } else {
		return FALSE;
	}
}

// Get best route for arp table
static inline ARPE *get_best_route_arp(uint32_t ip, ARP_STRUCT arp_table)
{
    ARPE *entry = NULL;
    for (int i = 0; i < arp_table.arp_table_len; ++i) {
    	if (arp_table.arp_table[i].ip == ip) {
            entry = &arp_table.arp_table[i];
            break;
        }
    }
    return entry;
}

// Gest best route for rtable
static inline RTE* get_best_route(uint32_t dest_ip, RT_STRUCT rtable) {
	RTE *bc = NULL;
	for (int i = 0; i < rtable.rtable_len; ++i) {
		if ((rtable.rtable[i].mask & dest_ip) == rtable.rtable[i].prefix) {
			if (bc == NULL) {
				bc = &rtable.rtable[i];
			}
			else if(ntohl(bc->mask) < ntohl(rtable.rtable[i].mask)) {
				bc = &rtable.rtable[i];
			} 
		}
	}
	return bc;
}

// Forward package
static inline int forward(packet *message, ethhdr *eth_hdr, iphdr *ip_hdr, RT_STRUCT rtable, ARP_STRUCT arp_table)
{
	RTE* entry = get_best_route(ip_hdr->daddr, rtable);

	if ((*entry).mask == 0) {
		return FAILURE;
	} else {
		message->interface = entry->interface;
	}

	// Get MAC for next hop
	ARPE *arp_entry = get_best_route_arp((*entry).next_hop, arp_table);
	if (arp_entry == NULL) {
		return FAILURE;
	}

	// Change the address in the header
    memmove(eth_hdr->ether_dhost, arp_entry->mac, ETH_ALEN);
	get_interface_mac(entry->interface, eth_hdr->ether_shost);

	--ip_hdr->ttl;
	ip_hdr->check = ip_hdr->check - ~ip_hdr->ttl - ip_hdr->ttl;

	// Send packet
	send_packet(message);

	return TRUE;
}

// Send ICMP
static inline void send_icmp(int interface, ethhdr * eth_hdr, iphdr * ip_hdr,
                uint8_t type, uint8_t code)
{
	// Create packet
    packet icmp_packet;
    icmp_packet.interface = interface;

    // Get new headers
    ethhdr *aux_eth = (ethhdr *) icmp_packet.payload;
    iphdr *icmp_packet_ip = (iphdr *) (icmp_packet.payload + sizeof(*aux_eth));
    icmphdr *aux_icmp = (icmphdr *) (icmp_packet.payload + sizeof(*icmp_packet_ip) + sizeof(*aux_eth));
	DIE(!aux_eth || !icmp_packet_ip || !aux_icmp, "ICMP ERROR!");

    // Se completeaza header ip
    memcpy(icmp_packet_ip, ip_hdr, sizeof(iphdr));
    uint16_t daddr = icmp_packet_ip->daddr;
    icmp_packet_ip->daddr = ip_hdr->saddr;
    icmp_packet_ip->saddr = daddr;
    icmp_packet_ip->id = 0;
    icmp_packet_ip->ttl = 64;
    icmp_packet_ip->version = 4;
    icmp_packet_ip->protocol = 1;
    icmp_packet_ip->tot_len = htons(sizeof(icmphdr) + sizeof(iphdr));
    icmp_packet_ip->check = 0;
    icmp_packet_ip->check = ip_checksum((uint8_t *)icmp_packet_ip, sizeof(iphdr));
    
    // Se completeaza header ICMP
    aux_icmp->type = type;
    aux_icmp->code = code;
    aux_icmp->un.echo.sequence = 0;
    aux_icmp->un.echo.id = 0;
    aux_icmp->checksum = 0;
    aux_icmp->checksum = icmp_checksum((uint16_t *)aux_icmp, sizeof(icmphdr));

    // Scriu adresele MAC in ether header
    aux_eth->ether_type = htons(ETHERTYPE_IP);
    memcpy(aux_eth->ether_shost, eth_hdr->ether_dhost, 6);
    memcpy(aux_eth->ether_dhost, eth_hdr->ether_shost, 6);
    icmp_packet.len = sizeof(ethhdr) + sizeof(iphdr) + sizeof(icmphdr);

    // Se trimite packetul
    send_packet(&icmp_packet);
}

// Create an ARP request
static inline void create_arp_request(packet * message, RTE * entry){
    char *broad = "ff:ff:ff:ff:ff:ff";
	char *tha = "00:00:00:00:00:00";

    message->interface = entry->interface;
    message->len = sizeof(ethhdr) + sizeof(arphdr);

    ethhdr *eth_hdr = (ethhdr *)message->payload;
    arphdr *arp_hdr = (arphdr *)(message->payload + sizeof(ethhdr));

    // Completez arp header
    arp_hdr->htype = htons(ARPHRD_ETHER);
    arp_hdr->ptype = htons(2048);
    arp_hdr->hlen = 6;
    arp_hdr->plen = 4;
    arp_hdr->op = htons(ARPOP_REQUEST);

    get_interface_mac(entry->interface, arp_hdr->sha);
    uint32_t aux1 = inet_addr(get_interface_ip(entry->interface));
    // Setez source ip address cu adresa ip a interfetei prin care trimit
    arp_hdr->spa = aux1;
    // Setez target hardware address in 00:00...
    hwaddr_aton(tha, arp_hdr->tha);
    
    // Target IP address = ip adresa a next hop
    arp_hdr->tpa = entry->next_hop;

    eth_hdr->ether_type = htons(ETHERTYPE_ARP);
    // Source MAC Address = adresa mac a interfetei prin care se trimite
    get_interface_mac(entry->interface, eth_hdr->ether_shost);
    
    // Scriu adresa broadcast in ether header ca destinatie
    hwaddr_aton(broad, eth_hdr->ether_dhost);
}

// Create an ARP reply
static inline void create_arp_reply(packet * message, ethhdr * eth_hdr, arphdr * arp_hdr){
    uint32_t spa = arp_hdr->spa;
    uint32_t tpa = arp_hdr->tpa;
    arp_hdr->tpa = spa;
    arp_hdr->spa = tpa;
    memcpy(arp_hdr->tha, arp_hdr->sha, sizeof( arp_hdr->sha));
    get_interface_mac(message->interface, arp_hdr->sha);
    
    arp_hdr->op = htons(ARPOP_REPLY);

    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
    memcpy(eth_hdr->ether_shost, arp_hdr->sha, sizeof(arp_hdr->sha));
}

int main(int argc, char *argv[])
{
	init(argc - 2, argv + 2);

	// Route table
	RT_STRUCT route_table = get_rtable(argv[1]);
	qsort(route_table.rtable, route_table.rtable_len, sizeof(RTE), cmp_fct_sort);

	// ARP table
	ARP_STRUCT arp_table = get_arptable();

	// Variables
	iphdr* ip_hdr = NULL;
	arphdr* arp_hdr = NULL;
	icmphdr* icmp_hdr = NULL;

	// Packet queue
	queue my_queue = queue_create();
	
	// Get packets continuously
	do {
		// Get packet
		packet message;
		int rc = get_packet(&message);
		DIE_NEW(rc < 0, "Didn't receive packet");
		
		// Get ethernet header
		ethhdr *eth_hdr = (ethhdr *) message.payload;

		// Check if packet is for me
		uint8_t mac[6];
		bool for_me = TRUE;
		get_interface_mac(message.interface, mac);
		for(int i = 0; i < 6; ++i) {
			if(mac[i] != eth_hdr->ether_dhost[i]) {
				for(int j = 0; j < 6; ++j){
					if(eth_hdr->ether_dhost[j] != 0xff) 
						for_me = FALSE;
				}
			}
		}

		// Drop package
		if(for_me == FALSE)
			continue;

		// Verificare IP Header / ARP Header
		switch(ntohs(eth_hdr->ether_type)) {
			// IP
			case ETHERTYPE_IP:
				// Get header
				ip_hdr = (iphdr*)(message.payload + sizeof(ethhdr));
				DIE_NEW(!ip_hdr, "Couldn't get IP header!");

				// Validations
				if (validate_checksum(ip_hdr) == FALSE) {
					continue;
				}

				if (ip_hdr->ttl -1 <= 0) {
					send_icmp(message.interface, eth_hdr, ip_hdr, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
					continue;
				}
				
				// Check if we are tHe destination, otherwise forward the packet
				if (inet_addr(get_interface_ip(message.interface)) == ip_hdr->daddr && ip_hdr->protocol == 1) {
					
					// Get ICMP header
					icmp_hdr = (icmphdr *)(message.payload + sizeof(ethhdr) + sizeof(iphdr));
					DIE(!icmp_hdr, "Coulnd't get ICMP header!");
					if (icmp_hdr->type == ICMP_ECHO) {
						send_icmp(message.interface, eth_hdr, ip_hdr, ICMP_ECHOREPLY, 0);
						continue;
					}
				} else {
					int code = forward(&message, eth_hdr, ip_hdr, route_table, arp_table);
					// Daca forward a esuat cu codul 0 -> trimit ICMP Destination unreachable
					if (code == 0) {
						// Completarea header si trimitere ICMP
						send_icmp(message.interface, eth_hdr, ip_hdr, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);
						continue;
					}
					// Daca forward a esuat cu -1 -> salvez pachetul in coada si creez un ARP Request
					else if (code == -1) {
						// Adaug packetul in coada
						packet *aux = (packet *)calloc(1, sizeof(packet));
						memcpy(aux, &message, sizeof(packet));
						queue_enq(my_queue, aux);
						// Generez arp request
						RTE* entry = get_best_route(ip_hdr->daddr, route_table);
						packet p;
						create_arp_request(&p, entry);
						send_packet(&p);
						continue;
					}
					continue;
				}
			// ARP
			case ETHERTYPE_ARP:
				arp_hdr = (arphdr *)(message.payload + sizeof(ethhdr));
				// Deoarece e ARP salvez datele necesare in cache
				arp_table.arp_table[arp_table.arp_table_len].ip = arp_hdr->spa;
				memcpy(arp_table.arp_table[arp_table.arp_table_len].mac, arp_hdr->sha, 6);
				arp_table.arp_table_len++;
				if (ntohs(arp_hdr->op) == ARPOP_REQUEST) {
					// Am primit arp request -> creez arp reply
					create_arp_reply(&message, eth_hdr, arp_hdr);
					send_packet(&message);
					continue;
				}
				else if (ntohs(arp_hdr->op) == ARPOP_REPLY) {
					// Am primit arp reply -> trimit pachetele care il asteptau
					arp_hdr = (arphdr *)(message.payload + sizeof(ethhdr));
					queue aux_q = queue_create();

					packet * waiting_packet;
					iphdr* ip_hdr_waiting;
					ethhdr *eth_hdr_waiting;

					// Se cauta pachetele in coada
					while (!queue_empty(my_queue)) {
						waiting_packet = (packet *)queue_deq(my_queue);

						eth_hdr_waiting = (ethhdr *)waiting_packet->payload;
						ip_hdr_waiting = (iphdr*)(waiting_packet->payload + sizeof(ethhdr));

						if (get_best_route(ip_hdr_waiting->daddr, route_table)->next_hop == arp_hdr->spa) {
							// E Pachetul care il astepta -> trimite-l
							forward(waiting_packet, eth_hdr_waiting, ip_hdr_waiting, route_table, arp_table);
							// Pachetul care era adaugat in coada era alocat dinamic, deci il dezaloc
						}
						else {
							// Daca nu e pachetul necesar -> il pun in coada auxiliara
							queue_enq(aux_q, waiting_packet);
						}
					}
					// Reconstruiesc coada
					my_queue = aux_q;
				}

			default:
				DIE(TRUE, "HEADER UNRECOGNIZED! ONLY IP AND ARP IMPLEMENTED!");
				break;
		}
	} while (TRUE);

	return 0;
}