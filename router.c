#include "queue.h"
#include "skel.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

typedef enum {
	FALSE,
	TRUE
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

#define MAX_ENTRIES 1<<17
#define MAX_ARP_CACHE MAX_ENTRIES

typedef struct route_table_entry route_table_entry;
typedef route_table_entry RTE;
typedef struct arp_entry arp_entry;
typedef arp_entry ARPE;

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

// Create and return the routing table
RT_STRUCT get_rtable(char* argv_1) {
	RT_STRUCT route_table = {NULL, 0};
	SAFE_ALLOC(&route_table.rtable, "calloc", MAX_ENTRIES, sizeof(RTE));
	route_table.rtable_len = read_rtable(argv_1, route_table.rtable);
	return route_table;
}

// Create and return the ARP table
ARP_STRUCT get_arptable() {
	ARP_STRUCT arp_table = {NULL, 0};
	SAFE_ALLOC(&arp_table.arp_table, "calloc", MAX_ARP_CACHE, sizeof(ARPE));
	return arp_table;
}

uint16_t incremental_internet_checksum(uint16_t old_checksum, uint16_t old_v, uint16_t new_v){
    return old_checksum - ~old_v - new_v;
}

int compare(const void *a, const void *b) {
	uint32_t a1 = ((RTE *)a)->prefix;
    uint32_t b1 = ((RTE *)b)->prefix;
	int res = b1 - a1;
	if(res == 0){
		return ((RTE *)b)->mask - ((RTE *)a)->mask;
	}
    return res;
}

ARPE *get_arp_entry(uint32_t ip, ARPE *arp_table, int n) {
    ARPE *entry = NULL;

    int i;

    for (i = 0; i < n; i++) {
    	if (arp_table[i].ip == ip) {
            entry = &arp_table[i];
            break;
        }
    }
    return entry;
}

int validate_checksum(struct iphdr *ip_hdr) {
	uint32_t old_check = ip_hdr->check;
    ip_hdr->check = 0;
    ip_hdr->check = ip_checksum((uint8_t *)ip_hdr, sizeof(struct iphdr));
    
    if (old_check != ip_hdr->check) {
        return 0;
    }
    return 1;
}

void get_entry_binary(RTE *rtable, uint32_t ip, int low, int high, int* found){
    if(high < low) return;
    int mid = (low + high) / 2;
    uint32_t prefix = ip & rtable[mid].mask;
    if(prefix == rtable[mid].prefix) {
        (*found) = mid;
    }
    if(rtable[mid].prefix > prefix) get_entry_binary(rtable, ip, mid + 1, high, found);
    else get_entry_binary(rtable, ip, low, mid - 1, found);
}

RTE get_entry(RTE *rtable, int nr, uint32_t ip) {
    RTE ret;
    ret.mask = 0;
    int res = -1;
    get_entry_binary(rtable, ip, 0, nr - 1, &res);
    if(res != -1) ret = rtable[res];
	return ret;
}

int trimite_mai_departe(packet *message, RTE *rtable, int n, ARPE *arp_table, int narp, 
	struct ether_header *eth_hdr, struct iphdr *ip_hdr) {
	// Longest prefix match
	RTE entry = get_entry(rtable, n, ip_hdr->daddr);

	if (entry.mask == 0) {
		return 0;
	}

	// Se cauta in arp cache mac-ul pentru next hop
	ARPE *arp_entry = get_arp_entry(entry.next_hop, arp_table, narp);

	if (arp_entry == NULL) {
		return -1;
	}

	// rescrierea adrese din ethernet header
    memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETH_ALEN);
	get_interface_mac(entry.interface, eth_hdr->ether_shost);

	// update la ttl si la checksum
	ip_hdr->ttl--;
	ip_hdr->check = incremental_internet_checksum(ip_hdr->check, ip_hdr->ttl, ip_hdr->ttl);

	// trimiterea packetului
	message->interface = entry.interface;
	send_packet(message);

	return 1;
}

void send_icmp(int interface, struct ether_header * eth_hdr, 
                struct iphdr * ip_hdr, RTE * rtable, 
                int nr, ARPE * arptable, int na, 
                uint8_t type, uint8_t code){
    packet aux;
    aux.interface = interface;

    // Setez pointeri
    struct ether_header *aux_eth = (struct ether_header *)aux.payload;
    struct iphdr *aux_ip = (struct iphdr *)(aux.payload 
                            + sizeof(struct ether_header));
    struct icmphdr *aux_icmp = (struct icmphdr *)(aux.payload 
                                + sizeof(struct iphdr) 
                                + sizeof(struct ether_header));

    // Se completeaza header ip
    memcpy(aux_ip, ip_hdr, sizeof(struct iphdr));
    uint16_t daddr = aux_ip->daddr;
    aux_ip->daddr = ip_hdr->saddr;
    aux_ip->saddr = daddr;
    aux_ip->id = 0;
    aux_ip->ttl = 64;
    aux_ip->version = 4;
    aux_ip->protocol = 1;
    aux_ip->tot_len = htons(sizeof(struct icmphdr) + sizeof(struct iphdr));
    aux_ip->check = 0;
    aux_ip->check = ip_checksum((uint8_t *)aux_ip, sizeof(struct iphdr));
    
    // Se completeaza header ICMP
    aux_icmp->type = type;
    aux_icmp->code = code;
    aux_icmp->un.echo.sequence = 0;
    aux_icmp->un.echo.id = 0;
    aux_icmp->checksum = 0;
    aux_icmp->checksum = icmp_checksum((uint16_t *)aux_icmp, sizeof(struct icmphdr));

    // Scriu adresele MAC in ether header
    aux_eth->ether_type = htons(ETHERTYPE_IP);
    memcpy(aux_eth->ether_shost, eth_hdr->ether_dhost, 6);
    memcpy(aux_eth->ether_dhost, eth_hdr->ether_shost, 6);
    aux.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
    // Se trimite packetul
    send_packet(&aux);
}

void create_arp_request(packet * message, RTE * entry){
    char *broad = "ff:ff:ff:ff:ff:ff";
	char *tha = "00:00:00:00:00:00";

    message->interface = entry->interface;
    message->len = sizeof(struct ether_header) + sizeof(struct arp_header);

    struct ether_header *eth_hdr = (struct ether_header *)message->payload;
    struct arp_header *arp_hdr = (struct arp_header *)(message->payload + sizeof(struct ether_header));

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

void create_arp_reply(packet * message, struct ether_header * eth_hdr, struct arp_header * arp_hdr){
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


/**
 * @brief Verificare daca packet pentru router
 * 
 * @param message packet
 * @return int 1 daca da si 0 cazs contrar
 */
int verify_for_router(packet * message){
	struct ether_header *eth_hdr = (struct ether_header *)message->payload;
	uint8_t mac[6];
	get_interface_mac(message->interface, mac);
	for(int i = 0; i < 6; i++){
		if(mac[i] != eth_hdr->ether_dhost[i]){
			for(int j = 0; j < 6; j++){
				if(eth_hdr->ether_dhost[j] != 0xff) return 0;
			}
			return 1;
		}
	}
	return 1;
}

int main(int argc, char *argv[])
{
	init(argc - 2, argv + 2);

	// Route table
	RT_STRUCT route_table = get_rtable(argv[1]);
	qsort(route_table.rtable, route_table.rtable_len, sizeof(RTE), compare);

	// ARP table
	ARP_STRUCT arp_table = get_arptable();

	// Packet queue
	queue my_queue = queue_create();
	
	while (TRUE) {
		// Get packet
		packet message;
		int rc = get_packet(&message);
		DIE_NEW(rc < 0, "Didn't receive packet");

		struct ether_header *eth_hdr = (struct ether_header *)message.payload;
		if(verify_for_router(&message) == 0) continue;
		// Verificare daca e IP Header
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			struct iphdr *ip_hdr = (struct iphdr *)(message.payload + sizeof(struct ether_header));
			// Verific TTL
			if (ip_hdr->ttl <= 1) {
				// ICMP TTL Exceeded
				send_icmp(message.interface, eth_hdr, ip_hdr, route_table.rtable, route_table.rtable_len, arp_table.arp_table, arp_table.arp_table_len, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
				continue;
			}
			// Validare Checksum
			if (!validate_checksum(ip_hdr)) {
				continue;
			}
			// Verificare daca destinatia din IP Header e routerul asta
			// Si daca IP Protocol e 1 -> ICMP atunci e pentru router
			if (ip_hdr->protocol == 1 && inet_addr(get_interface_ip(message.interface)) == ip_hdr->daddr) {
				// Extrag headerul ICMP
				struct icmphdr *icmp_hdr = (struct icmphdr *)(message.payload + sizeof(struct ether_header) + 
					sizeof(struct iphdr));
				// Daca e echo request
				if (icmp_hdr->type == ICMP_ECHO) {
					// Trimit echo reply
					send_icmp(message.interface, eth_hdr, ip_hdr, route_table.rtable, route_table.rtable_len, arp_table.arp_table, arp_table.arp_table_len, ICMP_ECHOREPLY, 0);
					continue;
				}
			}
			// Daca e altfel de pachet
			else {
				// Trebuie trimis mai departe
				int code = trimite_mai_departe(&message, route_table.rtable, route_table.rtable_len, arp_table.arp_table, arp_table.arp_table_len, eth_hdr, ip_hdr);
				// Daca forward a esuat cu codul 0 -> trimit ICMP Destination unreachable
				if (code == 0) {
					// Completarea header si trimitere ICMP
					send_icmp(message.interface, eth_hdr, ip_hdr, route_table.rtable, route_table.rtable_len, arp_table.arp_table, arp_table.arp_table_len, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);
					continue;
				}
				// Daca forward a esuat cu -1 -> salvez pachetul in coada si creez un ARP Request
				else if (code == -1) {
					// Adaug packetul in coada
					packet *aux = (packet *)calloc(1, sizeof(packet));
					memcpy(aux, &message, sizeof(packet));
					queue_enq(my_queue, aux);
					// Generez arp request
					RTE entry = get_entry(route_table.rtable, route_table.rtable_len, ip_hdr->daddr);
					packet p;
					create_arp_request(&p, &entry);
					send_packet(&p);
					continue;
				}
				continue;
			}
		}
		// Verificare de protocol ARP 
		else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
        	struct arp_header *arp_hdr = (struct arp_header *)(message.payload + sizeof(struct ether_header));
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
				struct arp_header *arp_hdr = (struct arp_header *)(message.payload + sizeof(struct ether_header));
				queue aux_q = queue_create();

    			packet * waiting_packet;
				struct iphdr *ip_hdr_waiting;
				struct ether_header *eth_hdr_waiting;

				// Se cauta pachetele in coada
    			while (!queue_empty(my_queue)) {
    				waiting_packet = (packet *)queue_deq(my_queue);

					eth_hdr_waiting = (struct ether_header *)waiting_packet->payload;
    				ip_hdr_waiting= (struct iphdr *)(waiting_packet->payload + sizeof(struct ether_header));

    				if (get_entry(route_table.rtable, route_table.rtable_len, ip_hdr_waiting->daddr).next_hop == arp_hdr->spa) {
						// E Pachetul care il astepta -> trimite-l
    					trimite_mai_departe(waiting_packet, route_table.rtable, route_table.rtable_len, arp_table.arp_table, arp_table.arp_table_len, eth_hdr_waiting, ip_hdr_waiting);
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
		}
	}
}
