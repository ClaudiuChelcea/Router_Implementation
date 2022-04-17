#include "queue.h"
#include "skel.h"
#include <stdio.h>



#define MAX_ENTRIES 1<<17
#define MAX_ARP_CACHE MAX_ENTRIES

uint16_t incremental_internet_checksum(uint16_t old_checksum, uint16_t old_v, uint16_t new_v){
    return old_checksum - ~old_v - new_v;
}

int compare(const void *a, const void *b) {
	uint32_t a1 = ((struct route_table_entry *)a)->prefix;
    uint32_t b1 = ((struct route_table_entry *)b)->prefix;
	int res = b1 - a1;
	if(res == 0){
		return ((struct route_table_entry *)b)->mask - ((struct route_table_entry *)a)->mask;
	}
    return res;
}

struct arp_entry *get_arp_entry(uint32_t ip, struct arp_entry *arp_table, int n) {
    struct arp_entry *entry = NULL;

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

void get_entry_binary(struct route_table_entry *rtable, uint32_t ip, int low, int high, int* found){
    if(high < low) return;
    int mid = (low + high) / 2;
    uint32_t prefix = ip & rtable[mid].mask;
    if(prefix == rtable[mid].prefix) {
        (*found) = mid;
    }
    if(rtable[mid].prefix > prefix) get_entry_binary(rtable, ip, mid + 1, high, found);
    else get_entry_binary(rtable, ip, low, mid - 1, found);
}

struct route_table_entry get_entry(struct route_table_entry *rtable, int nr, uint32_t ip) {
    struct route_table_entry ret;
    ret.mask = 0;
    int res = -1;
    get_entry_binary(rtable, ip, 0, nr - 1, &res);
    if(res != -1) ret = rtable[res];
	return ret;
}

int trimite_mai_departe(packet *m, struct route_table_entry *rtable, int n, struct arp_entry *arp_table, int narp, 
	struct ether_header *eth_hdr, struct iphdr *ip_hdr) {
	// Longest prefix match
	struct route_table_entry entry = get_entry(rtable, n, ip_hdr->daddr);

	if (entry.mask == 0) {
		return 0;
	}

	// Se cauta in arp cache mac-ul pentru next hop
	struct arp_entry *arp_entry = get_arp_entry(entry.next_hop, arp_table, narp);

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
	m->interface = entry.interface;
	send_packet(m);

	return 1;
}

void send_icmp(int interface, struct ether_header * eth_hdr, 
                struct iphdr * ip_hdr, struct route_table_entry * rtable, 
                int nr, struct arp_entry * arptable, int na, 
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

void create_arp_request(packet * m, struct route_table_entry * entry){
    char *broad = "ff:ff:ff:ff:ff:ff";
	char *tha = "00:00:00:00:00:00";

    m->interface = entry->interface;
    m->len = sizeof(struct ether_header) + sizeof(struct arp_header);

    struct ether_header *eth_hdr = (struct ether_header *)m->payload;
    struct arp_header *arp_hdr = (struct arp_header *)(m->payload + sizeof(struct ether_header));

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

void create_arp_reply(packet * m, struct ether_header * eth_hdr, struct arp_header * arp_hdr){
    uint32_t spa = arp_hdr->spa;
    uint32_t tpa = arp_hdr->tpa;
    arp_hdr->tpa = spa;
    arp_hdr->spa = tpa;
    memcpy(arp_hdr->tha, arp_hdr->sha, sizeof( arp_hdr->sha));
    get_interface_mac(m->interface, arp_hdr->sha);
    
    arp_hdr->op = htons(ARPOP_REPLY);

    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
    memcpy(eth_hdr->ether_shost, arp_hdr->sha, sizeof(arp_hdr->sha));
}


/**
 * @brief Verificare daca packet pentru router
 * 
 * @param m packet
 * @return int 1 daca da si 0 cazs contrar
 */
int verify_for_router(packet * m){
	struct ether_header *eth_hdr = (struct ether_header *)m->payload;
	uint8_t mac[6];
	get_interface_mac(m->interface, mac);
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
	packet m;
	int rc;

	// Do not modify this line
	init(argc - 2, argv + 2);
	// Crearea coada de pachete
	queue q = queue_create();
	// Citire route table
	struct route_table_entry * rtable = calloc(MAX_ENTRIES, sizeof(struct route_table_entry));
	int rtable_size = read_rtable(argv[1], rtable);
	// Alocare pentru arp table cache
	struct arp_entry *arptable = calloc(MAX_ARP_CACHE, sizeof(struct arp_entry));
	int arptable_size = 0;
	// Sortare route table
	qsort(rtable, rtable_size, sizeof(struct route_table_entry), compare);
	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");
		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		if(verify_for_router(&m) == 0) continue;
		// Verificare daca e IP Header
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
			// Verific TTL
			if (ip_hdr->ttl <= 1) {
				// ICMP TTL Exceeded
				send_icmp(m.interface, eth_hdr, ip_hdr, rtable, rtable_size, arptable, arptable_size, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
				continue;
			}
			// Validare Checksum
			if (!validate_checksum(ip_hdr)) {
				continue;
			}
			// Verificare daca destinatia din IP Header e routerul asta
			// Si daca IP Protocol e 1 -> ICMP atunci e pentru router
			if (ip_hdr->protocol == 1 && inet_addr(get_interface_ip(m.interface)) == ip_hdr->daddr) {
				// Extrag headerul ICMP
				struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + sizeof(struct ether_header) + 
					sizeof(struct iphdr));
				// Daca e echo request
				if (icmp_hdr->type == ICMP_ECHO) {
					// Trimit echo reply
					send_icmp(m.interface, eth_hdr, ip_hdr, rtable, rtable_size, arptable, arptable_size, ICMP_ECHOREPLY, 0);
					continue;
				}
			}
			// Daca e altfel de pachet
			else {
				// Trebuie trimis mai departe
				int code = trimite_mai_departe(&m, rtable, rtable_size, arptable, arptable_size, eth_hdr, ip_hdr);
				// Daca forward a esuat cu codul 0 -> trimit ICMP Destination unreachable
				if (code == 0) {
					// Completarea header si trimitere ICMP
					send_icmp(m.interface, eth_hdr, ip_hdr, rtable, rtable_size, arptable, arptable_size, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);
					continue;
				}
				// Daca forward a esuat cu -1 -> salvez pachetul in coada si creez un ARP Request
				else if (code == -1) {
					// Adaug packetul in coada
					packet *aux = (packet *)calloc(1, sizeof(packet));
					memcpy(aux, &m, sizeof(packet));
					queue_enq(q, aux);
					// Generez arp request
					struct route_table_entry entry = get_entry(rtable, rtable_size, ip_hdr->daddr);
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
        	struct arp_header *arp_hdr = (struct arp_header *)(m.payload + sizeof(struct ether_header));
			// Deoarece e ARP salvez datele necesare in cache
			arptable[arptable_size].ip = arp_hdr->spa;
			memcpy(arptable[arptable_size].mac, arp_hdr->sha, 6);
			arptable_size++;
    		if (ntohs(arp_hdr->op) == ARPOP_REQUEST) {
				// Am primit arp request -> creez arp reply
				create_arp_reply(&m, eth_hdr, arp_hdr);
				send_packet(&m);
				continue;
        	}
        	else if (ntohs(arp_hdr->op) == ARPOP_REPLY) {
				// Am primit arp reply -> trimit pachetele care il asteptau
				struct arp_header *arp_hdr = (struct arp_header *)(m.payload + sizeof(struct ether_header));
				queue aux_q = queue_create();

    			packet * waiting_packet;
				struct iphdr *ip_hdr_waiting;
				struct ether_header *eth_hdr_waiting;

				// Se cauta pachetele in coada
    			while (!queue_empty(q)) {
    				waiting_packet = (packet *)queue_deq(q);

					eth_hdr_waiting = (struct ether_header *)waiting_packet->payload;
    				ip_hdr_waiting= (struct iphdr *)(waiting_packet->payload + sizeof(struct ether_header));

    				if (get_entry(rtable, rtable_size, ip_hdr_waiting->daddr).next_hop == arp_hdr->spa) {
						// E Pachetul care il astepta -> trimite-l
    					trimite_mai_departe(waiting_packet, rtable, rtable_size, arptable, arptable_size, eth_hdr_waiting, ip_hdr_waiting);
						// Pachetul care era adaugat in coada era alocat dinamic, deci il dezaloc
    				}
					else {
						// Daca nu e pachetul necesar -> il pun in coada auxiliara
						queue_enq(aux_q, waiting_packet);
					}
    			}
				// Reconstruiesc coada
    			q = aux_q;
        	}
		}
	}
}
