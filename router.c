#include "queue.h"
#include "skel.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    FAILURE = -1,
    FALSE = 0,
    TRUE = 1
} bool;

// Strings are equal
#define STRING_EQ 0

// Verify condition
#define DIE_NEW(assertion, message)                                                 \
    if (assertion == TRUE) {                                                        \
        fprintf(stderr, "Error at line %d in file %s!\n", __LINE__, __FILE__);      \
        perror(message);                                                            \
        exit(errno);                                                                \
    }

// Allocate a pointer safe
#define SAFE_ALLOC(pointer, alloc_type, count, size)                                \
    if (strcmp(alloc_type, "malloc") == STRING_EQ) {                                \
        *pointer = malloc(count * size);                                            \
        if (*pointer == NULL) {                                                     \
            DIE_NEW(TRUE, "Couldn't allocate pointer!");                            \
        }                                                                           \
    } else if (strcmp(alloc_type, "calloc") == STRING_EQ) {                         \
        *pointer = calloc(count, size);                                             \
        if (*pointer == NULL) {                                                     \
            DIE_NEW(TRUE, "Couldn't allocate pointer!");                            \
        }                                                                           \
    } else {                                                                        \
        DIE_NEW(TRUE, "Couldn't allocate pointer due to unrecognized alloc type!"); \
    }

#define MAX_ENTRIES 1 << 17
#define MAX_ARP_CACHE 1 << 7
#define MAC_LEN 6

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
static inline int cmp_fct_sort(const void* a, const void* b)
{
    // If prefixes are equal, return masks' difference
    // Otherwise return the prefixes' difference
    int diff = (uint32_t)((RTE*)b)->prefix - (uint32_t)((RTE*)a)->prefix;
    if (!diff) {
        return (uint32_t)((RTE*)b)->mask - (uint32_t)((RTE*)a)->mask;
    } else {
        return diff;
    }
}

// Create and return the routing table
static inline RT_STRUCT get_rtable(char* argv_1)
{
    RT_STRUCT route_table = { NULL, 0 };
    SAFE_ALLOC(&route_table.rtable, "calloc", MAX_ENTRIES, sizeof(RTE));
    route_table.rtable_len = read_rtable(argv_1, route_table.rtable);
    return route_table;
}

// Create and return the ARP table
static inline ARP_STRUCT get_arptable()
{
    ARP_STRUCT arp_table = { NULL, 0 };
    SAFE_ALLOC(&arp_table.arp_table, "calloc", MAX_ARP_CACHE, sizeof(ARPE));
    return arp_table;
}

// Check if the packet is received correctly using checksum
static inline int is_checksum_correct(iphdr* ip_hdr)
{
    int ip_hdr_check = ip_hdr->check;
    ip_hdr->check = 0;
    ip_hdr->check = ip_checksum((uint8_t*)ip_hdr, sizeof(struct iphdr));
    if (ip_hdr->check == ip_hdr_check) {
        return TRUE;
	} else {
    	return FALSE;
	}
}

// Get the index of the ip in the route_table
static inline void get_rt_ip_index(RT_STRUCT rtable, uint32_t ip, int low, int high, int* index)
{
    // Stop condition
    if (high < low) {
        return;
    } else { // Loop
        int mid = (low + high) / 2;
        uint32_t prefix = ip & rtable.rtable[mid].mask;
        if (prefix == rtable.rtable[mid].prefix) {
            (*index) = mid;
        }

        if (rtable.rtable[mid].prefix > prefix) {
            get_rt_ip_index(rtable, ip, mid + 1, high, index);
        } else {
            get_rt_ip_index(rtable, ip, low, mid - 1, index);
        }
    }
}

// Return the biggest set bite position
static inline int biggest_bit_index(int n)
{
    int cnt = 0;
    while (n) {
        ++cnt;
        n >>= 1;
    }

    return cnt;
}

// Get best entry in rtable with binary search
static inline RTE get_best_route_rtable(RT_STRUCT rtable, uint32_t ip)
{
    // Create default route
    RTE route;
    route.mask = 0;

    // Index of route in the rtable
    int index = 0;

    // Find route
    get_rt_ip_index(rtable, ip, 0, rtable.rtable_len - 1, &index);

    // Return rtable entry
    if (index == -1) {
        return route;
    } else {
        route = rtable.rtable[index];
        return route;
    }
}

// Get best route for arp table
static inline ARPE* get_best_route_arp(uint32_t ip, ARP_STRUCT arp_table)
{
    for (int i = 0; i < arp_table.arp_table_len; ++i) {
        if (arp_table.arp_table[i].ip == ip) {
            return &arp_table.arp_table[i];
        }
    }
    return NULL;
}

// Forward package
static inline int forward(packet* message, ethhdr* eth_hdr, iphdr* ip_hdr, RT_STRUCT rtable, ARP_STRUCT arp_table)
{
    RTE entry = get_best_route_rtable(rtable, ip_hdr->daddr);

    if (entry.mask == 0) {
        return FALSE;
    } else {
        message->interface = entry.interface;
    }

    // Get MAC for next hop
    ARPE* arp_entry = get_best_route_arp(entry.next_hop, arp_table);
    if (arp_entry == NULL) {
        return FAILURE;
    }

    // Change the address in the header
    memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETH_ALEN);
    get_interface_mac(entry.interface, eth_hdr->ether_shost);

    --ip_hdr->ttl;
    ip_hdr->check = ip_hdr->check - ~ip_hdr->ttl - ip_hdr->ttl;

    // Send packet
    send_packet(message);

    return TRUE;
}

// Send ICMP
static inline void send_icmp(int interface, ethhdr* eth_hdr, iphdr* ip_hdr,
    uint8_t type, uint8_t code)
{
	// Check receiving headers correctly
	DIE(!eth_hdr, "DIDN'T RECEIVE ETH_HEADER CORRECTLY. Can't send ICMP!");
	DIE(!ip_hdr, "DIDN'T RECEIVE IP_HEADER CORRECTLY. Can't send ICMP!");

    // Create packet
    packet icmp_packet;
	icmp_packet.interface = interface;

    // Get new headers
    ethhdr* aux_eth = (ethhdr*)icmp_packet.payload;
    iphdr* icmp_packet_ip = (iphdr*)(icmp_packet.payload + sizeof(*aux_eth));
    icmphdr* aux_icmp = (icmphdr*)(icmp_packet.payload + sizeof(*icmp_packet_ip) + sizeof(*aux_eth));
    DIE(!aux_eth || !icmp_packet_ip || !aux_icmp, "ICMP SEND ERROR!");

	// Complete ICMP header
    aux_icmp->type = type;
    aux_icmp->code = code;
    aux_icmp->un.echo.sequence = 0;
    aux_icmp->un.echo.id = 0;
    aux_icmp->checksum = 0;
    aux_icmp->checksum = icmp_checksum((uint16_t*)aux_icmp, sizeof(icmphdr));

    // Create header
    memcpy(icmp_packet_ip, ip_hdr, sizeof(iphdr));
    uint16_t daddr = icmp_packet_ip->daddr;
    icmp_packet_ip->daddr = ip_hdr->saddr;
    icmp_packet_ip->saddr = daddr;
    icmp_packet_ip->id = 0;
    icmp_packet_ip->ttl = 1<<6;
    icmp_packet_ip->version = 4;
    icmp_packet_ip->protocol = 1;
    icmp_packet_ip->tot_len = htons(sizeof(icmphdr) + sizeof(iphdr));
    icmp_packet_ip->check = 0;
    icmp_packet_ip->check = ip_checksum((uint8_t*)icmp_packet_ip, sizeof(iphdr));

    // Write MAC addresses in header and send
    aux_eth->ether_type = htons(ETHERTYPE_IP);
    memcpy(aux_eth->ether_shost, eth_hdr->ether_dhost, MAC_LEN);
    memcpy(aux_eth->ether_dhost, eth_hdr->ether_shost, MAC_LEN);
    icmp_packet.len = sizeof(*aux_eth) + sizeof(*icmp_packet_ip) + sizeof(*aux_icmp);
    send_packet(&icmp_packet);
}

// Create arp request in entry
static inline void create_arp_request(packet* message, RTE* entry)
{
	// Change message	
    message->interface = entry->interface;
    message->len = sizeof(ethhdr) + sizeof(arphdr);

	// Get headers from message and complete them
    ethhdr* eth_hdr = (ethhdr*)message->payload;
	DIE(!eth_hdr, "Couldn't get ETHERNET HEADER!");
    arphdr* arp_hdr = (arphdr*)(message->payload + sizeof(ethhdr));
    DIE(!arp_hdr, "Couldn't get ARP HEADER!");
	arp_hdr->htype = htons(ARPHRD_ETHER);
    arp_hdr->ptype = htons(1<<11);
    arp_hdr->hlen = 6;
    arp_hdr->plen = 4;
    arp_hdr->op = htons(ARPOP_REQUEST);
    get_interface_mac(entry->interface, arp_hdr->sha);
    arp_hdr->spa = inet_addr(get_interface_ip(entry->interface));
    hwaddr_aton("00:00:00:00:00:00", arp_hdr->tha);
    arp_hdr->tpa = entry->next_hop;
    eth_hdr->ether_type = htons(ETHERTYPE_ARP);
    get_interface_mac(entry->interface, eth_hdr->ether_shost);
    hwaddr_aton("ff:ff:ff:ff:ff:ff", eth_hdr->ether_dhost);
}

// Swap two ints
static inline void uint32_t_swap(uint32_t* a, uint32_t* b) {
	int tmp = * (uint32_t*) a;
	*a = * (uint32_t*) b;
	*b = tmp;
}

// Create ARP reply
static inline void create_arp_reply(packet* message, ethhdr* eth_hdr, arphdr* arp_hdr)
{
	// Swap tpa and spa
	uint32_t_swap(&arp_hdr->tpa, &arp_hdr->spa);

	// Change header
    memcpy(arp_hdr->tha, arp_hdr->sha, sizeof(arp_hdr->sha));
    get_interface_mac(message->interface, arp_hdr->sha);
    arp_hdr->op = htons(ARPOP_REPLY);
    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
    memcpy(eth_hdr->ether_shost, arp_hdr->sha, sizeof(arp_hdr->sha));
}

int main(int argc, char* argv[])
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
    iphdr* waiting_iphdr = NULL;
    packet* tmp = NULL;
    packet* waiting_packet = NULL;
    waiting_iphdr;
    ethhdr* waiting_ethhdr = NULL;
    RTE* entry = NULL;
    RTE arp_entry;
    queue tmp_queue;
    packet packet_arp_request;

    // Packet queue
    queue my_queue = queue_create();

    // Get packets continuously
    do {
        // Get packet
        packet message;
        int rc = get_packet(&message);
        DIE_NEW(rc < 0, "Didn't receive packet");

        // Get ethernet header
        ethhdr* eth_hdr = (ethhdr*)message.payload;

        // Check if packet is for me
        uint8_t mac[MAC_LEN];
        bool for_me = TRUE;
        get_interface_mac(message.interface, mac);
        for (int i = 0; i < 6; ++i) {
            if (mac[i] != eth_hdr->ether_dhost[i]) {
                for (int j = 0; j < 6; ++j) {
                    if (eth_hdr->ether_dhost[j] != 0xff)
                        for_me = FALSE;
                }
            }
        }

        // Drop package
        if (for_me == FALSE)
            continue;

        // Verificare IP Header / ARP Header
        switch (ntohs(eth_hdr->ether_type)) {
        // IP
        case ETHERTYPE_IP:
            // Get header
            ip_hdr = (iphdr*)(message.payload + sizeof(ethhdr));
            DIE_NEW(!ip_hdr, "Couldn't get IP header!");

            // Validations
            if (is_checksum_correct(ip_hdr) == FALSE) {
                continue;
            }

            if (ip_hdr->ttl - 1 <= 0) {
                send_icmp(message.interface, eth_hdr, ip_hdr, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
                continue;
            }

            // Check if we are tHe destination, otherwise forward the packet
            if (inet_addr(get_interface_ip(message.interface)) == ip_hdr->daddr && ip_hdr->protocol == 1) {

                // Get ICMP header
                icmp_hdr = (icmphdr*)(message.payload + sizeof(ethhdr) + sizeof(iphdr));
                DIE(!icmp_hdr, "Coulnd't get ICMP header!");
                if (icmp_hdr->type == ICMP_ECHO) {
                    send_icmp(message.interface, eth_hdr, ip_hdr, ICMP_ECHOREPLY, 0);
                    continue;
                }
            } else {
                int forward_ans = forward(&message, eth_hdr, ip_hdr, route_table, arp_table);
                if (forward_ans == FALSE) {
                    send_icmp(message.interface, eth_hdr, ip_hdr, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);
                } else if (forward_ans == FAILURE) { // Save it to queue
                    SAFE_ALLOC(&tmp, "calloc", 1, sizeof(packet));
                    DIE(!tmp, "Couldn't queue packet!");

                    memcpy(tmp, &message, sizeof(packet));
                    queue_enq(my_queue, tmp);

                    // Create ARP request
                    arp_entry = get_best_route_rtable(route_table, ip_hdr->daddr);
                    create_arp_request(&packet_arp_request, &arp_entry);
                    send_packet(&packet_arp_request);
                }

                // In the end, always continue
                continue;
            }
            break;

        // ARP
        case ETHERTYPE_ARP:
            // Get header
            arp_hdr = (arphdr*)(message.payload + sizeof(ethhdr));
            DIE(!arp_hdr, "Couldn't get arp header!");

            // Save in cache
            arp_table.arp_table[arp_table.arp_table_len].ip = arp_hdr->spa;
            memcpy(arp_table.arp_table[arp_table.arp_table_len++].mac, arp_hdr->sha, MAC_LEN);

            // Decide if we have an request or reply
            switch (ntohs(arp_hdr->op)) {
            // If request, we reply
            case ARPOP_REQUEST:
                create_arp_reply(&message, eth_hdr, arp_hdr);
                send_packet(&message);
                continue;
                break;

            // If reply, send waiting packets
            case ARPOP_REPLY:
                // Create queue of packets
                tmp_queue = queue_create();
                DIE(!tmp_queue, "Couldn't create auxiliary queue!");

                // Get packets
                while (queue_empty(my_queue) == FALSE) {
                    // Get packet
                    waiting_packet = (packet*)queue_deq(my_queue);
                    DIE(!waiting_packet, "Couldn't get waiting packet!");

                    // Get ethernet header
                    waiting_ethhdr = (ethhdr*)waiting_packet->payload;
                    DIE(!waiting_ethhdr, "Couldn't get ethernet header of waiting packet!");

                    // Get IP header
                    waiting_iphdr = (iphdr*)(waiting_packet->payload + sizeof(ethhdr));
                    DIE(!waiting_iphdr, "Couldn't get IP header of waiting packet!");

                    if (get_best_route_rtable(route_table, waiting_iphdr->daddr).next_hop == arp_hdr->spa) {
                        forward(waiting_packet, waiting_ethhdr, waiting_iphdr, route_table, arp_table);
                    } else {
                        queue_enq(tmp_queue, waiting_packet);
                    }
                }

                // Get the unsent packages back
                my_queue = tmp_queue;
                break;

            default:
                DIE(TRUE, "Not request nor reply!");
                break;
            }
            break;

        default:
            DIE(TRUE, "HEADER UNRECOGNIZED! ONLY IP AND ARP IMPLEMENTED!");
            break;
        }
    } while (TRUE);

    return 0;
}