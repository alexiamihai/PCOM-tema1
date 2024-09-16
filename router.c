#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "queue.h"
#include "lib.h"
#include "protocols.h"

/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* ARP table */
struct arp_table_entry *arp_table;
int arp_table_len;

// arp table dinamic
struct arp_table_entry *new_arp_table;
int new_arp_table_len;

queue q;

typedef struct trie {
	struct route_table_entry *route;
	struct trie *childnode[2];
} trie;

typedef struct arppacket {
	uint32_t ip_dest;
	int interface;
	char *packet;
	size_t len;
} arppack;

// functie pentru a verifica tipul protocolului
int check_protocol(uint16_t protocol_type) {
    int ok = -1; // nu ne intereseaza
    if (protocol_type == 0x0800) {
        ok = 0; // ip
    }
    if (protocol_type == 0x0806) {
        ok = 1; // arp
    }
    return ok;
}

/*
 Returns a pointer (eg. &rtable[i]) to the best matching route, or NULL if there
 is no matching route.
*/
struct route_table_entry *get_best_route(uint32_t ip_dest) {
    /* We can iterate through rtable for (int i = 0; i < rtable_len; i++)*/
    struct route_table_entry *best = NULL;
    for (int i = 0; i < rtable_len; i++) {
        if ((ip_dest & rtable[i].mask) == rtable[i].prefix) {

            if (best == NULL)
                best = &rtable[i];
            else if (ntohl(best->mask) < ntohl(rtable[i].mask)) {
                best = &rtable[i];
            }
        }
    }
    return best;
}

struct arp_table_entry *get_arp_entry(uint32_t ip_dest) {
    /* We can iterate through the arp_table for (int i = 0; i < arp_table_len; i++) */

    for (int i = 0; i < new_arp_table_len; i++) {
        if (new_arp_table[i].ip == ip_dest) {
            return &new_arp_table[i];
        }
    }
    return NULL;
}

void insert_in_trie(trie *root, struct route_table_entry *route, uint32_t mask, uint32_t prefix) {
    // incepem de la radacina
    trie *currentnode = root;
    int i, currentbit;

    for (i = 31; i >= 0; i--) {
        currentbit = (prefix >> i) & 1;
        // verific daca bitul corespunzator din masca e setat
        if (mask & (1 << i)) {
            if (currentnode->childnode[currentbit] == NULL) {
                // aloc memorie pentru un copil nou si il initializez
                currentnode->childnode[currentbit] = malloc(sizeof(trie));
				currentnode->childnode[currentbit]->route = NULL;
				currentnode->childnode[currentbit]->childnode[0] = NULL;
				currentnode->childnode[currentbit]->childnode[1] = NULL;
            }
            currentnode = currentnode->childnode[currentbit];
        } else {
            break;
        }
    }
    currentnode->route = route;
}

struct route_table_entry *search_in_trie(trie *root, uint32_t ip_dest) {
	struct route_table_entry *best = NULL;
	trie* currentnode = root;
	int currentbit, i;
    // parcurg adresa bit cu bit si extrag bitul corespunzator pentru fiecare nivel
   	for (i = 31; i >= 0; i--) {
		currentbit = (ip_dest >> i) & 1;
        if (currentnode->childnode[currentbit] != NULL) {
            // actualizez ruta si ma mut pe nodul copil
			currentnode = currentnode->childnode[currentbit];
			best = currentnode->route;
        }
        // ruta gresita
		else {
			break;
		}
    }
    return best;
}

void set_arp_header(struct arp_header *arp_header, int arp_type, uint32_t ip_sender, u_int32_t ip_dest, int interface,  uint8_t *mac_dest)
{
    arp_header->htype = htons(1);
	arp_header->ptype = htons(0x0800);
	arp_header->hlen = 6;
	arp_header->plen = 4;
	arp_header->op = htons(arp_type);

    // am obtinut adresa mac a interfetei senderului si am copiat adresa destinatiei
    get_interface_mac(interface, arp_header->sha); // adresa mac senderului
    memcpy(arp_header->tha, mac_dest, 6 * sizeof(uint8_t)); // adresa mac target

	arp_header->spa = ip_sender; // adresa ip sender
	arp_header->tpa = ip_dest;	// adresa ip target
}

void set_ethernet_header(struct ether_header *eth_header, uint8_t *mac, int interface) {
    // am obtinut adresa mac a interfetei senderului si am copiat adresa destinatiei
    memcpy(eth_header->ether_dhost, mac, 6 * sizeof(uint8_t));
	get_interface_mac(interface, eth_header->ether_shost);
	eth_header->ether_type = htons(0x0806); // protocol arp
}

void handle_arp_request(uint32_t ip, int interface) {
    // aici am creat pachetul, alocand spatiu
    long ether_size = sizeof(struct ether_header);
    long arp_size = sizeof(struct arp_header);

    uint8_t packet[ether_size + arp_size];
    // am initializat pointerii pt header urile ethernet si arp
 	struct ether_header *ether_header = (struct ether_header *)packet;
 	struct arp_header *arp_header = (struct arp_header *)(packet + ether_size);

    // vreau ca adresa mac a destinatiei sa fie adresa de broadcast
    uint8_t broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    set_ethernet_header(ether_header, broadcast_mac, interface);

    // nu cunoastem adresa mac a destinatarului asa ca o initializam cu 0
    uint8_t unknown_mac[6] = {0};
    // adresa ip a senderului
    char *interface_ip = get_interface_ip(interface);
    set_arp_header(arp_header, 1, inet_addr(interface_ip), ip, interface, unknown_mac);
    // trimit pachetul
    send_to_link(interface, (char *)packet, sizeof(packet));
}

void handle_arp_reply(struct arp_header *arp_header, struct ether_header *eth_header, int interface) {
    // aici am creat pachetul
    long ether_size = sizeof(struct ether_header);
    long arp_size = sizeof(struct arp_header);

    uint8_t packet[ether_size + arp_size];
 	struct ether_header *eth_hdr = (struct ether_header *)packet;
 	struct arp_header *arp_hdr = (struct arp_header *)(packet + ether_size);

    set_ethernet_header(eth_hdr, eth_header->ether_shost, interface);
    set_arp_header(arp_hdr, 2, arp_header->tpa, arp_header->spa, interface,  eth_header->ether_shost);

    send_to_link(interface, (char *)packet, sizeof(packet));
}

void handle_arp_packet(struct arp_header *arp_header, struct ether_header *eth_header, int interface) {
    // determin daca am primit request sau reply
    uint16_t opcode = ntohs(arp_header->op);
    if (opcode == 1) {
        // am primit request deci trimit un reply
        handle_arp_reply(arp_header, eth_header, interface);
    } else if (opcode == 2) {
        // am primit reply, deci trebuie sa actualizez cache-ul( noua tabela arp dinamica)
        // si sa parcurg coada pentru a verifica ce pachete pot fi trimise
        struct arp_table_entry *find_entry = get_arp_entry(arp_header->spa);
        // daca aveam deja intrarea in tabela, trebuie sa mai actualizam mac ul
        if(find_entry) {
            memcpy(find_entry->mac, arp_header->sha, 6 * sizeof(uint8_t));
        }
       // altfel actualizam tabela si adaugam o noua intrare
        else {
            new_arp_table[new_arp_table_len].ip = arp_header->spa;
            memcpy(new_arp_table[new_arp_table_len].mac, arp_header->sha, 6 * sizeof(uint8_t));
            new_arp_table_len++;
            find_entry = get_arp_entry(arp_header->spa);
        }
        // acum parcurg coada
        // retin intr-un vector pachetele care nu pot fi inca trimise
        arppack *unsent_packets[9999];
        int num_unsent_packets = 0;
        while(!queue_empty(q)) {
            // extrag pachetul
            arppack *packet = (arppack *) queue_deq(q);
            char *pack = packet->packet;
            struct ether_header *eth = (struct ether_header *)pack;
            // verific daca adresa ip de destinatie este diferita de adresa ip a senderului arp
            if(packet->ip_dest != arp_header->spa) {
                // daca da atunci nu trimit pachetul
                unsent_packets[num_unsent_packets] = packet;
                num_unsent_packets++;
            }
            else {
                // caut in tabel o intrare pt ip ul senderului
                struct arp_table_entry *search = NULL;
                for(int i = 0; i < new_arp_table_len; i++) {
                    if(new_arp_table[i].ip == arp_header->spa) {
                        search = &new_arp_table[i];
                    }
                }
                // daca nu am gasit nu trimit pachetul
                if(!search) {
                    unsent_packets[num_unsent_packets] = packet;
                    num_unsent_packets++;
                }
                else {
                    // daca da copiez adresa destinatarului si trimit pachetul
                    memcpy(eth->ether_dhost, search->mac, 6);
				    send_to_link(packet->interface, packet->packet, packet->len);
                }
            }
        }

        // adaug pachetele care nu au putut fi trimise inapoi in coada
        for(int i = 0; i < num_unsent_packets; i++) {
            queue_enq(q, unsent_packets[i]);
        }
    }
}

void set_icmp_header(struct icmphdr *icmp_hdr, uint8_t type, uint8_t code) {
    // setez tipul si codul si calculez checksum ul
    icmp_hdr->type = type;
    icmp_hdr->code = code;
    icmp_hdr->checksum = checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr) + (sizeof(struct iphdr) + 8) );
}

void set_iph_header(struct iphdr *ip_hdr, uint32_t ip_dest, int interface) {
    // lungimea totala a pachetului
    ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + (sizeof(struct iphdr) + 8) );
    ip_hdr->ttl = 64;
    ip_hdr->protocol = 1;
    ip_hdr->check = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
    ip_hdr->saddr = inet_addr(get_interface_ip(interface));
    ip_hdr->daddr = ip_dest;
}

void icmp_error(uint32_t ip_dest, char *packet, int interface, uint8_t type, uint8_t code)
{
    // pointeri catre header urile ip si icmp
    long iphdr_size = sizeof(struct iphdr);
    long ether_size = sizeof(struct ether_header);
    long icmphdr_size = sizeof(struct icmphdr);

    struct icmphdr *icmp_hdr = (struct icmphdr *)(packet + ether_size + iphdr_size);
    struct iphdr *ip_hdr = (struct iphdr *)(packet + ether_size);

    // copiez header ul ip in zona de date a celui icmp
    memcpy((uint8_t *)icmp_hdr + icmphdr_size, ip_hdr, iphdr_size + 8);
    // am setat header urile
    set_icmp_header(icmp_hdr, type, code);
    set_iph_header(ip_hdr, ip_dest, interface);

    // trimit pachetul
    send_to_link(interface, packet, ether_size + ntohs(ip_hdr->tot_len));
}

// functie pentru a verifica daca am primit mesaj icmp echo request
int check_echo_request(struct icmphdr * icmp_hdr, struct iphdr *ip_hdr, int interface, char *packet) {
    int ok = 0;
    if(icmp_hdr->code == 0 && icmp_hdr->type == 8) {
        if(ip_hdr->daddr == inet_addr(get_interface_ip(interface))) {
            ok = 1;
            // trimit echo reply, type 0, code 0
            icmp_error(ip_hdr->saddr, packet, interface, 0, 0);
        }
    }
    return ok;
}

int main(int argc, char *argv[]) {
    char buf[MAX_PACKET_LEN];
	int i;

    // Do not modify this line
    init(argc - 2, argv + 2);

    /* Code to allocate the ARP and route tables */
    rtable = malloc(sizeof(struct route_table_entry) * 100000);
    /* DIE is a macro for sanity checks */
    DIE(rtable == NULL, "memory");
    rtable_len = read_rtable(argv[1], rtable);

    // am initializat radacina pt trie
	trie *root = malloc(sizeof(trie));
	root->route = NULL;
	root->childnode[0] = NULL;
	root->childnode[1] = NULL;


	for(i = 0; i < rtable_len; i++) {
		uint32_t network_prefix = htonl(rtable[i].prefix);
		uint32_t network_mask = htonl(rtable[i].mask);
		insert_in_trie(root, &rtable[i], network_mask, network_prefix);
	}

    // creez noul tabel dinamic ARP
    new_arp_table = malloc(sizeof(struct arp_table_entry) * 999999);
    new_arp_table_len = 0;

    // am initializat coada necesara pt arp
    q = queue_create();

    while (1) {

        int interface;
        size_t len;
        // aici primim pachete
        interface = recv_from_any_link(buf, &len);
        DIE(interface < 0, "recv_from_any_links");

        struct ether_header *eth_hdr = (struct ether_header *) buf;
        /* Note that packets received are in network order,
        any header field which has more than 1 byte will need to be converted to
        host order. For example, ntohs(eth_hdr->ether_type). The opposite is needed when
        sending a packet on the link. */

        // am extras tipul de protocol si verific tipul lui
        uint16_t protocol_type = ntohs(eth_hdr->ether_type);
        int ok = check_protocol(protocol_type);

        // nu ne intereseaza pachetul
        if(ok == -1) {
            continue;
        }
        // avem pachet ip
        if(ok == 0) {
            struct icmphdr * icmp_hdr = (struct icmphdr * )(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
            struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

            // verific echo request
            int check = check_echo_request(icmp_hdr, ip_hdr, interface, buf);
            if(check) {
                continue;
            }

            uint16_t old_check = ip_hdr->check;
            ip_hdr->check = 0;
            if(old_check != htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)))) {
                memset(buf, 0, sizeof(buf));
                continue;
            }

            // caut cea mai buna cale in tabela de rutare
            uint32_t network_daddr = htonl(ip_hdr->daddr);
            struct route_table_entry *best_router = search_in_trie(root, network_daddr);
            if(best_router == NULL) {
                // daca nu exista dau drop pachetului si trimit eroare icmp destination unreachable (type 3, code 0)
                icmp_error(ip_hdr->saddr, buf, interface, 3, 0);
                continue;
            }

            // verific daca a expirat timpul
            if(ip_hdr->ttl <= 1) {
                // daca a expirat dau drop pachetului si trimit eroare icmp time exceeded (type 11, code 0)
                icmp_error(ip_hdr->saddr, buf, interface, 11, 0);
                continue;
            }
            // altfel actualizez ttl ul
            uint16_t old_ttl;
            old_ttl = ip_hdr->ttl;
            ip_hdr->ttl--;
            ip_hdr->check = ~(~old_check +  ~((uint16_t)old_ttl) + (uint16_t)ip_hdr->ttl) - 1;

            // actualizez adresele ethernet
            struct arp_table_entry *nexthop_mac = get_arp_entry(best_router->next_hop);
            if (!nexthop_mac) {
                // am cautat in cache, dar cum nu am gasit nimic, inseamna ca facem ARP request
                // si adaugam pachetul in coada pt a putea fi trimis dupa raspunsul lui ARP
                // aici adaug pachetul in coada
                arppack *new_packet = malloc(sizeof(arppack));
                new_packet->packet = malloc(len);
	            memcpy(new_packet->packet, buf, len);
                new_packet->len = len;
	            new_packet->ip_dest = best_router->next_hop;
	            new_packet->interface = best_router->interface;
	            queue_enq(q, new_packet);
                // trimit arp request
                handle_arp_request(new_packet->ip_dest, new_packet->interface);
            }
            // cazul in care am gasit intrare in cache
            else {
                memcpy(eth_hdr->ether_dhost, nexthop_mac->mac, sizeof(eth_hdr->ether_dhost));
                get_interface_mac(best_router->interface, eth_hdr->ether_shost);
                send_to_link(best_router->interface, buf, len);
            }
        }
        // pachet arp
        if (ok == 1) {
            struct arp_header *arp_header = (struct arp_header *)(buf + sizeof(struct ether_header));
           handle_arp_packet(arp_header, eth_hdr, interface);
        }
    }
}