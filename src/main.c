#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
//#include "/usr/include/pcap/pcap.h"
#include <sys/types.h>
#include <pcap/pcap.h>
/*#include "pcal/pcap.h"*/

#include "../include/params.h"
#include "../include/setup.h"
#include "../include/bpf.h"
#include "../include/core.h"


/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
    u_char ip_vhl;		/* version << 4 | header length >> 2 */
    u_char ip_tos;		/* type of service */
    u_short ip_len;		/* total length */
    u_short ip_id;		/* identification */
    u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* don't fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
    u_char ip_ttl;		/* time to live */
    u_char ip_p;		/* protocol */
    u_short ip_sum;		/* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;	/* source port */
    u_short th_dport;	/* destination port */
    tcp_seq th_seq;		/* sequence number */
    tcp_seq th_ack;		/* acknowledgement number */
    u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;		/* window */
    u_short th_sum;		/* checksum */
    u_short th_urp;		/* urgent pointer */
};

    /* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

const struct sniff_ethernet *ethernet; /* The ethernet header */


void got_packet_cb(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip *ip; /* The IP header */
    const struct sniff_tcp *tcp; /* The TCP header */
    const u_char *payload; /* Packet payload */

    u_int size_ip;
    u_int size_tcp;

    ethernet = (struct sniff_ethernet*)(packet);
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }
    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    printf("Packet received\n");
}


int main(int argc, char *argv[])
{
    struct prog_args pr_args = {0};

    parse_params(argc, argv, &pr_args); //geting command line parameters

    status_val status = setup_prog_ctx(&pr_args); //setting up program context
    if (status) {
	LOG(L_CRIT, status);
        goto error;
    }

    if (!pr_args.bpf_enabled) {
	status = build_bpf(&pr_args);
	if (status) {
	    LOG(L_CRIT, status);
	    goto error;
	}
    }

    pcap_t *handle;
//	char *dev;
//    char *dev = argv[1];
    char *dev = "eno1";
    char errbuf[ERRBUF_SIZE] = {0};
    struct bpf_program fp;
    char filter_exp[BUF_SIZE];
    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct pcap_pkthdr header;
    const u_char *packet;

    const struct sniff_ip *ip; /* The IP header */
    const struct sniff_tcp *tcp; /* The TCP header */
    const char *payload; /* Packet payload */

    u_int size_ip;
    u_int size_tcp;

    sprintf(filter_exp, "tcp");
//    sprintf(filter_exp, "port %s", argv[2]);

//    if (!(dev = pcap_lookupdev( errbuf))) {
//		fprintf(stderr, "Could not get default device: %s/n", errbuf);
//		goto error;
//    }

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Could not get netmask for device: %s/n", dev);
        net = 0;
        mask = 0;
    }

    if (!(handle = pcap_open_live(dev, BUF_SIZE, 1, 1000, errbuf))) {
        fprintf(stderr, "Could not open device %s: %s/n", dev, errbuf);
        goto error;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Could not parse filter %s: %s/n", filter_exp, pcap_geterr(handle));
        goto error;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not install filter %s: %s/n", filter_exp, pcap_geterr(handle));
        goto error;
    }

//    if (pcap_datalink(handle) != DLT_EN10MB) {
//        fprintf(stderr, "Required ethernet headers for device %s are not supported/n", dev);
//        goto error;
//    }

//	packet = pcap_next(handle, &header);
    status = core_init();
    if (status) {
	LOG(L_CRIT, status);
    }
    
    pcap_loop(handle, -1, got_packet_cb, NULL);

    printf("Packet received of length: %d/n", header.len);

    pcap_close(handle);

    return 0;
error:
    return 1;
}
