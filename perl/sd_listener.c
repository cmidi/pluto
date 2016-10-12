/*
 * Acme Packet
 *
 * v1.0
 *
 * SD Listener: is used to listen on a specified Ethernet interface or
 * UDP IPv4 address and port for traffic from an SD2/SD3/SD4 and compare that
 * traffic to a given .(p)cap file returning either failure if they
 * are different or success if they are the same.
 *
 * Note: SD Listener can also be used to replay a .(p)cap file to an SD2/SD3/SD4.
 *
 * This program is meant to be compiled on a UNIX/Linux system. Execute:
 * gcc sd_listener.c -o sd_listener.out -lpcap -lpthread
 *
 * sd_listener.c
 *
 * Created on: Jul 27, 2009
 * Author: smcculley
 */

#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <pcap.h>
#include <pthread.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <getopt.h>

//Some distros lack these defines in ethernet.h - Define here if not defined.
#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN 0x8100
#endif

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86dd
#endif

#define MAX_PACKET_LEN 1500
#define MAX_BUFFER_LEN 1024  //For some reason I get a seg fault when using sudo on this file for sizes > 900
#define MAC_LEN 6
#define ONE_SECOND 1000000
#define MAX_PLAY_SIZE 65535
#define SOURCE_PORT 6000
#define DEST_PORT 6666
#define MAX_HOP 5000         //max number of packets allow to jump for searching match packet

#define IP6F_OFF_SHIFT  3    //Shift to get offset from ip6f_offlg.
#define DISPLAY_NUMPKT  4999 //Used with -s flag, if number of packets to send is > this, display status.

typedef struct _pcap_pkt_t
{
    struct timeval  te;
    struct timespec ts;
    uint16_t        dataLen;
    void           *data;
} pcap_pkt;

typedef struct _pcap_pkts_t
{
    char           fileName[MAX_BUFFER_LEN];
    uint32_t       numPkts;
    uint32_t       maxPktLen;
    struct timeval timeout_te;
    pcap_pkt      *pkts;
} pcap_pkts;

typedef struct _play_pkt_t
{
    struct timeval  te;
    struct timespec ts;
    uint16_t        dataLen;
    void           *data;
} play_pkt;

typedef struct _play_pkts_t
{
    uint32_t       numPkts;
    uint32_t       maxPktLen;
    play_pkt      *pkts;
} play_pkts;

typedef struct _pkt_node_t
{
    pcap_pkt      *index;
    struct _pkt_node_t *prev;
    struct _pkt_node_t *next;
} pkt_node;

typedef struct _ether_hdr
{
    uint8_t  destMAC[MAC_LEN];
    uint8_t  srcMAC[MAC_LEN];
    uint16_t etherType; /*Used to determine if packet is IPv4 or IPv6*/
} ether_hdr;

typedef struct _ether_tag_hdr
{
    uint8_t  destMAC[MAC_LEN];
    uint8_t  srcMAC[MAC_LEN];
    uint16_t tag;
    uint16_t vlan;
    uint16_t etherType; /*Used to determine if packet is IPv4 or IPv6*/
} ether_tag_hdr;

typedef struct _arp_hdr
{
    uint16_t htype;
    uint16_t ptype;
    uint8_t  hlen;
    uint8_t  plen;
    uint16_t mode;
    uint8_t  srcMAC[MAC_LEN];
    uint32_t srcIP;
    uint8_t  destMAC[MAC_LEN];
    uint32_t destIP;
} __attribute__((packed)) arp_hdr; 

typedef struct _icmp6_advert_hdr
{
    struct nd_neighbor_advert neighborAdvert;
    struct nd_opt_hdr optionHdr;
    uint8_t linkLayerAddr[MAC_LEN];
} icmp6_advert_hdr;

#define icmp6_type                neighborAdvert.nd_na_hdr.icmp6_type
#define icmp6_code                neighborAdvert.nd_na_hdr.icmp6_code
#define icmp6_cksum               neighborAdvert.nd_na_hdr.icmp6_cksum
#define icmp6_target              neighborAdvert.nd_na_target
#define icmp6_flag                neighborAdvert.nd_na_hdr.icmp6_data32[0]
#define option_type               optionHdr.nd_opt_type
#define option_len                optionHdr.nd_opt_len

typedef struct _rtp_hdr
{
    uint8_t  version;
    uint8_t  payloadType;
    uint16_t seqNum;
    uint32_t timestamp;
    uint32_t ssrc;
} rtp_hdr;

typedef struct _rtp_event
{
    uint8_t  eventID;
    uint8_t  erv;
    uint16_t duration;
} rtp_event;

typedef struct _rtp_pt_map
{
    uint8_t old;
    uint8_t new;
} rtp_pt_map_t;

typedef struct _config_t
{
    char            interface[MAX_BUFFER_LEN];
    bool            bInterfaceDefined;
    pcap_pkts       pcap;
    bool            bPcapDefined;
    uint32_t        timeOut;

    struct in6_addr outerSrcAddr;
    uint16_t        outerSrcPort;
    struct in6_addr outerDstAddr;
    uint16_t        outerDstPort;
    uint8_t         outerToS;
    uint8_t         outerTTL;

    uint32_t        optionalHeader[10];

    struct in6_addr innerSrcAddr;
    uint16_t        innerSrcPort;
    struct in6_addr innerDstAddr;
    uint16_t        innerDstPort;
    uint8_t         innerToS;
    uint8_t         innerTTL;

    uint32_t        rtpInitialSsrcTx;
    uint32_t        rtpSubseqSsrcTx;

    rtp_pt_map_t   *rtpPtMap;
    uint32_t        numRtpPtMap;

    uint32_t        userNumPkts;
    uint32_t        payloadSize;
    uint32_t        diffSize;
    uint32_t        fixTs;

} config_t;

typedef struct _tcpOpts_t
{
    uint16_t chunk[12];
} tcpOpts_t;


typedef struct _listener_info_t
{
    bool     bRespondARP;
    bool     bTimeout;
    bool     bVerbose;
    bool     bHMU;
    bool     bVerifyRTPEventTS;
    bool     bDontCalcL4Checksum;
    bool     bLI;
    bool     bFixTs;
    bool     bStatus;
    bool     bHop;
    bool     bGen;
    bool     bForward;
} listener_info_t;

typedef struct _listener_stats_t
{
    uint32_t expectedPktsRx;
    uint32_t unknownPktsRx;
    uint32_t pktsTx;
    uint32_t arpRx;
    uint32_t arpTx;
    uint32_t icmpv6Rx;
    uint32_t icmpv6Tx;
    uint32_t unsupportedType;
    uint32_t maxHop;
} listener_stats_t;

/********* GLOBALS **********/

config_t               *replayConfig;
config_t               *listenConfig;
listener_info_t        *info;
listener_stats_t       *stats;
play_pkts              *playPkts;
pkt_node               *listenList;

static char            errbuf[PCAP_ERRBUF_SIZE];
static pthread_t       listenThread;
static pthread_t       udpThread;
static pthread_mutex_t replayMutex;
static pthread_cond_t  replayCond;
static pthread_t       replayThread;

bool use_udp_thread    = false;
int udp_capture        = 0;
uint16_t capPkts       = 0;

static const char usage[] =
    "sd_listener [options]\n"
    "\t--rsa     [x]\t Replay source IPv4/IPv6 address\n"
    "\t--rsp     [x]\t Replay source port\n"
    "\t--rda     [x]\t Replay destination IPv4/IPv6 address\n"
    "\t--rdp     [x]\t Replay destination port\n"
    "\t--rtos    [x]\t Replay TOS value for IPv4 packets. Default is 0\n"
    "\t--rttl    [x]\t Replay TTL for IPv6/Ipv4 packets. Default is 64\n"
    "\t--rif     [x]\t Interface used to replay the .pcap\n"
    "\t--rpc     [x]\t Location of replay .pcap\n"
    "\t--rnumpkt [x]\t Specify number of packets to send from the replay side.\n"
    "\t--rpt     [x]-[y]\t Replace all RTP packets in replay .(p)cap which have\n"
    "\t               \t RTP payload type [x] with RTP payload type [y] (can be used multiple\n"
    "\t               \t times to replace different payload types in the same .(p)cap)\n"
    "\t--rsize   [x]\t Specify payloadsize of first packet to send. Generate only.\n"
    "\t--rdiff   [x]\t Specify payloadsize difference between successive packets. Generate only.\n"
    "\n"
    "\t--lsa     [x]\t Listen source IPv4/IPv6 address\n"
    "\t--lsp     [x]\t Listen source port\n"
    "\t--lda     [x]\t Listen destination IPv4/IPv6 address\n"
    "\t--ldp     [x]\t Listen destination port\n"
    "\t--ltos    [x]\t Listen TOS value for IPv4 packets. Default is 0\n"
    "\t--lttl    [x]\t Listen TTL for IPv6/Ipv4 packets. Default is 64\n"
    "\t--lif     [x]\t Interface used to listen for packets to compare against the listen .pcap\n"
    "\t--lpc     [x]\t Location of listen .pcap\n"
    "\t--lnumpkt [x]\t Specify number of packets for the listening side.\n"
    "\t--lpt     [x]-[y]\t Replace all RTP packets in listen .(p)cap which have\n"
    "\t                \t RTP payload type [x] with RTP payload type [y] (can be used multiple\n"
    "\t                \t times to replace different payload types in the same .(p)cap)\n"
    "\n"
    "\t--irsa  [x]\t Inner replay source IPv4/IPv6 address\n"
    "\t--irsp  [x]\t Inner source port\n"
    "\t--irda  [x]\t Inner replay destination IPv4/IPv6 address\n"
    "\t--irdp  [x]\t Inner replay destination port\n"
    "\t--irtos [x]\t Inner replay TOS value for IPv4 packets. Default is 0\n"
    "\n"
    "\t--ilsa  [x]\t Inner listen source IPv4/IPv6 address\n"
    "\t--ilsp  [x]\t Inner listen source port\n"
    "\t--ilda  [x]\t Inner listen destination IPv4/IPv6 address\n"
    "\t--ildp  [x]\t Inner listen destination port\n"
    "\t--ilttl [x]\t Inner listen TTL for IPv6/IPv4 packets. Default is 64\n"
    "\t--iltos [x]\t Inner listen TOS value for IPv4 packets. Default is 0\n"
    "\n"
    "\t--tmo     [x]\t Listening timeout\n"
    "\t--vrets   [x]\t Verify RTP Event timestamp\n"
    "\t--fixts   [x]\t Force set the gap between sent packets to .0005.\n"
    "\t--udp     [x]\t Listen from UDP Socket for packets\n"
    "\t--capture [x]\t Capture from UDP Socket and create pcap\n"
    "\t--forward [x]\t Forward traffic to another sd_listener instance\n"
    "\n"
    "\tAll arguments are optional and order does not matter\n"
    "\tReplay arguments replace respective fields from processed Replay .(p)cap\n"
    "\tListen arguments replace respective fields from processed Listen .(p)cap\n\n"
    "\t-r  [x]\t Location of replay .(p)cap file\n"
    "\t-R  [x]\t Replay interface [x]\n"
    "\t       \t Note: If -R and -A are used, interface listener will drop ARP packets\n"
    "\t       \t from interface -R [x]\n"
    "\t-l  [x]\t Location of listener .(p)cap file\n"
    "\t-L  [x]\t Enable interface listening with Ethernet interface name [x]\n"
    "\t-t  [x]\t Timeout period in seconds (integer)\n"
    "\t-A     \t Allow interface listening to respond to ARP packets\n"
    "\t-v     \t Enable Verbose mode"
    "\t-F  [x]\t Location of SD Listener config file\n"
    "\t-H  [x]\t Enable HMU\n"
    "\t-d  [x]\t Don't calculate L4 checksum\n"
    "\t-s     \t Display sending status if sending more than 5000 packets.\n"
    "\t-h  [x]\t Print this menu\n"
    "\t-f  [x]\t Listen out of order tolerant option\n"
    "\t-g  [x]\t Enable packet generation\n";
/******* END GLOBALS *******/

#define REPLAY_THREAD_LOCK            pthread_mutex_lock(&replayMutex);
#define REPLAY_THREAD_UNLOCK           pthread_mutex_unlock(&replayMutex);

#define REPLAY_THREAD_WAIT            pthread_cond_wait(&replayCond, &replayMutex);
#define REPLAY_THREAD_BROADCAST        pthread_cond_broadcast(&replayCond);

#define LOG(format, args...) if (info->bVerbose) printf(format "\n", ## args)
#define ERR(format, args...) fprintf(stderr, format "\n", ## args)


#define IP6_PROTO_FRAG   44

/*
 *
 * id of 1 means that the address being processed is a replay address
 * id of 2 means that the address being processed is a listen address
 *
 */
void print_buffer(uint8_t *buffer, uint16_t bufferLen)
{
    int i;
    uint8_t *print_ptr = (uint8_t *)buffer;

    printf("%s: buf_len = %d, data = %p\n", __FUNCTION__, bufferLen, buffer);
    for (i = 0; i < (bufferLen); i++)
    {
        if ((i % 16) == 0)
        {
            printf("\n%4.4x  ", i);
        }
        else if (i%4 == 0)
        {
            printf(" ");
        }
        printf("%02x ", *(print_ptr + i));
    }
    printf("\n\n");
}

int in6_pton(char *addr, struct in6_addr *in6_addr)
{
    if(strstr(addr, ".") != NULL)
    {
        in6_addr->s6_addr32[0] = in6_addr->s6_addr32[1] = in6_addr->s6_addr32[2] = 0;
        return inet_pton(AF_INET, addr, &in6_addr->s6_addr32[3]);
    }
    else if(strstr(addr, ":") != NULL)
    {
        return inet_pton(AF_INET6, addr, in6_addr);
    }

    return 0;
}
#if 0
int in6_ntop(struct in6_addr *ip)
{ 
    #define MAX_CONV 32
    static char strbuf[MAX_CONV][INET6_ADDRSTRLEN];
    static unsigned int index = 0;  
    index++;
    index %= MAX_CONV;

    return inet_ntop(AF_INET6, ip, strbuf[index], sizeof(strbuf[0]));;
}
#endif
int in6_isAddrZero(struct in6_addr *in6_addr)
{
    if(in6_addr->s6_addr32[0] == 0 &&
       in6_addr->s6_addr32[1] == 0 &&
       in6_addr->s6_addr32[2] == 0 &&
       in6_addr->s6_addr32[3] == 0)
    {
        return 1;
    }
    return 0;
}

int in6_isAddrV6(struct in6_addr *in6_addr)
{
    if(in6_addr->s6_addr32[0] != 0 ||
       in6_addr->s6_addr32[1] != 0 ||
       in6_addr->s6_addr32[2] != 0)
    {
        return 1;
    }
    return 0;
}

void in6_zeroAddr(struct in6_addr *in6_addr)
{
    in6_addr->s6_addr32[0] = 0;
    in6_addr->s6_addr32[1] = 0;
    in6_addr->s6_addr32[2] = 0;
    in6_addr->s6_addr32[3] = 0;

}

int in6_cmpAddr(struct in6_addr *addr1, struct in6_addr *addr2)
{
    if(addr1->s6_addr32[0] == addr2->s6_addr32[0] &&
       addr1->s6_addr32[1] == addr2->s6_addr32[1] &&
       addr1->s6_addr32[2] == addr2->s6_addr32[2] &&
       addr1->s6_addr32[3] == addr2->s6_addr32[3])
    {
        return 1;
    }
    return 0;
}

void in6_cpyAddr(struct in6_addr *destAddr, struct in6_addr *srcAddr)
{
    destAddr->s6_addr32[0] = srcAddr->s6_addr32[0];
    destAddr->s6_addr32[1] = srcAddr->s6_addr32[1];
    destAddr->s6_addr32[2] = srcAddr->s6_addr32[2];
    destAddr->s6_addr32[3] = srcAddr->s6_addr32[3];
}

uint16_t modcsum_16(uint16_t csum, uint16_t orig_value, uint16_t new_value)
{
    uint32_t sum = (~csum & 0xffff);

    if(orig_value != 0)
    {
        sum = sum + (~orig_value & 0xffff);
    }

    sum += new_value;

    /* Keep only last 16 bits of the calculated sum and add the carries */
    while(sum >> 16)
    {
        sum = (sum >> 16) + (sum & 0xffff);
    }

    /* Return one's complement of sum */
    sum = ~sum;
    return (uint16_t)sum;
}

uint16_t modcsum_32(uint16_t csum, uint32_t orig_value, uint32_t new_value)
{
    uint16_t sum = csum;
    uint16_t orig16 = 0;
    uint16_t new16 = 0;

    orig16 = (uint16_t)(orig_value >> 16);
    new16 = (uint16_t)(new_value >> 16);
    sum = modcsum_16(sum, orig16, new16);

    orig16 = (uint16_t)(orig_value & 0xffff);
    new16 = (uint16_t)(new_value & 0xffff);
    sum = modcsum_16(sum, orig16, new16);

    return (uint16_t)sum;
}

uint16_t ipcsum(int len, uint16_t *buff)
{
    uint32_t sum = 0;

    // make 16 bit words out of every two adjacent 8 bit words in the packet
    // and add them up
    while(len>0){
        sum += *(buff++);
        if(sum & 0x80000000)   /* if high order bit set, fold */
            sum = (sum & 0xFFFF) + (sum >> 16);
        len -= 2;
    }

    if(len) /* take care of left over byte */
    {
        sum += (uint32_t) *(uint8_t *)buff;
    }

    /* Keep only last 16 bits of the 32 bit calculated sum and add the carries */
    while(sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return ((uint16_t) ~sum);
}

uint16_t l4csum(struct in6_addr *srcAddr,
                struct in6_addr *dstAddr,
                uint16_t *buffer,
                uint16_t bufferLen,
                uint16_t proto)
{
    uint32_t sum;
    uint16_t *u16Ptr;
    uint16_t len;
    uint16_t i;

    sum = 0;
    len = bufferLen;

    u16Ptr = (uint16_t *)buffer;
    while(len > 1)
    {
        sum += *(u16Ptr++);
        if(sum & 0x80000000)
        {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        len -= 2;
    }

    if(len) /* take care of left over byte */
    {
        sum += (uint32_t) *(uint8_t *)u16Ptr;
    }

    /* Add the pseudo header which contains src/dst address, proto, and proto_length */

    /* Since in the IPv4 case u32[0 - 2] of the IP Address are zero, adding them to the sum
     * will not change the outcome of the checksum. Therefore, we can treat both IPv4 and IPv6 cases
     * the same when calculating the pseudo header
     */
    for(i = 0; i < 4; i++)
    {
        u16Ptr = (uint16_t *)&srcAddr->s6_addr32[i];
        sum += *(u16Ptr++);
        sum += *u16Ptr;
    }

    /* Since in the IPv4 case u32[0 - 2] of the IP Address are zero, adding them to the sum
     * will not change the outcome of the checksum. Therefore, we can treat both IPv4 and IPv6 cases
     * the same when calculating the pseudo header
     */
    for(i = 0; i < 4; i++)
    {
        u16Ptr = (uint16_t *)&dstAddr->s6_addr32[i];
        sum += *(u16Ptr++);
        sum += *u16Ptr;
    }

    sum += htons(proto);
    sum += htons(bufferLen);

    /* Keep only last 16 bits of the 32 bit calculated sum and add the carries */
    while(sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    /* Return one's complement of sum */
    sum = ~((uint16_t)sum);

    if (sum == 0)
    {
        return (uint16_t)0xffff;
    }
    else
    {
        return (uint16_t)sum;
    }
}

void get_MAC_addr(int sock, char *interface, char *ifmac, int *cardIndex)
{
    int ret;
    struct ifreq card;

    strcpy(card.ifr_name, interface);

    ret = ioctl(sock, SIOCGIFHWADDR, &card);
    if(ret < 0)
    {
        perror(" int_MAC_addr ioctl");
        exit(1);
    }
    if(ifmac != NULL)
        memcpy(ifmac, card.ifr_hwaddr.sa_data, 6);

    ret = ioctl(sock, SIOCGIFINDEX, &card);
    if(ret < 0)
    {
        perror("int_MAC_addr ioctl");
        exit(1);
    }

    if(cardIndex != NULL)
        *cardIndex = card.ifr_ifindex;
}

void insertList(pcap_pkt *pktIndex)
{
    pkt_node *p, *newNode;
    newNode =(pkt_node *)malloc(sizeof(pkt_node));
    if(!newNode)
    {
	ERR("Unable to malloc memory for listenList");
	exit(1);
    }
    newNode->index = pktIndex;
    newNode->next = NULL;

    if(!listenList){
	newNode->prev = NULL;
	listenList = newNode;
    }
    else{
	p = listenList;
	while(p->next){
	    p = p->next;
	}
	newNode->prev = p;
	p->next = newNode;
    }
}

void deleteList(pkt_node *node)
{
    if(!listenList || !node){
	return;
    }
    if(listenList == node){
	listenList = node->next;
    }
    if(node->next){
	node->next->prev = node->prev;
    }
    if(node->prev){
	node->prev->next = node->next;
    }
    free(node);
}

void init_pcap_pkts(config_t *pktCfg)
{
    pcap_pkts          *pkts = NULL;
    pcap_t             *pcap = NULL;
    struct pcap_pkthdr *pkthdr = NULL;
    u_char             *pktdata = NULL;
    pcap_pkt           *pktIndex = NULL;
    void               *nextPtr = NULL;
    uint32_t            i = 0;

    ether_hdr          *ethHdr = NULL;
    ether_tag_hdr      *ethTagHdr = NULL;
    uint16_t            etherType = 0;

    struct ip6_hdr     *ip6Hdr = NULL;
    struct iphdr       *ipHdr = NULL;
    struct udphdr      *udpHdr = NULL;
    struct tcphdr      *tcpHdr = NULL;
    tcpOpts_t          *tcpOpts = NULL;
    rtp_hdr            *rtpHdr = NULL;

    uint32_t            id = 0;
    uint16_t            fragmentOffset = 0;
    uint16_t            innerfragmentOffset = 0;
    uint32_t            innerid = 0;
    struct ip6_frag    *frag6Hdr = NULL;
    uint16_t            moreFragments = 0;
    uint16_t            isFrag  = 0;

    uint16_t            origL4Checksum = 0;

    uint16_t            inneroffset = 0;
    uint16_t            outeroffset = 0;
    uint8_t             outerProtocol = 0;
    void               *outerL4Ptr = NULL;
    uint16_t            outerL4Len = 0;

    uint8_t             innerProtocol = 0;
    void               *innerL4Ptr = NULL;
    uint16_t            innerL4Len = 0;

    //void             *liHdr = NULL;

    void               *payload = NULL;
    uint16_t            payloadLen = 0;
    uint16_t           *outerChecksumPtr = NULL;
    uint16_t           *innerChecksumPtr = NULL;

    uint16_t            outerPktLen = 0; /* Includes size of all IP/IP6/LI/UDP/TCP headers and payload*/
    uint16_t            outerPayloadLen = 0;
    uint16_t            innerPayloadLen = 0;

    struct timeval      prev_te = {0, 0};
    struct timeval      current_te = {0, 0};
    struct timespec     current_ts = {0, 0};
    
    if(pktCfg == NULL)
    {
        ERR("%s: provided with NULL pktCfg", __FUNCTION__);
        exit(1);
    }

    pkts = (pcap_pkts *)&pktCfg->pcap;

    pcap = pcap_open_offline(pkts->fileName, errbuf);
    if(!pcap)
    {
        ERR("Can't open PCAP file '%s'", pkts->fileName);
        exit(1);
    }
    
    pkthdr = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
    if(!pkthdr)
    {
        ERR("Can't allocate memory for pcap pkthdr");
        exit(1);
    }

    while((pktdata = (u_char *) pcap_next(pcap, pkthdr)) != NULL)
    {
        outerPktLen = 0;

        /*********** Start Parsing the Original PCAP Packet ***********/
        ethHdr = (ether_hdr *) pktdata;
        if (ntohs(ethHdr->etherType) == ETHERTYPE_VLAN) /* VLAN */
        {
            ethTagHdr = (ether_tag_hdr *) pktdata;
            etherType = ethTagHdr->etherType;
            nextPtr = (uint8_t *)pktdata + sizeof(ether_tag_hdr);

        }
        else
        {
            etherType = ethHdr->etherType;
            nextPtr = (uint8_t *)pktdata + sizeof(ether_hdr);
        }

        if(ntohs(etherType) == ETHERTYPE_IP) /* IPv4 */
        {
            ipHdr = (struct iphdr *)nextPtr;

            outerProtocol = ipHdr->protocol;
            outerL4Ptr = (uint8_t *)ipHdr + sizeof(struct iphdr);
            payload = outerL4Ptr;

            fragmentOffset = ipHdr->frag_off;
            id = (uint32_t)(ntohs(ipHdr->id));
            outeroffset = (htons(fragmentOffset) & 0x1fff);
            moreFragments = ((htons(fragmentOffset) & 0x2000) >> 13);
            if((htons(fragmentOffset) & 0x3fff) != 0)
            {
                isFrag = 1;   
            }
            else
            {
                isFrag = 0;
            }

            payloadLen = (uint16_t)(ntohs(ipHdr->tot_len) - sizeof(struct iphdr));
        }
        else if (ntohs(etherType) == ETHERTYPE_IPV6) /* IPv6 */
        {
            ip6Hdr = (struct ip6_hdr *)nextPtr;
            
            if(ip6Hdr->ip6_nxt == IP6_PROTO_FRAG) //IP6 Fragment
            { 
                isFrag = 1;
                frag6Hdr = (struct ip6_frag *)((uint8_t *)ip6Hdr + sizeof(struct ip6_hdr));
                id = ntohl(frag6Hdr->ip6f_ident);
                
                moreFragments = ntohs(frag6Hdr->ip6f_offlg) & ntohs(IP6F_MORE_FRAG);
                outeroffset  = (ntohs(frag6Hdr->ip6f_offlg) & ntohs(IP6F_OFF_MASK)) >> IP6F_OFF_SHIFT;
                
                outerProtocol = frag6Hdr->ip6f_nxt;
                outerL4Ptr = (uint8_t *)frag6Hdr + sizeof(struct ip6_frag);

                payload = outerL4Ptr;
                payloadLen = (uint16_t)ntohs(ip6Hdr->ip6_plen) - sizeof(struct ip6_frag);
            }
            else
            {
                isFrag = 0;
                outerProtocol = ip6Hdr->ip6_nxt;
                outerL4Ptr = (uint8_t *)ip6Hdr + sizeof(struct ip6_hdr);

                payload = outerL4Ptr;
                payloadLen = (uint16_t)ntohs(ip6Hdr->ip6_plen);
            }

        }
        else
        {
            /* Ignoring non IPv4/IPv6 packets */
            stats->unsupportedType++;
            continue;
        }

        if(in6_isAddrV6(&pktCfg->outerSrcAddr) &&
           in6_isAddrV6(&pktCfg->outerDstAddr))
        {
            outerPktLen += sizeof(struct ip6_hdr);                

            if(isFrag){
           
                outerPktLen += sizeof(struct ip6_frag);
            }
            
        }
        else if (!in6_isAddrV6(&pktCfg->outerSrcAddr) &&
                 !in6_isAddrV6(&pktCfg->outerDstAddr))
        {
            outerPktLen += sizeof(struct iphdr);
        }
        else
        {
            /* Should not happen */
            stats->unsupportedType++;
            continue;
        }
        
        if((outerProtocol == IPPROTO_UDP)&& (outeroffset == 0))
        {
            udpHdr = (struct udphdr *)((void *)outerL4Ptr);

            payload = (uint8_t *)udpHdr + sizeof(struct udphdr);

            if(payloadLen > sizeof(struct udphdr)){
                    payloadLen -= sizeof(struct udphdr);
                }


            outerPktLen += sizeof(struct udphdr);

            outerL4Len = udpHdr->len;

            if(moreFragments && ipHdr != NULL)
            {
                /* Original Packet is IPv4 */
                origL4Checksum = udpHdr->check;
                origL4Checksum = modcsum_32(origL4Checksum, ipHdr->saddr, 0);
                origL4Checksum = modcsum_32(origL4Checksum, ipHdr->daddr, 0);
                origL4Checksum = modcsum_16(origL4Checksum, udpHdr->source, 0);
                origL4Checksum = modcsum_16(origL4Checksum, udpHdr->dest, 0);
            }
            else if(moreFragments && ip6Hdr != NULL) 
            {
                /* Original Packet is IPv6 */
                origL4Checksum = udpHdr->check; 

                //Mod IPv6 addresses into checksum in 32 bit chunks. 
                uint8_t i;
                for(i = 0; i < 4; i++){
                    origL4Checksum = modcsum_32(origL4Checksum, ip6Hdr->ip6_src.s6_addr32[i], 0);
                    origL4Checksum = modcsum_32(origL4Checksum, ip6Hdr->ip6_dst.s6_addr32[i], 0);
                }

                //Mod UDP source/destination port into checksum.
                origL4Checksum = modcsum_16(origL4Checksum, udpHdr->source, 0);
                origL4Checksum = modcsum_16(origL4Checksum, udpHdr->dest, 0);

            }

            rtpHdr = (rtp_hdr *) ((uint8_t *)udpHdr + sizeof(struct udphdr));

            if(rtpHdr->version == 0x80)
            {
                /* We believe this is an RTP packet now though I guess it could be an unlucky UDP hit */

                for(i = 0; i < pktCfg->numRtpPtMap; i++)
                {
                    if((rtpHdr->payloadType & 0x7f) == pktCfg->rtpPtMap[i].old)
                    {
                        rtpHdr->payloadType &= 0x80;
                        rtpHdr->payloadType |= pktCfg->rtpPtMap[i].new;
                    }
                }

                if(!pktCfg->rtpInitialSsrcTx)
                {
                    pktCfg->rtpInitialSsrcTx = rtpHdr->ssrc;
                }
                else
                {
                    pktCfg->rtpSubseqSsrcTx = rtpHdr->ssrc;
                }
            }

        }
        else if((outerProtocol == IPPROTO_TCP)&& (outeroffset == 0))
        {
            tcpHdr = (struct tcphdr *)((void *)outerL4Ptr);
            tcpOpts = (tcpOpts_t *)((uint8_t *)tcpHdr + sizeof(struct tcphdr));
            
            payload = (uint8_t *)tcpHdr + (tcpHdr->doff << 2);
            payloadLen -= (tcpHdr->doff << 2);
            outerPktLen += (tcpHdr->doff << 2);
        }
        else if((outerProtocol == IPPROTO_IPIP) ||
                (outerProtocol == IPPROTO_IPV6))
        {
            if((outerProtocol == IPPROTO_IPIP))
            {
                ipHdr = (struct iphdr *)((void *)outerL4Ptr);

                innerProtocol = ipHdr->protocol;
                innerL4Ptr = (uint8_t *)ipHdr + sizeof(struct iphdr);
                payload = innerL4Ptr;
                innerfragmentOffset = ipHdr->frag_off;
                innerid = htons((uint16_t)ipHdr->id);
                moreFragments = ((htons(innerfragmentOffset) & 0x2000) >> 13);
                inneroffset = (htons(innerfragmentOffset) & 0x1fff);
                if((htons(innerfragmentOffset) & 0x3fff))
                {
                    isFrag = 1;
                }
                else
                {
                    isFrag = 0;
                }
                
                //tot_len in inner ipHdr is jumbo pkt size, not frag size
                innerPayloadLen = (uint16_t)(ntohs(ipHdr->tot_len) - sizeof(struct iphdr));
                payloadLen -= sizeof(struct iphdr);
            }
            else
            {

                ip6Hdr = (struct ip6_hdr *)((void *)outerL4Ptr);

                innerProtocol = ip6Hdr->ip6_nxt;
                innerL4Ptr = (uint8_t *)ip6Hdr + sizeof(struct ip6_hdr);
                payload = innerL4Ptr;
                payloadLen = (uint16_t)ntohs(ip6Hdr->ip6_plen);
            }
            outerL4Ptr = NULL;

            if(in6_isAddrV6(&pktCfg->innerSrcAddr) &&
               in6_isAddrV6(&pktCfg->innerDstAddr))
            {
                outerProtocol = IPPROTO_IPV6;
                outerPktLen += sizeof(struct ip6_hdr);
      
            }
            else if (!in6_isAddrV6(&pktCfg->innerSrcAddr) &&
                     !in6_isAddrV6(&pktCfg->innerDstAddr))
            {
                outerProtocol = IPPROTO_IPIP;
                outerPktLen += sizeof(struct iphdr);
            }
            else
            {
                /* Should not happen */
                stats->unsupportedType++;
                continue;
            }

            //only set innerPayloadLen to payloadLen for non IPIP case
            if(outerProtocol != IPPROTO_IPIP)
            {
                innerPayloadLen = payloadLen;
            }

            if((innerProtocol == IPPROTO_UDP) && (inneroffset == 0))
            {
                udpHdr = (struct udphdr *)((void *)innerL4Ptr);

                payload = (uint8_t *)udpHdr + sizeof(struct udphdr);
                payloadLen -= sizeof(struct udphdr);
                outerPktLen += sizeof(struct udphdr);
                innerL4Len = udpHdr->len;

            }
            else if(innerProtocol == IPPROTO_TCP)
            {
                tcpHdr = (struct tcphdr *)((void *)innerL4Ptr);
                tcpOpts = (tcpOpts_t *)((uint8_t *)tcpHdr + sizeof(struct tcphdr));

                payload = (uint8_t *)tcpHdr + (tcpHdr->doff << 2);
                payloadLen -= (tcpHdr->doff << 2);
                outerPktLen += (tcpHdr->doff << 2);
            }
            else if((innerProtocol == IPPROTO_UDP) && (inneroffset != 0))
            {
                payload = innerL4Ptr;
                payloadLen =  payloadLen;
                outerPktLen = outerPktLen;        
            }
            else
            {
                /* Skipping non-UDP/TCP packets for now */
                stats->unsupportedType++;
                continue;
            }
        }
        else if(outeroffset)
        {
            payload = outerL4Ptr;
            payloadLen =  payloadLen;
            outerPktLen = outerPktLen;
        }
        else
        {
            /* Skipping non-UDP/TCP packets for now */
            stats->unsupportedType++;
            continue;
        }
        
        outerPktLen += payloadLen;

        /*********** Start Creating Our Modified Packet ***********/                              
        pkts->pkts = (pcap_pkt *) realloc((void *)pkts->pkts, ((sizeof(pcap_pkt) * (pkts->numPkts + 1))));
        if(!pkts->pkts)
        {
            ERR("Unable to realloc memory for pkts");
            exit(1);
        }
        pktIndex = (pcap_pkt *)((char *)pkts->pkts + (sizeof(pcap_pkt) * pkts->numPkts));
        memset(pktIndex, 0, sizeof(pcap_pkt));
        pktIndex->dataLen = outerPktLen;
        pktIndex->data = (void *)malloc(pktIndex->dataLen);
        if(!pktIndex->data)
        {
            ERR("Unable to malloc memory for data");
            exit(1);
        }
        memset(pktIndex->data, 0, pktIndex->dataLen);

        nextPtr = (void *)(pktIndex->data);

        /*********** Outer L3 Processing ***********/
        if(in6_isAddrZero(&pktCfg->outerSrcAddr) ||
           in6_isAddrZero(&pktCfg->outerDstAddr))
        {
        }
        else if(in6_isAddrV6(&pktCfg->outerSrcAddr) &&
                in6_isAddrV6(&pktCfg->outerDstAddr))
        {
  
            /* Operating in v6 mode, create whole new header */
            outerPayloadLen = outerPktLen - sizeof(struct ip6_hdr);
            
            ip6Hdr = (struct ip6_hdr *)((void *)nextPtr);
            in6_cpyAddr(&(ip6Hdr->ip6_src), &pktCfg->outerSrcAddr);
            in6_cpyAddr(&(ip6Hdr->ip6_dst), &pktCfg->outerDstAddr);
            ip6Hdr->ip6_flow= (6 << 28);
            ip6Hdr->ip6_flow |= (pktCfg->outerToS << 20);
            ip6Hdr->ip6_flow = htonl(ip6Hdr->ip6_flow);
            ip6Hdr->ip6_plen = htons(outerPayloadLen); 
            ( 0 != isFrag ) ? (ip6Hdr->ip6_nxt = IP6_PROTO_FRAG) : (ip6Hdr->ip6_nxt = outerProtocol);
            (pktCfg->outerTTL != 0) ? (ip6Hdr->ip6_hlim = pktCfg->outerTTL) : (ip6Hdr->ip6_hlim = 64);
            
            nextPtr = (uint8_t *)ip6Hdr + sizeof(struct ip6_hdr);
            
            
            if(isFrag){
            
                /* NBT - Add the frag header if we have a fragment. */
                frag6Hdr = (struct ip6_frag *)((uint8_t *)ip6Hdr + sizeof(struct ip6_hdr));
                frag6Hdr->ip6f_nxt = outerProtocol;
                frag6Hdr->ip6f_reserved = 0;
                frag6Hdr->ip6f_ident = htonl(id);
                frag6Hdr->ip6f_offlg = htons(outeroffset << 3 | moreFragments);
                
                nextPtr = (uint8_t *)frag6Hdr + sizeof(struct ip6_frag);
                
                uint8_t i;
                for(i = 0; i < 4; i++){
                    origL4Checksum = modcsum_32(origL4Checksum, 0, ip6Hdr->ip6_src.s6_addr32[i]);
                    origL4Checksum = modcsum_32(origL4Checksum, 0, ip6Hdr->ip6_dst.s6_addr32[i]);
                }
            }
            
        }
        else if(!in6_isAddrV6(&pktCfg->outerSrcAddr) &&
                !in6_isAddrV6(&pktCfg->outerDstAddr))
        {
            /* Operating in v4 mode, create whole new header */
            outerPayloadLen = outerPktLen - sizeof(struct iphdr);

            ipHdr = (struct iphdr *)((void *)nextPtr);
            ipHdr->version = 4;
            ipHdr->ihl = 5;
            ipHdr->tos = pktCfg->outerToS;
            ipHdr->tot_len = htons(outerPktLen);
            (isFrag!=0)? (ipHdr->id=(htons((uint16_t)id))):(ipHdr->id = 0);//id; //fragment change
            /*ipHdr->frag_off = htons(0x4000);*/
            /*ipHdr->frag_off = fragmentOffset;*/
            (isFrag!=0)? (ipHdr->frag_off=fragmentOffset):(ipHdr->frag_off = 0);
            (pktCfg->outerTTL != 0) ? (ipHdr->ttl = pktCfg->outerTTL) : (ipHdr->ttl = 64);
            ipHdr->protocol = outerProtocol;
            ipHdr->check = 0;
            ipHdr->saddr = pktCfg->outerSrcAddr.s6_addr32[3];
            ipHdr->daddr = pktCfg->outerDstAddr.s6_addr32[3];
            ipHdr->check = ipcsum(sizeof(struct iphdr), (uint16_t *)ipHdr);
            nextPtr = (uint8_t *)ipHdr + sizeof(struct iphdr);

            if(moreFragments)
            {
                origL4Checksum = modcsum_32(origL4Checksum, 0, ipHdr->saddr);
                origL4Checksum = modcsum_32(origL4Checksum, 0, ipHdr->daddr);
            }
        }
        else
        {
            printf("%s: outerSrc and outerDest are two different address families\n", __FUNCTION__);
            exit(1);
        }
        
        /*********** Outer L4 Processing ***********/
        if(outerL4Ptr != NULL)
        {
            if((outerProtocol == IPPROTO_UDP) && (outeroffset == 0))
            /* if(outerProtocol == IPPROTO_UDP) */
            {

                memcpy(nextPtr, (void *)outerL4Ptr, sizeof(struct udphdr));

                udpHdr = (struct udphdr *)((void *)nextPtr);
                outerL4Ptr = (void *)nextPtr;

                if(pktCfg->outerSrcPort)
                {
                    udpHdr->source = htons(pktCfg->outerSrcPort);
                }

                if(pktCfg->outerDstPort)
                {
                    udpHdr->dest = htons(pktCfg->outerDstPort);
                }

                origL4Checksum = modcsum_16(origL4Checksum, 0, udpHdr->source);
                origL4Checksum = modcsum_16(origL4Checksum, 0, udpHdr->dest);

                udpHdr->check = 0;
                udpHdr->len = outerL4Len;
                outerChecksumPtr = (uint16_t *)&udpHdr->check;

                nextPtr = (uint8_t *)udpHdr + sizeof(struct udphdr);
            }
            else if((outerProtocol == IPPROTO_TCP) && (outeroffset == 0))
            {
                memcpy(nextPtr, (void *)outerL4Ptr, (tcpHdr->doff << 2));

                tcpHdr = (struct tcphdr *)(void *)nextPtr;
                tcpOpts = (tcpOpts_t *)((uint8_t *)tcpHdr + sizeof(struct tcphdr));
      
                outerL4Ptr = (void *)nextPtr;

                if(pktCfg->outerSrcPort)
                {
                    tcpHdr->source = htons(pktCfg->outerSrcPort);
                }

                if(pktCfg->outerDstPort)
                {
                    tcpHdr->dest = htons(pktCfg->outerDstPort);
                }

                /* Zero the options field of the TCP header. */
                memset(tcpOpts, 0, ((tcpHdr->doff << 2) - sizeof(struct tcphdr)));
                tcpHdr->check = 0;
                outerChecksumPtr = (uint16_t *)&tcpHdr->check;

                nextPtr = (uint8_t *)tcpHdr + (tcpHdr->doff << 2);
            }
            else if(((outerProtocol == IPPROTO_UDP)||(outerProtocol == IPPROTO_TCP)) && (outeroffset != 0))
            {

            }
            else
            {
                stats->unsupportedType++;
                continue;
            }
        }

        /*********** Inner L3 Processing ***********/
        if(in6_isAddrZero(&pktCfg->innerSrcAddr) &&
           in6_isAddrZero(&pktCfg->innerDstAddr))
        {
        }
        else if(in6_isAddrV6(&pktCfg->innerSrcAddr) ||
                in6_isAddrV6(&pktCfg->innerDstAddr))
        {
            /* Operating in v6 mode, create whole new header */

            ip6Hdr = (struct ip6_hdr *)((void *)nextPtr);

            in6_cpyAddr(&(ip6Hdr->ip6_src), &pktCfg->innerSrcAddr);
            in6_cpyAddr(&(ip6Hdr->ip6_dst), &pktCfg->innerDstAddr);
            ip6Hdr->ip6_flow = htonl(6 << 28);
            ip6Hdr->ip6_flow = pktCfg->innerToS;
            ip6Hdr->ip6_plen = htons(innerPayloadLen);
            ( 0 != isFrag) ? (ip6Hdr->ip6_nxt = IP6_PROTO_FRAG) : (ip6Hdr->ip6_nxt = innerProtocol);
            ip6Hdr->ip6_hlim = 64; 
             
            nextPtr = (uint8_t *)ip6Hdr + sizeof(struct ip6_hdr);

            if(isFrag){
                
                /* NBT - Add the frag header if we have a fragment. */
                
                frag6Hdr = (struct ip6_frag *)((uint8_t *)ip6Hdr + sizeof(struct ip6_hdr));
                frag6Hdr->ip6f_nxt = innerProtocol;
                frag6Hdr->ip6f_reserved = 0;
                frag6Hdr->ip6f_ident = htonl(id);
                frag6Hdr->ip6f_offlg = htons(inneroffset << 3) ;
                frag6Hdr->ip6f_offlg |= htons(moreFragments);
                
                nextPtr = (uint8_t *)frag6Hdr + sizeof(struct ip6_frag);
            }
             
       
        }
        else if(!in6_isAddrV6(&pktCfg->innerSrcAddr) &&
                !in6_isAddrV6(&pktCfg->innerDstAddr))
        {
            /* Operating in v4 mode, create whole new header */

            ipHdr = (struct iphdr *)((void *)nextPtr);
            ipHdr->version = 4;
            ipHdr->ihl = 5;
            ipHdr->tos = pktCfg->innerToS;
            ipHdr->tot_len = htons(innerPayloadLen + sizeof(struct iphdr));
            (isFrag!=0) ? (ipHdr->id=htons((uint16_t)innerid)):(ipHdr->id = 0);
            //ipHdr->frag_off = htons(0x4000);
            /*ipHdr->frag_off = fragmentOffset;*/
            (isFrag!=0)? (ipHdr->frag_off=innerfragmentOffset):(ipHdr->frag_off = 0);
            if(pktCfg->innerTTL != 0)
            {
                ipHdr->ttl = pktCfg->innerTTL;
            }
            else
            {
                ipHdr->ttl = 64;
            }
            ipHdr->protocol = innerProtocol;
            ipHdr->check = 0;
            ipHdr->saddr = pktCfg->innerSrcAddr.s6_addr32[3];
            ipHdr->daddr = pktCfg->innerDstAddr.s6_addr32[3];
            ipHdr->check = ipcsum(sizeof(struct iphdr), (uint16_t *)ipHdr);
            nextPtr = (uint8_t *)ipHdr + sizeof(struct iphdr);
        }
        else
        {
            printf("%s: innerSrc and innerDest are two different address families\n", __FUNCTION__);
            exit(1);
        }

        /*********** Inner L4 Processing ***********/
        if(innerL4Ptr != NULL)
        {
            if((innerProtocol == IPPROTO_UDP) && (inneroffset == 0))
            {
                memcpy(nextPtr, (void *)innerL4Ptr, sizeof(struct udphdr));

                udpHdr = (struct udphdr *)((void *)nextPtr);
                innerL4Ptr = (void *)nextPtr;

                if(pktCfg->innerSrcPort)
                {
                    udpHdr->source = htons(pktCfg->innerSrcPort);
                }

                if(pktCfg->innerDstPort)
                {
                    udpHdr->dest = htons(pktCfg->innerDstPort);
                }
                udpHdr->check = 0;
                innerChecksumPtr = (uint16_t *)&udpHdr->check;

                nextPtr = (uint8_t *)udpHdr + sizeof(struct udphdr);
            }
            else if((innerProtocol == IPPROTO_TCP)&&(inneroffset == 0))
            {
                memcpy(nextPtr, (void *)innerL4Ptr, sizeof(struct tcphdr));

                tcpHdr = (struct tcphdr *)((void *)nextPtr);
                innerL4Ptr = (void *)nextPtr;

                if(pktCfg->innerSrcPort)
                {
                    tcpHdr->source = htons(pktCfg->innerSrcPort);
                }

                if(pktCfg->innerDstPort)
                {
                    tcpHdr->dest = htons(pktCfg->innerDstPort);
                }
                tcpHdr->check = 0;
                innerChecksumPtr = (uint16_t *)&tcpHdr->check;

                nextPtr = (uint8_t *)tcpHdr + (tcpHdr->doff << 2);
            }
            else if(((innerProtocol == IPPROTO_UDP)||(outerProtocol == IPPROTO_TCP)) && (inneroffset != 0))
            {

                nextPtr = (uint8_t *)ipHdr + sizeof(struct iphdr);
            }
            else
            {
                stats->unsupportedType++;
                continue;
            }
        }

        /* Append rest of the payload onto the packet */
     
        memcpy(nextPtr, payload, payloadLen);

        if(outerChecksumPtr != NULL && outeroffset == 0)
        {
            if(moreFragments)
            {
                *outerChecksumPtr = origL4Checksum;
            }
            else
            {
                *outerChecksumPtr = l4csum(&pktCfg->outerSrcAddr,
                                           &pktCfg->outerDstAddr,
                                           (uint16_t *)outerL4Ptr,
                                           outerPayloadLen,
                                           (uint16_t)outerProtocol);
            
                if(*outerChecksumPtr == 0x0000)
                {
                    printf("Calculated outer checksum is 0!\n");
                    *outerChecksumPtr = 0xffff;
                }
            }
        }

        if(innerChecksumPtr != NULL)
        {
            *innerChecksumPtr = l4csum(&pktCfg->innerSrcAddr,
                                       &pktCfg->innerDstAddr,
                                       (uint16_t *)innerL4Ptr,
                                       innerPayloadLen,
                                       (uint16_t)innerProtocol);

            if(*innerChecksumPtr == 0x0000)
            {
                printf("Calculated outer checksum is 0!\n");
                *innerChecksumPtr = 0xffff;
            }
        }

        timersub(&(pkthdr->ts), &(prev_te), &current_te);
        pktIndex->te = current_te;

        current_ts.tv_sec = current_te.tv_sec;
        current_ts.tv_nsec = current_te.tv_usec * 1000;
        pktIndex->ts = current_ts;
        prev_te = pkthdr->ts;

        pkts->numPkts++;

        if(pktIndex->dataLen > pkts->maxPktLen)
        {
            pkts->maxPktLen = pktIndex->dataLen;
        }
    }

    pcap_close(pcap);
    free(pkthdr);
}

void init_pkts_list(config_t *pktCfg)
{
    pcap_pkts          *pkts = NULL;
    pcap_pkt           *pktIndex = NULL;
    uint32_t           numNodes = 0;

    if(pktCfg == NULL)
    {
        ERR("%s: provided with NULL pktCfg", __FUNCTION__);
        exit(1);
    }

    pkts = (pcap_pkts *)&pktCfg->pcap;

    while(numNodes < pkts->numPkts)
    {
	pktIndex = (pcap_pkt *)((char *)pkts->pkts + (sizeof(pcap_pkt) * numNodes));
	insertList(pktIndex);
	numNodes++;
    }
}

void init_play_pkts(config_t *pktCfg)
{
    play_pkt           *pktIndex = NULL;
    void               *nextPtr = NULL;

    void               *payload = NULL;
    uint16_t            payloadLen = 0;

    uint32_t            i = 0;

    if(pktCfg == NULL)
    {
        ERR("%s: provided with NULL pktCfg", __FUNCTION__);
        exit(1);
    }

    /************** Start Creating Play Packet **************/
    playPkts = (play_pkts *)malloc(sizeof(play_pkts));
    playPkts->numPkts = 0;
    playPkts->maxPktLen = 0;
    playPkts->pkts = NULL;

    while(playPkts->numPkts < pktCfg->userNumPkts)
    {
	playPkts->pkts = (play_pkt *)realloc((void *)playPkts->pkts, (sizeof(play_pkt) * (playPkts->numPkts + 1)));
	if(!playPkts->pkts)
	{
	    ERR("Unable to malloc memory for pkts");
	    exit(1);
	}

        payloadLen = pktCfg->payloadSize + (playPkts->numPkts * pktCfg->diffSize);

	pktIndex = (play_pkt *)((char *)playPkts->pkts + sizeof(play_pkt) * playPkts->numPkts);
	memset(pktIndex, 0, sizeof(play_pkt));
	pktIndex->dataLen = payloadLen;
	pktIndex->data = (void *)malloc(pktIndex->dataLen);
	if(!pktIndex->data)
	{
	    ERR("Unable to malloc memory for data");
	    exit(1);
	}
	memset(pktIndex->data, 0, pktIndex->dataLen);
	nextPtr = (void *)(pktIndex->data);

	/* Append rest of the payload onto the packet */
	payload = (uint8_t *)((void *)nextPtr);
	i = 0;
	while(i < payloadLen)
	{
	    memset(nextPtr, i % 128 , 1);
	    i++;
	    nextPtr++;
	}

	playPkts->numPkts++;

	if(pktIndex->dataLen > playPkts->maxPktLen)
	{
	    playPkts->maxPktLen = pktIndex->dataLen;
	}
    }
}

int verify_rtp_event_timestamp(struct udphdr *recvUdpHdr, struct udphdr *pcapUdpHdr)
{
    static int latchTimestamp = 0;
    static uint32_t currentTimestamp = 0;
    rtp_hdr *rtpHdr = NULL;

    rtpHdr = (rtp_hdr *) ((uint8_t *)recvUdpHdr + sizeof(struct udphdr));

    if(!latchTimestamp)
    {
        latchTimestamp = 1;
        currentTimestamp = rtpHdr->timestamp;
    }

    if(currentTimestamp == rtpHdr->timestamp)
    {
        /* We have verified that the timestamps are not changing */
        /* Remove timestamps from RTP header as well as from the UDP checksum */

        rtpHdr = (rtp_hdr *) ((uint8_t *)recvUdpHdr + sizeof(struct udphdr));
        recvUdpHdr->check = modcsum_32(recvUdpHdr->check, rtpHdr->timestamp, 0);
        rtpHdr->timestamp = 0;


        rtpHdr = (rtp_hdr *) ((uint8_t *)pcapUdpHdr + sizeof(struct udphdr));
        pcapUdpHdr->check = modcsum_32(pcapUdpHdr->check, rtpHdr->timestamp, 0);
        rtpHdr->timestamp = 0;

        return 0;
    }
    else
    {
        return 1;
    }
}

int check_packet(void *recvPkt, pcap_pkts *pcap)
{
    struct iphdr     *recvIpHdr = NULL;
    struct iphdr     *pcapIpHdr = NULL;
    struct ip6_hdr   *recvIp6Hdr = NULL;
    struct ip6_hdr   *pcapIp6Hdr = NULL;
    struct ip6_frag  *pcapFrag6Hdr = NULL;
    struct ip6_frag  *recvFrag6Hdr = NULL;
    uint16_t          recvPktLength = 0;
    uint16_t          pcapPktLength = 0;
    uint8_t           protocol = 0;
    void             *recvL4Ptr = NULL;
    void             *pcapL4Ptr = NULL;
    struct iphdr     *recvInnerIpHdr = NULL;
    struct iphdr     *pcapInnerIpHdr = NULL;
    struct ip6_hdr   *recvInnerIp6Hdr = NULL;
    struct ip6_hdr   *pcapInnerIp6Hdr = NULL;
    struct udphdr    *recvUdpHdr = NULL;
    struct udphdr    *pcapUdpHdr = NULL;
    struct tcphdr    *recvTcpHdr = NULL;
    struct tcphdr    *pcapTcpHdr = NULL;
    uint16_t          dataLen = 0;
    pcap_pkt         *pktIndex  = NULL;
    uint16_t          fragmentedpacket = 0;
    uint16_t          offset;
    tcpOpts_t        *recvTcpOpts;
    tcpOpts_t        *pcapTcpOpts;
    uint32_t          recvTcpAckSeqOffs = 0;
    uint32_t          pcapTcpAckSeqOffs = 0;
    static uint32_t   recvTcpAckSeqLast = 0;
    static uint32_t   pcapTcpAckSeqLast = 0;
    uint16_t         *oldPcapSeq = NULL;
    uint16_t         *newPcapSeq = NULL;
    uint16_t         *recvOptsPtr= NULL;

    pkt_node         *listIndex = NULL;
    uint16_t          hop = 0;

    if(info->bHop)
    {
        listIndex = listenList;
    }

    do
    {
    if(info->bHop){
        pktIndex = (pcap_pkt *)listIndex->index;
    }
    else{
        pktIndex = pcap->pkts + stats->expectedPktsRx % pcap->numPkts;
    }

    if((*(uint8_t *)recvPkt >> 4) == 0x4) /* IPv4 Packet */
    {
        pcapIpHdr = (struct iphdr *)(pktIndex->data);
        recvIpHdr = (struct iphdr *)(recvPkt);

        if((recvIpHdr->saddr != pcapIpHdr->saddr) ||
           (recvIpHdr->daddr != pcapIpHdr->daddr))
        {
            /* Packet was not destined for this listener */
            stats->unknownPktsRx++;
            return 1;
        }

        if(( htons(recvIpHdr->frag_off) & 0x3fff )!=0)
        {
            fragmentedpacket = 1;
            offset = ( htons(recvIpHdr->frag_off) & 0x0fff);
        }
        recvIpHdr->check = modcsum_16(recvIpHdr->check, recvIpHdr->id, pcapIpHdr->id);
        recvIpHdr->id = pcapIpHdr->id;

        recvIpHdr->check = modcsum_16(recvIpHdr->check, recvIpHdr->frag_off, pcapIpHdr->frag_off);
        recvIpHdr->frag_off = pcapIpHdr->frag_off;

        if(recvIpHdr->protocol != pcapIpHdr->protocol)
        {
            /* Packet was not destined for this listener */
            stats->unknownPktsRx++;
            return 1;
        }

        protocol = recvIpHdr->protocol;
        if(protocol == IPPROTO_IPIP)
        {
            recvInnerIpHdr = (struct iphdr *)((uint8_t *)recvIpHdr + (recvIpHdr->ihl << 2));
            pcapInnerIpHdr = (struct iphdr *)((uint8_t *)pcapIpHdr + (pcapIpHdr->ihl << 2));

            if((recvInnerIpHdr->saddr != pcapInnerIpHdr->saddr) ||
               (recvInnerIpHdr->daddr != pcapInnerIpHdr->daddr))
            {
                /* Packet was not destined for this listener */
                stats->unknownPktsRx++;
                return 1;
            }
            if(( htons(recvInnerIpHdr->frag_off) & 0x3fff )!=0)
            {

                fragmentedpacket = 1;
                offset = ( htons(recvInnerIpHdr->frag_off) & 0x0fff);
            }
            recvInnerIpHdr->check = modcsum_16(recvInnerIpHdr->check, recvInnerIpHdr->id,pcapInnerIpHdr->id);
            recvInnerIpHdr->id = pcapInnerIpHdr->id;
            recvInnerIpHdr->check = modcsum_16(recvInnerIpHdr->check, recvInnerIpHdr->frag_off, pcapInnerIpHdr->frag_off);
            recvInnerIpHdr->frag_off = pcapInnerIpHdr->frag_off;

            protocol = recvInnerIpHdr->protocol;

            recvL4Ptr = (uint8_t *)recvInnerIpHdr + (recvInnerIpHdr->ihl << 2);
            pcapL4Ptr = (uint8_t *)pcapInnerIpHdr + (pcapInnerIpHdr->ihl << 2);

        }
        else if(protocol == IPPROTO_IPV6)
        {
            recvInnerIp6Hdr = (struct ip6_hdr *)((uint8_t *)recvIpHdr + (recvIpHdr->ihl << 2));
            pcapInnerIp6Hdr = (struct ip6_hdr *)((uint8_t *)pcapIpHdr + (pcapIpHdr->ihl << 2));

            protocol = recvInnerIp6Hdr->ip6_nxt;

            recvL4Ptr = (uint8_t *)recvInnerIp6Hdr + sizeof(struct ip6_hdr);
            pcapL4Ptr = (uint8_t *)pcapInnerIp6Hdr + sizeof(struct ip6_hdr);
        }
        else
        {
            recvL4Ptr = (uint8_t *)recvIpHdr + (recvIpHdr->ihl << 2);
            pcapL4Ptr = (uint8_t *)pcapIpHdr + (pcapIpHdr->ihl << 2);
        }

        recvPktLength = recvIpHdr->tot_len;
        pcapPktLength = pcapIpHdr->tot_len;

        dataLen = (uint16_t)(ntohs(recvIpHdr->tot_len));
    }
    else if((*(uint8_t *)recvPkt >> 4) == 0x6) /* IPv6 Packet */
    {
        pcapIp6Hdr = (struct ip6_hdr *)(pktIndex->data);
        recvIp6Hdr = (struct ip6_hdr *)(recvPkt);

        if(!in6_cmpAddr(&(pcapIp6Hdr->ip6_src), &(recvIp6Hdr->ip6_src)) ||
           !in6_cmpAddr(&(pcapIp6Hdr->ip6_dst), &(recvIp6Hdr->ip6_dst)))
        {
            /* Packet was not destined for this listener */
            stats->unknownPktsRx++;
            return 1;
        }

        if(recvIp6Hdr->ip6_nxt != pcapIp6Hdr->ip6_nxt)
        {
            /* Packet was not destined for this listener */
            stats->unknownPktsRx++;
            return 1;
        }

        protocol = recvIp6Hdr->ip6_nxt;

        if(protocol == IPPROTO_IPIP)
        {
            recvInnerIpHdr = (struct iphdr *)((uint8_t *)recvIpHdr + (recvIpHdr->ihl << 2));
            pcapInnerIpHdr = (struct iphdr *)((uint8_t *)pcapIpHdr + (pcapIpHdr->ihl << 2));

            if((recvInnerIpHdr->saddr != pcapInnerIpHdr->saddr) ||
               (recvInnerIpHdr->daddr != pcapInnerIpHdr->daddr))
            {
                /* Packet was not destined for this listener */
                stats->unknownPktsRx++;
                return 1;
            }

            recvInnerIpHdr->check = modcsum_16(recvInnerIpHdr->check, recvInnerIpHdr->id, 0);
            recvInnerIpHdr->id = 0;
            recvInnerIpHdr->check = modcsum_16(recvInnerIpHdr->check, recvInnerIpHdr->frag_off, 0);
            recvInnerIpHdr->frag_off = 0;

            protocol = recvInnerIpHdr->protocol;

            recvL4Ptr = (uint8_t *)recvInnerIpHdr + (recvInnerIpHdr->ihl << 2);
            pcapL4Ptr = (uint8_t *)pcapInnerIpHdr + (pcapInnerIpHdr->ihl << 2);

        }
        else if(protocol == IPPROTO_IPV6)
        {
            recvInnerIp6Hdr = (struct ip6_hdr *)((uint8_t *)recvIpHdr + (recvIpHdr->ihl << 2));
            pcapInnerIp6Hdr = (struct ip6_hdr *)((uint8_t *)pcapIpHdr + (pcapIpHdr->ihl << 2));

            protocol = recvInnerIp6Hdr->ip6_nxt;

            recvL4Ptr = (uint8_t *)recvInnerIp6Hdr + sizeof(struct ip6_hdr);
            pcapL4Ptr = (uint8_t *)pcapInnerIp6Hdr + sizeof(struct ip6_hdr);
        }
        else
        {
            recvL4Ptr = (uint8_t *)recvIp6Hdr + sizeof(struct ip6_hdr);
            pcapL4Ptr = (uint8_t *)pcapIp6Hdr + sizeof(struct ip6_hdr);

            if(protocol == IP6_PROTO_FRAG)
            {
                recvFrag6Hdr = (struct ip6_frag *)((uint8_t *)recvIp6Hdr + sizeof(struct ip6_hdr));
                pcapFrag6Hdr = (struct ip6_frag *)((uint8_t *)pcapIp6Hdr + sizeof(struct ip6_hdr));
                recvFrag6Hdr->ip6f_ident = 0;
                pcapFrag6Hdr->ip6f_ident = 0;

                fragmentedpacket = 1;
                offset = (htons(recvFrag6Hdr->ip6f_offlg) & 0xfff8);

                protocol = recvFrag6Hdr->ip6f_nxt;

                recvL4Ptr += sizeof(struct ip6_frag);
                pcapL4Ptr += sizeof(struct ip6_frag);
            }
        }

        recvPktLength = recvIp6Hdr->ip6_plen;
        pcapPktLength = pcapIp6Hdr->ip6_plen;

        dataLen = (uint16_t)(ntohs(recvIp6Hdr->ip6_plen) + sizeof(struct ip6_hdr));

    }

    /* Check to see if the packet we have received has UDP/TCP ports matching those that we expect */
    if(protocol == IPPROTO_UDP)
    {
        recvUdpHdr = (struct udphdr *)recvL4Ptr;
        pcapUdpHdr = (struct udphdr *)pcapL4Ptr;

        if(fragmentedpacket == 0)
        {
            if((recvUdpHdr->source != pcapUdpHdr->source) || (recvUdpHdr->dest != pcapUdpHdr->dest))
            {
                /* Either something went wrong in the SD or the packet was not destined for this
                 * instance of the SD_Listener. Either way, discard this packet and continue to look
                 * for the next packet.
                 */
                if(info->bVerbose)
                {
                    printf("\nUDP ports did not match\n");
                    printf("\nUDP source port recv(%d) pcap(%d)\n", ntohs(recvUdpHdr->source), ntohs(pcapUdpHdr->source));
                    printf("\nUDP dest port recv(%d) pcap(%d)\n", ntohs(recvUdpHdr->dest), ntohs(pcapUdpHdr->dest));
                }
                stats->unknownPktsRx++;
                return 1;
            }

            if(info->bVerifyRTPEventTS)
            {
                if(verify_rtp_event_timestamp(recvUdpHdr, pcapUdpHdr) != 0)
                {
                    rtp_hdr *recvRtpHdr = (rtp_hdr *) ((uint8_t *)recvUdpHdr + sizeof(struct udphdr));
                    rtp_hdr *pcapRtpHdr = (rtp_hdr *) ((uint8_t *)pcapUdpHdr + sizeof(struct udphdr));

                    ERR("\nRTP Timestamps did not match recv(%d) pcap(%d)\n", recvRtpHdr->timestamp, pcapRtpHdr->timestamp);
                    
                    if(info->bVerbose)
                    {
                        printf("Received packet:\n");
                        print_buffer((uint8_t *)recvPkt, ntohs(recvIpHdr->tot_len));

                        printf("Expected packet:\n");
                        print_buffer((uint8_t *)pktIndex->data, ntohs(pcapIpHdr->tot_len));
                    }
                    exit(1);
                }
            }
        }
        else
        {
            recvUdpHdr->check = pcapUdpHdr->check;
            if(offset == 0)
            {
                if((recvUdpHdr->source != pcapUdpHdr->source) || (recvUdpHdr->dest != pcapUdpHdr->dest))
                {
                    /* Check next packet */
                    if(info->bHop && listIndex->next && (hop < MAX_HOP)){
                        hop++;
                        listIndex = listIndex->next;
                        continue;
                    }

                    /* Either something went wrong in the SD or the packet was not destined for this
                     * instance of the SD_Listener. Either way, discard this packet and continue to look
                     * for the next packet.
                     */
                    if(info->bVerbose)
                    {
                        printf("\nUDP did not match %d %d\n",ntohs(recvUdpHdr->source),ntohs(pcapUdpHdr->source));
                        printf("\nUDP did not match %d %d\n",ntohs(recvUdpHdr->dest),ntohs(pcapUdpHdr->dest));
                    }

                    stats->unknownPktsRx++;
                    return 1;
                }

                if(info->bVerifyRTPEventTS)
                {
                    if(verify_rtp_event_timestamp(recvUdpHdr, pcapUdpHdr) != 0)
                    {
                        rtp_hdr *recvRtpHdr = (rtp_hdr *) ((uint8_t *)recvUdpHdr + sizeof(struct udphdr));
                        rtp_hdr *pcapRtpHdr = (rtp_hdr *) ((uint8_t *)pcapUdpHdr + sizeof(struct udphdr));

                        ERR("\nRTP Timestamps did not match recv(%d) pcap(%d)\n", recvRtpHdr->timestamp, pcapRtpHdr->timestamp);

                        if(info->bVerbose)
                        {
                            printf("Received packet:\n");
                            print_buffer((uint8_t *)recvPkt, ntohs(recvIpHdr->tot_len));

                            printf("Expected packet:\n");
                            print_buffer((uint8_t *)pktIndex->data, ntohs(pcapIpHdr->tot_len));
                        }
                        exit(1);
                    }
                }
            }
        }

        if(info->bDontCalcL4Checksum && recvUdpHdr->check == 0)
        {
            pcapUdpHdr->check = 0;
        }
    }
    else if(protocol == IPPROTO_TCP)
    {
        recvTcpHdr = (struct tcphdr *)recvL4Ptr;
        pcapTcpHdr = (struct tcphdr *)pcapL4Ptr;
        recvTcpOpts = (tcpOpts_t *)((uint8_t *)recvTcpHdr + sizeof(struct tcphdr));
        pcapTcpOpts = (tcpOpts_t *)((uint8_t *)pcapTcpHdr + sizeof(struct tcphdr));

        if((recvTcpHdr->source != pcapTcpHdr->source) ||
           (recvTcpHdr->dest != pcapTcpHdr->dest))
        {
            /* Either something went wrong in the SD or the packet was not destined for this
             * instance of the SD_Listener. Either way, discard this packet and continue to look
             * for the next packet.
             */

            if(info->bVerbose){
                printf("TCP: Mismatch between source and destination ports.");
            }

            stats->unknownPktsRx++;
            return 1;
        }

        /* NBT - Calculate the delta between the last sequence number and the current sequence number. */
        /* Compare the deltas of the  received and the expected pcap. If there's a match, set the seq  */
        /* and ack_seq of the expected to match the received. We do this because the seq and seq ack   */
        /* are always random.                                                                          */

        if(recvTcpAckSeqLast == 0){
            recvTcpAckSeqLast = recvTcpHdr->ack_seq;
        }
        else{
            if( (ntohl(recvTcpAckSeqLast)) > (ntohl(recvTcpHdr->ack_seq)) ){
                recvTcpAckSeqOffs = (ntohl(recvTcpAckSeqLast)   - ntohl(recvTcpHdr->ack_seq));
            }
            else{
                recvTcpAckSeqOffs = (ntohl(recvTcpHdr->ack_seq) - ntohl(recvTcpAckSeqLast));
            }
        }
        
        if(pcapTcpAckSeqLast == 0){
            pcapTcpAckSeqLast = pcapTcpHdr->ack_seq;
        }
        else{
            if( (ntohl(pcapTcpAckSeqLast)) > (ntohl(pcapTcpHdr->ack_seq)) ){
                pcapTcpAckSeqOffs = (ntohl(pcapTcpAckSeqLast) - ntohl(pcapTcpHdr->ack_seq));
            }
            else{
                pcapTcpAckSeqOffs = (ntohl(pcapTcpHdr->ack_seq) - ntohl(pcapTcpAckSeqLast));
            }
        }

        /*DEBUG -----------------------------------------------------------------------------*/
        if(info->bVerbose){
            
            printf("TCP: Last Received Ack-Sequence Number: 0x%08x\n", ntohl(recvTcpAckSeqLast));
            printf("TCP: Received Ack-Sequence number:      0x%08x\n", ntohl(recvTcpHdr->ack_seq));
            printf("TCP: Received Offset:                   0x%08x\n", recvTcpAckSeqOffs);
            printf("-------------------------------------------------\n");
            printf("TCP: Last pcap Ack-Sequence number:     0x%08x\n", ntohl(pcapTcpAckSeqLast));
            printf("TCP: Current pcap Ack-Sequence number:  0x%08x\n", ntohl(pcapTcpHdr->ack_seq));
            printf("TCP: Current pcap Ack-Sequence offset:  0x%08x\n", pcapTcpAckSeqOffs);

        }
        /*-----------------------------------------------------------------------------------*/

        /*Set the "current" sequence number to the "last" sequence number for the next call. */

        recvTcpAckSeqLast = recvTcpHdr->ack_seq;
        pcapTcpAckSeqLast = pcapTcpHdr->ack_seq;

        /*Modify RECV checksum: Change checksum to reflect options changing to zero.                  */
        /*English: Full TCP header size MINUS the size of only the TCP structure. This will leave us  */
        /*with the size of the TCP options field. Increment the pointer and [i] by 2 bytes.           */

        uint8_t i;
        recvOptsPtr = (uint16_t *)recvTcpOpts;

        for (i = 0; i < ((recvTcpHdr->doff << 2) - sizeof(struct tcphdr)); i+=2, recvOptsPtr++) {

            recvTcpHdr->check = modcsum_16(recvTcpHdr->check, *recvOptsPtr, 0);

        }

        /*Set RECV options to zero.                                                             */

        memset(recvTcpOpts, 0, ((recvTcpHdr->doff << 2) - sizeof(struct tcphdr)));


        /*Modify PCAP checksum: Change checksum to reflect replacing the PCAP sequence numbers  */
        /*with the sequence numbers from the RECV packet. */

        oldPcapSeq = ((uint16_t *)&pcapTcpHdr->seq);
        newPcapSeq = ((uint16_t *)&recvTcpHdr->seq);

        if(oldPcapSeq == NULL || newPcapSeq == NULL){
            printf("TCP: Error. Sequence number pointer(s) are NULL:%s\n", __FUNCTION__);
            exit(1);
        }

        /*NBT- We need to mod two 32 bit fields (ACK/ACK_SEQ), our function mods 16 bits at a time. */
        /* So, loop through four times to fully mod the 64 bit field. */

        for( i = 0 ; i < 4; i++, oldPcapSeq++, newPcapSeq++){

            pcapTcpHdr->check = modcsum_16(pcapTcpHdr->check, *oldPcapSeq, *newPcapSeq);

        }

        /*If the offsets of RECV and PCAP match, set PCAP->seq and seq_ack to RECV */

        if(pcapTcpAckSeqOffs == recvTcpAckSeqOffs){
            pcapTcpHdr->seq = recvTcpHdr->seq;
            pcapTcpHdr->ack_seq = recvTcpHdr->ack_seq;
        }
        else{
            printf("\nTCP: Error: Received Ack-Sequence number offset does not match the expected's offset.\n");
            printf("TCP: Error: Reminder - the Ack-Seq of the received is not copied to current pcap because of this mismatch.\n");

        }

        if(info->bDontCalcL4Checksum && (recvTcpHdr->check == 0))
        {
            pcapTcpHdr->check = 0;
        }
    }
    else
    {
        /* All other protocol's will just be memcmp'd without doing this check */
    }

    //This is the packet we want to forward
    if(info->bForward)
    {
        stats->expectedPktsRx++;
        /* Received an expected packet, reset our provided pcap's timeout */
        gettimeofday(&(pcap->timeout_te), NULL);
        LOG("Expected packet received, total packets Rx: %d", stats->expectedPktsRx);
        return 0;
    }

    if(recvPktLength != pcapPktLength)
    {
        if(info->bHop && listIndex->next && (hop < MAX_HOP)){
            hop++;
            listIndex = listIndex->next;
            continue;
        }

        ERR("%s: Received vs. expected packet length: Mismatch", __FUNCTION__);
        ERR("Recv length: %d, expected length: %d", ntohs(recvPktLength), ntohs(pcapPktLength));

        printf("Received packet:\n");
        if(recvIpHdr == NULL){
            print_buffer((uint8_t *)recvPkt, (ntohs(recvIp6Hdr->ip6_plen) + sizeof(struct ip6_hdr)));
        }
        else{
            print_buffer((uint8_t *)recvPkt, ntohs(recvIpHdr->tot_len));
        }

        printf("Expected packet:\n");
        if(pcapIpHdr == NULL){
            print_buffer((uint8_t *)pktIndex->data, (ntohs(pcapIp6Hdr->ip6_plen) + sizeof(struct ip6_hdr)));
        }
        else{
            print_buffer((uint8_t *)pktIndex->data, ntohs(pcapIpHdr->tot_len));
        }
        exit(1);
    }

    if(memcmp(recvPkt, pktIndex->data, dataLen) != 0)
    {
        if(info->bHop && listIndex->next && (hop < MAX_HOP)){
            hop++;
            listIndex = listIndex->next;
            continue;
        }

        printf("%s: Received vs. expected packet memcmp: Mismatch\n", __FUNCTION__);
        printf("%s: Received packet:\n", __FUNCTION__);
        print_buffer((uint8_t *)recvPkt, dataLen);

        printf("%s: Expected packet:\n", __FUNCTION__);
        print_buffer((uint8_t *)pktIndex->data, dataLen);
        exit(1);
    }
    else
    {
        stats->expectedPktsRx++;
        /* Received an expected packet, reset our provided pcap's timeout */
        gettimeofday(&(pcap->timeout_te), NULL);
        LOG("Expected packet received, total packets Rx: %d", stats->expectedPktsRx);

        /* Delete the matched packet entry from listenList */
        if(info->bHop){
            deleteList(listIndex);
            if(hop > stats->maxHop ){
                stats->maxHop = hop;
            }
        }
        return 0;
    }
    }while(1);
}

//UDP Thread
void *udp_thread(void *arg)
{
    //IPv4 : sockaddr_in
    struct sockaddr_in  sa;
    //IPv6 : sockaddr_in6
    struct sockaddr_in6 sa6;
    //Commons for IPv4 & IPv6
    struct sockaddr     from_addr;
    socklen_t           slen;

    pcap_pkts           *pcap = NULL;
    pcap_pkt        *pktIndex = NULL;
    struct timeval         ts = { 0, 0 };
    struct timeval current_te = { 0, 0 };
    struct timeval    temp_te = { 0, 0 };
    struct timeval     cap_tm = { 0, 0 };

    char              *buffer = NULL;
    uint16_t     maxBufferLen = 65489;/*set to max socket recv buffer*/
    uint16_t         l3Length = 0;
    uint32_t    listenNumPkts = 0;

    int                  sock = 0;
    int                  ret  = 0;
    void     *expectedPayload = NULL;

    //Declares for capturing
    struct iphdr       *ipHdr = NULL;
    struct ip6_hdr    *ip6Hdr = NULL;
    struct udphdr     *udpHdr = NULL;
    struct pcap_pkthdr *pkthdr;
    ether_hdr         *ethHdr = NULL;
    void         *buildBuffer = NULL;
    void         *nextPtr     = NULL;
    pcap_t                *pd;
    pcap_dumper_t    *pdumper;

    if(arg == NULL)
    {
        if(!udp_capture)
        {
            printf("%s: Provided arg is NULL\n", __FUNCTION__);
            exit(1);
        }
    }

    if(!udp_capture)
    {
        pcap = (pcap_pkts *) arg;
        if(pcap == NULL){
            printf("Failed in reading pcap\n");
            exit(1);
        }

        pktIndex = pcap->pkts + stats->expectedPktsRx % pcap->numPkts;
    }

    buffer = (char *)malloc(maxBufferLen);
    if(buffer == NULL)
    {
        perror("Failed to allocated packet buffer\n");
        exit(1);
    }

    //Socket : IPv4
    if(!in6_isAddrV6(&listenConfig->outerSrcAddr) &&
            !in6_isAddrV6(&listenConfig->outerDstAddr))
    {
        sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if(sock < 0)
        {
            perror("udp_thread socket");
            exit(1);
        }

        bzero(&sa, sizeof(sa));
        sa.sin_family      = AF_INET;
        sa.sin_port        = htons(listenConfig->outerDstPort);
        sa.sin_addr.s_addr = htonl(INADDR_ANY);

        l3Length = sizeof(struct iphdr);
        slen = sizeof(struct sockaddr_in);
    }
    //Socket : IPv6
    else
    {
        sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        if(sock < 0)
        {
            perror("udp_thread socket");
            exit(1);
        }

        bzero(&sa6, sizeof(sa6));
        sa6.sin6_family      = AF_INET6;
        sa6.sin6_port        = htons(listenConfig->outerDstPort);
        sa6.sin6_addr        = in6addr_any;

        l3Length = sizeof(struct ip6_hdr);
        slen = sizeof(struct sockaddr_in6);
    }

    /* Enable timeout ability on sock allowing recvfrom to timeout */
    ts.tv_sec = listenConfig->timeOut;
    ret = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &ts, sizeof(ts));
    if(ret < 0)
    {
        perror("udp_thread setsockopt");
        close(sock);
        exit(1);
    }

    //Bind : IPv4
    if(!in6_isAddrV6(&listenConfig->outerSrcAddr) &&
                !in6_isAddrV6(&listenConfig->outerDstAddr))
    {
        ret = bind(sock, (struct sockaddr *)&sa, sizeof(sa));
        if(ret < 0)
        {
            perror("udp_thread bind");
            close(sock);
            exit(1);
        }
    }
    //Bind : IPv6
    else
    {
        ret = bind(sock, (struct sockaddr *)&sa6, sizeof(sa6));
        if(ret < 0)
        {
            perror("udp_thread bind");
            close(sock);
            exit(1);
        }
    }


    if(!udp_capture)
    {
        LOG("%s: pcap->fileName %s", __FUNCTION__, pcap->fileName);
        LOG("%s: pcap->maxPktLen %d", __FUNCTION__, pcap->maxPktLen);
        LOG("%s: pcap->numPkts %d", __FUNCTION__, pcap->numPkts);

        if(listenConfig->pcap.timeout_te.tv_sec == 0 &&
                listenConfig->pcap.timeout_te.tv_usec == 0)
        {
            gettimeofday(&(listenConfig->pcap.timeout_te), NULL);
        }

        //Set listenNumPkts based on if we have a specified numPkts from the user.
        if(listenConfig->userNumPkts && pcap->numPkts != 0){
            listenNumPkts = listenConfig->userNumPkts;
        }
        else{
            listenNumPkts = pcap->numPkts;
        }
    }
    else
    {
        gettimeofday(&(cap_tm), NULL);
    }

    if(udp_capture)
    {
        if(access(listenConfig->pcap.fileName, F_OK) != -1)
        {
            printf("udp_thread - File with name %s already exists\n", listenConfig->pcap.fileName);
            close(sock);
            exit(0);
        }
        else
        {
            pd = pcap_open_dead(DLT_EN10MB, 65535);

            pdumper = pcap_dump_open(pd, listenConfig->pcap.fileName);
            if(pdumper == NULL)
            {
                close(sock);
                if(info->bVerbose)
                    ERR("udp_thread pcap_dump_open file error");
                close(sock);
                exit(0);
            }
        }
    }

    uint32_t recvdpkts = 0;
    if(!udp_capture)
    {
        recvdpkts = stats->expectedPktsRx;
    }
    else
    {
        recvdpkts = 0;
        listenNumPkts = 1;
    }

    //Set capture packets value to 0 at start of capture
    capPkts = 0;

    REPLAY_THREAD_BROADCAST;

    while(stats->expectedPktsRx < listenNumPkts)
    {
        memset(buffer, 0, maxBufferLen);

        ret = recvfrom(sock, buffer, maxBufferLen, 0, &from_addr, &slen);
        if(ret < 0)
        {
            close(sock);
            if(info->bVerbose)
                ERR("udp_thread recvfrom: Timed out");
            exit(0);
        }

        /* Before doing anything check to see if we have exceeded our alloted timeout */
        if(!udp_capture)
        {
            gettimeofday(&current_te, NULL);

            if(pcap->timeout_te.tv_sec != 0 || pcap->timeout_te.tv_usec != 0)
            {
                timersub(&current_te, &(pcap->timeout_te), &temp_te);
                if((uint32_t)temp_te.tv_sec >= listenConfig->timeOut)
                {
                    ERR("ERROR: UDP Thread has timed-out");
                    close(sock);
                    exit(1);
                }
            }
        }
        else
        {
            gettimeofday(&current_te, NULL);

            if(cap_tm.tv_sec != 0 || cap_tm.tv_usec != 0)
            {
                timersub(&current_te, &(cap_tm), &temp_te);
                if((uint32_t)temp_te.tv_sec >= listenConfig->timeOut)
                {
                    ERR("ERROR: UDP Thread has timed-out");
                    close(sock);
                    exit(1);
                }
            }
        }

        if(udp_capture)
        {
            pkthdr = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
            if(!pkthdr)
            {
                ERR("Can't allocate memory for pcap pkthdr");
                close(sock);
                exit(1);
            }

            pkthdr->caplen     = (uint32_t)(ret + sizeof(ether_hdr) + l3Length + sizeof(struct udphdr));
            pkthdr->len        = pkthdr->caplen;

            //Build buffer to be written
            buildBuffer = (void *)malloc(sizeof(ether_hdr) + l3Length + sizeof(struct udphdr) + ret);
            nextPtr = buildBuffer;

            //If IPv4 build v4 pcap
            if(!in6_isAddrV6(&listenConfig->outerSrcAddr) && !in6_isAddrV6(&listenConfig->outerDstAddr))
            {
                //Ethernet Header
                ethHdr = (ether_hdr *)nextPtr;
                ethHdr->etherType = htons(ETHERTYPE_IP);

                nextPtr = (uint8_t *)nextPtr + sizeof(ether_hdr);

                //IPv4 Header
                ipHdr = (struct iphdr *)nextPtr;
                ipHdr->ihl      = 5;
                ipHdr->ttl      = 64;
                ipHdr->version  = 4;
                ipHdr->protocol = IPPROTO_UDP;
                ipHdr->saddr    = listenConfig->outerSrcAddr.s6_addr32[3];
                ipHdr->daddr    = listenConfig->outerDstAddr.s6_addr32[3];
                ipHdr->tot_len  = htons(pkthdr->caplen - sizeof(ether_hdr));

                nextPtr = (uint8_t *)nextPtr + sizeof(struct iphdr);
            }
            //If IPv6 build v6 pcap
            else if(in6_isAddrV6(&listenConfig->outerSrcAddr) && in6_isAddrV6(&listenConfig->outerDstAddr))
            {
                //Ethernet Header
                ethHdr = (ether_hdr *)nextPtr;
                ethHdr->etherType = htons(ETHERTYPE_IPV6);

                nextPtr = (uint8_t *)nextPtr + sizeof(ether_hdr);

                //IPv6 Header
                ip6Hdr = (struct ip6_hdr *)nextPtr;
                in6_cpyAddr(&(ip6Hdr->ip6_src), &listenConfig->outerSrcAddr);
                in6_cpyAddr(&(ip6Hdr->ip6_dst), &listenConfig->outerDstAddr);
                ip6Hdr->ip6_flow = (6 << 28);
                ip6Hdr->ip6_flow = htonl(ip6Hdr->ip6_flow);
                ip6Hdr->ip6_plen = htons(pkthdr->caplen - sizeof(ether_hdr) - sizeof(struct ip6_hdr));
                ip6Hdr->ip6_hlim = 64;
                ip6Hdr->ip6_nxt  = IPPROTO_UDP;

                nextPtr = (uint8_t *)nextPtr + sizeof(struct ip6_hdr);
            }

            //UDP Header
            udpHdr         = (struct udphdr *)nextPtr;
            udpHdr->dest   = htons(listenConfig->outerDstPort);
            udpHdr->source = htons(listenConfig->outerSrcPort);
            udpHdr->len    = htons(pkthdr->caplen - sizeof(ether_hdr) - l3Length);

            nextPtr = (uint8_t *)nextPtr + sizeof(struct udphdr);

            //Payload
            memcpy(nextPtr, buffer, ret);
            pcap_dump((u_char *)pdumper, pkthdr, (u_char *)buildBuffer);

            //Increment captured packet count
            capPkts++;
        }
        else
        {
            //Expected payload (with L3/L4 headers)
            expectedPayload = pktIndex->data;

            //Modify data pointer to point to payload of received packet
            expectedPayload = (uint8_t *)pktIndex->data + l3Length + sizeof(struct udphdr);

            if(memcmp(buffer, (uint8_t *)expectedPayload, (uint16_t)ret) != 0)
            {
                printf("%s: Received vs. expected packet memcmp: Mismatch\n", __FUNCTION__);
                printf("%s: Received packet:\n", __FUNCTION__);
                print_buffer((uint8_t *)buffer, (uint16_t)ret);

                printf("%s: Expected packet:\n", __FUNCTION__);
                print_buffer((uint8_t *)expectedPayload, (uint16_t)ret);
                close(sock);
                exit(1);
            }
            else
            {
                stats->expectedPktsRx++;
                /* Received an expected packet, reset our provided pcap's timeout */
                gettimeofday(&(pcap->timeout_te), NULL);
                LOG("Expected packet received, total packets Rx: %d", stats->expectedPktsRx);
            }

            pktIndex = pcap->pkts + stats->expectedPktsRx % listenNumPkts;
        }

        if(udp_capture)
        {
            free(buildBuffer);
            free(pkthdr);
        }
    }//end of while

    free(buffer);
    if(udp_capture)
    {
        pcap_close(pd);
        pcap_dump_close(pdumper);
    }
    close(sock);
    return 0;
}

void modify_fwd_pkt(void *buffer, config_t *pktCfg, bool isV6)
{
    void              *nextPtr = NULL;
    struct ip6_hdr    *ip6Hdr = NULL;
    struct iphdr      *ipHdr = NULL;
    struct udphdr     *udpHdr = NULL;

    uint8_t            outerProtocol = 0;
    void              *outerL4Ptr = NULL;
    uint16_t          *outerChecksumPtr = NULL;
    uint16_t           outerPayloadLen = 0;

    nextPtr = (void *)buffer;

    //For now we only support IPv4/IPv6 UDP packet
    if(!isV6)
    {
        ipHdr = (struct iphdr *)nextPtr;

        //update IP header
        ipHdr->check = 0;
        ipHdr->saddr = pktCfg->outerSrcAddr.s6_addr32[3];
        ipHdr->daddr = pktCfg->outerDstAddr.s6_addr32[3];
        ipHdr->check = ipcsum(sizeof(struct iphdr), (uint16_t *)ipHdr);
        
        outerProtocol = ipHdr->protocol;
        outerL4Ptr = (uint8_t *)ipHdr + sizeof(struct iphdr);

        outerPayloadLen = (uint16_t)(ntohs(ipHdr->tot_len) - sizeof(struct iphdr));
    }
    else
    {
        ip6Hdr = (struct ip6_hdr *)nextPtr;
        
        //Update IP header
        in6_cpyAddr(&(ip6Hdr->ip6_src), &pktCfg->outerSrcAddr);
        in6_cpyAddr(&(ip6Hdr->ip6_dst), &pktCfg->outerDstAddr);
        
        outerProtocol = ip6Hdr->ip6_nxt;
        outerL4Ptr = (uint8_t *)ip6Hdr + sizeof(struct ip6_hdr);

        outerPayloadLen = (uint16_t)ntohs(ip6Hdr->ip6_plen);
    }
    
    if(outerProtocol == IPPROTO_UDP && outerL4Ptr != NULL)
    {
        udpHdr = (struct udphdr *)((void *)outerL4Ptr); 

        //update UDP header
        if(pktCfg->outerSrcPort)
        {
            udpHdr->source = htons(pktCfg->outerSrcPort);
        }
        if(pktCfg->outerDstPort)
        {
            udpHdr->dest = htons(pktCfg->outerDstPort);
        }

        udpHdr->check = 0;
        outerChecksumPtr = (uint16_t *)&udpHdr->check;

        *outerChecksumPtr = l4csum(&pktCfg->outerSrcAddr,
                                   &pktCfg->outerDstAddr,
                                   (uint16_t *)outerL4Ptr,
                                   outerPayloadLen,
                                   (uint16_t)outerProtocol);
            
        if(*outerChecksumPtr == 0x0000)
        {
            printf("Calculated outer checksum is 0!\n");
            *outerChecksumPtr = 0xffff;
        }           
    }
}

void *interface_thread(void *arg)
{
    pcap_pkts          *pcap = NULL;
    char                listenMAC[MAC_LEN];
    char                replayMAC[MAC_LEN];
    uint32_t            addr = 0;
    uint32_t            listenNumPkts = 0;
    struct sockaddr_ll  device;
    char               *buffer;
    uint16_t            bufferLen;
    
    ether_hdr          *ethhdr = NULL;
    struct ip6_hdr     *ip6Hdr = NULL;
    struct iphdr       *ipHdr = NULL;

    void               *l3Header = NULL;
    arp_hdr            *arphdr = NULL;
    struct ip6_hdr     *ip6hdr = NULL;
    icmp6_advert_hdr   *icmp6hdr = NULL;
    struct in6_addr     tempAddr;
    int                 sock, ret;
    struct timeval      ts = {0,0};
    struct timeval      current_te = { 0, 0 };
    struct timeval      temp_te = { 0, 0 };

    bool                isV6 = false;
    int                 fwdLen, fwd_sock = -1;
    pcap_pkt           *pktIndex = NULL;
    struct ifreq        interface;
    struct sockaddr_in  sockaddr_v4;
    struct sockaddr_in6 sockaddr_v6;

    //Create forward sock
    if(info->bForward)
    {
        sockaddr_v4.sin_family = AF_INET;
        sockaddr_v4.sin_addr.s_addr = replayConfig->outerDstAddr.s6_addr32[3];
        sockaddr_v4.sin_port = htons(IPPROTO_RAW);

        sockaddr_v6.sin6_family = AF_INET6;
        sockaddr_v6.sin6_addr = replayConfig->outerDstAddr;
        sockaddr_v6.sin6_port = htons(IPPROTO_RAW);

        isV6 = (in6_isAddrV6(&(replayConfig->outerDstAddr))) ? true : false;

        if(isV6)
        {
            fwd_sock = socket(PF_INET6, SOCK_RAW, IPPROTO_RAW);
        }
        else
        {
            fwd_sock = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
        }

        if(fwd_sock < 0)
        {
            ERR("Can't create fwd raw socket (need to run as root?)");
            exit(1);
        }
    
        if(replayConfig->bInterfaceDefined)
        {
            strcpy(interface.ifr_name, replayConfig->interface);
            ret = setsockopt(fwd_sock, SOL_SOCKET, SO_BINDTODEVICE, &interface, sizeof(interface));
            if(ret < 0)
            {
                perror("replay_thread setsockopt");
                exit(1);
            }
        }

        pktIndex = (pcap_pkt *)malloc(sizeof(pcap_pkt));
    }

    if(arg == NULL)
    {
        printf("%s: Provided arg is NULL\n", __FUNCTION__);
        exit(1);
    }

    pcap = (pcap_pkts *) arg;
    bufferLen = info->bForward ? MAX_BUFFER_LEN : (pcap->maxPktLen + sizeof(ether_hdr));
    buffer = (char *)malloc(bufferLen);
    if(buffer == NULL)
    {
        perror("%s: Failed to allocated packet buffer\n");
        exit(1);
    }

    sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sock < 0)
    {
        perror("interface_thread socket");
        exit(1);
    }

    /* Enable timeout ability on sock allowing recv to timeout */
    ts.tv_sec = listenConfig->timeOut;
    ret = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &ts, sizeof(ts));
    if(ret < 0)
    {
        perror("interface_thread setsockopt");
        close(sock);
        exit(1);
    }

    memset(&device, 0, sizeof(device));
    get_MAC_addr(sock, listenConfig->interface, listenMAC, &device.sll_ifindex);
    device.sll_family = AF_PACKET;
    device.sll_protocol = htons(ETH_P_ALL);
    device.sll_halen = htons(6);

    ret = bind(sock, (struct sockaddr *) &device, sizeof(device));
    if(ret < 0)
    {
        perror("interface_thread bind");
        exit(1);
    }

    if(replayConfig->bInterfaceDefined)
    {
        get_MAC_addr(sock, replayConfig->interface, replayMAC, NULL);
    }

    LOG("%s: pcap->fileName %s", __FUNCTION__, pcap->fileName);
    LOG("%s: pcap->maxPktLen %d", __FUNCTION__, pcap->maxPktLen);
    LOG("%s: pcap->numPkts %d", __FUNCTION__, pcap->numPkts);
    
    if(listenConfig->pcap.timeout_te.tv_sec == 0 &&
       listenConfig->pcap.timeout_te.tv_usec == 0)
    {
        gettimeofday(&(listenConfig->pcap.timeout_te), NULL);
    }

    REPLAY_THREAD_BROADCAST;

    //Set listenNumPkts based on if we have a specified numPkts from the user.
    if(listenConfig->userNumPkts && pcap->numPkts != 0){
        listenNumPkts = listenConfig->userNumPkts;
    }
    else{
        listenNumPkts = pcap->numPkts;
    }

    while(stats->expectedPktsRx < listenNumPkts)
    {
        memset(buffer, 0, pcap->maxPktLen);

        ret = recv(sock, buffer, bufferLen, 0);
        if(ret < 0)
        {
            close(sock);
            if(info->bVerbose)
                ERR("interface_thread recv: Timed out");
            exit(0);
        }

        if(!info->bForward)
        {
            /* Before doing anything check to see if we have exceeded our alloted timeout */
            gettimeofday(&current_te, NULL);
            if(pcap->timeout_te.tv_sec != 0 || pcap->timeout_te.tv_usec != 0)
            {
                timersub(&current_te, &(pcap->timeout_te), &temp_te);
                if((uint32_t)temp_te.tv_sec >= listenConfig->timeOut)
                {
                    ERR("ERROR: Interface Thread has timed-out");
                    exit(1);
                }
            }
        }

        ethhdr = (ether_hdr *) buffer;
        l3Header = (void *)((uint8_t *)ethhdr + sizeof(ether_hdr));
        
        if(ntohs(ethhdr->etherType) == ETHERTYPE_IP) /* IPv4 */
        {
            if(info->bForward) 
            {
                if(check_packet((void *)l3Header, pcap) == 0)
                {
                    ipHdr = (struct iphdr *)((void *)l3Header);
                    fwdLen = ntohs(ipHdr->tot_len);

                    modify_fwd_pkt(l3Header, replayConfig, 0);
                    
                    memset(pktIndex, 0, sizeof(pcap_pkt));
                    pktIndex->dataLen = fwdLen;
                    pktIndex->data = (void *)malloc(pktIndex->dataLen);
                    memcpy(pktIndex->data, l3Header, pktIndex->dataLen);
        
                    ret = sendto(fwd_sock, (void *)pktIndex->data, pktIndex->dataLen, MSG_DONTWAIT,
                                (struct sockaddr *) &sockaddr_v4, sizeof(struct sockaddr_in));
                    if(ret < 0)
                    {
                        close(sock);
                        perror("replay_thread sendto");
                        exit(1);
                    }
                    usleep(ONE_SECOND / 100);
                    free(pktIndex->data);
                }
            }
            else
            {
                check_packet((void *)l3Header, pcap);
            }
        }
        else if(ntohs(ethhdr->etherType) == ETHERTYPE_IPV6)/* IPv6 */
        {
            ip6hdr = (struct ip6_hdr *) ((char *) ethhdr + sizeof(ether_hdr));

            if (ip6hdr->ip6_nxt == 0x3a) /* ICMPv6 */
            {
                stats->icmpv6Rx++;

                if(info->bRespondARP)
                {

                    if(replayConfig->bInterfaceDefined)
                    {
                        if(memcmp(ethhdr->srcMAC, replayMAC, MAC_LEN) == 0)
                        {
                            /* Dropping ARP originating from replay Ethernet interface */
                            continue;
                        }
                    }

                    /* Swap the MAC addresses around preparing for sendto */
                    memcpy(ethhdr->destMAC, ethhdr->srcMAC, MAC_LEN);
                    memcpy(ethhdr->srcMAC, listenMAC, MAC_LEN);

                    in6_cpyAddr(&tempAddr, &ip6hdr->ip6_src);
                    in6_cpyAddr(&ip6hdr->ip6_src, &listenConfig->outerSrcAddr);
                    ip6hdr->ip6_src.s6_addr16[7] = ip6hdr->ip6_dst.s6_addr16[7];
                    in6_cpyAddr(&ip6hdr->ip6_dst, &tempAddr);

                    icmp6hdr = (icmp6_advert_hdr *) ((char *) ip6hdr + sizeof(struct ip6_hdr));

                    if (memcmp(ethhdr->destMAC, listenMAC, MAC_LEN) == 0)
                    {
                        /* Dropping ICMPv6 replies going to self */
                        continue;

                    }

                    if (icmp6hdr->icmp6_type != 0x87)
                    {
                        /* Dropping non-solicitation ICMPv6 packets */
                        continue;
                    }

                    /* Replying to ICMPv6 solicitation */
                    icmp6hdr->icmp6_type = 0x88; /* Advertisement */
                    icmp6hdr->icmp6_cksum = 0;
                    icmp6hdr->icmp6_flag = htonl(0x60000000);
                    icmp6hdr->icmp6_target = ip6hdr->ip6_src;
                    icmp6hdr->option_type = 2; /* Target link-layer address */
                    icmp6hdr->option_len = 1;
                    memcpy(icmp6hdr->linkLayerAddr, listenMAC, MAC_LEN);

                    ret = sendto(sock, buffer, ret, MSG_DONTWAIT,
                                (struct sockaddr *) &device, sizeof(device));
                    if (ret < 0)
                    {
                        close(sock);
                        perror("interface_thread sendto");
                        exit(1);
                    }

                    stats->icmpv6Tx++;
                }
            }
            else
            {
                if(info->bForward) 
                {
                    if(check_packet((void *)l3Header, pcap) == 0)
                    {
                        ip6Hdr = (struct ip6_hdr *)((void *)l3Header);
                        fwdLen = ntohs(ip6Hdr->ip6_plen) + sizeof(struct ip6_hdr);

                        modify_fwd_pkt(l3Header, replayConfig, 1);
                    
                        memset(pktIndex, 0, sizeof(pcap_pkt));
                        pktIndex->dataLen = fwdLen;
                        pktIndex->data = (void *)malloc(pktIndex->dataLen);
                        memcpy(pktIndex->data, l3Header, pktIndex->dataLen);

                        usleep(ONE_SECOND / 100);
                        ret = sendto(fwd_sock, (void *)pktIndex->data, pktIndex->dataLen, MSG_DONTWAIT,
                                    (struct sockaddr *) &sockaddr_v6, sizeof(struct sockaddr_in6));
                        if(ret < 0)
                        {
                            close(sock);
                            perror("replay_thread sendto");
                            exit(1);
                        } 
                        free(pktIndex->data);
                    }
                }
                else
                {
                    check_packet((void *)l3Header, pcap);
                }
            }
        }
        else if(ntohs(ethhdr->etherType) == 0x0806) /* ARP */
        {
            stats->arpRx++;
            if(info->bRespondARP)
            {
                if(replayConfig->bInterfaceDefined)
                {
                    if(memcmp(ethhdr->srcMAC, replayMAC, MAC_LEN) == 0)
                    {
                        /* Dropping ARP originating from replay Ethernet interface */
                        continue;
                    }
                }
                
                /* Swap the MAC addresses around preparing for sendto */
                memcpy(ethhdr->destMAC, ethhdr->srcMAC, MAC_LEN);
                memcpy(ethhdr->srcMAC, listenMAC, MAC_LEN);

                arphdr = (arp_hdr *) ((char *) ethhdr + sizeof(ether_hdr));

                if(memcmp(arphdr->srcMAC, listenMAC, MAC_LEN) == 0)
                {
                    /* Dropping ARP originating from self */
                    continue;
                }
                
                if((*(uint32_t*)&listenConfig->outerDstAddr.s6_addr32[3] == arphdr->destIP))
                {       
                    
                    /* Replying to ARP request */
                    arphdr->mode = htons(ARPOP_REPLY);
                    memcpy(arphdr->destMAC, arphdr->srcMAC, MAC_LEN);
                    memcpy(arphdr->srcMAC, listenMAC, MAC_LEN);
                    addr = 0;
                    addr = arphdr->srcIP;
                    arphdr->srcIP = arphdr->destIP;
                    arphdr->destIP = addr;
                    
                    ret = sendto(sock, buffer, ret, MSG_DONTWAIT,
                                 (struct sockaddr *) &device, sizeof(device));
                    if(ret < 0)
                    {
                        close(sock);
                        perror("interface_thread sendto");
                        exit(1);
                    }

                    stats->arpTx++;
                }
            }
        }
    }

    if(info->bForward)
    {
        close(fwd_sock);
        free(pktIndex);
    }
    free(buffer);

    return 0;
}

void *replay_thread(void *arg)
{
    pcap_pkts *pcap;
    pcap = (pcap_pkts *)arg;
    int ret = -1;
    int sock = -1;
    bool isV6 = false;
    struct ifreq interface;
    struct iphdr *ipHdr = NULL;
    struct ip6_hdr *ip6Hdr = NULL;
    struct ip6_frag *frag6Hdr = NULL;
    struct sockaddr_in sockaddr_v4;
    struct sockaddr_in6 sockaddr_v6;
    pcap_pkt *pktIndex;

    uint8_t protocol = 0;
    uint16_t offset = 0; 
    uint32_t sendNumPkts = 0; 
    
    struct timeval ts          = { 0, 0 };     //0 
    struct timeval localPkt_te = { 0, 0 };     //0
    struct timeval tmp_te      = { 0, 500 };   //0.00050
    struct timeval fixTs_pkt   = { 0, replayConfig->fixTs * 1000 };  //set to fixTs ms
    struct timeval fixTs_frag  = { 0, 1};      //0.000001

    LOG("%s: pcap->fileName %s", __FUNCTION__, pcap->fileName);
    LOG("%s: pcap->maxPktLen %d", __FUNCTION__, pcap->maxPktLen);
    LOG("%s: pcap->numPkts %d", __FUNCTION__, pcap->numPkts);

    sockaddr_v4.sin_family = AF_INET;
    sockaddr_v4.sin_addr.s_addr = replayConfig->outerDstAddr.s6_addr32[3];
    sockaddr_v4.sin_port = htons(IPPROTO_RAW);

    sockaddr_v6.sin6_family = AF_INET6;
    sockaddr_v6.sin6_addr = replayConfig->outerDstAddr;
    sockaddr_v6.sin6_port = htons(IPPROTO_RAW);

    isV6 = (in6_isAddrV6(&(replayConfig->outerDstAddr))) ? true : false;

    if(isV6)
    {
        sock = socket(PF_INET6, SOCK_RAW, IPPROTO_RAW);
    }
    else
    {
        sock = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
    }

    if(sock < 0)
    {
        ERR("Can't create raw socket (need to run as root?)");
        exit(1);
    }

    if(replayConfig->bInterfaceDefined)
    {
        strcpy(interface.ifr_name, replayConfig->interface);
        ret = setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, &interface, sizeof(interface));
        if(ret < 0)
        {
            perror("replay_thread setsockopt");
            exit(1);
        }
    }

    if(listenConfig->bPcapDefined && !info->bForward)
    {
        REPLAY_THREAD_LOCK;
        REPLAY_THREAD_WAIT;

        LOG("Replay thread is awake, getting ready to send packets.");

        /* Give the listener enough time to setup and start listening */
        usleep(ONE_SECOND / 100);
        REPLAY_THREAD_UNLOCK;
    }

    /* Enable timeout ability on sock allowing recv to timeout */
    ts.tv_sec = replayConfig->timeOut;
    ret = setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &ts, sizeof(ts));
    if(ret < 0)
    {
        perror("replay_thread setsockopt");
        close(sock);
        exit(1);
    }

    //NBT - Check if the user has specified a number of packets to replay.
    if(replayConfig->userNumPkts && pcap->numPkts != 0){
        sendNumPkts = replayConfig->userNumPkts;
    }
    else{
        sendNumPkts = pcap->numPkts;
    }

    //NBT - Use timeval gap between last packet and last packet -1 if we have more than 1 packet in the pcap.
    if(pcap->numPkts > 1)
    {
        tmp_te = pcap->pkts[pcap->numPkts - 1].te;
        //printf( "tmp_te:  %ld.%.6ld\n", tmp_te.tv_sec, tmp_te.tv_usec);
    }

    //Send packets until we reach the send count.
    while(stats->pktsTx < sendNumPkts)
    {
        pktIndex = (pcap_pkt *)&pcap->pkts[stats->pktsTx % pcap->numPkts];
        
        //set time gap between frags and pkts
        if(info->bFixTs)
        {
            if(isV6)
            {
                ip6Hdr = (struct ip6_hdr *)(pktIndex->data);
                protocol = ip6Hdr->ip6_nxt;
                if(protocol == IP6_PROTO_FRAG)
                {
                    frag6Hdr = (struct ip6_frag *)((uint8_t *)ip6Hdr + sizeof(struct ip6_hdr));
                    offset = (htons(frag6Hdr->ip6f_offlg) & 0xfff8);
                }
                else
                {
                    offset = 0;
                }
            }
            else
            {
                ipHdr = (struct iphdr *)(pktIndex->data);
                offset = (htons(ipHdr->frag_off) & 0x0fff);
            }
            if(offset != 0)
            {
                localPkt_te = fixTs_frag;
            }
            else
            {
                localPkt_te = fixTs_pkt;
            }
        }
        else
        {
            localPkt_te = pktIndex->te;
        }

        if(stats->pktsTx)
        {
            if(!(stats->pktsTx % pcap->numPkts) && !info->bFixTs){
                 localPkt_te = tmp_te;
            }
            select(NULL,NULL,NULL,NULL, &(localPkt_te));
        }

        if(info->bVerbose)
        {
            print_buffer((uint8_t *)pktIndex->data, pktIndex->dataLen);
        }

        if(isV6)
        {
            ret = sendto(sock, (void *)pktIndex->data, pktIndex->dataLen, MSG_DONTWAIT,
                        (struct sockaddr *) &sockaddr_v6, sizeof(struct sockaddr_in6));
        }
        else
        {
            ret = sendto(sock, (void *)pktIndex->data, pktIndex->dataLen, MSG_DONTWAIT,
                        (struct sockaddr *) &sockaddr_v4, sizeof(struct sockaddr_in));
        }
        if(ret < 0)
        {
            close(sock);
            perror("replay_thread sendto");
            exit(1);
        }

        stats->pktsTx++;

        //Display a sending status.
        if(sendNumPkts > DISPLAY_NUMPKT && info->bStatus){
            printf("SD Listener: Sending %d of %d packets, ", stats->pktsTx, sendNumPkts);
            printf("%3.2f%% complete.", (stats->pktsTx / (double)sendNumPkts) * 100);
            printf("\r");
            fflush(stdout);
        }

    }
    close(sock);

    return 0;
}

void play_thread()
{
    int ret = -1;
    int sock = -1;
    bool isV6 = false;
    int val = 0;
    struct ifreq interface;
    struct sockaddr_in sockaddr_v4;
    struct sockaddr_in sockaddr_v4_sa;
    struct sockaddr_in6 sockaddr_v6;
    play_pkt *pktIndex;

    uint32_t sendNumPkts = 0;

    sockaddr_v4.sin_family = AF_INET;
    sockaddr_v4.sin_addr.s_addr =replayConfig->outerDstAddr.s6_addr32[3];
    sockaddr_v4.sin_port = htons(replayConfig->outerDstPort);

    sockaddr_v4_sa.sin_family = AF_INET;
    sockaddr_v4_sa.sin_addr.s_addr = INADDR_ANY;
    sockaddr_v4_sa.sin_port = htons(replayConfig->outerSrcPort);

    sockaddr_v6.sin6_family = AF_INET6;
    sockaddr_v6.sin6_addr = replayConfig->outerDstAddr;
    sockaddr_v6.sin6_port = htons(replayConfig->outerDstPort);

    isV6 = (in6_isAddrV6(&(replayConfig->outerDstAddr))) ? true : false;

    if(isV6)
    {
        sock = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    }
    else
    {
        sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    }

    if(sock < 0)
    {
        ERR("Can't create socket (need to run as root?)");
        exit(1);
    }

    if(replayConfig->bInterfaceDefined)
    {
        strcpy(interface.ifr_name,replayConfig->interface);
        ret = setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, &interface, sizeof(interface));
        if(ret < 0)
        {
            perror("play_thread setsockopt");
            close(sock);
            exit(1);
        }

        //setting source port
        ret = bind(sock, (struct sockaddr *)&sockaddr_v4_sa, sizeof(struct sockaddr_in));
        if(ret < 0)
        {
            perror("play_thread bind");
            close(sock);
            exit(1);
        }

        val = MAX_PLAY_SIZE;
        ret = setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val));
        if(ret < 0)
        {
            perror("play_thread setsockopt");
            close(sock);
            exit(1);
        }

        //enable linux fragmentation
        val = IP_PMTUDISC_DONT;
        ret = setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val));
        if(ret < 0)
        {
            perror("play_thread setsockopt");
            close(sock);
            exit(1);
        }
    }

    sendNumPkts = replayConfig->userNumPkts;

    while(stats->pktsTx < sendNumPkts)
    {
	pktIndex = (play_pkt *)&playPkts->pkts[stats->pktsTx % playPkts->numPkts];

	if(info->bVerbose)
    {
        print_buffer((uint8_t *)pktIndex->data, pktIndex->dataLen);
    }

	if(isV6)
	{
	    ret = sendto(sock, (void *)pktIndex->data, pktIndex->dataLen, MSG_DONTWAIT,
	                (struct sockaddr *) &sockaddr_v6, sizeof(struct sockaddr_in6));
	}
	else
	{
        ret = sendto(sock, (void *)pktIndex->data, pktIndex->dataLen, MSG_DONTWAIT,
                        (struct sockaddr *) &sockaddr_v4, sizeof(struct sockaddr_in));
	}
	if(ret < 0)
	{
        close(sock);
        perror("play_thread sendto");
        exit(1);
	}

	/*Larger packet with more frags needs longer time to reassemble and re-fragment, */
        /*set time gap depends on pktSize between sending to reduce packet drop. */
	if(pktIndex->dataLen < 20000){
	    usleep(10000);
	}
	else if(pktIndex->dataLen < 30000){
	    usleep(30000);
	}
	else if(pktIndex->dataLen < 40000){
	    usleep(40000);
	}
	else if(pktIndex->dataLen < 50000){
	    usleep(60000);
	}
	else{
	    usleep(100000);
	}

	stats->pktsTx++;

	//Display a sending status.
	if(sendNumPkts > DISPLAY_NUMPKT && info->bStatus){
	    printf("SD Listener: Sending %d of %d packets, ", stats->pktsTx, sendNumPkts);
	    printf("%3.2f%% complete.", (stats->pktsTx / (double)sendNumPkts) * 100);
	    printf("\r");
	    fflush(stdout);
	}
    }
    close(sock);
}

void create_udp_thread(pcap_pkts *pkts)
{
    if(pthread_create(&udpThread, 0, udp_thread, (void *) pkts) != 0)
    {
        printf("sd_listener: unable to spawn udp_thread\n");
        exit(1);
    }
}

void create_interface_thread(pcap_pkts *pkts)
{
    if(pthread_create(&listenThread, 0, interface_thread, (void *) pkts) != 0)
    {
        printf("sd_listener: unable to spawn interface_thread\n");
        exit(1);
    }
}

void create_replay_thread(pcap_pkts *pkts)
{
    if(pthread_create(&replayThread, 0, replay_thread, (void *) pkts) != 0)
    {
        printf("sd_listener: unable to spawn replay_thread\n");
        exit(1);
    }
}

bool process_line(char *line)
{
    if(line != NULL)
    {
        char *newline = strchr(line, '\n');
        if(newline != NULL)
            *newline = '\0'; /* Overwrites trailing \n */
        line = NULL;
        return true;
    }
    else
    {
        fprintf(stderr, "Inputed line was NULL");
        return false;
    }
}

void process_config_file(char *fileName)
{
    char buffer[MAX_BUFFER_LEN];
    char *args = NULL;
    char *bufferPtr;
    int result = 0;
    FILE *file;

    process_line(fileName);

    file = fopen(fileName, "r");
    if(file == NULL)
    {
        fprintf(stderr, "process_file fopen: Cannot open file.\n");
        return;
    }

    while(fgets(buffer, MAX_BUFFER_LEN, file) != NULL)
    {
        if(strlen(buffer) < 3)
        {
            /* Need atleast 1 char for identifier, 1 space, and 1 char for argument */
            continue;
        }

        args = strtok(buffer, " ");

        /* Set bufferPtr past arguments to point to relevant data */
        bufferPtr = strtok(NULL, " ");
        process_line(bufferPtr);

        if(strcmp(args, "rsa") == 0)
        {
            result = in6_pton(bufferPtr, &(replayConfig->outerSrcAddr));
            if(!result)
            {
                continue;
            }
        }
        else if(strcmp(args, "rsp") == 0)
        {
            replayConfig->outerSrcPort = (uint16_t) atoi(bufferPtr);
        }
        else if(strcmp(args, "rda") == 0)
        {
            result = in6_pton(bufferPtr, &(replayConfig->outerDstAddr));

            if(!result)
            {
                continue;
            }
        }
        else if(strcmp(args, "rdp") == 0)
        {
            replayConfig->outerDstPort = (uint16_t) atoi(bufferPtr);
        }
        else if(strcmp(args, "rtos") == 0)
        {
            replayConfig->outerToS = (uint8_t) atoi(bufferPtr);
        }
        else if(strcmp(args, "rttl") == 0)
        {
            replayConfig->outerTTL = (uint8_t) atoi(bufferPtr);
        }
        else if(strcmp(args, "lsa") == 0)
        {
            result = in6_pton(bufferPtr, &(listenConfig->outerSrcAddr));
            if(!result)
            {
                continue;
            }
        }
        else if(strcmp(args, "lsp") == 0)
        {
            listenConfig->outerSrcPort = (uint16_t) atoi(bufferPtr);
        }
        else if(strcmp(args, "lda") == 0)
        {
            result = in6_pton(bufferPtr, &(listenConfig->outerDstAddr));
            if(!result)
            {
                continue;
            }
        }
        else if(strcmp(args, "ldp") == 0)
        {
            listenConfig->outerDstPort = (uint16_t) atoi(bufferPtr);
        }
        else if(strcmp(args, "ltos") == 0)
        {
            listenConfig->outerToS = (uint8_t) atoi(bufferPtr);
        }
        else if(strcmp(args, "lttl") == 0)
        {
            listenConfig->outerTTL = (uint8_t) atoi(bufferPtr);
        }
        else if(strcmp(args, "irsa") == 0)
        {
            result = in6_pton(bufferPtr, &(replayConfig->innerSrcAddr));
            if(!result)
            {
                continue;
            }
        }
        else if(strcmp(args, "irsp") == 0)
        {
            replayConfig->innerSrcPort = (uint16_t) atoi(bufferPtr);
        }
        else if(strcmp(args, "irda") == 0)
        {
            result = in6_pton(bufferPtr, &(replayConfig->innerDstAddr));
            if(!result)
            {
                continue;
            }
        }
        else if(strcmp(args, "irdp") == 0)
        {
            replayConfig->innerDstPort = (uint16_t) atoi(bufferPtr);
        }
        else if(strcmp(args, "ilsa") == 0)
        {
            result = in6_pton(bufferPtr, &(listenConfig->innerSrcAddr));
            if(!result)
            {
                continue;
            }
        }
        else if(strcmp(args, "ilsp") == 0)
        {
            listenConfig->innerSrcPort = (uint16_t) atoi(bufferPtr);
        }
        else if(strcmp(args, "ilda") == 0)
        {
            result = in6_pton(bufferPtr, &(listenConfig->innerDstAddr));
            if(!result)
            {
                continue;
            }
        }
        else if(strcmp(args, "ildp") == 0)
        {
            listenConfig->innerDstPort = (uint16_t) atoi(bufferPtr);
        }
        else if(strcmp(args,"ilttl")==0)
        {
            listenConfig->innerTTL = (uint8_t) atoi(bufferPtr);
        }
        else if(strcmp(args, "rif") == 0)
        {
            memcpy(replayConfig->interface, bufferPtr, strlen(bufferPtr));
            if(!process_line(replayConfig->interface))
                return;
            replayConfig->bInterfaceDefined = true;
        }
        else if(strcmp(args, "lif") == 0)
        {
            memcpy(listenConfig->interface, bufferPtr, strlen(bufferPtr));
            if(!process_line(listenConfig->interface))
                return;
            listenConfig->bInterfaceDefined = true;
        }
        else if(strcmp(args, "rpc") == 0)
        {
            memcpy(replayConfig->pcap.fileName, bufferPtr, strlen(bufferPtr));
            if(!process_line(replayConfig->pcap.fileName))
                return;
            replayConfig->bPcapDefined = true;
        }
        else if(strcmp(args, "lpc") == 0)
        {
            memcpy(listenConfig->pcap.fileName, bufferPtr, strlen(bufferPtr));
            if(!process_line(listenConfig->pcap.fileName))
                return;
            listenConfig->bPcapDefined = true;
        }
        else if(strcmp(args, "tmo") == 0)
        {
            replayConfig->timeOut = (uint32_t) atoi(bufferPtr);
            listenConfig->timeOut = (uint32_t) atoi(bufferPtr);
        }
        else if(strcmp(args, "rpt") == 0)
        {
            if(info->bVerbose) printf("Entered rpt with: %s\n", bufferPtr);

            replayConfig->rtpPtMap = (rtp_pt_map_t *) realloc((void *)replayConfig->rtpPtMap,
                                                              ((sizeof(rtp_pt_map_t) * (replayConfig->numRtpPtMap + 1))));
            if(!replayConfig->rtpPtMap)
            {
                fprintf(stderr, "Unable to realloc memory for pkts\n");
                exit(1);
            }
            memset(&(replayConfig->rtpPtMap[replayConfig->numRtpPtMap]), 0, sizeof(rtp_pt_map_t));

            bufferPtr = strtok(bufferPtr, "->");
            if(bufferPtr != NULL)
            {
                replayConfig->rtpPtMap[replayConfig->numRtpPtMap].old = (uint8_t)atoi(bufferPtr);

                if(info->bVerbose)
                {
                    printf("%s: Old Replay RTP PT = %d\n", __FUNCTION__,
                           replayConfig->rtpPtMap[replayConfig->numRtpPtMap].old);
                }
            }

            bufferPtr = strtok(NULL, "->");
            if(bufferPtr != NULL)
            {
                replayConfig->rtpPtMap[replayConfig->numRtpPtMap].new = (uint8_t)atoi(bufferPtr);

                if(info->bVerbose)
                {
                    printf("%s: New Replay RTP PT = %d\n", __FUNCTION__,
                           replayConfig->rtpPtMap[replayConfig->numRtpPtMap].new);
                }
            }

            replayConfig->numRtpPtMap++;
        }
        else if(strcmp(args, "lpt") == 0)
        {
            if(info->bVerbose) printf("Entered lpt with: %s\n", bufferPtr);

            listenConfig->rtpPtMap = (rtp_pt_map_t *) realloc((void *)listenConfig->rtpPtMap,
                                                              ((sizeof(rtp_pt_map_t) * (listenConfig->numRtpPtMap + 1))));
            if(!listenConfig->rtpPtMap)
            {
                fprintf(stderr, "Unable to realloc memory for pkts\n");
                exit(1);
            }
            memset(&(listenConfig->rtpPtMap[listenConfig->numRtpPtMap]), 0, sizeof(rtp_pt_map_t));

            bufferPtr = strtok(bufferPtr, "->");
            if(bufferPtr != NULL)
            {
                listenConfig->rtpPtMap[listenConfig->numRtpPtMap].old = (uint8_t)atoi(bufferPtr);

                if(info->bVerbose)
                {
                    printf("%s: Old Listen RTP PT = %d\n", __FUNCTION__,
                           listenConfig->rtpPtMap[listenConfig->numRtpPtMap].old);
                }
            }

            bufferPtr = strtok(NULL, "->");
            if(bufferPtr != NULL)
            {
                listenConfig->rtpPtMap[listenConfig->numRtpPtMap].new = (uint8_t)atoi(bufferPtr);

                if(info->bVerbose)
                {
                    printf("%s: New Listen RTP PT = %d\n", __FUNCTION__,
                           listenConfig->rtpPtMap[listenConfig->numRtpPtMap].new);
                }
            }

            listenConfig->numRtpPtMap++;
        }
        else
        {
            /* Ignoring all other character combinations */
            if(info->bVerbose)
            {
                printf("Unknown option found, skipping: %s.\n", args);
            }
        }
        memset(buffer, 0, MAX_BUFFER_LEN); /* Clear out the buffer */
    }

    fclose(file);
}

bool process_args(int argc, char **argv)
{
    /* Long options */
    static struct option long_options[] = {
        {"rpc",     required_argument,  0, 'r'},
        {"rif",     required_argument,  0, 'R'},
        {"lpc",     required_argument,  0, 'l'},
        {"lif",     required_argument,  0, 'L'},
        {"tmo",     required_argument,  0, 't'},
        {"rsa",     required_argument,  0, 0},
        {"rsp",     required_argument,  0, 0},
        {"rda",     required_argument,  0, 0},
        {"rdp",     required_argument,  0, 0},
        {"rtos",    required_argument,  0, 0},
        {"rttl",    required_argument,  0, 0},
        {"lsa",     required_argument,  0, 0},
        {"lsp",     required_argument,  0, 0},
        {"lda",     required_argument,  0, 0},
        {"ldp",     required_argument,  0, 0},
        {"ltos",    required_argument,  0, 0},
        {"lttl",    required_argument,  0, 0},
        {"irsa",    required_argument,  0, 0},
        {"irsp",    required_argument,  0, 0},
        {"irda",    required_argument,  0, 0},
        {"irdp",    required_argument,  0, 0},
        {"ilsa",    required_argument,  0, 0},
        {"ilsp",    required_argument,  0, 0},
        {"ilda",    required_argument,  0, 0},
        {"ildp",    required_argument,  0, 0},
        {"ilttl",   required_argument,  0, 0},
        {"irtos",   required_argument,  0, 0},
        {"iltos",   required_argument,  0, 0},
        {"rpt",     required_argument,  0, 0},
        {"lpt",     required_argument,  0, 0},
        {"vrets",   required_argument,  0, 0},
        {"rnumpkt", required_argument,  0, 0},
        {"lnumpkt", required_argument,  0, 0},
        {"fixts",   required_argument,  0, 0},
        {"forward", no_argument,        0, 0},
		{"udp",     no_argument,        0, 0},
        {"capture", no_argument,        0, 0},
		{"rsize",   required_argument,  0, 0},
		{"rdiff",   required_argument,  0, 0},
        /* Don't remove me */
        {0, 0, 0, 0}
    };

    /* Short options */
    static char * short_options = "Fr:R:l:L:t:AvHdhsfg";

    int opt_index = 0, opt = 0;
    while((opt = getopt_long(argc, argv, short_options, long_options, &opt_index)) != -1)
    {
        switch (opt)
        {
        case 'F':
            process_config_file(argv[optind++]);
            break;
            
        case 'r':
            strcpy(replayConfig->pcap.fileName, optarg);
            replayConfig->bPcapDefined = true;
            LOG("Replay pcap = %s", replayConfig->pcap.fileName);
            break;

        case 'R':
            memcpy(replayConfig->interface, optarg, strlen(optarg));
            replayConfig->bInterfaceDefined = true;
            LOG("Replay interface = %s", replayConfig->interface);
            break;

        case 'l':
            strcpy(listenConfig->pcap.fileName, optarg);
            listenConfig->bPcapDefined = true;
            LOG("Listen pcap = %s", listenConfig->pcap.fileName);
            break;

        case 'L':
            memcpy(listenConfig->interface, optarg, strlen(optarg));
            listenConfig->bInterfaceDefined = true;
            LOG("Listen interface = %s", listenConfig->interface);
            break;

        case 't':
            listenConfig->timeOut = replayConfig->timeOut = (uint32_t) atoi(optarg);
            LOG("Replay/Listen timeout = %d", replayConfig->timeOut);
            break;

        case 'A':
            info->bRespondARP = true;
            LOG("ARP responses enabled");
            break;

        case 'v':
            info->bVerbose = true;
            LOG("Verbosity enabled");
            break;

        case 'H':
            info->bHMU = true;
            LOG("HMU enabled");
            break;

        case 'd':
            info->bDontCalcL4Checksum = true;
            LOG("Dont calculate L4 checksum enabled");
            break;

        case 'h':
            printf("Syntax:\n%s\n", usage);
            return false;
            break;

        case 's':
            info->bStatus = true;
            break;

		case 'f':
		    info->bHop = true;
		    LOG("Out of order tolerance enabled");
		    break;

 	       case 'g':
		    info->bGen = true;
		    LOG("Packet generation enabled");
		    break;

        case 0:
            if (strcmp("rsa", long_options[opt_index].name) == 0)
            {
                if(!in6_pton(optarg, &(replayConfig->outerSrcAddr)))
                {
                    printf("Unable to process replay outer source address!\n");
                    return false;
                }
                LOG("Replay outer source = %s", optarg);
            }
            else if (strcmp("rsp", long_options[opt_index].name) == 0)
            {
                replayConfig->outerSrcPort = (uint16_t)atoi(optarg);
                LOG("Replay outer source port = %d", replayConfig->outerSrcPort);
            }
            else if (strcmp("rda", long_options[opt_index].name) == 0)
            {
                if(!in6_pton(optarg, &(replayConfig->outerDstAddr)))
                {
                    printf("Unable to process replay outer destination address!\n");
                    return false;
                }
                LOG("Replay outer destination = %s", optarg);
            }
            else if (strcmp("rdp", long_options[opt_index].name) == 0)
            {
                replayConfig->outerDstPort = (uint16_t)atoi(optarg);
                LOG("Replay outer destination port = %d", replayConfig->outerDstPort);
            }
            else if (strcmp("rtos", long_options[opt_index].name) == 0)
            {
                replayConfig->outerToS = (uint8_t) atoi(optarg);
                LOG("Replay TOS = %d", replayConfig->outerToS);
            }
            else if (strcmp("rttl", long_options[opt_index].name) == 0)
            {
                replayConfig->outerTTL = (uint8_t) atoi(optarg);
                LOG("Replay outer TTL = %d", replayConfig->outerTTL);
            }
            else if (strcmp("lsa", long_options[opt_index].name) == 0)
            {
                if(!in6_pton(optarg, &(listenConfig->outerSrcAddr)))
                {
                    printf("Unable to process listener outer source address!\n");
                    return false;
                }
                LOG("Listen outer source = %s", optarg);
            }
            else if (strcmp("lsp", long_options[opt_index].name) == 0)
            {
                listenConfig->outerSrcPort = (uint16_t)atoi(optarg);
                LOG("Listen outer source port = %d", listenConfig->outerSrcPort);
            }
            else if (strcmp("lda", long_options[opt_index].name) == 0)
            {
                if(!in6_pton(optarg, &(listenConfig->outerDstAddr)))
                {
                    printf("Unable to process listener outer destination address!\n");
                    return false;
                }
                LOG("Listen outer destination = %s", optarg);
            }
            else if (strcmp("ldp", long_options[opt_index].name) == 0)
            {
                listenConfig->outerDstPort = (uint16_t)atoi(optarg);
                LOG("Listen outer destination port = %d", listenConfig->outerDstPort);
            }
            else if (strcmp("ltos", long_options[opt_index].name) == 0)
            {
                listenConfig->outerToS = (uint8_t) atoi(optarg);
                LOG("Listen TOS = %d", listenConfig->outerToS);
            }
            else if (strcmp("lttl", long_options[opt_index].name) == 0)
            {
                listenConfig->outerTTL = (uint8_t) atoi(optarg);
                LOG("Listen TTL = %d", listenConfig->outerTTL);
            }
            else if (strcmp("irsa", long_options[opt_index].name) == 0)
            {
                if(!in6_pton(optarg, &(replayConfig->innerSrcAddr)))
                {
                    printf("Unable to process replay inner source address!\n");
                    return false;
                }

                LOG("Replay inner source = %s", optarg);
            }
            else if (strcmp("irsp", long_options[opt_index].name) == 0)
            {
                replayConfig->innerSrcPort = (uint16_t)atoi(optarg);
                LOG("Replay inner source port = %d", replayConfig->innerSrcPort);
            }
            else if (strcmp("irda", long_options[opt_index].name) == 0)
            {
                if(!in6_pton(optarg, &(replayConfig->innerDstAddr)))
                {
                    printf("Unable to process replay inner destination address!\n");
                    return false;
                }

                LOG("Replay inner destination = %s", optarg);
            }
            else if (strcmp("irdp", long_options[opt_index].name) == 0)
            {
                replayConfig->innerDstPort = (uint16_t)atoi(optarg);
                LOG("Replay inner destination port = %d", replayConfig->innerDstPort);
            }
            else if(strcmp("ilsa", long_options[opt_index].name) == 0)
            {
                if(!in6_pton(optarg, &(listenConfig->innerSrcAddr)))
                {
                    printf("Unable to process listen inner source address!\n");
                    return false;
                }
                LOG("Listen inner source = %s", optarg);
            }
            else if (strcmp("ilsp", long_options[opt_index].name) == 0)
            {
                listenConfig->innerSrcPort = (uint16_t)atoi(optarg);
                LOG("Listen inner source port = %d", listenConfig->innerSrcPort);
            }
            else if(strcmp("ilda", long_options[opt_index].name) == 0)
            {
                if(!in6_pton(optarg, &(listenConfig->innerDstAddr)))
                {
                    printf("Unable to process listen inner destination address!\n");
                    return false;
                }
                LOG("Listen inner destination = %s", optarg);
            }
            else if (strcmp("ildp", long_options[opt_index].name) == 0)
            {
                listenConfig->innerDstPort = (uint16_t)atoi(optarg);
                LOG("Listen inner destination port = %d", listenConfig->innerDstPort);
            }
            else if (strcmp("ilttl",long_options[opt_index].name)==0)
            {
                listenConfig->innerTTL = (uint8_t) atoi(optarg);
                LOG("Listen TTL = %d", listenConfig->innerTTL);
            }
            else if (strcmp("iltos", long_options[opt_index].name) == 0)
            {
                listenConfig->innerToS = (uint8_t) atoi(optarg);
                LOG("Inner Listen TOS = %d", listenConfig->innerToS);
            }
            else if (strcmp("irtos", long_options[opt_index].name) == 0)
            {
                replayConfig->innerToS = (uint8_t) atoi(optarg);
                LOG("Inner Replay TOS = %d", replayConfig->innerToS);
            }
            else if(strcmp("rpt", long_options[opt_index].name) == 0)
            {
                LOG("Entered rpt with: %s", optarg);

                //Create a copy of the opt-arg since we'll need to modify for strtok
                char *ptr = 0, *buffer = (char*)malloc(strlen(optarg) + 1);
                strcpy(buffer, optarg);

                replayConfig->rtpPtMap = (rtp_pt_map_t *) realloc((void *)replayConfig->rtpPtMap,
                                                                  ((sizeof(rtp_pt_map_t) * (replayConfig->numRtpPtMap + 1))));
                if(!replayConfig->rtpPtMap)
                {
                    ERR("Unable to realloc memory for pkts");
                    exit(1);
                }
                memset(&(replayConfig->rtpPtMap[replayConfig->numRtpPtMap]), 0, sizeof(rtp_pt_map_t));

                ptr = strtok(buffer, "->");
                if(ptr != NULL)
                {
                    replayConfig->rtpPtMap[replayConfig->numRtpPtMap].old = (uint8_t)atoi(ptr);
                    LOG("%s: Old Replay RTP PT = %d", __FUNCTION__,
                        replayConfig->rtpPtMap[replayConfig->numRtpPtMap].old);
                }

                ptr = strtok(NULL, "->");
                if(ptr != NULL)
                {
                    replayConfig->rtpPtMap[replayConfig->numRtpPtMap].new = (uint8_t)atoi(ptr);
                    LOG("%s: New Replay RTP PT = %d", __FUNCTION__,
                        replayConfig->rtpPtMap[replayConfig->numRtpPtMap].new);
                }

                replayConfig->numRtpPtMap++;
                free(buffer);
            }
            else if(strcmp("lpt", long_options[opt_index].name) == 0)
            {
                LOG("Entered lpt with: %s", optarg);

                //Create a copy of the opt-arg since we'll need to modify for strtok
                char *ptr = 0, *buffer = (char*)malloc(strlen(optarg) + 1);
                strcpy(buffer, optarg);

                listenConfig->rtpPtMap = (rtp_pt_map_t *) realloc((void *)listenConfig->rtpPtMap,
                                                                  ((sizeof(rtp_pt_map_t) * (listenConfig->numRtpPtMap + 1))));
                if(!listenConfig->rtpPtMap)
                {
                    ERR("Unable to realloc memory for pkts");
                    exit(1);
                }
                memset(&(listenConfig->rtpPtMap[listenConfig->numRtpPtMap]), 0, sizeof(rtp_pt_map_t));

                ptr = strtok(buffer, "->");
                if(ptr != NULL)
                {
                    listenConfig->rtpPtMap[listenConfig->numRtpPtMap].old = (uint8_t)atoi(ptr);
                    LOG("%s: Old Listen RTP PT = %d", __FUNCTION__,
                        listenConfig->rtpPtMap[listenConfig->numRtpPtMap].old);
                }

                ptr = strtok(NULL, "->");
                if(ptr != NULL)
                {
                    listenConfig->rtpPtMap[listenConfig->numRtpPtMap].new = (uint8_t)atoi(ptr);
                    LOG("%s: New Listen RTP PT = %d", __FUNCTION__,
                        listenConfig->rtpPtMap[listenConfig->numRtpPtMap].new);
                }

                listenConfig->numRtpPtMap++;
                free(buffer);
            }
            else if(strcmp("vrets", long_options[opt_index].name) == 0)
            {
                info->bVerifyRTPEventTS = true;
            }
            else if(strcmp("forward", long_options[opt_index].name) == 0)
            {
                info->bForward = true;
            }
            else if(strcmp("fixts", long_options[opt_index].name) == 0)
            {
                info->bFixTs = true;
                replayConfig->fixTs = (uint32_t)atoi(optarg);
            }
            else if(strcmp("udp", long_options[opt_index].name) == 0)
            {
            	use_udp_thread = true;
            }
            else if(strcmp("capture", long_options[opt_index].name) == 0)
            {
                udp_capture = 1;
            }
            else if (strcmp("rnumpkt", long_options[opt_index].name) == 0)
            {
                replayConfig->userNumPkts = (uint32_t)atoi(optarg);
            }
            else if (strcmp("lnumpkt", long_options[opt_index].name) == 0)
            {
                listenConfig->userNumPkts = (uint32_t)atoi(optarg);
            }
            else if (strcmp("rsize", long_options[opt_index].name) == 0)
            {
                replayConfig->payloadSize = (uint32_t)atoi(optarg);
            }
		    else if (strcmp("rdiff", long_options[opt_index].name) == 0)
            {
                replayConfig->diffSize = (uint32_t)atoi(optarg);
            }
            break;

        default:
            printf("Syntax:\n%s\n", usage);
            return false;
        }
    }

    bool listenSetup = false, replaySetup = false;

    if(replayConfig->bPcapDefined)
    {
        //Do not allow the user to use a zero address
        //since we can't tell if its V4 or V6
        if (in6_isAddrZero(&replayConfig->outerSrcAddr) ||
            in6_isAddrZero(&replayConfig->outerDstAddr))
        {
            ERR("Replay outer source and/or destination cannot be zero.");
            exit(1);
        }


        init_pcap_pkts(replayConfig);

        create_replay_thread(&(replayConfig->pcap));
        replaySetup = true;
    }
    else if(info->bGen)
    {
        //Do not allow the user to use a zero address
        //since we can't tell if its V4 or V6
        if (in6_isAddrZero(&replayConfig->outerDstAddr))
        {
            ERR("Play outer destination cannot be zero.");
            exit(1);
        }

        init_play_pkts(replayConfig);
        play_thread();
        replaySetup = true;
    }

    usleep(ONE_SECOND / 100);

    if(listenConfig->bPcapDefined)
    {
        if(!listenConfig->timeOut)
        {
            listenConfig->timeOut = 1;
        }

        //Do not allow the user to use a zero address
        //since we can't tell if its V4 or V6
        if (in6_isAddrZero(&listenConfig->outerSrcAddr) ||
            in6_isAddrZero(&listenConfig->outerDstAddr))
        {
            ERR("Listen outer source and/or destination cannot be zero.");
            exit(1);
        }

        if(!udp_capture)
            init_pcap_pkts(listenConfig);

		if(info->bHop){
		    init_pkts_list(listenConfig);
		}

        if(listenConfig->bInterfaceDefined && use_udp_thread == false)
        {
            create_interface_thread(&(listenConfig->pcap));
            listenSetup = true;
        }
        else if(listenConfig->bInterfaceDefined && use_udp_thread == true)
        {
            if(udp_capture)
            {
                create_udp_thread(NULL);
            }
            else
            {
                create_udp_thread(&(listenConfig->pcap));
            }
        }
        else
        {
            printf("*** Missing mandatory fields. Use 'lif' ***\n");
            printf("Syntax: %s\n", usage);
            return false;
        }
    }

    if(!listenSetup && !replaySetup)
    {
        printf("*** Missing mandatory fields 'rpc' and/or 'lif' ***\n");
        printf("Syntax: %s\n", usage);
        return false;
    }

    if(replaySetup && !listenSetup)
    {
        LOG("Broadcasting to replay thread");
        REPLAY_THREAD_BROADCAST;
    }

    return true;
}

void cleanup()
{
    pcap_pkts    *pkts = NULL;
    pcap_pkt     *pktIndex = NULL;
    play_pkt     *playIndex = NULL;

    if(replayConfig->bPcapDefined)
    {
        pkts = (pcap_pkts *)&replayConfig->pcap;
        while(pkts->numPkts > 0)
        {
            pktIndex = (pcap_pkt *)((char *)pkts->pkts + sizeof(pcap_pkt) * (pkts->numPkts - 1));
            free(pktIndex->data);
            pkts->numPkts--;
        }
        free(pkts->pkts);
    }
    else if(info->bGen)
    {
        while(playPkts->numPkts > 0)
        {
            playIndex = (play_pkt *)((char *)playPkts->pkts + sizeof(play_pkt) * (playPkts->numPkts - 1));
            free(playIndex->data);
            playPkts->numPkts--;
        }
        free(playPkts->pkts);
        free(playPkts);
    }

    if(listenConfig->bPcapDefined)
    {
        pkts = (pcap_pkts *)&listenConfig->pcap;
        while(pkts->numPkts > 0)
        {
            pktIndex = (pcap_pkt *)((char *)pkts->pkts + sizeof(pcap_pkt) * (pkts->numPkts - 1));
            free(pktIndex->data);
            pkts->numPkts--;
        }
        free(pkts->pkts);
    }

    while(listenList)
    {
        deleteList(listenList);
    }

    free(replayConfig);
    free(listenConfig);
    free(info);
    free(stats);
}

void sd_listener_wrapup()
{
    bool success = true;

    if(!listenThread && !replayThread)
    {
        return;
    }

    if(listenThread)
    {
        if(listenConfig->userNumPkts){
            if(stats->expectedPktsRx != listenConfig->userNumPkts){
                success = false;
            }
        }
        else if(stats->expectedPktsRx != listenConfig->pcap.numPkts)
        {
            success = false;
        }

        //If we failed to parse the pcap, numPkts will be zero. Call it a fail!
        if(listenConfig->bPcapDefined && (listenConfig->pcap.numPkts == 0)){
            success = false;
        }
    }
    if(udpThread)
    {
        if(listenConfig->userNumPkts){
            if(stats->expectedPktsRx != listenConfig->userNumPkts){
                success = false;
            }
        }
        else if(stats->expectedPktsRx != listenConfig->pcap.numPkts)
        {
            success = false;
        }

        //If we failed to parse the pcap, numPkts will be zero. Call it a fail!
        if(listenConfig->bPcapDefined && (listenConfig->pcap.numPkts == 0)){
            success = false;
        }
    }

    if(replayThread)
    {
        if(replayConfig->userNumPkts){
            if(stats->pktsTx != replayConfig->userNumPkts){
                success = false;
            }
        }
        else if(stats->pktsTx != replayConfig->pcap.numPkts)
        {
            success = false;
        }
        
        //If we failed to parse the pcap, numPkts will be zero. Call it a fail!
        if(replayConfig->bPcapDefined && (replayConfig->pcap.numPkts == 0)){
            success = false;
        }
    }

    printf("\n");
    if(success)
    {
        printf("SD Listener             : Success\n");
    }
    else
    {
        printf("SD Listener             : Fail\n");
    }

    if(info->bGen)
    {
        if(replayConfig->userNumPkts){
            printf("Play defined num pkts : %d\n", replayConfig->userNumPkts);
        }
        printf("Play pkts tx          : %d\n", stats->pktsTx);
    }

    if(replayThread)
    {
        printf("Replay pcap num pkts    : %d\n", replayConfig->pcap.numPkts);

        if(replayConfig->userNumPkts){
            printf("Replay defined num pkts : %d\n", replayConfig->userNumPkts);
        }
        printf("Replay pkts tx          : %d\n", stats->pktsTx);
    }

    if(listenThread)
    {
        printf("Listen pcap num pkts    : %d\n", listenConfig->pcap.numPkts);
        
        if(listenConfig->userNumPkts){
            printf("Listen defined num pkts : %d\n", listenConfig->userNumPkts);
        }

        printf("Listen expected pkts rx : %d\n", stats->expectedPktsRx);
        printf("Listen unknown pkts rx  : %d\n", stats->unknownPktsRx);
        printf("Listen ARP's rx         : %d\n", stats->arpRx);
        printf("Listen ARP's tx         : %d\n", stats->arpTx);
        printf("Listen ICMPv6's rx      : %d\n", stats->icmpv6Rx);
        printf("Listen ICMPv6's tx      : %d\n", stats->icmpv6Tx);
		printf("Listen max hop          : %d\n", stats->maxHop);
    }
    if(udpThread && !udp_capture)
    {
        printf("Listen pcap num pkts    : %d\n", listenConfig->pcap.numPkts);

        if(listenConfig->userNumPkts){
            printf("Listen defined num pkts : %d\n", listenConfig->userNumPkts);
        }

        printf("Listen expected pkts rx : %d\n", stats->expectedPktsRx);
        printf("Listen unknown pkts rx  : %d\n", stats->unknownPktsRx);
    }
    else if(udpThread && udp_capture)
    {
        printf("Capture pkts rx         : %d\n", capPkts);
    }

    if(replayThread || listenThread || udpThread){
        printf("Unsupported packet type : %d\n", stats->unsupportedType);
    }

    if(info->bHMU && replayThread)
    {
        if(replayConfig->rtpInitialSsrcTx)
        {
            printf("initialSSRC             : 0x%08x\n", replayConfig->rtpInitialSsrcTx);
        }

        if(replayConfig->rtpSubseqSsrcTx)
        {
            printf("subsequentSSRC          : 0x%08x\n", replayConfig->rtpSubseqSsrcTx);
        }
    }

    cleanup();
}

int main(int argc, char *argv[])
{
    
    int error = 0;

    replayConfig = (config_t *)malloc(sizeof(config_t));
    if(replayConfig == NULL)
    {
        printf("%s: Unable to malloc memory for replayConfig\n", __FUNCTION__);
        exit(1);
    }

    listenConfig = (config_t *)malloc(sizeof(config_t));
    if(listenConfig == NULL)
    {
        printf("%s: Unable to malloc memory for listenConfig\n", __FUNCTION__);
        exit(1);
    }

    info = (listener_info_t *)malloc(sizeof(listener_info_t));
    if(info == NULL)
    {
        printf("%s: Unable to malloc memory for info\n", __FUNCTION__);
        exit(1);
    }

    stats = (listener_stats_t *)malloc(sizeof(listener_stats_t));
    if(stats == NULL)
    {
        printf("%s: Unable to malloc memory for stats\n", __FUNCTION__);
        exit(1);
    }

    memset(replayConfig, 0, sizeof(config_t));
    memset(listenConfig, 0, sizeof(config_t));
    memset(info, 0, sizeof(listener_info_t));
    memset(stats, 0, sizeof(listener_stats_t));
    replayThread = 0;
    listenThread = 0;
    udpThread    = 0;

    atexit(sd_listener_wrapup);

    pthread_mutex_init(&replayMutex, NULL);
    pthread_cond_init(&replayCond, NULL);

    if(!process_args(argc, argv))
        exit(1);

    if(replayThread)
    {
        pthread_join(replayThread, NULL);

        if(replayConfig->userNumPkts){
            
            if(stats->pktsTx != replayConfig->userNumPkts)
            {
                printf("Error: stats->pktsTx != replayConfig->pcap.numPkts\n");
                error = 1;
            }
        }
        else if(stats->pktsTx != replayConfig->pcap.numPkts)
        {
            error = 1;
        }
    }

    if(listenThread)
    {
        pthread_join(listenThread, NULL);

        if(listenConfig->userNumPkts){
            if(stats->expectedPktsRx != listenConfig->userNumPkts)
            {
                error = 1;
            }
        }
        else if(stats->expectedPktsRx != listenConfig->pcap.numPkts)
        {
            error = 1;
        }
    }

    if(udpThread)
    {
        pthread_join(udpThread, NULL);

        if(listenConfig->userNumPkts){
            if(stats->expectedPktsRx != listenConfig->userNumPkts)
            {
                error = 1;
            }
        }
        else if(stats->expectedPktsRx != listenConfig->pcap.numPkts)
        {
            error = 1;
        }
    }

    pthread_mutex_destroy(&replayMutex);
    pthread_cond_destroy(&replayCond);

    exit(error);
}

