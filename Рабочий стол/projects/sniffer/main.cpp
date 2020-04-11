#include <cstdio>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/if_arp.h>

void callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char*
packet) {
    static int num = 0;
    num++;
    ethhdr *eth;
    eth = (ethhdr *) packet;
    printf("Ethernet:\n");
    printf("\tNumber: %d\n", num);
    printf("\tSender addr:%02X:%02X:%02X:%02X:%02X:%02X\n", eth->h_source[0], eth->h_source[1], eth->h_source[2],
           eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    printf("\tDestination addr./:%02X:%02X:%02X:%02X:%02X:%02X\n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
           eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    printf("\tProtocol: 0x%04x\n", htons(eth->h_proto));
    printf("\tSize packet: %d\n", pkthdr->caplen);
    if (htons(eth->h_proto) == ETH_P_IP) {
        iphdr *ip = (struct iphdr *) (packet + sizeof(struct ethhdr));
        printf("\tIP:\n");
        printf("\t\tSource addr: %s\n",inet_ntoa(*(in_addr*)&ip->saddr));
        printf("\t\tDestination addr: %s\n",inet_ntoa(*(in_addr*)&ip->daddr));
        printf("\t\tTTL: %d\n",ip->ttl);
        printf("\t\tProtocol: 0x%04x\n",htons(ip->protocol));
        if (ip->protocol == IPPROTO_UDP) {
            int ip_header_size = ip->ihl * 4;
            char* next_header = (char*)ip + ip_header_size;
            struct udphdr* udp = (struct udphdr*)next_header;
            int data_size = pkthdr->len - sizeof(struct ethhdr) -
                            ip_header_size ;
            printf("\t\tUDP:\n");
            printf("\t\t\tSource port: %d\n",ntohs(udp->source));
            printf("\t\t\tDestination port: %d\n",ntohs(udp->dest));
            printf("\t\t\tSize: %d\n",data_size);
        }
    }
    if (htons(eth->h_proto) == ETH_P_ARP){
        struct arphdr *arp = (struct arphdr *)(packet + sizeof(struct ethhdr));
        printf("\tARP:\n");
        if (htons(arp->ar_op) == 0x0001){
            printf("\t\tType packet: Request\n");
        }
        else if (htons(arp->ar_op) == 0x0002){
            printf("\t\tType packet: Answer\n");

        }

    }
}
int main(int argc, char *argv[])
{
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    dev = pcap_lookupdev(errbuf);
    if (dev == nullptr) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 1;
    }
    pcap_t *handle;
    handle = pcap_open_live(dev,BUFSIZ,true,1000,errbuf);
    if (handle == nullptr){
        fprintf(stderr,"Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }
    if (pcap_datalink(handle) != DLT_EN10MB)
    {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers -not supported\n", dev);
        return 2;
    }
    pcap_loop(handle,-1,callback,nullptr);
    return 0;
}