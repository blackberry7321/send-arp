#include <libnet.h>

uint32_t ResolveAttackerIp(const char *dev);

uint8_t* ResolveAttackerMac(const char* dev);

void PrintAttacker(uint8_t* mac, uint32_t ip);

bool SendArpRequest(pcap_t* handle, const char* dev, const char* senderIp, uint8_t* senderMac);

bool SendArpReply(pcap_t* handle, uint8_t* attackerMac, const char* senderIp, uint8_t* senderMac, const char* targetIp);
