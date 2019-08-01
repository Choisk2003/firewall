#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <pcap.h>
#include "../header/protocol/all.h"

bool compareIp(ip_addr ip, ip_addr iip){
	if(ip.a == iip.a && ip.b == iip.b && ip.c == iip.c && ip.d == iip.d){
		return true;
	}
	return false;
}

void printMac(const uint8_t *_mac)
{
	printf(": %02X:%02X:%02X:%02X:%02X:%02X\n", _mac[0], _mac[1], _mac[2], _mac[3], _mac[4], _mac[5]);
}

void printIp(ip_addr ip)
{
	printf(": %d.%d.%d.%d\n", ip.a, ip.b, ip.c, ip.d);
}

void printData(uint32_t size, const u_char *data)
{
	printf("===================================================================================\n");
	int i = 0;
	int j = 0;
	int line = 0;
	printf("%04d  ", line);
	for (i; j < size; i++)
	{
		printf("%02X ", data[i]);
		if ((i + 1) % 8 == 0 && (i + 1) % 16 != 0)
			printf("  ");
		if ((i + 1) % 16 == 0)
		{
			printf("\t");
			for (j; j < size; j++)
			{
				if ((data[j] >= 0 && data[j] <= 32) || data[j] > 126)
				{
					printf(".");
				}
				else
				{
					printf("%c", data[j]);
				}
				if ((j + 1) % 8 == 0 && (j + 1) % 16 != 0)
					printf("  ");
				if ((j + 1) % 16 == 0)
				{
					line += 10;
					printf("\n%04d  ", line);
					j++;
					break;
				}
			}
		}
	}

	printf("\n===================================================================================\n");
}

void printIdenSeq(const icmp_iden_seq *icmp_)
{
	printf("ICMP IDENTIFIER(BE): %d (0x%04X)\n", ntohs(icmp_->icmp_iden), ntohs(icmp_->icmp_iden));

	printf("ICMP IDENTIFIER(LE): %d (0x%04X)\n", icmp_->icmp_iden, icmp_->icmp_iden);

	printf("ICMP SEQUENCE NUMBER(BE): %d (0x%04X)\n", ntohs(icmp_->icmp_seqNum), ntohs(icmp_->icmp_seqNum));

	printf("ICMP SEQUENCE NUMBER(LE): %d (0x%04X)\n", icmp_->icmp_seqNum, icmp_->icmp_seqNum);
}

void printIcmpCode(const icmp_header *icmp)
{
	printf("ICMP CODE: %d\n", icmp->icmp_code);
}