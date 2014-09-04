/***************SimpelSniffer.c*************/
//auther:duanjigang@2006s
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#define BUFFER_MAX 2048

int main(int argc, char *argv[])
{
	
	int sock, n_read, proto;	
	char buffer[BUFFER_MAX];
	char *ethhead, *iphead, *tcphead, *udphead, *icmphead, *p;
	
	if((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0)
	{
		fprintf(stdout, "create socket error\n");
		exit(0);
	}
	
	while(1) 
	{
		n_read = recvfrom(sock, buffer, 2048, 0, NULL, NULL);
		/*
		14   6(dest)+6(source)+2(type or length)
		+
		20   ip header 
		+
		8   icmp,tcp or udp header
		= 42
		*/
		if(n_read < 42) 
		{
			fprintf(stdout, "Incomplete header, packet corrupt\n");
			continue;
		}
		
		ethhead = buffer;
		p = ethhead;
		int n = 0XFF;
		printf("MAC: %.2X:%02X:%02X:%02X:%02X:%02X==>"
			"%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
			p[6]&n, p[7]&n, p[8]&n, p[9]&n, p[10]&n, p[11]&n,
			p[0]&n, p[1]&n, p[2]&n, p[3]&n, p[4]&n, p[5]&n);

        iphead = ethhead + 14;  
        p = iphead + 12;
        
        printf("IP: %d.%d.%d.%d => %d.%d.%d.%d\n",
			p[0]&0XFF, p[1]&0XFF, p[2]&0XFF, p[3]&0XFF,
			p[4]&0XFF, p[5]&0XFF, p[6]&0XFF, p[7]&0XFF);
		
		proto = (iphead + 9)[0];
		p = iphead + 20;
		printf("Protocol: ");
		switch(proto)
		{
        case IPPROTO_ICMP: printf("ICMP\n");break;
        case IPPROTO_IGMP: printf("IGMP\n");break;
        case IPPROTO_IPIP: printf("IPIP\n");break;
        case IPPROTO_TCP :
        case IPPROTO_UDP :  printf("%s,", proto == IPPROTO_TCP ? "TCP": "UDP"); 
			printf("source port: %u,",
				(p[0]<<8)&0XFF00 |  p[1]&0XFF);
			printf("dest port: %u\n", (p[2]<<8)&0XFF00 | p[3]&0XFF);
			break;
        case IPPROTO_RAW : printf("RAW\n");break;
        default:printf("Unkown, please query in include/linux/in.h\n");
		}
	}
}
