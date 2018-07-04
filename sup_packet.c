#include"sup_packet.h"
#include<linux/tcp.h>
#include<linux/ip.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<string.h>
#include<malloc.h>
#include<pcap.h>

#define socket_num 10
Socket *sockets[socket_num];
int handshakes[socket_num];
int sockets_count;
int start=0;
void  socket_copy(Socket *socket1,Socket *socket2)
{
	strcpy(socket1->src_ip,socket2->src_ip);
	strcpy(socket1->dst_ip,socket2->dst_ip);
	socket1->src_port=socket2->src_port;
	socket1->dst_port=socket2->dst_port;
	socket1->prot=socket2->prot;
}
int is_same(Socket *socket1,Socket *socket2)
{
	int sip=strcmp(socket1->src_ip,socket2->src_ip);
	int dip=strcmp(socket1->dst_ip,socket2->dst_ip);
	int sport=socket1->src_port==socket2->src_port;
	int dport=socket1->dst_port==socket2->dst_port;
	int rsip=strcmp(socket1->src_ip,socket2->dst_ip);
	int rdip=strcmp(socket1->dst_ip,socket2->src_ip);
	int rsport=socket1->src_port==socket2->dst_port;
	int rdport=socket1->dst_port==socket2->src_port;
	int prot=socket1->prot==socket2->prot;
	int samedire=(sip==0&&dip==0&&sport==1&&dport==1);
	int redire=(rsip==0&&rdip==0&&rsport==1&&rdport==1);
	if((samedire==1||redire==1)&&prot==1)
		return 1;
	else
		return 0;
}
int analysis(packet_info **p_info,struct pcap_pkthdr *pkt,const u_char *packet)
{
	int offset=14;
	int len=pkt->len;
	packet_info *info=*p_info;
	if(len>offset)
	{
		struct in_addr addr;
		struct iphdr* ip_h;
		ip_h=(struct iphdr*)(packet+offset);
		offset+=ip_h->ihl<<2;
		if(ip_h->protocol==6)
		{
			struct tcphdr *tcp_h;
			tcp_h=(struct tcphdr*)(packet+offset);
			offset+=tcp_h->doff<<2;
			len=ntohs(ip_h->tot_len)+14-offset;
			Socket *socket=(Socket *)malloc(sizeof(Socket));
			addr.s_addr=ip_h->saddr;
			strcpy(socket->src_ip,inet_ntoa(addr));
			addr.s_addr=ip_h->daddr;
			strcpy(socket->dst_ip,inet_ntoa(addr));
			socket->prot=ip_h->protocol;
			socket->src_port=ntohs(tcp_h->source);
			socket->dst_port=ntohs(tcp_h->dest);
			
			if(!start)
			{		
				int i;
				int flag=0;
				for(i=0;i<sockets_count;i++)
				{
					if(is_same(sockets[i],socket))
					{
						if(handshakes[i]==0&&tcp_h->syn==1&&tcp_h->ack==0)
							handshakes[i]=1;
						if(handshakes[i]==1&&tcp_h->syn==1&&tcp_h->ack==1)
							handshakes[i]=2;
						if(handshakes[i]==2&&tcp_h->syn==0&&tcp_h->ack==1)
							handshakes[i]=3;
						flag=1;
						break;
					}
				}	
				if(!flag)
				{
					socket_copy(sockets[sockets_count],socket);
					if(tcp_h->syn==1&&tcp_h->ack==0)
						handshakes[sockets_count]=1;
					sockets_count++;
				}
			
				for(i=0;i<sockets_count;i++)
					if(handshakes[i]==3)
					{
						socket_copy(info->socket,sockets[i]);
						start=1;
					}
				return 1;
			}
				
			if(len<=0)
				return 1;

			
			if(!is_same(info->socket,socket))
				return 2;
			if(info->len==0)
			{
				info->syn_seq=ntohl(tcp_h->seq);
				info->syn_ack=ntohl(tcp_h->ack_seq);
				memcpy(info->payload,packet+offset,len);
				info->len=len;
			}
			else
			{
				int dev=(ntohl(tcp_h->seq)-info->syn_seq)+(ntohl(tcp_h->ack_seq)-info->syn_ack);
				memcpy(info->payload+dev,packet+offset,len);
				info->len+=len;
			}
		}
		else
			return EOF;
		
	}
	else
	{
		printf("packet length error!\n");
		return EOF;
	}
	*p_info=info;
	
}
int get_packet(int num,char *filter,packet_info **p_info,char *filename)
{
	
	/*init handshake count*/
	int i;
	for(i=0;i<socket_num;i++)
	{
		sockets[i]=(Socket*)malloc(sizeof(Socket));
		handshakes[i]=0;
	}
	sockets_count=0;

	packet_info *info=NULL;
	info=(packet_info *)malloc(sizeof(packet_info));
	info->socket=(Socket *)malloc(sizeof(Socket));
	info->len=0;
	info->capacity=65535;
	info->payload=(unsigned char*)malloc(sizeof(unsigned char)*info->capacity);

	char ebuf[PCAP_ERRBUF_SIZE];
	/*open a pcap file*/
	pcap_t *device=pcap_open_offline(filename,ebuf);
	if(!device)
	{
		printf("error:%s\n",ebuf);
		return;
	}
	/*init filter*/
	struct bpf_program fp;
	pcap_compile(device,&fp,filter,1,0);
	pcap_setfilter(device,&fp);
	
	/*catch pakcet*/
	struct pcap_pkthdr *pkt;
	const u_char *packet;
	int ret;
	if(num==-1)
	{
		while(1)
		{
			ret=pcap_next_ex(device,&pkt,&packet);
			if(ret==EOF||ret==0)
				return EOF;
			if(ret==-2)
				break;
			if(analysis(&info,pkt,packet)==EOF)
				return EOF;
		}	
	}
	else
	{
		int count=0;
		while(count<num)
		{
			ret=pcap_next_ex(device,&pkt,&packet);
			if(ret==EOF||ret==0)
				return EOF;
			if(ret==-2)
				break;
			if(analysis(&info,pkt,packet)==EOF)
				return EOF;
			count++;
		}	
	}
	printf("count:%d\n",sockets_count);
	for(i=0;i<sockets_count;i++)
	{
		printf("handshakes %d :%d \n",i,handshakes[i]);
		pat_print_socket(sockets[i]);
	}
	*p_info=info;
	pcap_close(device);	
}
