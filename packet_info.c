#include"packet_info.h"
#include<linux/tcp.h>
#include<linux/ip.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<netinet/if_ether.h>
#include<string.h>
#include<malloc.h>
#include"pat_print.h"
http_session *request;
http_session *response;

http_info *info;
		
unsigned char *head;
unsigned char *body;
int hl;
int bl;
int count=0;
int count_get=0;
int count_response=0;
int socket_copy(Socket *socket1,Socket *socket2)
{
	strcpy(socket1->src_ip,socket2->src_ip);
	strcpy(socket1->dst_ip,socket2->dst_ip);
	socket1->src_port=socket2->src_port;
	socket1->dst_port=socket2->dst_port;
	socket1->prot=socket2->prot;
}
http_session *session_create()
{
	http_session *session;
	session=(http_session*)malloc(sizeof(http_session));
	if(!session)
		return NULL;
	session->socket=(Socket*)malloc(sizeof(Socket));
	session->syn_seq=-1;
	session->fin_seq=-1;
	session->len=0;
	session->payload=(unsigned char*)malloc(sizeof(unsigned char)*65535);
} 
int is_samedirection(Socket *socket1,Socket *socket2)
{
	int sip=strcmp(socket1->src_ip,socket2->src_ip);
	int dip=strcmp(socket1->dst_ip,socket2->dst_ip);
	int sport=socket1->src_port==socket2->src_port;
	int dport=socket1->dst_port==socket2->dst_port;
	int prot=socket1->prot==socket2->prot;
	if(sip==0&&dip==0&&sport==1&&dport==1&&prot==1)
		return 1;
	else
		return 0;
}
int is_samesession(Socket *socket1,Socket *socket2)
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

void parse_tcp(http_info *info,const u_char *packet,int offset,int len)
{
	struct tcphdr *tcp_h;
	tcp_h=(struct tcphdr*)(packet+offset);
	offset+=tcp_h->doff<<2;
	info->socket->src_port=ntohs(tcp_h->source);
	info->socket->dst_port=ntohs(tcp_h->dest);
	info->seq=ntohl(tcp_h->seq);
	info->len=len-offset;
	info->payload=(u_char *)(packet+offset);
}
void parse_ip(http_info *info,const u_char *packet,int offset,int len)
{
	if(len>offset)
	{
		struct in_addr addr;
		struct iphdr* ip_h;
		ip_h=(struct iphdr*)(packet+offset);
		addr.s_addr=ip_h->saddr;
		strcpy(info->socket->src_ip,inet_ntoa(addr));
		addr.s_addr=ip_h->daddr;
		strcpy(info->socket->dst_ip,inet_ntoa(addr));
		info->socket->prot=ip_h->protocol;
		offset+=sizeof(struct iphdr);
		if(ip_h->protocol==6)
			parse_tcp(info,packet,offset,len);
	}
	else
	{
		printf("packet length error!\n");
		return;
	}
}
void call_back(u_char *user,const struct pcap_pkthdr *pkthdr,const u_char *packet)
{
	count++;
	int offset=sizeof(struct ether_header);
	parse_ip(info,packet,offset,pkthdr->len);
	if(request->syn_seq==-1)
	{
		socket_copy(request->socket,info->socket);
		request->syn_seq=info->seq;
		request->fin_seq=info->seq;
			
	}else if(response->syn_seq==-1)
	{
		
		socket_copy(response->socket,info->socket);
		response->syn_seq=info->seq;
		response->fin_seq=info->seq;
	}
	else if(pkthdr->len>60)
	{
		if(is_samedirection(request->socket,info->socket))
		{
			int offset=(info->seq-request->syn_seq)-1;
			memcpy(request->payload+offset,info->payload,info->len);
			request->fin_seq=info->seq;
			request->len=offset+info->len;
			count_get++;
		}
		if(is_samedirection(response->socket,info->socket))
		{
			int offset=(info->seq-response->syn_seq)-1;
			memcpy(response->payload+offset,info->payload,info->len);
			response->fin_seq=info->seq;
			response->len=offset+info->len;
			count_response++;
		}
		//print_02x(info->payload,info->len);
	}
		
}
void analysis(int num,char *buf,char *filename)
{
	request=session_create();
	response=session_create();
	info=(http_info *)malloc(sizeof(struct info));
	info->socket=(Socket *)malloc(sizeof(Socket));

	head=(char *)malloc(sizeof(unsigned char)*1024);	
	body=(char *)malloc(sizeof(unsigned char)*65535);	
	char ebuf[PCAP_ERRBUF_SIZE];
	/*open a pcap file*/
	pcap_t *device=pcap_open_offline(filename,ebuf);
	if(!device)
	{
		printf("error:%s\n",ebuf);
		return;
	}
	/*catch pakcet*/
	int i=0;
	struct bpf_program fp;
	pcap_compile(device,&fp,buf,1,0);
	pcap_setfilter(device,&fp);
	pcap_loop(device,num,call_back,NULL);
	pat_print_socket(request->socket);
	printf("request_count:%d request_len:%d\n",count_get,request->len);
//	print_char(request->payload,request->len);
	if(split(&head,&hl,&body,&bl,request->payload,request->len)!=EOF)
	{		
		printf("request_finish head_len:%d body_len:%d\n",hl,bl);
		//print_char(body,bl);
		getChunk(&body,bl);
	}
	pat_print_socket(response->socket);
	printf("response_count:%d response_len:%d\n",count_response,response->len);
	if(split(&head,&hl,&body,&bl,response->payload,response->len)!=EOF)
	{		
		printf("response_finish head_len:%d body_len:%d\n",hl,bl);
		//print_char(body,bl);
		getChunk(&body,bl);
	}
	printf("total:%d\n",count);
	pcap_close(device);	
}
