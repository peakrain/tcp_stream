#include"sup_packet.h"
#include"sup_session.h"
#include"pat_gzip.h"
#include<stdio.h>
#include<malloc.h>
#include<string.h>
int main(int argc,char *argv[])
{
	if(argc!=3)
	{
		printf("syntax error!\n");
		return;
	}
	char *filename=argv[1];
	int n=atoi(argv[2]);
	packet_info *info;
	get_packet(n,"tcp",&info,filename);
	pat_print_socket(info->socket);
	printf("TCP Stream:\n");
	pat_print_gzc(info->payload,info->len);
	tcp_stream_parse(info->payload,info->len);
	return 0;
}
