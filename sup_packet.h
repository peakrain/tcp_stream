#ifndef _sup_packet_h
#define _sup_packet_h

#include<stdint.h>
/*******************************
 *五元组
********************************/
typedef struct socket{
	char src_ip[20];//源IP地址
	char dst_ip[20];//目的IP地址
	int src_port;//源端口
	int dst_port;//目的端口
	int prot;//网络协议号
}Socket;
/*******************************
 *数据包主要数据
 * *****************************/
typedef struct{
	Socket *socket;
	int syn_seq;
	int syn_ack;
	int len;
	int capacity;
	unsigned char *payload;
}packet_info;
int is_same(Socket *socket1,Socket *socket2);
void socket_copy(Socket *socket1,Socket *socket2);
int get_packet(int num,char *filter,packet_info **info,char *filename);
#endif
