#ifndef _packet_info_h
#define _packet_info_h

#include<pcap.h>
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
 *
 * *****************************/
typedef struct info{
	Socket *socket;
	int seq;
	int len;
	u_char *payload;
}http_info;
/*******************************
 *
 * *****************************/
typedef struct session{
	Socket *socket; 
	int syn_seq;
	int fin_seq;
	int len;
	unsigned char* payload;
}http_session;
/*******************************
 *Function:sessionInit
 *Description:初始化会话结构体
 *Calls:malloc
 *Called By:
 *Input:
 *Output:
 *Return:
 *******************************/
http_session *session_create();
/*******************************
 *Function:is_sameconnection
 *Description:判断是否是同一个连接
 *Calls:
 *Called By:
 *Input:socket1,socket2
 *Output:
 *Return:是返1，否返0
 *******************************/
int is_sameconnection(Socket *socket1,Socket *socket2);
/*******************************
 *Function:is_samedirection
 *Description:判断是否同一连接的同一方向
 *Calls:
 *Called By:
 *Input:socket1,sockt2
 *Output:
 *Return:是返1,否返0
 *******************************/
int is_samedirection(Socket *socket1,Socket *socket2);
/*******************************
 *Function:socket_copy
 *Description:复制socket结构休
 *Calls:strpcy
 *Called By:
 *Input:Socket
 *Output:
 *Return:成功返0，失败返-1
 *******************************/
int socket_copy(Socket *socket1,Socket *socket2);
/*******************************
 *Function:
 *Description:
 *Calls:
 *Called By:
 *Input:
 *Output:
 *Return:
 *******************************/
/*******************************
 *Function:
 *Description:
 *Calls:
 *Called By:
 *Input:
 *Output:
 *Return:
 *******************************/
#endif
