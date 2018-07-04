#include"sup_packet.h"
#include<stdio.h>
/*
 *
 *@param
 *	c:字符
 * @return
 *	属于ASCII表中可打印字符返回１，否则返回0
 */
int  is_ascii(unsigned char c)
{
	int up=c-0x7E;
	int down=0x20-c;
	if(up<=0&&down<=0)
		return 1;
	return 0;
}
/*
 *@brief
 *	 五元组数据打印
 *@param
 *	data:无符号型字符串
 *	len:字符串长度
 * @return
 *	无返回值
 */
void pat_print_socket(Socket *info)
{
	printf("Src_IP:%s ",info->src_ip);
	printf("Dst_IP:%s ",info->dst_ip);
	printf("Src_Port:%d ",info->src_port);
	printf("Dst_Port:%d ",info->dst_port);
	printf("Protocol:%d\n",info->prot);	
}
/*
 *@brief
 *	打印HTTP中压缩了的字符串
 *@param
 *	data:无符号型字符串
 *	len:字符串长度
 * @return
 *	无返回值
 */
void pat_print_gzc(unsigned char *data,int len)
{
	int i,up,down;
	for(i=0;i<len;i++)
	{
		if(i<len-1&&data[i+1]==0x0a&&data[i]==0x0d)
		{
			printf("\n");
			i++;
			continue;
		}
		if(is_ascii(data[i]))
			printf("%c",data[i]);
		else
			printf(".");
	}
	printf("\n");
} 
/*
 *＠brief
 *	以16进制输出无符号型字符串
 *@param
 *	data:无符号型字符串
 *	len:字符串长度
 * @return
 *	无返回值
 */
void pat_print_02x(unsigned char *data,int len)
{
	int i;
	for(i=0;i<len;i++)
	{
		printf("%02x ",data[i]);
		if((i+1)%16==0)
			printf("\n");
	}
	printf("\n");
}
