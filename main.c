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
//	pat_print_gzc(info->payload,info->len);
//	unsigned char *data[65535];
	unsigned char data[info->len];
	int len;
	int ret;
	unsigned char *p=info->payload;
	int info_len=info->len;
	http_session *mysession=(http_session *)malloc(sizeof(http_session)); 
	mysession->request=(sess_info *)malloc(sizeof(sess_info));
	mysession->response=(sess_info *)malloc(sizeof(sess_info));
	int state=0;//1代表请求　2代表响应
	while(1)
	{
		ret=auto_split(data,&len,p,info_len);
		if(ret==EOF)
			break;
		p=p+len+2;
		info_len=info_len-len-2;
	//	pat_print_gzc(data,len);
		if(strncmp(data,"GET",3)==0)
		{
			request_parse(&mysession->request,data);
			state=1;
		}
		else if(strncmp(data,"HTTP",4)==0)
		{
			response_parse(&mysession->response,data);
			state=2;
		}
		else
		{
			if(state==2)
			{
				int i;
				sess_info *p=mysession->response;
				unsigned char chunk[len];
				int clen=0;
				for(i=0;i<p->count;i++)
					if(strcmp(p->name[i],"Transfer-Encoding")==0)
					{
						if(strcmp(p->value[i],"chunked")==0)
							join_chunk(chunk,&clen,data,len);
						break;
					}
				int glen=0;
				unsigned char gzip[10*len];
				for(i=0;i<p->count;i++)
					if(strcmp(p->name[i],"Content-Encoding")==0)
					{
						if(strcmp(p->value[i],"gzip")==0)
						{
							glen=10*len;
							if(clen!=0)
	        						pat_gzip_uncompress(chunk,clen,gzip,&glen);
							else
	        						pat_gzip_uncompress(data,len,gzip,&glen);
						}
						break;
					}
				 if(glen!=0)
					p->body=gzip;
				 else if(clen!=0)
					p->body=chunk;
				else
					p->body=data;

			}
		}
	}
	int i;
	sess_info *req=mysession->request;
	sess_info *res=mysession->response;
	printf("请求头：\n");
	for(i=0;i<req->count;i++)
		printf("name:%s value:%s \n",req->name[i],req->value[i]);
	if(req->body!=NULL)
		printf("请求体:\n%s\n",req->body);
	printf("\n");
	printf("响应头：\n");
	for(i=0;i<res->count;i++)
		printf("name:%s value:%s \n",res->name[i],res->value[i]);
	if(res->body!=NULL)
		printf("响应体:\n%s\n",res->body);
	return 0;
}
