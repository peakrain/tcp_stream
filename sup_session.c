#include"sup_session.h"
#include<stdio.h>
#include<math.h>
#include<string.h>
#include<malloc.h>
#define line_size 1024
int request_parse(unsigned char *data)
{
	char ldata[line_size];
	char type[10];
	char uri[1024];
	char name[line_size];
	char value[line_size];
	if(get_line(ldata,&data)==EOF)
		return EOF;
	sscanf(ldata,"%s %s",type,uri);
	printf("name:请求类型 value:%s\n",type);
	printf("name:URI value:%s\n",uri);
	
	while(get_line(ldata,&data)!=EOF)	
	{
		if(sscanf(ldata,"%[^:]: %[^\n]",name,value)!=EOF)
		{
			printf("name:%s value:%s\n",name,value);
		}
	}
}

int response_parse(response_field *field,unsigned char *data)
{
	memset(field->Content_Encoding,'\0',field_size);
	memset(field->Transfer_Encoding,'\0',field_size);
	field->Content_Length=-1;
	char ldata[line_size];
	char version[10];
	char code[10];
	char name[line_size];
	char value[line_size];
	if(get_line(ldata,&data)==EOF)
		return EOF;
	sscanf(ldata,"%*[HTTP/]%s%s",version,code);
	printf("name:version value:%s\n",version);
	printf("name:code value:%s\n",code);
	
	while(get_line(ldata,&data)!=EOF)	
	{
		if(sscanf(ldata,"%[^:]: %[^\n]",name,value)!=EOF)
		{
			printf("name:%s value:%s\n",name,value);
			if(strcmp(name,"Transfer-Encoding")==0)
			{
				strcpy(field->Transfer_Encoding,value);
			}
			if(strcmp(name,"Content-Encoding")==0)
			{
				strcpy(field->Content_Encoding,value);
			}
			if(strcmp(name,"Content-Length")==0)
			{
				field->Content_Length=atoi(value);
			}
				
		}
	}	
}
int auto_split(unsigned char *data,int *len,unsigned char **source,int *slen,int flag)
{
	int i;
	unsigned char *p=*source;
	if(flag!=-1)
	{			
		*len=flag;
		memcpy(data,p,*len);
		p=p+flag;
		*source=p;
		*slen=*slen-flag;
		return 1;
	}
	for(i=0;i<*slen;i++)
		if(i<*slen-3)
		{
			if(p[i]==0x0d&&p[i+1]==0x0a&&p[i+2]==0x0d&&p[i+3]==0x0a)
			{
				*len=i+2;
				memcpy(data,p,*len);
				p=p+(i+4);
				*source=p;
				*slen=*slen-(i+4);
				return 0;
			}
		}
	return EOF;
}
int ctoi(unsigned char *str,int len)
{
	int i,result=0,temp;
	for(i=0;i<len;i++)
	{
		if(str[i]<=0x39&&str[i]>=0x30)
			temp=(int)(str[i]-'0');
		else if(str[i]<=0x46&&str[i]>=0x41)
			temp=(int)(str[i]-'A')+10;
		else if(str[i]<=0x66&&str[i]>=0x61)
			temp=(int)(str[i]-'a')+10;
		else
			return EOF;
		result+=temp*pow(16,len-i-1);
	
	}
	return result;
}
int join_chunk(unsigned char * out,int *u_len,unsigned char *source,int slen)
{
	int i;
	unsigned char *p=source;
	unsigned char temp[10];
	unsigned char out_stream[slen];
	int len=0;
	int l;
	int done=0;
	while(slen>0&&done==0)
	{	
		for(i=0;i<slen;i++)
			if(i<slen-1&&p[i]==0x0d&&p[i+1]==0x0a)
			{	
				if(i==0)
				{
					p=p+2;
					slen=slen-2;
					break;
				}
				memcpy(temp,p,i);	
				l=ctoi(temp,i);
				if(l==0)
				{
					done=1;
					break;
				}		
				p=p+i+2;
				memcpy(out_stream+len,p,l);
				len+=l;
				
				p=p+l;
				slen=slen-l-(i+2);
				break;
			}
	}
	memcpy(out,out_stream,len);
	*u_len=len;
	return 0;
}
int get_line(char *buf,unsigned char **data)
{
	char *p=*data;
	int t_len=strlen(p);
	if(t_len<=0)
		return EOF;
	int ebuf=sscanf(p,"%[^\r\n]",buf);
	if(ebuf==0)
		strcpy(buf,"");
	int len=strlen(buf)+sizeof("\r\n");
	p=p+len-1;
	*data=p;
	return ebuf;
}
int tcp_stream_parse(unsigned char *payload,int payload_len)
{
	int len;
	int ret;
	unsigned char *p=payload;
	int p_len=payload_len;
	unsigned char data[p_len];
	response_field field;
	field.Content_Length=-1;
	int state=0;//1代表请求　2代表响应
	while(1)
	{
		memset(data,'\0',payload_len);
		ret=auto_split(data,&len,&p,&p_len,field.Content_Length);
		field.Content_Length=-1;
		if(ret==EOF)
			break;
		if((strncmp(data,"GET",3)==0)||(strncmp(data,"POST",4)==0))
		{
			printf("请求头:\n");
			request_parse(data);
			printf("\n");
			state=1;
		}
		else if(strncmp(data,"HTTP",4)==0)
		{
			printf("响应头:\n");
			response_parse(&field,data);
			printf("\n");
			state=2;
		}
		else
		{
			if(state==2)
			{
				printf("响应体:\n");
				unsigned char chunk[len];
				int clen=0;
				if(strlen(field.Transfer_Encoding)!=0)
				{
					if(strcmp(field.Transfer_Encoding,"chunked")==0)
						join_chunk(chunk,&clen,data,len);
				}
				int glen=0;
				unsigned char gzip[10*len];
				if(strlen(field.Content_Encoding)!=0)
				{
					if(strcmp(field.Content_Encoding,"gzip")==0)
					{
						glen=10*len;
						if(clen!=0)
							pat_gzip_uncompress(chunk,clen,gzip,&glen);
						else
							pat_gzip_uncompress(data,len,gzip,&glen);
					}
				}
				if(glen!=0)
					printf("%s\n",gzip);
				 else if(clen!=0)
					printf("%s\n",chunk);
				else
					printf("%s\n",data);
				printf("\n");
				state=0;

			}
		}
	}
	return 0;
}
