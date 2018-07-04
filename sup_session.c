#include"sup_session.h"
#include<stdio.h>
#include<math.h>
#include<string.h>
#include<malloc.h>
#define line_size 1024
int request_parse(sess_info **info,unsigned char *data)
{
	sess_info *p=*info;
	if(p==NULL)
		p=(sess_info*)malloc(sizeof(sess_info));
	if(!p)
		return EOF;
	p->count=0;
	char ldata[line_size];
	char type[10];
	char uri[1024];
	char name[line_size];
	char value[line_size];
	if(get_line(ldata,&data)==EOF)
		return EOF;
	sscanf(ldata,"%s %s",type,uri);
	strcpy(p->name[p->count],"请求类型");
	strcpy(p->value[p->count],type);
	p->count++;
	
	strcpy(p->name[p->count],"URI");
	strcpy(p->value[p->count],uri);
	p->count++;

	
	while(get_line(ldata,&data)!=EOF)	
	{
		if(sscanf(ldata,"%[^:]: %[^\n]",name,value)!=EOF)
		{
			strcpy(p->name[p->count],name);
			strcpy(p->value[p->count],value);
			p->count++;
		}
	}
	*info=p;	
}

int response_parse(sess_info  **info,unsigned char *data)
{
	sess_info *p=*info;
	if(p==NULL)
		p=(sess_info*)malloc(sizeof(sess_info));
	if(!p)
		return EOF;
	char ldata[line_size];
	char version[10];
	char code[10];
	char name[line_size];
	char value[line_size];
	if(get_line(ldata,&data)==EOF)
		return EOF;
	sscanf(ldata,"%*[HTTP/]%s%s",version,code);
	strcpy(p->name[p->count],"version");
	strcpy(p->value[p->count],version);
	p->count++;
	
	strcpy(p->name[p->count],"code");
	strcpy(p->value[p->count],code);
	p->count++;
	
	while(get_line(ldata,&data)!=EOF)	
	{
		if(sscanf(ldata,"%[^:]: %[^\n]",name,value)!=EOF)
		{
			strcpy(p->name[p->count],name);
			strcpy(p->value[p->count],value);
			p->count++;
		}
	}	
}
int auto_split(unsigned char *data,int *len,unsigned char *source,int slen)
{
	int i;
	unsigned char *p=source;
	for(i=0;i<slen;i++)
		if(i<slen-3)
		{
			if(p[i]==0x0d&&p[i+1]==0x0a&&p[i+2]==0x0d&&p[i+3]==0x0a)
			{
				*len=i+2;
				memcpy(data,p,*len);
				if(slen-(i+4)<=0)
					return 1;
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
