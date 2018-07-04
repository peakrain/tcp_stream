#ifndef _sup_session_h
#define _sup_session_h

typedef struct info{
	int count;
	char name[25][40];
	char value[25][1024];
	char *body;
}sess_info;

typedef struct Session{
	sess_info  *request;
	sess_info  *response;
}http_session;

int auto_split(unsigned char  *data,int *len,unsigned char *source,int slen);
int join_chunk(unsigned char *out,int *u_len,unsigned char *source,int slen);
int get_line(char *buf,unsigned char **data);
#endif
