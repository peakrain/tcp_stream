/*
 * pat_gzip.h
 * Creatded On:2018年6月28日
 * Author:rain
 */
#ifndef _pat_gzip_h
#define _pat_gzip_h

#include<zlib.h>
#include<stdio.h>
/*
 *
 *@param
 *	pSrc:要解压的字符串
 *	srcSize:解压字符串长度
 *	out_data:解压后字符串缓冲区
 *	out_len:解压后字符串实际长度（输入的数值大于实际长度会变小）
 * @return
 *	成功返０，失败返回错误代号
 */

int pat_gzip_uncompress(unsigned char *pSrc,int srcSize,unsigned char *out_data,int *out_len)
{
	/*判别是否属于gzip压缩的数据*/
	if((*pSrc!=0x1f)||(*(pSrc+1)!=0x8b))
	{
		printf("non gzip\n");
		//return EOF;
	}
	/*初始化数据*/
	int ret=0;
	z_stream d_stream;
	d_stream.zalloc=Z_NULL;
	d_stream.zfree=Z_NULL;
	d_stream.opaque=Z_NULL;
	d_stream.next_in=Z_NULL;
	d_stream.avail_in=0;
	
	ret=inflateInit2(&d_stream,47);
	/*判断是否初始成功*/
	if(ret!=Z_OK)
	{
		printf("init error:%d\n",ret);
		return ret;
	}
	/*输入数据并解压*/	
	d_stream.next_in=pSrc;
	d_stream.avail_in=srcSize;
	d_stream.next_out=out_data;
	d_stream.avail_out=*out_len;
	ret=inflate(&d_stream,Z_NO_FLUSH);
	/*判别结果情况*/	
	switch(ret)
	{
		case Z_NEED_DICT:
			ret=Z_DATA_ERROR;
		case Z_DATA_ERROR:
		case Z_MEM_ERROR:
			(void)inflateEnd(&d_stream);
			return ret;
		
	}
	/*计算解压后字符串的实际长度*/
	*out_len=*out_len-d_stream.avail_out;
	return 0;
}
/*
 *
 *
 *
 */
int pat_gzip_compress(unsigned char *pSrc,int srcSize,unsigned char *out_data,int *out_len)
{
	/*初始化数据*/
	int ret;
	z_stream d_stream;
	d_stream.zalloc=Z_NULL;
	d_stream.zfree=Z_NULL;
	d_stream.opaque=Z_NULL;
	ret = deflateInit2(&d_stream,1,8,MAX_WBITS+16,8, Z_DEFAULT_STRATEGY);
	/*判断是否初始成功*/
	if(ret!=Z_OK)
	{
		printf("init error:%d\n",ret);
		return ret;
	}
	/*输入数据并解压*/	
	d_stream.next_in=pSrc;
	d_stream.avail_in=srcSize;
	d_stream.next_out=out_data;
	d_stream.avail_out=*out_len;
	ret=deflate(&d_stream,Z_NO_FLUSH);
	ret=deflate(&d_stream,Z_FINISH);
	/*判别结果情况*/	
	switch(ret)
	{
		case Z_NEED_DICT:
			ret=Z_DATA_ERROR;
		case Z_DATA_ERROR:
		case Z_MEM_ERROR:
			(void)inflateEnd(&d_stream);
			return ret;
		
	}
	/*计算解压后字符串的实际长度*/
	*out_len=*out_len-d_stream.avail_out;
	return 0;
}
#endif
