#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<inttypes.h>
//#include<stdbool.h>
//#include"libeventCS.h"
#include"esm_data.h"
#include"3gpp_23.003.h"
#include"mem2str2mem.h"
//mem str length这里是指long的mem2str之后的长度
//这里的mem是用的long
//guti用的是int
//taskname用的是5个character
//int mem_str_len=16;
//int guti_str_len=8;

//记得free
//void *p pointer;len sizeof(char)  len
//这个len很关键，不能
char* mem2str(const void* p,const int len)//return a malloc memory string end with '\0' 是左高右低的16进制
{
    char* res=(char*) malloc(len*2+1);//0-255 to 00-ff and one '\0'
    char* cur=res;
    for(int i=0;i<len;i++)
    {
        unsigned char val=(unsigned char)(*((char*)p+i));
        int val0=val/16;
        int val1=val%16;
        /*printf("val:%d\tval0:%d\tval1:%d\n",val,val0,val1);*/
        if(val1<10)
        {
            *cur='0'+val1;

        }else
        {
            *cur='A'+val1-10;

        }
        cur++;
        if(val0<10)
        {
            *cur='0'+val0;
        }else
        {
            *cur='A'+val0-10;
        }
        cur++;
    }
    *cur='\0';
    int i=0;
    int j=strlen(res)-1;
    while(i<j)//reverse
    {
        char tmp=res[j];
        res[j]=res[i];
        res[i]=tmp;
        i++;
        j--;
    }
    return res;
}

//记得free
void* str2mem(const char* str)//接受的参数也要是左高右低的16进制
{
    int len=strlen(str)/2;//每两个16进制数可以确定一个内存
    void *res=malloc(len);
    char *cur=(char*)res;
    cur=cur+len-1;//内存从后往前 写入，存储
    for(int i=0;i<len;i++)
    {
        unsigned char val=0;
        unsigned char val0,val1;
        const char ch0=str[2*i];
        if(ch0<='9'&&ch0>='0')
        {
            val0=ch0-'0';
        }else if(ch0<='F'&&ch0>='A')
        {
            val0=ch0-'A'+10;
        }
        const char ch1=str[2*i+1];
        if(ch1<='9'&&ch1>='0')
        {
            val1=ch1-'0';
        }else if(ch1<='F'&&ch1>='A')
        {
            val1=ch1-'A'+10;
        }
        val=val0*16+val1;
        *cur=(char)val;
        cur--;
    }
    return res;
}

int AnalysisPath(const char* const path,void * gutiPtr,void * esmCtxPtr)
{
    printf("Analysis Path we get\n");
	int guti_str_len = 2*sizeof(guti_t);
	int mem_str_len = 2*sizeof(esm_context_t);
    int len=strlen(path);
    if(len<=0)
        return 1;
    /*printf("length of path:%d\n",len);*/
    if(path[0]!='/') return 1;
    char* tsk_nm=(char*) malloc(sizeof(char)*6);
    for(int i=1;i<6;i++)
    {
        tsk_nm[i-1]=path[i];
    }
    tsk_nm[5]='\0';
    /*printf("task_name:%s\n",tsk_nm);*/


    char *guti_str=(char *)malloc(sizeof(char)*guti_str_len+1);
    for(int i=20;i<20+guti_str_len;i++)
    {
        guti_str[i-20]=path[i];
    }
    guti_str[guti_str_len]='\0';
    /*printf("guti_str:%s\n",guti_str);*/
    {
		memcpy(gutiPtr,str2mem(guti_str),sizeof(guti_t));
		/*
        guti_t * Guti=(guti_t*)str2mem(guti_str);
		printf("guti\t%s\n",guti_str);
        printf("guti:%d\n",Guti->m_tmsi);
		printf("guti:%d\n",Guti->gummei.mme_gid);
        printf("guti:%d\n",Guti->gummei.mme_code);
        free(Guti);
		*/

    }


    char* mem_str=(char*) malloc(sizeof(char)*mem_str_len+1);
    for(int i=20+guti_str_len+5;i<20+guti_str_len+5+mem_str_len;i++)
    {
        mem_str[i-20-guti_str_len-5]=path[i];
    }
    mem_str[mem_str_len]='\0';
    /*printf("mem_str:%s\n",mem_str);*/
    {
		memcpy(esmCtxPtr,str2mem(mem_str),sizeof(esm_context_t));
		/*
        long *p=(long*)str2mem(mem_str);
        printf("esmCtx\t%s\n",mem_str);
        //printf("esmCtx:%ld\n",*p);
        free(p);
		*/
    }




    free(tsk_nm);
    free(guti_str);
    free(mem_str);
	//printf("success\n");
    return 0;
}

//记得free返回值
char* GeneratePath(void* q,int m,void* p,int n,int tsk_nm )//
{
	int mem_str_len = 2*n;
	int guti_str_len = 2*m;
    char* path=(char*)malloc(mem_str_len+guti_str_len+25+1);
    path[0]='/';
    path[mem_str_len+guti_str_len+25]='\0';
    switch(tsk_nm)
    {
        case 0:
            {
                char *tmp="TASK0?task=00&guti=";
                strncpy(path+1,tmp,strlen(tmp));
            }
            break;
        default:
            {
                char *tmp="NONTK?task=00&guti=";
                strncpy(path+1,tmp,strlen(tmp));
            }
            break;

    }
    /*printf("path:%s\n",path);*/
    {
        char*p=mem2str(q,m);
        strncpy(path+20,p,strlen(p));
        free(p);
    }

    /*printf("path:%s\n",path);*/
    {
        char* tmp="&mem=";
        strncpy(path+20+guti_str_len,tmp,strlen(tmp));
    }
    /*printf("path:%s\n",path);*/
    {
        char* q=mem2str(p,n);
        strncpy(path+25+guti_str_len,q,strlen(q));
        free(q);
    }
	//printf("test dukl\n");
    //printf("path:%s\n",path);
    return path;

}
/*
int main()
{
    int i=122;
    long l=1231231;
    printf("We have a int :%d\t a long:%ld\n",i,l);
    char * path=GeneratePath((void*)&i,sizeof(int),(void*)&l,sizeof(long),0);
    printf("We generate path:\t%s\n",path);
    AnalysisPath(path);
    free(path);
    return 0;
}
*/
//注意n和各种len之间是可以公用的
