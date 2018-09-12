#include<stdlib.h>
#include<stdint.h>
#include<stdbool.h>

#include"hashAPI.h"
#include"obj_hashtable.h"
#include"hashtable.h"
#include"esm_data.h"
#include"dynamic_memory_check.h"
#include"common_defs.h"
#include<stdio.h>

const bool ESM_DEBUG = 1;
const int Key_size = sizeof(struct guti_s);
static obj_hash_table_t * esm_hash_pointer = NULL;

struct esm_context_s* esm_get_inplace(struct guti_s guti,struct esm_context_s **esm_p)
{
	struct esm_context_s *esm_context_t=NULL;
	obj_hashtable_get(esm_hash_pointer,&guti,Key_size,(void **)&esm_context_t);

	*esm_p=esm_context_t;
	if(ESM_DEBUG)
		{
			printf("esm_get_inplce函数内部得到的结果:%p\n",*esm_p);
		}
	return *esm_p;
}

int esm_insert(struct guti_s guti_t, struct esm_context_s esm_context_t)
{
	if(ESM_DEBUG)
		{
			printf("\nesm_insert start\n");
		}
	char* cid=malloc(sizeof(struct guti_s)+1);
	if(cid)
		{
			memcpy(cid,&guti_t,sizeof(struct guti_s));
		}
	struct esm_context_s * data=malloc(sizeof(struct esm_context_s));
	if(data)
		{
			memcpy(data,&esm_context_t,sizeof(struct esm_context_s));
		}
	/*hashtable_rc_t rc=obj_hashtable_insert(esm_hash_pointer,(void*)&guti_t,Key_size,&esm_context_t);*/
	hashtable_rc_t rc=obj_hashtable_insert(esm_hash_pointer,cid,Key_size,data);
	if(ESM_DEBUG)
		{
			struct esm_context_s * p;
			esm_get_inplace(guti_t,&p);
			if(memcmp(p,&esm_context_t,sizeof(struct esm_context_s))==0)
				{
					printf("这个是插入时取出的结果:\n");
					printf("wo get p:             %p      \n",p);
					printf("wo get p->esm_proc_data:             %p      \n",p->esm_proc_data);
					printf("n_pdns                %d      \n",p->n_pdns);
				}else{
					printf("\nNOT SAME\n");
				}
			printf("\nesm_insert end\nTEST\n");
		}
	if(HASH_TABLE_OK == rc) return RETURNok;
	else return RETURNerror;
				
} 

struct esm_context_s* esm_remove(struct guti_s guti)
{
	if(ESM_DEBUG)
		{
			printf("\nesm_remove start\n");
		}
	struct esm_context_s *esm_context_t=NULL;
	obj_hashtable_remove(esm_hash_pointer,&guti,Key_size,(void **)&esm_context_t);

	return esm_context_t;

}

int esm_init(void)
{
	if(ESM_DEBUG)
		{
			printf("\nesm_init start\n");
		}
	esm_hash_pointer=obj_hashtable_create(32,NULL,free_wrapper,free_wrapper,NULL);
	if(esm_hash_pointer) return RETURNok;
	else RETURNerror;
}

void esm_exit(void)
{
	obj_hashtable_destroy(esm_hash_pointer);
}
