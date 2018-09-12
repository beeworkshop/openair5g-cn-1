/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the Apache License, Version 2.0  (the "License"); you may not use this file
 * except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

/*****************************************************************************
  Source      emm_main.c

  Version     0.1

  Date        2012/10/10

  Product     NAS stack

  Subsystem   EPS Mobility Management

  Author      Frederic Maurel

  Description Defines the EPS Mobility Management procedure call manager,
        the main entry point for elementary EMM processing.

*****************************************************************************/
#include <pthread.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include "bstrlib.h"

#include "log.h"
#include "obj_hashtable.h"
#include "3gpp_24.007.h"
#include "3gpp_24.008.h"
#include "common_defs.h"
#include "emm_main.h"
#include "emm_data.h"
#include "mme_config.h"



/****************************************************************************/
/****************  E X T E R N A L    D E F I N I T I O N S  ****************/
/****************************************************************************/

/****************************************************************************/
/*******************  L O C A L    D E F I N I T I O N S  *******************/
/****************************************************************************/


/****************************************************************************/
/******************  E X P O R T E D    F U N C T I O N S  ******************/
/****************************************************************************/


/****************************************************************************
 **                                                                        **
 ** Name:    emm_main_initialize()                                     **
 **                                                                        **
 ** Description: Initializes EMM internal data                             **
 **                                                                        **
 ** Inputs:  None                                                      **
 **      Others:    None                                       **
 **                                                                        **
 ** Outputs:     None                                                      **
 **      Return:    None                                       **
 **      Others:    _emm_data                                  **
 **                                                                        **
 ***************************************************************************/
void
emm_main_initialize (
  mme_config_t * mme_config_p)
{
  OAILOG_FUNC_IN (LOG_NAS_EMM);
  /*
   * Retreive MME supported configuration data
   */
  memset(&_emm_data.conf, 0, sizeof(_emm_data.conf));
  if (mme_api_get_emm_config (&_emm_data.conf, mme_config_p) != RETURNok) {
    OAILOG_ERROR (LOG_NAS_EMM, "EMM-MAIN  - Failed to get MME configuration data");
  }
  OAILOG_FUNC_OUT(LOG_NAS_EMM);
}

/****************************************************************************
 **                                                                        **
 ** Name:    emm_main_cleanup()                                        **
 **                                                                        **
 ** Description: Performs the EPS Mobility Management clean up procedure   **
 **                                                                        **
 ** Inputs:  None                                                      **
 **          Others:    None                                       **
 **                                                                        **
 ** Outputs:     None                                                      **
 **          Return:    None                                       **
 **          Others:    None                                       **
 **                                                                        **
 ***************************************************************************/
void
emm_main_cleanup (
  void)
{
  OAILOG_FUNC_IN (LOG_NAS_EMM);
  OAILOG_FUNC_OUT(LOG_NAS_EMM);
}



/****************************************************************************/
/*********************  L O C A L    F U N C T I O N S  *********************/
/****************************************************************************/



//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//

/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the Apache License, Version 2.0  (the "License"); you may not use this file
 * except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

/*! \file mme_app_edns_emulation.c
  \brief
  \author Lionel Gauthier
  \company Eurecom
  \email: lionel.gauthier@eurecom.fr
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "bstrlib.h"

#include "log.h"
#include "obj_hashtable.h"
#include "mme_config.h"
#include "common_defs.h"
#include "dynamic_memory_check.h"
#include "mme_app_edns_emulation.h"

#include "emmData.h"

const bool ESM_DEBUG=1;

const int Key_size = sizeof(struct guti_s);

static obj_hash_table_t * esm_hash_pointer = NULL;

/*static obj_hash_table_t * g_e_dns_entries = NULL;*/


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
                  printf("n_pnds                %d      \n",p->n_pdns);
        }else
        {
            printf("\nNOT SAME\n");
        }
        printf("\nesm_insert end\nTEST\n");
    }
    if(HASH_TABLE_OK==rc) return RETURNok;
    else return RETURNerror;
}
//------------------------------------------------------------------------------
/*int mme_app_edns_add_sgw_entry(bstring id, struct in_addr in_addr)*/
/*{*/
  /*char * cid = calloc(1, blength(id)+1);*/
  /*if (cid) {*/
    /*strncpy(cid, (const char *)id->data, blength(id));*/

    /*struct in_addr *data = malloc(sizeof(struct in_addr));*/
    /*if (data) {*/
      /*data->s_addr = in_addr.s_addr;*/

      /*hashtable_rc_t rc = obj_hashtable_insert (g_e_dns_entries, cid, strlen(cid), data);*/
      /*if (HASH_TABLE_OK == rc) return RETURNok;*/
    /*}*/
  /*}*/
  /*return RETURNerror;*/
/*}*/



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
//------------------------------------------------------------------------------
/*int  mme_app_edns_init (const mme_config_t * mme_config_p)*/
/*{*/
  /*int rc = RETURNok;*/
  /*g_e_dns_entries = obj_hashtable_create (min(32, MME_CONFIG_MAX_SGW), NULL, free_wrapper, free_wrapper, NULL);*/
  /*if (g_e_dns_entries) {*/
    /*for (int i = 0; i < mme_config_p->e_dns_emulation.nb_sgw_entries; i++) {*/
      /*rc |= mme_app_edns_add_sgw_entry(mme_config_p->e_dns_emulation.sgw_id[i], mme_config_p->e_dns_emulation.sgw_ip_addr[i]);*/
    /*}*/
    /*return rc;*/
  /*}*/
  /*return RETURNerror;*/
/*}*/




void esm_exit(void)
{
    obj_hashtable_destroy(esm_hash_pointer);
}
//------------------------------------------------------------------------------
/*void  mme_app_edns_exit (void)*/
/*{*/
  /*obj_hashtable_destroy (g_e_dns_entries);*/
/*}*/

void esm_useless(void)
{
    if(ESM_DEBUG)
        printf("********************************\n");
}
