#include "esm_sapDef.h"
#include "bstrlib.h"
#include "3gpp_23.003.h"
#include "esm_proc.h"

#define GUTI_DATA_IND(mSGpTR) (mSGpTR)->ittiMsg.guti_msg
typedef struct guti_msg_s {
  int task;//task number
  guti_t                   _guti;        /* The GUTI assigned to the UE                     */
  const_bstring  apn;
  protocol_configuration_options_t *  pco;
  esm_ebr_timer_data_t *  data;



  proc_tid_t pti;
  esm_cause_t *esm_cause;
  emm_context_t * emm_context;

  bool* flag;
  esm_context_t *esm_p;
  esm_context_t esm_ctx;

  struct esm_proc_data_t *esm_proc_data;
  struct esm_proc_data_s proc;
} guti_msg_t;


#define RTN_DATA_IND(mSGpTR) (mSGpTR)->ittiMsg.guti_rtn
typedef struct guti_rtn_s {
  int task;//task number

  proc_tid_t pti;
  esm_cause_t *esm_cause;
  emm_context_t * emm_context;
  bool* flag;
  esm_context_t *esm_p;
  esm_context_t esm_ctx;

  struct esm_proc_data_t *esm_proc_data;
  struct esm_proc_data_s proc;
} guti_rtn_t;

