#include<stdlib.h>
#include<stdio.h>

//#include"libeventCS.h"
#include"libevent-client-mdfy.h"
#include"libevent-server-mdfy.h"
#include"http_parser.h"
#include"esm_data.h"
#include"3gpp_23.003.h"
#include"obj_hashtable.h"
#include"hashtable.h"

int main(){
/*
	guti_t Guti;
	esm_context_t EsmCtx;

	Guti.m_tmsi = 2;
	Guti.gummei.plmn.mcc_digit3 = 2;
	Guti.gummei.plmn.mcc_digit2 = 0;
	Guti.gummei.plmn.mcc_digit1 = 8;
	Guti.gummei.plmn.mnc_digit3 = 0;
	Guti.gummei.plmn.mnc_digit2 = 9;
	Guti.gummei.plmn.mnc_digit1 = 3;
	Guti.gummei.mme_gid = 10;
	Guti.gummei.mme_code = 10;


	EsmCtx.n_active_ebrs = 1;
	EsmCtx.n_active_pdns = 1;
	EsmCtx.n_pdns = 2;
	EsmCtx.is_emergency = false;
	//EsmCtx.esm_proc_data->...
	EsmCtx.T3489.id = 12;
	EsmCtx.T3489.sec = 11100;
*/
	int task = 5;
	long mem = 123321;
    char * path = GeneratePath((void*)&task,sizeof(int),(void*)&mem,sizeof(long),0);
	printf("path\t%s\n",path);
    char url[300];
	strcpy(url,"https://127.0.0.1:12201");
	strcat(url,path);
	free(path);
    Client(url);
	//guti_t GutiServer;
	//esm_context_t EsmCtxServer;
	//AnalysisPath(path,(void*)&GutiServer,(void*)&EsmCtxServer);
	/*
	printf("guti\t%d\n",GutiServer.m_tmsi);
    printf("guti\t%d\n",GutiServer.gummei.plmn.mcc_digit3);
    printf("guti\t%d\n",GutiServer.gummei.plmn.mcc_digit2);
    printf("guti\t%d\n",GutiServer.gummei.plmn.mcc_digit1);
    printf("guti\t%d\n",GutiServer.gummei.plmn.mnc_digit3);
    printf("guti\t%d\n",GutiServer.gummei.plmn.mnc_digit2);
    printf("guti\t%d\n",GutiServer.gummei.plmn.mnc_digit1);
    printf("guti\t%d\n",GutiServer.gummei.mme_gid);
    printf("guti\t%d\n",GutiServer.gummei.mme_code);
	*/

}

