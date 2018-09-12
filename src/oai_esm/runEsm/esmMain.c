#include"obj_hashtable.h"
#include"hashtable.h"
#include"esm_data.h"
#include"3gpp_23.003.h"
//#include"libeventCS.h"
//#include"libevent-server-mdfy.h"
//#include"libevent-client-mdfy.h"
//#include"hashAPI.h"
#include<stdio.h>
int main(){
	esm_init();
	Server("12201");
/*	
	int i=122;
	long l=1231231;
	printf("We have a int :%d\t a long:%ld\n",i,l);
	char * path=GeneratePath((void*)&i,sizeof(int),(void*)&l,sizeof(long),0);
	printf("We generate path:\t%s\n",path);
	char url[100];
	strcpy(url,"https://127.0.0.1:12201");
	strcat(url,path);
	printf("url:\t%s\n",url);
	//AnalysisPath(path);
	//free(path);
*/	
	return 0;
}
