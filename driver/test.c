#include<stdio.h>
//#include "_fdsl_queue.h"
#include "fdsl_route_table.h"

int main()
{
	/**
	struct fdsl_queue *queue;
	struct fdsl_queue_data *data;
	int err;
	char *values[]={"aa","bb","cc"};

	queue=fdsl_queue_init(3);

	for(int n=0;n<3;n++){
		err=fdsl_queue_push(queue,values[n],2);
	}


	for(int n=0;n<3;n++){
		data=fdsl_queue_pop(queue);
		if(NULL==data) printf("error\r\n");

		printf("%s\r\n",data->data);
	}**/

	struct fdsl_route_table *table;
	table=fdsl_route_table_init(IP_VERSION_4);
	
	fdsl_route_table_add(table,"hel\0",17);
	int ret=fdsl_route_table_exists(table,"hel\x80");
	fdsl_route_table_release(table);

	printf("%d\r\n",ret);


	return 0;
}

