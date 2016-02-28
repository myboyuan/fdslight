#ifndef FDSL_QUEUE_H
#define FDSL_QUEUE_H
#include<stdlib.h>
#include<sys/types.h>
#include<string.h>

#define FDSL_MTU 1600

struct fdsl_queue_data{
	ssize_t size;
	char data[FDSL_MTU];
	struct fdsl_queue_data *next;
};

struct fdsl_queue{
	size_t total_size;
	size_t have;
	struct fdsl_queue_data *begin;
	struct fdsl_queue_data *end;
};

struct fdsl_queue *fdsl_queue_init(size_t qsize)
{
	struct fdsl_queue *queue=malloc(sizeof(struct fdsl_queue));
	struct fdsl_queue_data *tmp_a=NULL,*first=NULL,*tmp_b=NULL;
	memset(queue,0,sizeof(struct fdsl_queue));

	queue->total_size=qsize;
	for (int n=0;n<qsize;n++){
		tmp_b=malloc(sizeof(struct fdsl_queue_data));
		if(NULL==first){
			first=tmp_b;
			tmp_a=tmp_b;
		}else{
			tmp_a->next=tmp_b;
			tmp_a=tmp_b;
		}
	}
	
	queue->begin=first;
	queue->end=first;
	tmp_a->next=first;

	return queue;
}

int fdsl_queue_push(struct fdsl_queue *queue,char *data,size_t size)
{
	struct fdsl_queue_data *tmp;

	if(size > FDSL_MTU) return -1;
	if(queue->total_size==queue->have) return -2;
	if(0==queue->have){
		tmp=queue->end;
	}else{
		tmp=queue->end->next;
		queue->end=tmp;
	}
	
	memcpy(tmp->data,data,size);
	tmp->size=size;
	queue->have++;

	return 0;
}


struct fdsl_queue_data *fdsl_queue_pop(struct fdsl_queue *queue)
{
	struct fdsl_queue_data *tmp=NULL;
	if(0==queue->have) return tmp;
	tmp=queue->begin;
	if(1!=queue->have){
		queue->begin=tmp->next;
	}
	queue->have--;

	return tmp;
}

void fdsl_queue_release(struct fdsl_queue *queue)
{
	struct fdsl_queue_data *tmp,*next;
	size_t size;

	size=queue->total_size;
	tmp=queue->begin;
	
	for(int n=0;n<size;n++){
		next=tmp->next;
		free(tmp);
		tmp=next;
	}

	free(queue);
}


#endif
