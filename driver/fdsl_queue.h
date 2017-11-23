#ifndef FDSL_QUEUE_H
#define FDSL_QUEUE_H

#ifdef FDSL_USER

#include<sys/types.h>
#include<stdlib.h>
#include<string.h>

#define MALLOC(size) malloc(size)
#define FREE(p) free(p)

#else

#include<linux/types.h>
#include<linux/vmalloc.h>
#include<linux/string.h>

#define MALLOC(size) vmalloc(size)
#define FREE(p) vfree(p)

#endif


#define FDSL_MTU 1501

struct fdsl_queue_data{
	struct fdsl_queue_data *next;
	struct fdsl_queue_data *previous;

	ssize_t size;
	char data[FDSL_MTU];
};

struct fdsl_queue{
	struct fdsl_queue_data *begin;
	// 数据结束位置
	struct fdsl_queue_data *end;
	// 列表对象
	struct fdsl_queue_data *list;

	// 总共能够存储的数据大小
	size_t total_size;
	// 已经使用的数据大小
	size_t have;
	//数据开始位置
};

struct fdsl_queue *fdsl_queue_init(size_t qsize)
{
	struct fdsl_queue *queue=MALLOC(sizeof(struct fdsl_queue));
	struct fdsl_queue_data *tmp_pre=NULL,*tmp=NULL;

	memset(queue,0,sizeof(struct fdsl_queue));

    for(int n=0;n<qsize;n++){
        tmp=MALLOC(sizeof(struct fdsl_queue_data));
        memset(tmp,0,sizeof(struct fdsl_queue_data));
        if(0==n) queue->list=tmp;
        else{
           tmp_pre->next=tmp;
           tmp->previous=tmp_pre;
        }

        tmp_pre=tmp;
    }

    queue->list->previous=tmp;
    tmp->next=queue->list;
    queue->total_size=qsize;

	return queue;
}

int fdsl_queue_push(struct fdsl_queue *queue,char *data,size_t size)
{
	struct fdsl_queue_data *tmp;

	if(size > FDSL_MTU) return -1;
	if(queue->total_size==queue->have) return -2;

    if(0==queue->have){
        tmp=queue->list;
        tmp->size=size;
        memcpy(tmp->data,data,size);
        queue->begin=tmp;
    }else{
        tmp=queue->end;
        tmp=tmp->next;
        tmp->size=size;
        memcpy(tmp->data,data,size);
    }

    queue->end=tmp;
    queue->have+=1;

	return 0;
}


struct fdsl_queue_data *fdsl_queue_pop(struct fdsl_queue *queue)
{
	struct fdsl_queue_data *tmp=NULL;
	if(0==queue->have) return tmp;

    tmp=queue->begin;
    queue->begin=tmp->next;
	queue->have-=1;

	return tmp;
}

void fdsl_queue_reset(struct fdsl_queue *queue)
{
    queue->have=0;
}

void fdsl_queue_release(struct fdsl_queue *queue)
{
	struct fdsl_queue_data *tmp_a=NULL,*tmp_b=NULL;
	size_t qsize=queue->total_size;

    for(int n=0;n<qsize;n++){
        if(0==n) tmp_a=queue->list;
        tmp_b=tmp_a->next;
        FREE(tmp_a);
        tmp_a=tmp_b;
    }
	FREE(queue);
}


#endif
