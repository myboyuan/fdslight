#ifndef FDSL_IP_FILTER_H
#define FDSL_IP_FILTER_H

#define FDSL_IP_VER4 4
#define FDSL_IP_VER6 16
#define FDSL_IP_BUCKET_SIZE 1000

#ifdef FDSL_LINUX_KERNEL
#include<linux/vmalloc.h>
#include<linux/string.h>

#define fdsl_malloc(size) vmalloc(size)
#define fdsl_free(p) vfree(p)
#else
#include<stdlib.h>
#include<string.h>

#define fdsl_malloc(size) malloc(size)
#define fdsl_free(p) free(p)
#endif

struct fdsl_ip_filter_ele {
	struct fdsl_ip_filter_ele *next;
	unsigned char value[16];
};

struct fdsl_ip_filter {
	struct fdsl_ip_filter_ele *elements[FDSL_IP_BUCKET_SIZE];
	int ip_ver;
};

#define FDSL_IP_ELE_SIZE sizeof(struct fdsl_ip_filter_ele)
#define FDSL_IP_SIZE sizeof(struct fdsl_ip_filter)


unsigned int __times33(const char *s,int size)
{
	unsigned int hash = 5381;
	for (int n = 0; n < size; n++) {
		hash += (hash << 5) + (*s++);
	}

	return (hash & 0x7FFFFFFF);
}

struct fdsl_ip_filter *fdsl_ip_filter_init(int ip_ver)
{
	struct fdsl_ip_filter *f;
	if (FDSL_IP_VER4 != ip_ver && FDSL_IP_VER6 != ip_ver) return NULL;

	f = (struct fdsl_ip_filter *)fdsl_malloc(FDSL_IP_SIZE);
	memset(f, 0, FDSL_IP_SIZE);
	f->ip_ver = ip_ver;

	return f;
}

int fdsl_ip_filter_find(struct fdsl_ip_filter *f, const char *s)
{
	struct fdsl_ip_filter_ele *tmp_ele;
	int bucket_p = __times33(s, f->ip_ver) % FDSL_IP_BUCKET_SIZE;
	int is_find = 0;

	tmp_ele = f->elements[bucket_p];

	if (NULL == tmp_ele) return 0;

	while (NULL!=tmp_ele) {
		is_find = (0 == memcmp(tmp_ele->value, s, f->ip_ver)) ? 1 : 0;
		if (is_find) return 1;
		tmp_ele=tmp_ele->next;
	}

	return is_find;
}

int fdsl_ip_filter_add(struct fdsl_ip_filter *f, const char *s)
{
	struct fdsl_ip_filter_ele *tmp;
	int bucket_p = __times33(s, f->ip_ver) % FDSL_IP_BUCKET_SIZE,is_first=1;

    // 避免加入相同的value
	if(1==fdsl_ip_filter_find(f,s)) return 0;

	if (NULL == f->elements[bucket_p]) {
		f->elements[bucket_p] = (struct fdsl_ip_filter_ele *)fdsl_malloc(FDSL_IP_ELE_SIZE);
		memset(f->elements[bucket_p], 0, FDSL_IP_ELE_SIZE);
	}else{
	    is_first=0;
	}

	tmp = f->elements[bucket_p];

	while (NULL != tmp->next) {
	    is_first=0;
		tmp = tmp->next;
	}

	if (!is_first) {
		tmp->next = (struct fdsl_ip_filter_ele *)fdsl_malloc(FDSL_IP_ELE_SIZE);
		memset(tmp->next, 0, FDSL_IP_ELE_SIZE);
		tmp = tmp->next;
	}

	memcpy(tmp->value, s, f->ip_ver);

	return 0;
}

int fdsl_ip_filter_delete(struct fdsl_ip_filter *f,const char *s)
{
    struct fdsl_ip_filter_ele *tmp_ele,*tmp_pre_ele;
    int bucket_p=__times33(s,f->ip_ver) % FDSL_IP_BUCKET_SIZE;
    int is_find=0,cnt=0;
    tmp_ele=f->elements[bucket_p];
   
    while(NULL!=tmp_ele){
        is_find = (0 == memcmp(tmp_ele->value, s, f->ip_ver)) ? 1 : 0;
        if(!is_find){
            tmp_pre_ele=tmp_ele;
            tmp_ele=tmp_ele->next;
            cnt++;
            continue;
        }
        if(0==cnt){
            f->elements[bucket_p]=NULL;
            if(NULL!=tmp_ele->next) f->elements[bucket_p]=tmp_ele->next;
        }
        else{
            tmp_pre_ele->next=tmp_ele->next;
        }
        fdsl_free(tmp_ele);
        break;
    }
    return 1;
}

void fdsl_ip_filter_release(struct fdsl_ip_filter *f)
{
	struct fdsl_ip_filter_ele *tmp_ele_a,*tmp_ele_b;

	for (int n = 0; n < FDSL_IP_BUCKET_SIZE; n++) {
		tmp_ele_a = f->elements[n];
		tmp_ele_b = tmp_ele_a;

		if (NULL == tmp_ele_a) continue;

		while (NULL != tmp_ele_a->next) {
			tmp_ele_b = tmp_ele_a->next;
			fdsl_free(tmp_ele_a);
			tmp_ele_a = tmp_ele_b;
		}

		fdsl_free(tmp_ele_a);
	}

	fdsl_free(f);

}

#endif