#ifndef FDSL_tcp_filter_H
#define FDSL_tcp_filter_H

#define FDSL_IP_VER4 4
#define FDSL_IP_VER6 16
#define FDSL_TF_BUCKET_SIZE 1000

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

struct fdsl_tcp_filter_ele {
	struct fdsl_tcp_filter_ele *next;
	unsigned char value[16];
	char have;
};

struct fdsl_tcp_filter {
	struct fdsl_tcp_filter_ele *elements[FDSL_TF_BUCKET_SIZE];
	int ip_ver;
};

#define FDSL_TF_ELE_SIZE sizeof(struct fdsl_tcp_filter_ele)
#define FDSL_TF_SIZE sizeof(struct fdsl_tcp_filter)


unsigned int __times33(const char *s,int size)
{
	unsigned int hash = 5381;
	for (int n = 0; n < size; n++) {
		hash += (hash << 5) + (*s++);
	}

	return (hash & 0x7FFFFFFF);
}

struct fdsl_tcp_filter *fdsl_tf_init(int ip_ver)
{
	struct fdsl_tcp_filter *f;
	if (FDSL_IP_VER4 != ip_ver && FDSL_IP_VER6 != ip_ver) return NULL;

	f = (struct fdsl_tcp_filter *)fdsl_malloc(FDSL_TF_SIZE);
	memset(f, 0, FDSL_TF_SIZE);
	f->ip_ver = ip_ver;

	return f;
}

int fdsl_tf_find(struct fdsl_tcp_filter *f, const char *s)
{
	struct fdsl_tcp_filter_ele *tmp_ele;
	int bucket_p = __times33(s, f->ip_ver) % FDSL_TF_BUCKET_SIZE;
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

int fdsl_tf_add(struct fdsl_tcp_filter *f, const char *s)
{
	struct fdsl_tcp_filter_ele *tmp;

	int bucket_p = __times33(s, f->ip_ver) % FDSL_TF_BUCKET_SIZE;

    // 避免加入相同的hash值
	if(1==fdsl_tf_find(f,s)) return 0;

	if (NULL == f->elements[bucket_p]) {
		f->elements[bucket_p] = (struct fdsl_tcp_filter_ele *)fdsl_malloc(FDSL_TF_ELE_SIZE);
		memset(f->elements[bucket_p], 0, FDSL_TF_ELE_SIZE);
	}

	tmp = f->elements[bucket_p];

	while (NULL != tmp->next) {
		tmp = tmp->next;
	}

	if (tmp->have) {
		tmp->next = (struct fdsl_tcp_filter_ele *)fdsl_malloc(FDSL_TF_ELE_SIZE);
		memset(tmp->next, 0, FDSL_TF_ELE_SIZE);
		tmp = tmp->next;
	}

	tmp->have = 1;
	memcpy(tmp->value, s, f->ip_ver);

	return 0;
}

void fdsl_tf_release(struct fdsl_tcp_filter *f)
{
	struct fdsl_tcp_filter_ele *tmp_ele_a,*tmp_ele_b;

	for (int n = 0; n < FDSL_TF_BUCKET_SIZE; n++) {
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