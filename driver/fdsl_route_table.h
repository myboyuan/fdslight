#ifndef FDSL_ROUTABLE_H
#define FDSL_ROUTABLE_H
//#include<stdlib.h>
//#include<string.h>
#include<linux/slab.h>
#include<linux/string.h>

#define IP_VERSION_4 4
#define IP_VERSION_6 6

struct __mask_to_ip_seg{
	unsigned char mask_v;
	char  ip_seg_set[256];
};

struct fdsl_ip_tree{
	struct fdsl_ip_tree *tree[256];
	char ip_seg_set[256];
	char mask_have[9];
	struct __mask_to_ip_seg *mask_to_ip_seg[9];
};

struct fdsl_route_table{
	int ip_version;
	struct fdsl_ip_tree *tree;
};

unsigned char __fdsl_route_table_get_seg_mask_v(int seg,int mask)
{
	unsigned char  v=0,n=0;

	if (seg * 8 <= mask) return 255;
	if(seg * 8 - mask > 8) return 0;	
	n=mask % 8;
	for(int i=0;i<n;i++){
		v|=1<<(7-i);
	}

	return v;
}

unsigned char __fdsl_route_table_get_seg_mask(int seg,int mask)
{
	unsigned char  v;
	if (seg * 8<=mask) return 8;
	if (seg * 8 - mask > 8) return 0;

	v=mask % 8;

	return v;
}

int __fdsl_route_table_is_subnet_seg(struct fdsl_ip_tree *tree,unsigned ip_seg)
{
	int result=0,mask_v=0,value;
	unsigned char index=0;

	struct __mask_to_ip_seg *tmp;

	for (int n=0;n<9;n++){
		index=tree->mask_have[n];

		if(-1==index) break;

		tmp=tree->mask_to_ip_seg[index];
		mask_v=tmp->mask_v;
		value=mask_v & ip_seg;
		if(!tmp->ip_seg_set[value]) return 0;
		if(value==ip_seg){
			result=1;
			break;
		}else{
			result=2;
			break;
		}
	}

	return result;
}

struct fdsl_ip_tree *__fdsl_route_table_tree_init(void)
{
	struct fdsl_ip_tree *tree;
	//tree=malloc(sizeof(struct fdsl_ip_tree));
	tree=kmalloc(sizeof(struct fdsl_ip_tree),GFP_ATOMIC);
	memset(tree,0,sizeof(struct fdsl_ip_tree));
	memset(tree->mask_have,-1,9);

	return tree;
}

void __fdsl_route_table_tree_release(struct fdsl_ip_tree *tree)
{
	struct __mask_to_ip_seg *t;
	int index;

    if(NULL==tree) return;

	for(int n=0;n<9;n++){
		index=tree->mask_have[n];
		if(index<0) break;
		t=tree->mask_to_ip_seg[index];
		//free(t);
		kfree(t);
	}
	
	for(int n=0;n<256;n++){
		if(NULL!=tree->tree[n]) __fdsl_route_table_tree_release(tree->tree[n]);
	}
	//free(tree);
	kfree(tree);
}

struct fdsl_route_table *fdsl_route_table_init(int ip_version)
{
	struct fdsl_route_table *table;
	if(IP_VERSION_4!=ip_version && IP_VERSION_4!=ip_version) return NULL;
	//table=malloc(sizeof(struct fdsl_route_table));
	table=kmalloc(sizeof(struct fdsl_route_table),GFP_ATOMIC);
	memset(table,0,sizeof(struct fdsl_route_table));
	table->ip_version=ip_version;

	return table;
}

int fdsl_route_table_add(struct fdsl_route_table *table,unsigned char *ip,int mask)
{
	int tree_deep=4,max_mask_size=32,ip_ver=table->ip_version;

	unsigned char ip_seg,seg_mask_v,seg_mask;

	struct fdsl_ip_tree **parent=NULL,*tmp_tree=NULL;

	struct __mask_to_ip_seg *tmp_m_to_ip_s;


	if(IP_VERSION_6==ip_ver) {
		tree_deep=16;
		max_mask_size=128;
	}

	if(mask<1 || mask>max_mask_size) return -2;

	if(NULL==table->tree) table->tree=__fdsl_route_table_tree_init();

	tmp_tree=table->tree;

	for(int n=0;n<tree_deep;n++){
		if(NULL==tmp_tree){
			tmp_tree=__fdsl_route_table_tree_init();
			*parent=tmp_tree;
		}

		ip_seg=ip[n];
		tmp_tree->ip_seg_set[ip_seg]=1;

		seg_mask=__fdsl_route_table_get_seg_mask(n+1,mask);

		if(NULL==tmp_tree->mask_to_ip_seg[seg_mask]){
			//tmp_m_to_ip_s=malloc(sizeof(struct __mask_to_ip_seg));
			tmp_m_to_ip_s=kmalloc(sizeof(struct __mask_to_ip_seg),GFP_ATOMIC);
			memset(tmp_m_to_ip_s,0,sizeof(struct __mask_to_ip_seg));
			tmp_tree->mask_to_ip_seg[seg_mask]=tmp_m_to_ip_s;
		}else{
			tmp_m_to_ip_s=tmp_tree->mask_to_ip_seg[seg_mask];
		}

		seg_mask_v=__fdsl_route_table_get_seg_mask_v(n+1,mask);
		tmp_m_to_ip_s->mask_v=seg_mask_v;
		tmp_m_to_ip_s->ip_seg_set[ip_seg]=1;

		for(int n=0;n<9;n++){
			if(tmp_tree->mask_have[n]<0) tmp_tree->mask_have[n]=seg_mask;break;
			if(tmp_tree->mask_have[n]==seg_mask) break;
		}

		parent=&(tmp_tree->tree[ip_seg]);
		tmp_tree=tmp_tree->tree[ip_seg];
	}

	return 0;
}

int fdsl_route_table_exists(struct fdsl_route_table *table,unsigned char  *ip)
{
	int tree_deep=4,t_val=0;
	unsigned char ip_seg;

	struct fdsl_ip_tree *tree;

	if(IP_VERSION_6==table->ip_version) tree_deep=16;

	tree=table->tree;
	if(NULL==tree) return 0;

	for(int n=0;n<tree_deep;n++){
		ip_seg=ip[n];

		if(tree->ip_seg_set[ip_seg]){
			tree=tree->tree[ip_seg];
			continue;
		}
		t_val=__fdsl_route_table_is_subnet_seg(tree,ip_seg);
		switch(t_val){
			case 0:return 0;
			case 1:return 1;
		}
	}

	return 1;
}

void fdsl_route_table_release(struct fdsl_route_table *table)
{
	struct fdsl_ip_tree *tree;
	
	tree=table->tree;
	__fdsl_route_table_tree_release(tree);
	//free(table);
	kfree(table);
}

#endif
