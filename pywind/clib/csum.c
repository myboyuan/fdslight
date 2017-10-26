#include<string.h>
#include "csum.h"

void csum_calc_ipaddr_change(char *ippkt,const char *address,char is_source)
{
        char *tmp_a=ippkt,*tmp_b=address;
        char ip_ver=((*ippkt) & 0xf0) >> 4;
        unsigned short csum,old_field,new_field;

        
        char off_addr,addr_len;
        unsigned char protocol,hdr_len;

        if(4==ip_ver){
                //
                if(is_source) off_addr=12;
                else off_addr=16;
                //
                addr_len=4;
                protocol=*(ippkt+9);
        }else{
                //
                if(is_source) off_addr=8;
                else off_addr=24;
                //
                addr_len=16;
                protocol=*(ippkt+6);
        }
        
        if(4==ip_ver){
                tmp_a=ippkt+10;
                csum=*((unsigned short *)tmp_a);
        
                if(is_source) tmp_a=ippkt+12;
                else tmp_a=ippkt+16;
        
                for(int n=0;n<2;n++){
                        old_field=*((unsigned short *)tmp_a);
                        new_field=*((unsigned short *)tmp_b);
        
                        csum=csum_calc_inre(old_field,new_field,csum);
        
                        tmp_a+=2;
                        tmp_b+=2;
                }

                tmp_a=ippkt+10;
                memcpy(tmp_a,(char *)(&csum),2);
        }

        tmp_a=ippkt+off_addr;
        
        switch(protocol){
                case 6:
                        break;
                case 17:
                case 136:
                        break;
                case 58:
                        if(6==ip_ver){

                        }
                break;
        }
        memcpy(tmp_a,address,addr_len);
}

unsigned short csum_calc_inre(unsigned short old_field,unsigned short new_field,unsigned short old_csum)
{
    unsigned long csum = old_csum - (~old_field & 0xFFFF) - new_field ;
    csum = (csum >> 16) + (csum & 0xffff);
    csum +=  (csum >> 16);
    return csum;
}

unsigned short csum_calc(char *buffer,size_t size)
{
    unsigned long sum;
    
    sum = 0;
    while (size > 1) {
            sum += *buffer++;
            size -= 2;
    }

    /*  Add left-over byte, if any */
    if (size)
            sum += *(unsigned char *)buffer;

    /*  Fold 32-bit sum to 16 bits */
    while (sum >> 16)
            sum  = (sum & 0xffff) + (sum >> 16);

    return (unsigned short)(~sum);
}

void csum_calc_ip(char *pkt,size_t size)
{

}