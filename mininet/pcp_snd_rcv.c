#include<stdio.h>
#include<pcap.h>
#include<stdlib.h>
#include<errno.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<netinet/if_ether.h>
#include<sys/types.h>
#include<string.h>
#include<net/if.h>

void main(int argc, char *argv[])
{
 int i,hostCount,N,sel_ret,fd[N];
 char errbuf[PCAP_ERRBUF_SIZE];
 hostCount=atoi(argv[1]);
 N=2*hostCount;
 pcap_t *handlers[N];
 char *devs[N];
 char dev[15];
 const u_char *packet[N];
 struct pcap_pkthdr hdr;
 for(i=0;i<N;i++)
 {
  sprintf(dev,"simhost-eth%d",i);
  handlers[i]=pcap_open_live(dev,BUFSIZ,1,-1,errbuf);
  fd[i]=pcap_get_selectable_fd(handlers[i]);
  if(handlers[i]==NULL)
  {
   fprintf(stderr,"Couldn't Open Device %s : %s\n",dev,errbuf);
  }
 }
 fd_set rdset;

label:
 while(1)
 {
  FD_ZERO(&rdset);
  for(i=0;i<N;i++)
  {
   FD_SET(fd[i],&rdset);
  }
  sel_ret=select(fd[N-1]+1,&rdset,NULL,NULL,NULL);
  printf ("select returned = %d\n",sel_ret);
  if(sel_ret==-1)
  {
   printf("ret=%d,errno=%d\n",sel_ret,errno);
   exit(1);
  }
  if(!sel_ret)
  {
   goto label;
  }
  for(i=0;i<N;i++)
  {
   if(FD_ISSET(fd[i],&rdset))
   {
    if((packet[i]=pcap_next(handlers[i],&hdr))!=NULL)
    {
     pcap_sendpacket(( (i%2) ? handlers[i-1] : handlers[i+1] ),packet[i],100);
    }
   }
  }
 }
 return;
}
