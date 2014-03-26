#include<stdio.h>
#include<pcap.h>
#include<stdlib.h>
#include<errno.h>
#include<sys/socket.h>
#include<sys/un.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<netinet/if_ether.h>
#include<sys/types.h>
#include<string.h>
#define BUFLEN 512
#define PORT 9930
#define CHUNK 1024
#include<net/if.h>
#include<pcap/pcap.h>
#include<unistd.h>
#include<sys/select.h>
#include<sys/time.h>

#define HOST_PATH "/simhost"

void err(char *s)
{
    perror(s);
    exit(1);
}


int main(int argc,char *argv[])
{

 int sd,fdmast;
 struct sockaddr_un hostaddr;
 char buf[256];
 int bytes,tick;
 fd_set master;
 fd_set rd_mast;

int n,i,sel_ret;
 int l;
 char errbuf[PCAP_ERRBUF_SIZE];
 u_char *ptr;


/*Tick receiving part */
 sd=socket(AF_UNIX,SOCK_DGRAM,0);
 if(sd<0)
 {
  perror("\n socket() Failed\n");
 }

 memset(&hostaddr,0,sizeof(hostaddr));
 hostaddr.sun_family=AF_UNIX;
 strcpy(hostaddr.sun_path,HOST_PATH);

 bind(sd,(struct sockaddr *)&hostaddr,SUN_LEN(&hostaddr));
// bytes=recvfrom(sd,buf,sizeof(buf),0,(struct sockaddr *)0,(int *)0);
// tick=atoi(buf);

 n=atoi(argv[1]);
 printf("%d",n);

 char dev[n];

 pcap_t *handles[n];
 int fd[n];
 fd_set rdset;

 const u_char *packet[n];
 struct pcap_pkthdr hdr;
 struct ether_header *eptr;

for(i=0;i<n;i++)
 {
  sprintf(dev,"simhost-eth%d",i);
  puts(dev);
  handles[i]=pcap_open_live(dev,BUFSIZ,1,-1,errbuf);

  if(handles[i]==NULL)
   {
    fprintf(stderr,"Couldn't open device %s : %s \n" ,dev, errbuf);

   }

  fd[i]=pcap_get_selectable_fd(handles[i]);

 }


label:
for(;;)
 {
  FD_ZERO(&rdset);
  FD_ZERO(&master);
  FD_ZERO(&rd_mast);

  FD_SET(sd,&master);
  fdmast=sd;


  for(i=0;i<n;i++)
  {
   FD_SET(fd[i],&rdset);
  }

rd_mast=master;

tick= select(fdmast+1,&rd_mast,NULL,NULL,NULL);
if(tick==-1)
     {
       printf("ret=%d,errno=%d\n",tick,errno);
       exit(1);
     }

/*if(!tick)
  {
   goto label;
  }*/

if(FD_ISSET(fdmast,&rd_mast))
 {
  bytes=recvfrom(sd,buf,sizeof(buf),0,(struct sockaddr *)0,(int *)0);
  tick=atoi(buf);
  printf("\n** Tick received %d ***\n",tick);
  sel_ret=select(fd[n-1]+1,&rdset,NULL,NULL,NULL);
  if(sel_ret==-1)
     {
       printf("ret=%d,errno=%d\n",sel_ret,errno);
       exit(1);
     }
  for(i=0;i<n;i++)
    {
      if(FD_ISSET(fd[i],&rdset))
      {

            if((packet[i]=pcap_next(handles[i],&hdr))!=NULL)
               {

                        l=hdr.len;
                        printf("Grabbed packet of length %d from fd %d\n",hdr.len, fd[i]);



                        printf("Ethernet address length is %d\n",ETHER_HDR_LEN);
                        
eptr = (struct ether_header *) packet;


                       if (ntohs (eptr->ether_type) == ETHERTYPE_IP)
                               {
                                 printf("Ethernet type hex:%x dec:%d is an IP packet\n",
                                 ntohs(eptr->ether_type),
                                 ntohs(eptr->ether_type));
                               }
                        else  if (ntohs (eptr->ether_type) == ETHERTYPE_ARP)
                               {
                                 printf("Ethernet type hex:%x dec:%d is an ARP packet\n",
                                 ntohs(eptr->ether_type),
                                 ntohs(eptr->ether_type));
                               }



                       ptr = eptr->ether_dhost;
                       i = ETHER_ADDR_LEN;
                       printf(" Destination Address: ");
                       do{
                          printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
                         }while(--i>0);
                       printf("\n");

                        ptr = eptr->ether_shost;
                          i = ETHER_ADDR_LEN;
                       printf(" Source Address:  ");
                        do{
                            printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
                          }while(--i>0);
                       printf("\n");

                        printf("sending Grabbed packet of length %d \n",hdr.len );
                        pcap_sendpacket(( (i%2) ? handles[i-1] : handles[i+1] ),packet[i],l);
                                      /*   l=hdr.len;
                 pcap_sendpacket(( (i%2) ? handles[i-1] : handles[i+1] ),packet[i],l);*/
               }
           }
        }

     }




 }
 return;

close(sd);
unlink(HOST_PATH);

}
