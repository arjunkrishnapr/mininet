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
#include<sys/queue.h>
#include<unistd.h>
#include<sys/select.h>
#include<sys/time.h>
#include<sys/un.h>
#include<pcap/pcap.h>
#include<netdb.h>
#include<ifaddrs.h>
#include<sys/ioctl.h>

#define BUFLEN 32
#define HOST_PATH "/home/mininet/simhost"
//#define EXTERNAL_CPATH "/home/mininet/SHCommand"

char temp[60];
//TAILQ_HEAD(tailhead,buffer) head[6];
//struct tailhead *headp;

void *AllInterface_name(int x);
void *HostInterface_name(char *,int x);

typedef struct buffer
{
 const u_char *data;
 TAILQ_ENTRY(buffer) entries;
}BUFFER;

void *AllInterface_name(int x)
{
 // char temp[60]="";
 int i;
 for(i=1;i<=x/2;i++)
 {
  sprintf(temp,"h%d-eth0",i);
  puts(temp);
 }
 for(i=1;i<=x/2;i++)
 {
  sprintf(temp,"s1-eth%d",i);
  puts(temp);
 }
 //return dev;
}

void *HostInterface_name(char *name,int x)
{
 int i;
 if(strcmp(name,"s1")==0)
 {
  for(i=1;i<=x/2;i++)
  {
   sprintf(temp,"s1-eth%d",i);
   puts(temp);
  }
 }
}

void Print_Pkt_Dtl(BUFFER *QBuf)
{
 struct pcap_pkthdr hdr;
 int offset = 26;
 if (hdr.caplen < 30)
 {
  fprintf(stderr,"Error: not enough captured packet data present to extract IP addresses.\n");
  return;
 }
 printf("Packet received from source address %d.%d.%d.%d\n",(QBuf->data)[offset],(QBuf->data)[offset+1],
                                                            (QBuf->data)[offset+2],(QBuf->data)[offset+3]);
 if(hdr.caplen >= 34)
 {
  printf("and destined for %d.%d.%d.%d\n",(QBuf->data)[offset+4],(QBuf->data)[offset+5],
                                          (QBuf->data)[offset+6],(QBuf->data)[offset+7]);
  printf("\n");
 }
}

void main(int argc, char *argv[])
{
 int filter_mode=0;

 int sd,fdmast;
 struct sockaddr_un hostaddr;
 struct sockaddr_un exthostaddr;
 char buf[BUFLEN];
 int bytes,tick;
 fd_set master;
 fd_set rd_mast;

 int ec,ecmd,ext_ret,num;
 struct timeval time_out;

 int i,sel_ret,l;
 char errbuf[PCAP_ERRBUF_SIZE];
 // n=atoi(argv[1]);
 // printf("%d",n);

 char *infname[10];
 struct ifaddrs *ifaddr,*ifa;
 int family,n=0,j=0;
 if (getifaddrs(&ifaddr)== -1)
 {
  perror("getifaddrs");
 }
 ifa=ifaddr;
 // ifa=ifa->ifa_next;
 for(ifa=ifa->ifa_next;ifa!=NULL;ifa=ifa->ifa_next)
 {
  if(ifa->ifa_addr==NULL)
  continue;
  family=ifa->ifa_addr->sa_family;
  if(family==AF_PACKET)
  {
   //  printf("%s \n",ifa->ifa_name);
   // ifa=ifa->ifa_next;
   infname[j]=ifa->ifa_name;
   n=n+1;
   j=j+1;
  }
 }
 // freeifaddrs(ifaddr);
 printf("Number of Interface %d \n",n);
 for(i=0;i<n;i++)
 {
  printf("%s \n",infname[i]);
 }

 sd=socket(AF_UNIX,SOCK_DGRAM,0);
 if(sd<0)
 {
  perror("\n socket() Failed\n");
 }

 memset(&hostaddr,0,sizeof(hostaddr));
 hostaddr.sun_family=AF_UNIX;
 strcpy(hostaddr.sun_path,HOST_PATH);

 unlink(HOST_PATH);
 bind(sd,(struct sockaddr *)&hostaddr,SUN_LEN(&hostaddr));

 char dev[n];
 int fd[n];
 pcap_t *handlers[n];
 const u_char *packet[n];
 struct pcap_pkthdr hdr;
 struct ether_header *eptr;
 struct ether_header *eptr1;
 u_char *ptr;

 TAILQ_HEAD(tailhead,buffer) head[n];                                   //Each buffer need heads, i.e.,N heads
 struct tailhead *headp;
 BUFFER *QBuf[n];                                                //There must be N no. of Queues

 for(i=0;i<n;i++)
 {
  TAILQ_INIT(&head[i]);                                     //Initialize N head
  //  sprintf(dev,"simhost-eth%d",i);
  //  puts(dev);
  // strcpy(dev,Interface_name(i));
  //puts(dev);
  handlers[i]=pcap_open_live(infname[i],BUFSIZ,1,-1,errbuf);
  if(handlers[i]==NULL)
  {
   fprintf(stderr,"Couldn't Open Device %s : %s\n",infname[i],errbuf);
  }
  fd[i]=pcap_get_selectable_fd(handlers[i]);  //Obtaining file descriptors of pcap_handlers         
 }

 fd_set rdset;
 fd_set extset;

label:
 while(1)
 {
  printf("\n");
  memset(buf,0,sizeof(buf));
  FD_ZERO(&rdset);
  FD_ZERO(&master);
  int max_fd=0;
  for(i=0;i<n;i++)
  {
   FD_SET(fd[i],&rdset);
   max_fd=(max_fd>fd[i]?max_fd:fd[i]);
  }
  FD_SET(sd,&master);

  sel_ret=select(sd+1,&master,NULL,NULL,NULL);
  printf ("select returned = %d\n",sel_ret);
  if(sel_ret==-1)
  {
   printf("ret=%d,errno=%d\n",sel_ret,errno);
   exit(1);
  }
  if(FD_ISSET(sd,&master))
  {
   bytes=recvfrom(sd,buf,sizeof(buf),0,(struct sockaddr *)0,(int *)0);
   //tick=atoi(buf);
   printf("Tick or Command received is %s \n",buf);
   filter_mode=0;
   if(strcmp(buf,"p")==0)
   {
    AllInterface_name(n);
   }
   else if(strcmp(buf,"s1")==0)
   {
    HostInterface_name(buf,n);
   }
   else if(strcmp(buf,"")==0)
   {
    goto label;
   }
   /* for(i=1;i<=n/2;i++)
   {
    sprintf(dev1,"h%d",i);
    if(strcmp(buf,dev1)==0)
      {
       filter_mode=1;
       break;
      }
   }*/

   sel_ret=select(max_fd+1,&rdset,NULL,NULL,NULL);
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
   for(i=0;i<n;i++)
   {
    if(FD_ISSET(fd[i],&rdset))
    {
     if(filter_mode==1)
     {
      if((packet[i]=pcap_next(handlers[i],&hdr))!=NULL)
      {
       l=hdr.len;
       pcap_sendpacket(( (i%2) ? handlers[i-1] : handlers[i+1]),packet[i],l);
      }
      // continue;
     }
     QBuf[i]=malloc(sizeof(QBuf[i]));
     // QBuf[i]=malloc(sizeof(struct buffer));
     if((packet[i]=pcap_next(handlers[i],&hdr))!=NULL)
     {
      QBuf[i]->data=packet[i];
      /*if(i%2==0)
      {
       printf("h%d-eth0 packet received \n",((i/2)+1));
      }
      else
      {
       printf("switch forwared the packet \n");
      }*/
      //  printf("%s Received the Packet ",infname[i]);

      TAILQ_INSERT_TAIL(&head[i],QBuf[i],entries);
      QBuf[i]=QBuf[i]->entries.tqe_next;
      //     printf("Ethernet address length is %d\n",ETHER_HDR_LEN);
      eptr= (struct ether_header *) packet[i];
      if(ntohs (eptr->ether_type) == ETHERTYPE_IP)
      {
       printf("\nEthernet type hex:%x dec:%d is an IP packet",
       ntohs(eptr->ether_type),
       ntohs(eptr->ether_type));
      }
      else  if(ntohs (eptr->ether_type) == ETHERTYPE_ARP)
      {
       printf("\nEthernet type hex:%x dec:%d is an ARP packet",
       ntohs(eptr->ether_type),
       ntohs(eptr->ether_type));
      }
      for(QBuf[i]=head[i].tqh_first;QBuf[i]!=NULL;QBuf[i]=QBuf[i]->entries.tqe_next)
      //    TAILQ_FOREACH(QBuf[i],&head[i],entries)
      {
       l=hdr.len;
       //   printf("%s",QBuf[i]->data);
       pcap_sendpacket(( (i%2) ? handlers[i-1] : handlers[i+1] ),QBuf[i]->data,l);
       /*if(i%2==0)
       {
        printf("h%d-eth0 sent the packet\n ", ((i/2)+1));
       }
       else
       {
        printf("Switch forwared the packet \n");
       }*/
       //  printf("%s Sent the packet\n ",infname[i]);
       if((i%2) ? printf(" %s Sent the Packet to %s",infname[i],infname[i-1]) : printf(" %s Sent the Packet to %s",infname[i],infname[i+1]));
       eptr1= (struct ether_header *) QBuf[i]->data;
       if( (ntohs (eptr1->ether_type) == ETHERTYPE_IP) && (strcmp(buf,"pd")==0))
       {
        Print_Pkt_Dtl(QBuf[i]);
       }
       while (head[i].tqh_first != NULL)
       {
        TAILQ_REMOVE(&head[i], head[i].tqh_first, entries);
       }
      }
     }
    }
   }
  }
  filter_mode=0;
 }
 close(sd);
 freeifaddrs(ifaddr);
 return;
}
