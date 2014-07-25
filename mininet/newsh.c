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
#include<netinet/ether.h>
#include<netinet/ip.h>
#include<netinet/udp.h>

#define MAX_NUM 1024
#define BUFLEN 32
#define HOST_PATH "/home/mininet/simhost"
#define MASTPATH "/home/mininet/master"


 char *infname[MAX_NUM];
 char *host_intf[MAX_NUM];
 char *temp,c[10];
 char h;
 int count[MAX_NUM];
 int sd;
 int bp_mode;

 unsigned short iphdrlen;
 u_char *ptr;
 char *addr;
 char *bpaddr1; 
 typedef struct buffer
 {
 const u_char *data;
 TAILQ_ENTRY(buffer) entries;
 }BUFFER;
 
 BUFFER *tbuf,*tbuf1,*tbuf2,*tempQBuf;
 struct ip * iph;
 struct ether_header *eptr;
 struct sockaddr_un mastaddr;
// sd=socket(AF_UNIX,SOCK_DGRAM,0);
// mastaddr.sun_family=AF_UNIX;
// strcpy(mastaddr.sun_path,MASTPATH);


 void Print_Pkt_Dtl(BUFFER *QBuf)
 {
  struct pcap_pkthdr hdr;
  int offset = 26;
  if (hdr.caplen < 30) 
  {
   fprintf(stderr,"Error: not enough captured packet data present to extract IP addresses.\n");
   return;
  }
  printf("\nip-addr: src: %d.%d.%d.%d",(QBuf->data)[offset], (QBuf->data)[offset+1], (QBuf->data)[offset+2], (QBuf->data)[offset+3]);
  
  if(hdr.caplen >= 34)  
  {
   printf(", dst: %d.%d.%d.%d\n",(QBuf->data)[offset+4], (QBuf->data)[offset+5],(QBuf->data)[offset+6],(QBuf->data)[offset+7]);
   printf("\n");
  }
 }

 unsigned short checksum(unsigned short *ptr, int len)
 {
  int sum = 0;
  unsigned short answer = 0;
  unsigned short *w = ptr;
  int nleft = len;
  while(nleft > 1)
  {
   sum += *w++;
   nleft -= 2;
  }
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  answer = ~sum;
  return(answer);
 }

int Print_Packet_Details(BUFFER *QBuf)
 {
   eptr= (struct ether_header *) QBuf->data;
   iph=(struct ip *) (QBuf->data + sizeof(struct ether_header));
  
   if (ntohs (eptr->ether_type) == ETHERTYPE_IP)
      {
          printf("proto: IP\n");

          printf("ip-addr: src: %s ",inet_ntoa((struct in_addr)iph->ip_src));
          printf(", dst: %s \n",inet_ntoa((struct in_addr)iph->ip_dst));

      }
   else  if (ntohs (eptr->ether_type) == ETHERTYPE_ARP)
      {
          printf("proto: ARP\n");

      }

   printf("mac-addr src : %s",ether_ntoa((struct ether_addr*)eptr->ether_shost));
   printf(", dst: %s",ether_ntoa((struct ether_addr*)eptr->ether_dhost));
   printf("\n");
  

  return 0;
 }

int Modify_packet_details(char opt_name[10],BUFFER *tbuf,char *addr)
 {
  eptr= (struct ether_header *) tbuf->data;
  iph=(struct ip *) (tbuf->data + sizeof(struct ether_header));
  iphdrlen = iph->ip_hl*4;
  struct udphdr *udph = (struct udphdr *)(tbuf->data+iphdrlen +  sizeof( struct ether_header));

  if(strcmp(opt_name,"src_mac")==0)
  {
   memcpy(eptr->ether_shost,ether_aton(addr),ETHER_ADDR_LEN);
   printf("New mac-addr src : %s",ether_ntoa((struct ether_addr *)eptr->ether_shost));
   printf(", dst: %s",ether_ntoa((struct ether_addr*)eptr->ether_dhost));
                        
  }
 
  else if(strcmp(opt_name,"dst_mac")==0)
  {
   memcpy(eptr->ether_dhost,ether_aton(addr),ETHER_ADDR_LEN);
   printf("mac-addr src : %s",ether_ntoa((struct ether_addr*)eptr->ether_shost));
   printf("New mac-addr dst : %s",ether_ntoa((struct ether_addr *)eptr->ether_dhost));
   printf("\n");
  }
 
  else if(strcmp(opt_name,"src_ip")==0)
  {
   if(ntohs (eptr->ether_type) == ETHERTYPE_IP)
   {
    udph->check=0;
    inet_aton(addr,&(iph->ip_src));
    iph->ip_sum=0;
    iph->ip_sum=(unsigned short)checksum((unsigned short *)iph, iph->ip_hl * 4);
    printf("New ip-addr src : %s",inet_ntoa((struct in_addr)iph->ip_src));
    printf(", dst : %s \n",inet_ntoa((struct in_addr)iph->ip_dst));
   }
 
  }
 
  else if(strcmp(opt_name,"dst_ip")==0)
  {
   if(ntohs (eptr->ether_type) == ETHERTYPE_IP)
   {
    udph->check=0;
    inet_aton(addr,&(iph->ip_dst));
    iph->ip_sum=0;
    iph->ip_sum=(unsigned short)checksum((unsigned short *)iph, iph->ip_hl * 4);
    printf("\nip-addr: src: %s ",inet_ntoa((struct in_addr)iph->ip_src));
    printf("New ip-addr dst : %s \n",inet_ntoa((struct in_addr)iph->ip_dst));
   }
  }
 return 0; 
 } 

 void Set_Break_Point(char bp_opt1[15],char *bpaddr1)
 {
  if(strcmp(bp_opt1,"src_ip")==0)
  {
   if(strcmp((inet_ntoa((struct in_addr)iph->ip_src)),bpaddr1)==0)
   {
    printf("\n*****breakpoint hit the halt command*******\n");
    mastaddr.sun_family=AF_UNIX;
    strcpy(mastaddr.sun_path,MASTPATH);
    if(sendto(sd,"h",sizeof(h), 0,(struct sockaddr *)&mastaddr, sizeof(struct sockaddr_un)) < 0)
    {
     perror("sending datagram message");
    }
   bp_mode=0;
   printf("\nBreakPoint is Disabled\n");
   }
  }

  else if(strcmp(bp_opt1,"dst_ip")==0)
  {
   if(strcmp((inet_ntoa((struct in_addr)iph->ip_dst)),bpaddr1)==0)
   {
    printf("\n*******breakpoint hit the halt command************\n");
    mastaddr.sun_family=AF_UNIX;
    strcpy(mastaddr.sun_path,MASTPATH);
    if (sendto(sd,"h",sizeof(h), 0,(struct sockaddr *)&mastaddr, sizeof(struct sockaddr_un)) < 0)
    {
     perror("sending datagram message");
    }
   bp_mode=0;
   printf("\nBreakPoint is Disabled\n");
   }
  }  

  else if(strcmp(bp_opt1,"src_mac")==0)
  {
   if(strcmp(ether_ntoa((struct ether_addr*)eptr->ether_shost),bpaddr1)==0)
   {
    printf("\n*******breakpoint hit the halt command************\n");
    mastaddr.sun_family=AF_UNIX;
    strcpy(mastaddr.sun_path,MASTPATH);

    if(sendto(sd,"h",sizeof(h), 0,(struct sockaddr *)&mastaddr, sizeof(struct sockaddr_un)) < 0)
    {
     perror("sending datagram message");
    }
   bp_mode=0;
   printf("\nBreakPoint is Disabled\n");
   }
  }

  else if(strcmp(bp_opt1,"dst_mac")==0)
  {
   if(strcmp(ether_ntoa((struct ether_addr*)eptr->ether_dhost),bpaddr1)==0)
   {
    printf("\n*******breakpoint hit the halt command************\n");
    mastaddr.sun_family=AF_UNIX;
    strcpy(mastaddr.sun_path,MASTPATH);
    if (sendto(sd,"h",sizeof(h), 0,(struct sockaddr *)&mastaddr, sizeof(struct sockaddr_un)) < 0)
    {
     perror("sending datagram message");
    }
   bp_mode=0;
   printf("\nBreakPoint is Disabled\n");
   }
  }
 }

                                                                                                    
  
 void main(int argc, char *argv[])
 {
 int k,bytes,tick=0,fdmast;
 int max_fd=0;
 int ec,ecmd,ext_ret,num,asign_mode=0,H_I;
 int mov_mode=0,mov_var;
 int i,sel_ret,l;
 int snaplen=65535;
 int family,j=0,n=0;
 char *str;
 char buf[BUFLEN];
 char opt[10];
 char i_name[10],opt_name[10];
 char s_intf[15],d_intf[15];
 char errbuf[PCAP_ERRBUF_SIZE];
 char bp[5],bp_iname[10],bp_opt1[15],spec_intf[10];
 struct ifaddrs *ifaddr,*ifa;
 struct sockaddr_un hostaddr;
 struct sockaddr_un exthostaddr;
 struct pcap_pkthdr hdr;
 fd_set master;
 fd_set rd_mast;
 bpaddr1=malloc(50);

   
 if(getifaddrs(&ifaddr)<0)   
 {
  perror("getifaddrs");
 }
  
 ifa=ifaddr;
 for(ifa=ifa->ifa_next;ifa!=NULL;ifa=ifa->ifa_next)
 {
  if(ifa->ifa_addr==NULL)
  continue;
  
 family=ifa->ifa_addr->sa_family;
 if(family==AF_PACKET)
 {
  if(ifa->ifa_name == "lo")
  {
   continue;
  }
    
  str=ifa->ifa_name;
  temp=malloc (strlen (str) + 1);
  sscanf(str,"sh%[^-]-%[^\n]",c,temp);
  k=atoi(c);
  infname[k]=malloc(strlen(str)+1);
  strcpy(infname[k],str);
  count[k]=k;
  host_intf[k]=malloc(strlen(str)+1);
  strcpy(host_intf[k],temp);
  n=n+1;
  free(temp);
 }
 }
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
 int count[n]; 
 pcap_t *handlers[n];
 const u_char *packet[n];

 TAILQ_HEAD(tailhead,buffer) head[n];       //Each buffer need heads, i.e.,N heads
 struct tailhead *headp;

 for(i=0;i<n;i++)
 {
   TAILQ_INIT(&head[i]);                                     
   handlers[i]=pcap_open_live(infname[i],snaplen,1,-1,errbuf);
   if(handlers[i]==NULL)
    {
     fprintf(stderr,"Couldn't Open Device %s : %s\n",infname[i],errbuf);
    }
    fd[i]=pcap_get_selectable_fd(handlers[i]);    
    count[i]=0;    
 }
  
 fd_set rdset;
 fd_set extset;
 
label:
while(1)
 {
  printf("\n");
  printf("-------------------------------------------------------------------------------\n");
  memset(buf,0,sizeof(buf));
  FD_ZERO(&rdset);
  FD_ZERO(&master);
  
  for(i=0;i<n;i++)
  {
   FD_SET(fd[i],&rdset);
   max_fd=(max_fd>fd[i]?max_fd:fd[i]);
  }
   FD_SET(sd,&master);

  sel_ret=select(sd+1,&master,NULL,NULL,NULL);
    
  if(sel_ret==-1)
  {
   printf("ret=%d,errno=%d\n",sel_ret,errno);
   exit(1);
  }
  
  if(FD_ISSET(sd,&master))
  {
      bytes=recvfrom(sd,buf,sizeof(buf),0,(struct sockaddr *)0,(int *)0);       
      int test = atoi(buf);
        if(test==4)
         {
          tick=tick+1;
         }
      printf("%d Tick is received\n",tick);
 
      if(strcmp(buf,"p")==0)
       {
         for(i=0;i<n;i++)
         {
         printf("%s \n",host_intf[i]);
         }
       }
      else if(strcmp(buf,"")==0)
       {
         goto label;
       }

      sel_ret=select(max_fd+1,&rdset,NULL,NULL,NULL);
 
      if(sel_ret==-1)
       {
         printf("ret=%d,errno=%d\n",sel_ret,errno);
         exit(1);
       }
      if(!sel_ret)
       {
         goto label;
       }
      
      if(test==4)
       {
         if(asign_mode==1)
              {
                 if((H_I%2) ? printf("\n%s ->  %s\n",host_intf[H_I],host_intf[H_I-1]) : printf("\n%s -> %s\n",host_intf[H_I],host_intf[H_I+1]));
               
                 Print_Packet_Details(tbuf1);

                 l=hdr.caplen;
                 pcap_sendpacket(( (H_I%2) ? handlers[H_I-1] : handlers[H_I+1] ),tbuf1->data,l);
                 asign_mode=0;
                   
                 for(i=0;i<n;i++)
                  {
                    if((H_I!=i) && (FD_ISSET(fd[i],&rdset)))
                     {
                         tbuf=malloc(sizeof(tbuf));
                         if((packet[i]=pcap_next(handlers[i],&hdr))!=NULL)
                         {
                          tbuf->data=packet[i];
                          TAILQ_INSERT_TAIL(&head[i],tbuf,entries);

                          if((i%2) ? printf("\n%s ->  %s\n",host_intf[i],host_intf[i-1]) : printf("\n%s -> %s\n",host_intf[i],host_intf[i+1]));

                         }

                         tbuf=TAILQ_FIRST(&head[i]);
                         if(tbuf!=NULL)
                         {
                          
                         Print_Packet_Details(tbuf);

                         l=hdr.caplen;
                         pcap_sendpacket(( (i%2) ? handlers[i-1] : handlers[i+1] ),tbuf->data,l);

                         TAILQ_REMOVE(&head[i],tbuf,entries);
                         free(tbuf);
                         }
                     }
                  }
              }
         else
         {
          for(i=0;i<n;i++)
           {
            if(mov_mode==1 && mov_var==i)
             {
              tbuf=TAILQ_FIRST(&head[i]);
              if(tbuf!=NULL)
                {

                        Print_Packet_Details(tbuf);

                        l=hdr.caplen;
                        pcap_sendpacket(( (i%2) ? handlers[i-1] : handlers[i+1] ),tbuf->data,l);

                        TAILQ_REMOVE(&head[i],tbuf,entries);
                        free(tbuf);


                        mov_mode=0;
                }
             }

            if(FD_ISSET(fd[i],&rdset))
             {
                tbuf=malloc(sizeof(tbuf));
                if((packet[i]=pcap_next(handlers[i],&hdr))!=NULL)
                 {
                   tbuf->data=packet[i];
                   TAILQ_INSERT_TAIL(&head[i],tbuf,entries);

                   if((i%2) ? printf("\n%s ->  %s\n",host_intf[i],host_intf[i-1]) : printf("\n%s -> %s\n",host_intf[i],host_intf[i+1]));

                 }

                tbuf=TAILQ_FIRST(&head[i]);
                if(tbuf!=NULL)
                 {

                  Print_Packet_Details(tbuf);


                  if((bp_mode==1) && strcmp(host_intf[i],bp_iname)==0)
                    {
                      printf("\n Checking for Break point Event..\n");
                      Set_Break_Point(bp_opt1,bpaddr1);
 
                    }


                  l=hdr.caplen;
                  pcap_sendpacket(( (i%2) ? handlers[i-1] : handlers[i+1] ),tbuf->data,l);

                  TAILQ_REMOVE(&head[i],tbuf,entries);
                  free(tbuf);
                }
             }
           }
         }
       }

      else
       {

                  addr=malloc(50);
                  sscanf(buf,"%[^ ]",opt);

                  if(strcmp(opt,"a")==0)
                   {
                    sscanf(buf,"%s %s %s %s",opt,i_name,opt_name,addr);

                    for(i=0;i<n;i++)
                     {
                      if(strcmp(host_intf[i],i_name)==0)
                      {
                       if(FD_ISSET(fd[i],&rdset))
                         {
                             tbuf1=malloc(sizeof(tbuf1));
                             if((packet[i]=pcap_next(handlers[i],&hdr))!=NULL)
                              {
                              H_I=i;
                              asign_mode=1;
                              tbuf1->data=packet[i];

                              TAILQ_INSERT_TAIL(&head[i],tbuf1,entries);
                              }
                              tbuf1=TAILQ_FIRST(&head[i]);
                              if(tbuf1!=NULL)
                              {
                                
                                     Modify_packet_details(opt_name,tbuf1,addr); 
         
                              }
                         }
                      }
                     }
                   }
                  else if(strcmp(opt,"m")==0)
                   {
                     sscanf(buf,"%s %s %s",opt,s_intf,d_intf);
                     for(i=0;i<n;i++)
                       {
                        if (strcmp(s_intf,host_intf[i])==0)
                         {
                          if(asign_mode==1)
                             {
                             tbuf1=TAILQ_FIRST(&head[i]);
                        
                              if(tbuf1!=NULL)
                              {
                                for(j=0;j<n;j++)
                                  {
                                   if(strcmp(d_intf,host_intf[j])==0)
                                    {

                                    mov_var=j;
                                    mov_mode=1;

                                    printf("\nmove after assign...%d..\n",mov_mode);

                                    tempQBuf=malloc(sizeof(tempQBuf));
                                    memcpy(tempQBuf,tbuf1,sizeof(tbuf1));

                                    TAILQ_INSERT_HEAD(&head[j],tempQBuf,entries);
                                    TAILQ_REMOVE(&head[i],tbuf1,entries);
                                    free(tbuf1);
                                    }
                                  }
                                  printf("\nmove sucess...\n");
                                  asign_mode=0;

                              }

                             }

                           else
                           {
                            if(FD_ISSET(fd[i],&rdset))
                             {
                             tbuf1=malloc(sizeof(tbuf1));
                             if((packet[i]=pcap_next(handlers[i],&hdr))!=NULL)
                              {
                                   tbuf1->data=packet[i];
                                   TAILQ_INSERT_TAIL(&head[i],tbuf1,entries);
                              }
                              tbuf1=TAILQ_FIRST(&head[i]);
                              if(tbuf1!=NULL)
                              {
                                 for(j=0;j<n;j++)
                                  {
                                   if(strcmp(d_intf,host_intf[j])==0)
                                    {
                                    mov_var=j;
                                    mov_mode=1;
                                    printf("\nmoved...%d..\n",mov_mode);

                                    tempQBuf=malloc(sizeof(tempQBuf));
                                    memcpy(tempQBuf,tbuf1,sizeof(tbuf1));

                                    TAILQ_INSERT_HEAD(&head[j],tempQBuf,entries);
                                    TAILQ_REMOVE(&head[i],tbuf1,entries);
                                    free(tbuf1);

                                     }
                                  }
                              }
                             }
                           }
                         }
                       }

                    }

                  else if(strcmp(opt,"b")==0)
                   {
                    sscanf(buf,"%s %s %s %s",bp,bp_iname,bp_opt1,bpaddr1);
                    bp_mode=1;
                    printf("\nBreak Point Enabled\n");

                   }
                 else if(strcmp(opt,"pd")==0)
                   {
                     sscanf(buf,"%s %s",bp,spec_intf);
                     printf("%s %s",bp,spec_intf);

                     for(i=0;i<n;i++)
                     {
                      if(strcmp(host_intf[i],spec_intf)==0)
                       {
                         tbuf2=malloc(sizeof(tbuf));

                         tbuf2=TAILQ_FIRST(&head[i]);
                         if(tbuf2!=NULL)
                         {
                         printf("\nSpecified Interface's Packet Details..\n");
                         Print_Packet_Details(tbuf2);
                         }
                         else
                          printf("\nNo Packets are Available in the Buffer\n");
                       }

                     }     
                            
                   }


       }

    }

  } 

  close(sd);  
  freeifaddrs(ifaddr);

  for(i=0;i<n;i++)
  {
   free(infname[i]);
   free(host_intf[i]);
  }

  return;
}




