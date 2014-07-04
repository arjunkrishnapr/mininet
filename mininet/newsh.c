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
//#define BUFSIZE 65535

#define HOST_PATH "/home/mininet/simhost"
#define MASTPATH "/home/mininet/master"
//#define EXTERNAL_CPATH "/home/mininet/SHCommand"


char *infname[MAX_NUM];
char *host_intf[MAX_NUM];
char *temp,c[10];
int count[MAX_NUM];

//char temp[60];

void *AllInterface_name(int x);
void *HostInterface_name(char *,int x);

 typedef struct buffer
  {
  const u_char *data;
  TAILQ_ENTRY(buffer) entries;
  }BUFFER;

/*void *AllInterface_name(int x)
 {
// char temp[60]="";
  int i=0;
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
 }*/
   
unsigned short checksum(unsigned short *ptr, int len)
    {
    int sum = 0;
    unsigned short answer = 0;
    unsigned short *w = ptr;
    int nleft = len;
     
    while(nleft > 1){
    sum += *w++;
    nleft -= 2;
    }
     
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;
    return(answer);
    } 
             

 void Print_Pkt_Dtl(BUFFER *QBuf)
 {

  struct pcap_pkthdr hdr;

  int offset = 26;
         
   if (hdr.caplen < 30) 
             {
     
               fprintf(stderr,
                        "Error: not enough captured packet data present to extract IP addresses.\n");
                return;
             }


    printf("\nip-addr: src: %d.%d.%d.%d",
                (QBuf->data)[offset], (QBuf->data)[offset+1], (QBuf->data)[offset+2], (QBuf->data)[offset+3]);
          
    if (hdr.caplen >= 34)  
          {
                printf(", dst: %d.%d.%d.%d\n",(QBuf->data)[offset+4], (QBuf->data)[offset+5],
                        (QBuf->data)[offset+6],(QBuf->data)[offset+7]);

           printf("\n");
          }

  }

void main(int argc, char *argv[])
{
 int k;
 char *str;

 int sd,fdmast;
 struct sockaddr_un hostaddr;
 struct sockaddr_un mastaddr;
 char buf[BUFLEN],h;
 char newbuf[BUFLEN];
 int bp_mode=0;
 int bytes,tick=0;
 fd_set master;
 fd_set rd_mast;
 
  
 int ec,ecmd,ext_ret,num; 
 struct timeval time_out;

 int i,j,sel_ret,l;
 char errbuf[PCAP_ERRBUF_SIZE];
 int snaplen=65535;
// n=atoi(argv[1]);
// printf("%d",n);
 
// char *infname[MAX_NUM];
 struct ifaddrs *ifaddr,*ifa;
 int family,n=0;
 if (getifaddrs(&ifaddr)== -1)
   {
    perror("getifaddrs");
   }
  ifa=ifaddr;
 // ifa=ifa->ifa_next;
  for(ifa=ifa->ifa_next;ifa!=NULL;ifa=ifa->ifa_next)
   {
     if(ifa->ifa_addr==NULL)
      {
        printf("\nError No: =%d",errno);
        continue;
      }
    //  if(ifa->ifa_addr && ifa->ifa_addr->sa_family==AF_PACKET)

     family=ifa->ifa_addr->sa_family;
     if(family==AF_PACKET)
        {
       //  printf("%s \n",ifa->ifa_name);
       //  ifa=ifa->ifa_next;
       //  infname[j]=malloc(sizeof(*infname));
       //  infname[j]=ifa->ifa_name;
       //  sscanf(infname[j],"%[^-]-%[^-]-%[^-]-%s",sh,c,ht,inf);
       //  k=atoi(c);
       //  count[j]=k; 
           if(ifa->ifa_name == NULL)
            {
             printf("\nError No: =%d",errno);
             continue;
            }
       /*    str=ifa->ifa_name;
           sscanf(str,"%[^-]-%[^-]-%[^-]-%s",sh,c,ht,inf);  
           k=atoi(c);
           infname[k]=malloc(strlen(str)+1);
           infname[k]=str;
           count[k]=k;  */
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
         //j=j+1;

        }
   }

 //freeifaddrs(ifaddr);
 printf("Number of Interface %d \n",n);
 
 for(i=0;i<n;i++)
  {
   printf("%s \n",infname[i]);
   //printf("%d \n",count[i]);
   //printf("%s \n",host_intf[i]);
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

 char opt[10];
 char i_name[10],opt_name[10];
 char s_intf[15],d_intf[15];
 char *addr; 
 //int *p,*q,*r,*s,t,u;
 char bp[5],bp_iname[10],bp_opt1[15],bp_opt2[15],*bpaddr1,*bpaddr2; 
 bpaddr1=malloc(50);
 bpaddr2=malloc(50);

 pcap_t *handlers[n];
 const u_char *packet[n];
 struct pcap_pkthdr hdr;
 struct ether_header *eptr;
 u_char *ptr;
 
 struct ip * iph;
 unsigned short iphdrlen;


 TAILQ_HEAD(tailhead,buffer) head[n];       //Each buffer need heads, i.e.,N heads
 struct tailhead *headp;
 //BUFFER *QBuf[n];                           //There must be N no. of Queues
 BUFFER *tbuf;                           
 BUFFER *tempQBuf;

 for(i=0;i<n;i++)
 {
   TAILQ_INIT(&head[i]);                                     //Initialize N head 
 //  sprintf(dev,"simhost-eth%d",i);
 //  puts(dev);
  // strcpy(dev,Interface_name(i));
   //puts(dev);
   handlers[i]=pcap_open_live(infname[i],snaplen,1,-1,errbuf);
   if(handlers[i]==NULL)
    {
     fprintf(stderr,"Couldn't Open Device %s : %s\n",infname[i],errbuf);
    }
    fd[i]=pcap_get_selectable_fd(handlers[i]);  //Obtaining file descriptors of pcap_handlers      

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
     int mov_count=1;
     int max_fd=0;
     for(i=0;i<n;i++)
     {
       FD_SET(fd[i],&rdset);
       max_fd=(max_fd>fd[i]?max_fd:fd[i]);
     }
     FD_SET(sd,&master);

     sel_ret=select(sd+1,&master,NULL,NULL,NULL);
     // printf ("select returned = %d\n",sel_ret);
     if(sel_ret==-1)
     {
      printf("ret=%d,errno=%d\n",sel_ret,errno);
      exit(1);
     }
  
     if(FD_ISSET(sd,&master))
     {
        bytes=recvfrom(sd,buf,sizeof(buf),0,(struct sockaddr *)0,(int *)0);
        tick=tick+1;
        printf("Tick or Command received is %d \n",tick);
 

        if(strcmp(buf,"p")==0)
         {
          //AllInterface_name(n);
          for(i=0;i<n;i++)
           {
//           sscanf(infname[i],"%[^-]-%[^-]-%[^-]-%s",sh,c,ht,inf);
//           printf("%s-%s \n",ht,inf);
             printf("%s \n",host_intf[i]);
           }
         }

        else if(strcmp(buf,"")==0)
        {
         goto label;
 
        }
        // bpaddr=malloc(50);
         sscanf(buf,"%s %s %s %s %s %s",bp,bp_iname,bp_opt1,bpaddr1,bp_opt2,bpaddr2);
         if(strcmp(bp,"b")==0)
          {
              bp_mode=1;
              printf("\nBreak Point Enabled\n");

          }
//         printf("\n%s %s %s %s\n",bp,bp_iname,bp_opt,bpaddr);
         sel_ret=select(max_fd+1,&rdset,NULL,NULL,NULL);
         // printf ("select returned = %d\n",sel_ret);
         if(sel_ret==-1)
         {
           printf("ret=%d,errno=%d\n",sel_ret,errno);
           exit(1);
         }
         if(!sel_ret)
         {
          goto label;
         }
         label1:
         for(i=0;i<n;i++)
          {
            
            if(FD_ISSET(fd[i],&rdset))
              { 
               // QBuf[i]=malloc(sizeof(QBuf[i]));
                tbuf=malloc(sizeof(tbuf));
                
                // QBuf[i]=malloc(sizeof(struct buffer));
                if((packet[i]=pcap_next(handlers[i],&hdr))!=NULL)
                 {
//                   count[i]=count[i]+1;
//                   printf("\n%d interface's count value is %d \n ",i,count[i]);

                   tbuf->data=packet[i];

                   TAILQ_INSERT_TAIL(&head[i],tbuf,entries);
                   //    QBuf[i]=QBuf[i]->entries.tqe_next;
                   if((i%2) ? printf("\n%s ->  %s\n",host_intf[i],host_intf[i-1]) : printf("\n%s -> %s\n",host_intf[i],host_intf[i+1]));
                            

                 
                 }
    
                tbuf=TAILQ_FIRST(&head[i]);
                if(tbuf!=NULL)
                 {
                  eptr= (struct ether_header *) tbuf->data;
                  iph=(struct ip *) (tbuf->data + sizeof(struct ether_header));
                  iphdrlen=iph->ip_hl*4;
                  struct udphdr *udph = (struct udphdr*)(tbuf->data + iphdrlen  + sizeof(struct ether_header));

                  addr=malloc(50);
                  sscanf(buf,"%s %s %s %s",opt,i_name,opt_name,addr);
                  sscanf(buf,"%s %s %s",opt,s_intf,d_intf);

                  // printf("%s %s %s %s \n",opt,i_name,opt_name,addr);
                  if (strcmp(opt,"a")==0)
                   {

                    if(strcmp(host_intf[i],i_name)==0)
                     {
                       if(strcmp(opt_name,"src_mac")==0)
                          {
                              memcpy(eptr->ether_shost,ether_aton(addr),ETHER_ADDR_LEN);
                 //             printf("New mac-addr src : %s",ether_ntoa((struct ether_addr *)eptr->ether_shost));
                //              printf(", dst: %s",ether_ntoa((struct ether_addr*)eptr->ether_dhost));


                          }
                       else if(strcmp(opt_name,"dst_mac")==0)
                          {
                            
                             memcpy(eptr->ether_dhost,ether_aton(addr),ETHER_ADDR_LEN);
                  //           printf("mac-addr src : %s",ether_ntoa((struct ether_addr*)eptr->ether_shost));
                  //           printf("New mac-addr dst : %s",ether_ntoa((struct ether_addr *)eptr->ether_dhost));
                             printf("\n");
                          }

                       else if(strcmp(opt_name,"src_ip")==0)
                          {
                             
                             if (ntohs (eptr->ether_type) == ETHERTYPE_IP)
                               {
                        
                                udph->check=0;
                                inet_aton(addr,&(iph->ip_src));
                    //            printf("New ip-addr src : %s",inet_ntoa((struct in_addr)iph->ip_src));
                    //            printf(", dst : %s \n",inet_ntoa((struct in_addr)iph->ip_dst));

                                iph->ip_sum=0;
                                iph->ip_sum=(unsigned short)checksum((unsigned short *)iph, iph->ip_hl * 4);
                            
                      
                               }

                          }                   
                       else if(strcmp(opt_name,"dst_ip")==0)
                          {

                             if (ntohs (eptr->ether_type) == ETHERTYPE_IP)
                               {
                                udph->check=0;
                                inet_aton(addr,&(iph->ip_dst));
                      //          printf("\nip-addr: src: %s ",inet_ntoa((struct in_addr)iph->ip_src));
                      //          printf("New ip-addr dst : %s \n",inet_ntoa((struct in_addr)iph->ip_dst));
                                
                                iph->ip_sum=0;
                                iph->ip_sum=(unsigned short)checksum((unsigned short *)iph, iph->ip_hl * 4);

                               }

                          }

                       }
                     }

                   else if((strcmp(opt,"m")==0) && (strcmp(s_intf,host_intf[i])==0))
                    {
//                      sscanf(buf,"%s %s %s",opt,s_intf,d_intf);
                    //  printf("\n%s %s %s",opt,s_intf,d_intf);    
                      if(mov_count==1)
                          {
                           for(j=0;j<n;j++)
                            {
                             if(strcmp(d_intf,host_intf[j])==0)
                              {
                              tempQBuf=malloc(sizeof(tempQBuf));
                              memcpy(tempQBuf,tbuf,sizeof(tbuf));

                              TAILQ_INSERT_HEAD(&head[j],tempQBuf,entries);
                              TAILQ_REMOVE(&head[i],tbuf,entries);
                              free(tbuf);
                              printf("Packet Moved from %s to  %s\n",s_intf,d_intf);
                              mov_count=0;
                              break;
                              
                              }                               
                            }
                  
                           goto label1;          
                          }
                         
                      }  
                                   
    
            //       else
            //        {
                    
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

                     
              //       }
                
                if(bp_mode==1)
                {
          
                  if(strcmp(host_intf[i],bp_iname)==0)
                         {
                           if(strcmp(bp_opt1,"src_ip")==0)
                           {
                             if(strcmp((inet_ntoa((struct in_addr)iph->ip_src)),bpaddr1)==0)
                             {
                              
                                   mastaddr.sun_family=AF_UNIX;
                                   strcpy(mastaddr.sun_path,MASTPATH);
                                  
                                   if (sendto(sd,"h",sizeof(h), 0,(struct sockaddr *)&mastaddr, sizeof(struct sockaddr_un)) < 0) 
                                      {
                                         perror("sending datagram message");
 
                                      }
                                  
                                  bp_mode=0;
                                  printf("\n*******breakpoint hit the halt command************\n");

                             }
                           }
                           else if(strcmp(bp_opt1,"dst_ip")==0)
                           {
                              if(strcmp((inet_ntoa((struct in_addr)iph->ip_dst)),bpaddr1)==0)
                                 {
                                   mastaddr.sun_family=AF_UNIX;
                                   strcpy(mastaddr.sun_path,MASTPATH);

                                   if (sendto(sd,"h",sizeof(h), 0,(struct sockaddr *)&mastaddr, sizeof(struct sockaddr_un)) < 0)
                                      {
                                         perror("sending datagram message");

                                      }
                                    bp_mode=0;
                                    printf("\n*******breakpoint hit the halt command************\n");

                                 }
                           }
                           else if(strcmp(bp_opt1,"src_mac")==0)
                           {
                             if(strcmp(ether_ntoa((struct ether_addr*)eptr->ether_shost),bpaddr1)==0)
                                 {
                                   
                                   mastaddr.sun_family=AF_UNIX;
                                   strcpy(mastaddr.sun_path,MASTPATH);

                                   if (sendto(sd,"h",sizeof(h), 0,(struct sockaddr *)&mastaddr, sizeof(struct sockaddr_un)) < 0)
                                      {
                                         perror("sending datagram message");

                                      }
                                     bp_mode=0;
                                     printf("\n*******breakpoint hit the halt command************\n");

                                 }
                           }

                            else if(strcmp(bp_opt1,"dst_mac")==0)
                           {
                             if(strcmp(ether_ntoa((struct ether_addr*)eptr->ether_dhost),bpaddr1)==0)
                                 {
                                  
                                   mastaddr.sun_family=AF_UNIX;
                                   strcpy(mastaddr.sun_path,MASTPATH);

                                   if (sendto(sd,"h",sizeof(h), 0,(struct sockaddr *)&mastaddr, sizeof(struct sockaddr_un)) < 0)
                                      {
                                         perror("sending datagram message");

                                      }
                                    bp_mode=0;
                                    printf("\n*******breakpoint hit the halt command************\n");

                                 }
                           }
                 
                         }          
                
                }
                          
               
              
                l=hdr.caplen;
                pcap_sendpacket(( (i%2) ? handlers[i-1] : handlers[i+1] ),tbuf->data,l);

             
                if( (ntohs (eptr->ether_type) == ETHERTYPE_IP) && (strcmp(buf,"pd")==0))

                {  
       
                 Print_Pkt_Dtl(tbuf);
 
                }
                 
           
                
                TAILQ_REMOVE(&head[i],tbuf,entries);
                free(tbuf);  
                       
    
            }
  
      }
 
    } 
  
   }
 //   for(i=0;i<n;i++)
 //    printf("%d interface's count value is %d \n ",i,count[i]);
  }
 


 close(sd);  
 freeifaddrs(ifaddr);
 for(i=0;i<n;i++)
   {
    free(infname[i]);
    free(host_intf[i]);
   }

 return ;
}





