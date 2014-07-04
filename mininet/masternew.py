import socket,os,signal
import sys
import time
from time import sleep
import threading
import Queue

n=int(sys.argv[1])
#print n
s=[]
HN=[]
l=4
debug_mode=1
filt_mode=0
none=0
Thread=[]

def handler(signal,frame):
    global Thread
    print "CTRL-C exiting..."
    os.remove('/home/mininet/master')

    sys.exit(0)


def send_tick_to_spec_host(sm,s,i):
    print("***Sending Tick to h%s****"%i)
    sm.sendto(str(l),("/home/mininet/simhost"))
       
#    time.sleep(1)
   
    s.sendto(str(l),("/h%s"%i))

def send_tick_to_simhost(sm):
    print("***Sending Tick to Simhost***")
    sm.sendto(str(l),("/home/mininet/simhost"))
  

def send_tick_to_all(s,sm):
    print("***Sending Tick****")
    sm.sendto(str(l),("/home/mininet/simhost"))

    for i in range(0,n-1):
        s[i].sendto(str(l),("/h%s"%(i+2))) 



def send(in_q):
          
         for i in range(0,n-1):
             s.append(socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM))
         

         sm=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)
         global filt_mode
         global debug_mode
         global none
         global j
         while(1):

         
            if debug_mode:
               data=in_q.get()
               if data== 's':
                  if filt_mode:
                     if none:
                        send_tick_to_simhost(sm)
                     else:
                        send_tick_to_spec_host(sm,s[j-2],j)
                  else:
                     send_tick_to_all(s,sm)
               
               elif data=='h':
                  pass
                   
       
            elif filt_mode:
                  if none:
                     send_tick_to_simhost(sm)
                  else:
                     send_tick_to_spec_host(sm,s[j-2],j)
                  time.sleep(1)

            else:
                send_tick_to_all(s,sm)     
                time.sleep(1)
           

         sm.close()
         for i in range(0,n-2):
             s[i].close() 
         os.remove('/home/mininet/master')
    



def receive(out_q):

    if os.path.exists("/home/mininet/master"):
       os.remove("/home/mininet/master")
    sr=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)
    sr.bind("/home/mininet/master")
    global debug_mode
    global filt_mode
    global none
    global j

    while(1):
      print "waitinggggggggggg"
#     k,addr=sr.recvfrom(1024)
      if debug_mode :
         k,addr=sr.recvfrom(1024)

         if k=='c':
               debug_mode=0
               sys.stdout.write(k)
               out_q.put(k)
               
         elif k=='s':
               sys.stdout.write(k)
               out_q.put(k)          
        

         elif k=='h':
       
              # out_q.put(k)
              pass
              
         elif k== 'all':
              filt_mode=0
              none=0

         else:
         
              filt_mode=1 
              if k=='none':
                  none=1
              else:    
                 sys.stdout.write(k)
                 j=int(k[1:])
                 #print j
                 out_q.put(j)
     


             
      else:
         k,addr=sr.recvfrom(1024)
         if k=='c':
              pass

         elif k=='s':
              pass
         

         elif k=='h':
              debug_mode=1
              out_q.put(k)
           
       

    sr.close()  


'''q=Queue.Queue()
    
t1=threading.Thread(target=receive,args=(q,))
t1.start()
t2=threading.Thread(target=send,args=(q,))
t2.start()'''
#t1.start()
#t2.start()


def main():
     q=Queue.Queue()
     global Thread
     t1=threading.Thread(target=receive,args=(q,))
     t2=threading.Thread(target=send,args=(q,))
     
     t1.daemon=True
     t1.start()
    
     t2.daemon=True
     t2.start()
    # t2.alive=True
     Thread.append(t1)
     Thread.append(t2)
     for t in Thread:
        while True:
          t.join(100000)
     print "exiting.."
     
if __name__ == '__main__':
     
   try:
     main()   
   except(KeyboardInterrupt,SystemExit):
     signal.signal(signal.SIGINT,handler)
   

