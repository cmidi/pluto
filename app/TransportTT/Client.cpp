/*Client side definations*/

#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <pcap.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/poll.h>
#include <pthread.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <sys/poll.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <map>
#include <queue>
#include <sys/epoll.h>
#include <utility>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "Misc.h"
#include "Client.h"
#ifdef __cplusplus
#include <iostream>
#include <boost/bind.hpp>
#include <boost/thread.hpp>
#include <boost/asio.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <utility>
using namespace std;
#warning "**Compiling C++**"
#else
#warning "**Compiling C**"
#endif
static std::map<int, char *> echoFilenameMap;
static std::map<int,SSL *> sslInfoMap;
typedef std::map<int,pthread_mutex_t *> mutexHash;
mutexHash g_mutexHash;


BIO *bio_err=0;
extern "C"
{
     stats g_cStats = {0};

}

int berr_exit(const char *s)
{
    BIO_printf(bio_err,"%s\n",s);
    ERR_print_errors(bio_err);
    return 0;
}
/*Dummy Client Class*/

static unsigned char dh512_pc[] = {
    0xDA,0x58,0x3C,0x16,0xD9,0x85,0x22,0x89,0xD0,0xE4,0xAF,0x75,
    0x6F,0x4C,0xCA,0x92,0xDD,0x4B,0xE5,0x33,0xB8,0x04,0xFB,0x0F,
    0xED,0x94,0xEF,0x9C,0x8A,0x44,0x03,0xED,0x57,0x46,0x50,0xD3,
    0x69,0x99,0xDB,0x29,0xD7,0x76,0x27,0x6B,0xA2,0xD3,0xD4,0x12,
    0xE2,0x18,0xF4,0xDD,0x1E,0x08,0x4C,0xF6,0xD8,0x00,0x3E,0x7C,
    0x47,0x74,0xE8,0x33,
};

static unsigned char dh512_gc[]={
    0x02,
};
/*
 * Message queue for inter thread communication
*/

Client::Client(config *config)
{
    inputSettings = config;
    m_num = config->id;
    long int size;
    tBuf = NULL;
    tBuf = new char[(config->mBufLen)+sizeof(encapsHeader)];
    if(!tBuf)
    {
    	LOG("buffer could not be allocated",1);
        return;
    }
    rBuf = new char[((config->mBufLen)*2)+sizeof(encapsHeader)];
    if(!rBuf)
    {
    	LOG("buffer could not be allocated",2);
        return;
    }
    memset(tBuf,0,(config->mBufLen ));

    if ( inputSettings->flags & MASK_FILEINPUT)
    {
        fileInitialize (inputSettings->mFileName,inputSettings,&size);
        g_testFileSize=size;
        fileBuf = (char *)malloc(sizeof(char)*g_testFileSize);
        if(!fileBuf)
        {
        	printf("Could not allocate buffer %d",(int)g_testFileSize);
        	exit(1);
        }
        CompleteFileMemCopy(fileBuf,inputSettings,g_testFileSize);
    }
    else
    {
        memset(tBuf,2,(config->mBufLen));
    }

}


Client::~Client()
{
    int i,rc;

	if(tBuf)
    {
		delete[]  tBuf;
        tBuf = NULL;
    }
	if(rBuf)
	{
		delete[]  rBuf;
		rBuf = NULL;
	}
	if(fileBuf)
	{
	    free(fileBuf);
	    fileBuf = NULL;
	}
	for(i = 0;i < inputSettings->connections;i++)
	{
	    if ( inputSettings->mSockFd[i] != INVALID_SOCKET ) {
        /*Added a user defined parameter between each close*/
	    if(inputSettings->flags & MASK_CLOSE_WAIT)
	        sleep(10);
	    if(inputSettings->clientType == PROTOCOL_TLS ||
	    		inputSettings->clientType == PROTOCOL_TCP)
	        shutdown(inputSettings->mSockFd[i],1);
	    rc = close( inputSettings->mSockFd[i] );
        inputSettings->mSockFd[i] = INVALID_SOCKET;
	    }
	}

}
    

int Client::Connect()
{
    int rc;
    int family;
    clock_t start,end;
    start = clock();
    if((inputSettings->flags) & MASK_ISIPV6)
    {
    	family = AF_INET6;
    }
    else
    {
        family = AF_INET;
    }
    inputSettings->mSockFd[0] = socket( family, SOCK_STREAM, 0 );
    if(inputSettings->mSockFd[0] < 0)
    {
        LOG("Cannot create client socket",inputSettings->mSockFd[0]);
        return ERR_SOCK_CREATE;
    }
    /* client to an address if specified*/
    //set socket options to be reused
    int yes = 1;
    rc = setsockopt(inputSettings->mSockFd[0],SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(int));
    if(!in6_isAddrZero(&(inputSettings->clientAddr)))
    {
        if((inputSettings->flags) & MASK_CLIENT_ISV6)
        {
            rc = bind(inputSettings->mSockFd[0],(struct sockaddr *) &inputSettings->clientV6,
                		     sizeof(inputSettings->clientV6));
        }
        else
        {
            rc = bind(inputSettings->mSockFd[0],(struct sockaddr *) &inputSettings->clientV4,
                		     sizeof(sockaddr_in));

        }
    }
    /*TODO Set socket options*/
#ifdef DEBUG
        sockaddr_in test;
        socklen_t addrlen = sizeof(sockaddr_in);
        getsockname(inputSettings->mSockFd[0],(struct sockaddr *)&test,&addrlen);
        printf("port:%d\n",ntohs(test.sin_port));
        char ip[50];
        printf("ip:%s\n",inet_ntop(AF_INET,&test.sin_addr,ip,50));
#endif
    if((inputSettings->flags) & MASK_ISIPV6)
    {
        rc = connect(inputSettings->mSockFd[0],(struct sockaddr *) &inputSettings->peerV6,
            		     sizeof(inputSettings->peerV6));
    }
    else
    {
        rc = connect(inputSettings->mSockFd[0],(struct sockaddr *) &inputSettings->peerV4,
            		     sizeof(inputSettings->peerV4));
    }

    if(rc < 0)
    {
    	LOG("Cannot connect client socket",rc);
        return ERR_CONNECT_SERVER;
    }
    end = clock();
    return rc; 
}

/*
 * Routine to send data out default is TCP no reporting mechanism
 * ONLY FOR TESTING
*/

int Client::process(void)
{

   char* readAt = tBuf;
   u_int64_t currenLen,totLen;
   struct itimerval it;
   struct sigaction sa;
   clock_t start,end;
   int err;


   if ( inputSettings->flags & MASK_TIME_MODE )
   {
#ifdef DEBUG
	    LOG("time mode",1);
#endif
	    memset(&sa,0,sizeof(sa));
	    sigaction(SIGALRM,&sa,NULL);
	    memset (&it, 0, sizeof (it));
   	    it.it_value.tv_sec = (int) (inputSettings->time / 100.0);
   	    it.it_value.tv_usec = (int) 10000 * (inputSettings->time -
   	    it.it_value.tv_sec * 100.0);
   	    err = setitimer( ITIMER_REAL, &it, NULL );
   	    if ( err != 0 )
   	    {
   	        LOG("setitimer",2);
   	        exit(1);
   	    }
   }
   /*Enter start of report*/
   start = clock();
   do {

	       // Read the next data block from file to buffer
           if(inputSettings->flags & MASK_TIME_MODE)
        	   continue;

	       if(inputSettings->Extractor_file != NULL)
	       {
	           fileBlockCopyToBuffer(tBuf,inputSettings);
	       }
           else
           {
        	   LOG("Client::process : File not found",1);
        	   //break;
           }
           // perform write
           currenLen = write( inputSettings->mSockFd[0], readAt, inputSettings->mBufLen );
           if ( currenLen < 0 )
           {
               LOG("Client::process : Failure in write(process)",currenLen);
               break;
           }
 	       totLen += currenLen;
           /*Have to confirm if the amount is more than file size and for underflow*/
 	       if( inputSettings->mAmount >= currenLen ) /*underflow check*/
           {
        	   inputSettings->mAmount -= currenLen;
           }
 	       else
           {
        	   inputSettings->mAmount = 0;
           }

       } while ((checkTransferComplete(inputSettings)) || (inputSettings->flags & MASK_TIME_MODE));
    /*Enter end of report*/
    end = clock();

    return currenLen;
}

int TcpClient::Connect()
{
	int rc;
	int retVal;
	int family;
	int i;
    clock_t start,end;
    pmsgq tempFdQ = fdMessageQ;
    pfdInfo connInfo;
    start = clock();
	if((inputSettings->flags) & MASK_ISIPV6)
	{
	    family = AF_INET6;
	}
	else
	{
        family = AF_INET;
	}
	/*
	 * The Info structure holds the pointer index to the file buffer
	 * This index makes the reading from a file independent for each connection
	 * after a connection is created we put the info structure for that connection
	 * in a map
	 * */
    /*Where should this be freed ??*/
	connInfo = (pfdInfo)calloc(inputSettings->connections,sizeof(fdInfo));
	if(!connInfo)
	{
	    LOG("Could not allocate memory for connection Info structures",1);
	    return -1;
	}
	for(i=0;i<inputSettings->connections;i++)
	{
	    inputSettings->mSockFd[i] = socket( family, SOCK_STREAM, 0 );
	    if(inputSettings->mSockFd[i] < 0)
	    {
	        LOG("Cannot create client socket",i);
	        continue;
	    }


	    if((inputSettings->flags) & MASK_CLIENT_NODELAY)
	    {
            int no_delay = 1;
            /*provided option is set*/
            rc = setsockopt( inputSettings->mSockFd[i], IPPROTO_TCP, TCP_NODELAY,
                                  &no_delay,sizeof(int));
            LOG("Client sockets have no delay set",1);
	    }
	    if(!in6_isAddrZero(&(inputSettings->clientAddr)))
	    {
	        if((inputSettings->flags) & MASK_CLIENT_ISV6)
	        {
	            rc = bind(inputSettings->mSockFd[i],(struct sockaddr *) &inputSettings->clientV6,
	                		     sizeof(inputSettings->clientV6));
	        }
	        else
	        {
	            rc = bind(inputSettings->mSockFd[i],(struct sockaddr *) &inputSettings->clientV4,
	                		     sizeof(inputSettings->clientV4));
	        }
	    }
	    /*TODO Set socket options*/
	    if((inputSettings->flags) & MASK_ISIPV6)
	    {
	        rc = connect(inputSettings->mSockFd[i],(struct sockaddr *) &inputSettings->peerV6,
	    		             sizeof(inputSettings->peerV6));
	    }
	    else
	    {
	        rc = connect(inputSettings->mSockFd[i],(struct sockaddr *) &inputSettings->peerV4,
	    		             sizeof(inputSettings->peerV4));
	    }
	    if(rc < 0)
	    {

	    	inputSettings->tstats.tNumConnectionErrors++;
	    	LOG("Cannot connect client socket",i);
	    	LOG(strerror(errno),1);
	        retVal = -1;
	    	continue;
	    }
	    else
	    {
#ifdef DEBUG
            LOG("Pushing fd to the queue for read thread fd:",inputSettings->mSockFd[i]);
#endif
            fdInfoMap.insert(std::make_pair(inputSettings->mSockFd[i],connInfo)); /*Use indexed connInfo like connInfo[i]*/
            connInfo++;
            rc = fcntl(inputSettings->mSockFd[i], F_GETFL,0);
            rc |= O_NONBLOCK;
            rc = fcntl(inputSettings->mSockFd[i], F_SETFL,rc);
            if(inputSettings->flags & MASK_ECHO_TEST)
            {

                pthread_mutex_lock(&tempFdQ->msgqLock);
                tempFdQ->fdQueue.push(inputSettings->mSockFd[i]);
	    	    if(tempFdQ->signalPush == 0)
	    	    {
	    		    tempFdQ->signalPush = 1;
	    	    }
#ifdef DEBUG
                LOG("Pushed fd to the queue for read thread fd:",inputSettings->mSockFd[i]);
                LOG("Pushed by thread ID:",returnTcpNum());
#endif
	    	    pthread_mutex_unlock(&tempFdQ->msgqLock);
            }
	    }
	    inputSettings->tstats.tNumConnections++;
	    sleep(inputSettings->delay/100);

	}
	initFdInfo(fileBuf, file_head, file_tail);

	end = clock();
	READ_START_BROADCAST;
	connectTime = (double)(end-start)/CLOCKS_PER_SEC;
	pthread_mutex_lock(&statslock);
	g_cStats.tNumConnectionErrors += inputSettings->tstats.tNumConnectionErrors;
	g_cStats.tNumConnections += inputSettings->tstats.tNumConnections;
	if(connectTime)
	     g_cStats.tconnectionRate = (double)g_cStats.tNumConnections/connectTime;
	pthread_mutex_unlock(&statslock);
	return retVal;
}

int TcpClient::readPoll()
{
	int rc;
	pmsgq tempFdread = fdMessageQ;
    struct epoll_event event;
    struct epoll_event *events;
    char *filename;
    static bool checkEmpty=false;

    int i;
    int currentSize = 0;
    int newFd,fd;
    int efd;
    int timeout = inputSettings->timeout*1000;
    if(timeout == 0)
    {
    	timeout = 10*1000;
    }
    efd = epoll_create(1000);
    if(efd == -1)
    {
        LOG("Server::EPoll():create1 errno:",errno);
        LOG(strerror(errno),1);
        return -1;
    }
    events = (struct epoll_event*)calloc(MAX_SOCKET_FD,sizeof(events));
    if(!events)
    {
        LOG("Could not allocate events",1);
    	return -1;
    }
/*ONLY start after the first client thread has started*/

    READ_MUTEX_LOCK;
	READ_START_WAIT;
	READ_MUTEX_UNLOCK;
addToTable:
    for(;;)
    {

    	if(!tempFdread->fdQueue.empty())
    	{
    		checkEmpty=true;
    		pthread_mutex_lock(&tempFdread->msgqLock);
    		newFd = tempFdread->fdQueue.front();
            tempFdread->fdQueue.pop();
            pthread_mutex_unlock(&tempFdread->msgqLock);
            if(newFd > 0)
            {
                rc = fcntl(newFd, F_GETFL,0);
                rc |= O_NONBLOCK;
                rc = fcntl(newFd, F_SETFL,rc);

                if(rc < 0)
                {
                   LOG("blocking error",1);
                   return -1;
                }

            }
#ifdef DEBUG
            LOG("poped and received FD:",newFd);
#endif
            event.data.fd = newFd;
            event.events = EPOLLIN | EPOLLET;

            fd = epoll_ctl(efd,EPOLL_CTL_ADD,newFd,&event);
#ifdef DEBUG
            LOG("FD in epoll table:",event.data.fd);
#endif
            filename = (char *)malloc(FILENAME_SIZE);
            if(!filename)
            {
            	LOG("Could not allocate buffer",1);
            	return -1;
            }
            if((inputSettings->flags) & MASK_PEERB_ISV6)
            {
            	snprintf(filename,20,"EchoTest%d",event.data.fd);

            }
            else
            {
                sockaddr_in echoFileName;
                socklen_t addrlen = sizeof(sockaddr_in);
                getsockname(event.data.fd,(struct sockaddr *)&echoFileName,&addrlen);
            	snprintf(filename,20,"EchoTest%d",ntohs(echoFileName.sin_port));

            }
            if(filename)
            {
            	echoFilenameMap.insert(std::make_pair(newFd,filename));
            }

    	}
    	else
    	{

    		pthread_mutex_lock(&tempFdread->msgqLock);
    		tempFdread->signalPush = 0;
    		pthread_mutex_unlock(&tempFdread->msgqLock);
    		break;
    	}

    }
    do{

    	if((!checkEmpty)||tempFdread->signalPush == 1)
    	{
#ifdef DEBUG
    		LOG("Getting push request again",tempFdread->signalPush);
#endif
    		pthread_mutex_lock(&tempFdread->msgqLock);
    		tempFdread->signalPush = 0;
    		pthread_mutex_unlock(&tempFdread->msgqLock);
    		goto addToTable;
    	}

    	currentSize = epoll_wait(efd,events,MAX_SOCKET_FD,timeout);
    	if(currentSize <= 0)
    	{
#ifdef DEBUG
    		LOG("Server::EPoll: epoll_wait()",1);
#endif
        	if((!checkEmpty)||tempFdread->signalPush == 1)
        	{
#ifdef DEBUG
        		LOG("Getting push request again",tempFdread->signalPush);
#endif
        		pthread_mutex_lock(&tempFdread->msgqLock);
        		tempFdread->signalPush = 0;
        		pthread_mutex_unlock(&tempFdread->msgqLock);
        		goto addToTable;
        	}
        	else
                break;
    	}
    	for(i = 0; i < currentSize;i++)
        {
            if((events[i].events == 0 )||(events[i].events != POLLIN))
            {
#ifdef DEBUG

                LOG("revent is:",events[i].events);
#endif
            	continue;
            }
#ifdef DEBUG
            LOG("FD is:",events[i].data.fd);

#endif
                rc = readProcess(events[i].data.fd);
            	if(rc < 0)
                {
#ifdef DEBUG
                     LOG("Close FD:",events[i].data.fd);
                     LOG("ALL data or error received on FD",events[i].data.fd);
#endif
                     epoll_ctl(efd,EPOLL_CTL_DEL,events[i].data.fd,NULL);

                }
        }

    }while(1);
    pthread_mutex_lock(&statslock);
    g_cStats.tTotalDataReceived = inputSettings->tstats.tTotalDataReceived;
    g_cStats.tDataReceived = inputSettings->tstats.tDataReceived;
    pthread_mutex_unlock(&statslock);
    return rc;
}

int TcpClient::readProcess(int fd)
{
    int rc;
    int currLen = 0;
    std::map<int, char *>::iterator iechoFilenameMap;
    iechoFilenameMap = echoFilenameMap.find(fd);
    do
    {
        currLen = read( fd, rBuf,
        		      (inputSettings->mBufLen));


        if(currLen <= 0)
        {
        	if((errno != EWOULDBLOCK)||(errno != EAGAIN))
            {
                LOG("Error in(not EWOULDBLOACK)receive on:",fd);
                LOG(strerror(errno),errno);
                LOG("Len returned:",currLen);
            	rc = -1;
                return rc;
            }
#ifdef DEBUG
        	LOG(strerror(errno),1);
#endif
        	rc = 0;
            break;
        }
        if(likely(iechoFilenameMap != echoFilenameMap.end()) )
        {

        	getTestFile(iechoFilenameMap->second,rBuf,currLen, g_testFileSize);
        }
        inputSettings->tstats.tTotalDataReceived += currLen;
        inputSettings->tstats.tDataReceived++;
    }while(1);

    if(currLen == 0)
    	rc = -1;
    return rc;
}

int TcpClient::process(void)
{
   unsigned  int i;
   unsigned long packetId=0;
   struct timeval packetTime;
   clock_t start,end;
   //srand(time(NULL));
   long int currenLen=0;
   unsigned long int totLen=0;
   unsigned long int totrLen=0;
   unsigned int avg;
   struct itimerval it;
   int len[MAX_SOCKET_FD] = {0};
   struct sigaction sa;
   //sockaddr_in echoFileName;
  // socklen_t addrlen = sizeof(sockaddr_in);
   int readBytes;
   int err;
#ifdef DEBUG
	unsigned short int packetThreadId = (unsigned short)returnTcpNum();
	LOG("Thread ID: ",packetThreadId);
#endif
   if ( inputSettings->flags & MASK_TIME_MODE )
   {

	    memset(&sa,0,sizeof(sa));
	    sa.sa_handler = &toolAlarmWrapup;
	    sigaction(SIGALRM,&sa,NULL);
	    memset (&it, 0, sizeof (it));
   	    it.it_value.tv_sec = (int) (inputSettings->time / 100.0);
   	    it.it_value.tv_usec = (int) 10000 * (inputSettings->time -
   	    it.it_value.tv_sec * 100.0);
   	    err = setitimer( ITIMER_REAL, &it, NULL );
   	    if ( err != 0 )
   	    {
   	        LOG("setitimer",2);
   	        exit(1);
   	    }
   }
   memset(&packetTime,0,sizeof(timeval));
   /*Enter start of report*/
   start = clock();
   do {

	       //int randoomDelay = rand() % 10 + 1; // should randomize the time delay for packet from 1 to 5 secs
	       if(inputSettings->flags & MASK_TIME_MODE)
	           continue;
	       // Read the next data block from file to buffer
           gettimeofday(&packetTime,NULL);
           if(inputSettings->Extractor_file != NULL)
	       {

        	   //readBytes = fileBlockCopyToBuffer(readAt,inputSettings);

	       }
           else
           {
        	   LOG("Client::process : File not found",1);
        	   LOG("Using Default",1);
        	   //break;
           }
           // perform write
           packetId++;

	       for(i=0;i<(unsigned int)inputSettings->connections;i++)
	       {
	    	   ifdInfoMap = fdInfoMap.find(inputSettings->mSockFd[i]);
	    	   len[i] = 0;

	    	   if(likely(ifdInfoMap != fdInfoMap.end()))
	    	   {
	    		   readBytes = ReadDataFileBuffer(ifdInfoMap->second, &tBuf,inputSettings->mBufLen);

				   if(readBytes)
				   {

					   len[i] = write( inputSettings->mSockFd[i], tBuf, readBytes);

				   }
				   if (len[i] < 0)
				   {

					   if(unlikely((errno != EWOULDBLOCK)||(errno != EAGAIN)))
					   {
						   LOG(strerror(errno),errno);
						   break;
					   }
					   else
					   {
	#ifdef DEBUG
						   LOG(strerror(errno),errno);
	#endif
						   ifdInfoMap->second->connStats.errorEagain++;
						   continue;
					   }
				   }
	#if 0 //AUB: Put it at the end
			   else {
			   ifdInfoMap->second->fileBufIndex += len[i];
			   if(ifdInfoMap->second->fileBufIndex >= (file_tail-1))
					   ifdInfoMap->second->fileBufIndex = file_tail;
			   }
	#endif
				   totLen += len[i];
				   inputSettings->tstats.tTotalDataTransfered = totLen;
				   avg = (unsigned int)totLen/inputSettings->connections;
				   inputSettings->tstats.tDataTransfered++;
				  ifdInfoMap->second->connStats.tTotalDataTransfered += len[i];
				  currenLen = totLen/(inputSettings->connections*packetId);
				  if(!(inputSettings->flags & MASK_ECHO_TEST))
				   {
	#ifdef DEBUG
					      int rlen[MAX_SOCKET_FD] = {0};
					      rlen[i] = read( inputSettings->mSockFd[i], rBuf, (inputSettings->mBufLen)*2);
						  if(rlen[i] > 0)
						  {
							  totrLen += rlen[i];

							  LOG("Read from the Echo server",rlen[i]);

						  }
	#endif
				   }
			   //AUB: This code moved from above..save some time by removing element from queue
				   ifdInfoMap->second->fileBufIndex += len[i];
				   if(ifdInfoMap->second->fileBufIndex >= (file_tail-1))
				   {
					  ifdInfoMap->second->fileBufIndex = file_tail;
					  fdInfoMap.erase(inputSettings->mSockFd[i]);
				   }
	           }
	        }
	        /*Have to confirm if the amount is more than file size and for underflow*/
	        if( inputSettings->mAmount >= (u_int64_t)currenLen ) /*underflow check*/
            {
    	        inputSettings->mAmount -= currenLen;
            }
	        else
            {
    	        inputSettings->mAmount = 0;
            }
	       //sleep(inputSettings->delay/100);
	       pthread_mutex_lock(&statslock);
	       g_cStats.tEDataTransferRate = ((double)totLen*(double)inputSettings->pThread);
	       pthread_mutex_unlock(&statslock);
   } while ((!fdInfoMap.empty())||(inputSettings->flags & MASK_TIME_MODE));
//  AUB: check for empty queue } while (checkIndTransferComplete(inputSettings)||(inputSettings->flags & MASK_TIME_MODE));
    /*Enter end of report*/
   end = clock();
   sendTime = (double)(end - start)/CLOCKS_PER_SEC;
   pthread_mutex_lock(&statslock);
   g_cStats.tDataTransfered += inputSettings->tstats.tDataTransfered;
   g_cStats.tAverageData = avg;
   g_cStats.tTotalDataTransfered += totLen;
   if(!(inputSettings->flags & MASK_ECHO_TEST))
   {
	   g_cStats.tTotalDataReceived += totrLen;
   }
   pthread_mutex_unlock(&statslock);

   return currenLen;
}


TLSClient::TLSClient(config *config):Client(config)
{

	m_tlsNumid = threadId;
	pthread_mutex_lock(&statslock);
	threadId++;
	pthread_mutex_unlock(&statslock);

	pthread_mutex_lock(&liblock);
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    pthread_mutex_unlock(&liblock);
    const char *ssl_method;
    bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
    if(inputSettings->clientType == PROTOCOL_TLS)
    	ssl_method = "TLSv1";
    else if(inputSettings->clientType == PROTOCOL_DTLS)
    	ssl_method = "DTLSv1";
    else
    	ssl_method = "TLSv1";
    if(!strcmp(ssl_method,"SSLv2"))
    {
        meth = SSLv2_method();
        LOG("SSLv2 compatible method selected",1);
    }
    else if(!strcmp(ssl_method,"SSLv3"))
    {
        meth = SSLv3_method();
        LOG("SSLv3 compatible method selected",1);
    }
    else if(!strcmp(ssl_method,"TLSv1"))
    {
        meth = TLSv1_method();
        LOG("TLSv1 compatible method selected",1);
    }
    else if(!strcmp(ssl_method,"DTLSv1"))
    {
    	meth = DTLSv1_method();
    }
    else
    {
        meth = SSLv23_method();
        LOG("SSL compatible method selected",1);
    }
    ctx = SSL_CTX_new(meth);
}

TLSClient::~TLSClient()
{
#ifdef DEBUG
    LOG("Deleted TLS Client",1);
#endif
    SSL_CTX_free(ctx);
}

int TLSClient::configure()
{

    char *keyfile = inputSettings->keyFile;
    char *ca_list = inputSettings->ca_list;
	/* Load our keys and certificates*/
    /* Load our keys and certificates*/
    if(!(SSL_CTX_use_certificate_chain_file(ctx,
      keyfile)))
    {
       LOG("Can't read certificate file",1);
       return -1;
    }
    if(!(SSL_CTX_use_PrivateKey_file(ctx,
      keyfile,SSL_FILETYPE_PEM)))
    {
       LOG("cannot read key file",1);
       return -1;
    }
    if((inputSettings->flags & MASK_CA_VERIFY))
    {
        if(!(SSL_CTX_load_verify_locations(ctx,
        		ca_list,0)))
        {
            LOG("Can't read CA list",1);
            return -1;
        }
    }
    if(inputSettings->ciphers)
    {
		DH *dh = NULL;
		if(strstr(inputSettings->ciphers, "DHE") != NULL)
        {

            dh = get_dh512(dh512_pc,dh512_gc);
            SSL_CTX_set_tmp_dh(ctx,dh);
        }
		printf("ciphers are %s",inputSettings->ciphers);
    	SSL_CTX_set_cipher_list(ctx,inputSettings->ciphers);
		if(!dh)
            DH_free(dh);
    }
    return 0;
}

int TLSClient::Connect()
{
	int rc;
	int rcval=0;
	int family;
	int i;
    clock_t start,end;
    pfdInfo connInfo;
    double connectTime;


	configure();
	if((inputSettings->flags) & MASK_ISIPV6)
	{
	    family = AF_INET6;
	}
	else
	{
        family = AF_INET;
	}
	start = clock();
	connInfo = (pfdInfo)calloc(inputSettings->connections,sizeof(fdInfo));
    if(!connInfo)
    {
        LOG("Could not allocate memory for connection Info structures",1);
	    return -1;
    }
	for(i=0;i<inputSettings->connections;i++)
	{
	    inputSettings->mSockFd[i] = socket( family, SOCK_STREAM, 0 );
	    if(inputSettings->mSockFd[i] < 0)
	    {
	        LOG("Cannot create client socket",i);
	        rcval = -1;
	        continue;
	    }
	    int yes = 1;
	    //int nodelay = 1;
	    rc = setsockopt(inputSettings->mSockFd[i],SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(int));
        //rc = setsockopt( inputSettings->mSockFd[i], IPPROTO_TCP, TCP_NODELAY,
                             // &nodelay,sizeof(int));
	    if(!in6_isAddrZero(&(inputSettings->clientAddr)))
	    {
	        if((inputSettings->flags) & MASK_CLIENT_ISV6)
	        {
	            rc = bind(inputSettings->mSockFd[i],(struct sockaddr *) &inputSettings->clientV6,
	                		     sizeof(inputSettings->clientV6));
	        }
	        else
	        {
	            rc = bind(inputSettings->mSockFd[i],(struct sockaddr *) &inputSettings->clientV4,
	                		     sizeof(inputSettings->clientV4));

	        }
	    }

	    /*TODO Set socket options*/
	    if((inputSettings->flags) & MASK_ISIPV6)
	    {
	        rc = connect(inputSettings->mSockFd[i],(struct sockaddr *) &inputSettings->peerV6,
	    		             sizeof(inputSettings->peerV6));
	    }
	    else
	    {
	        rc = connect(inputSettings->mSockFd[i],(struct sockaddr *) &inputSettings->peerV4,
	    		             sizeof(inputSettings->peerV4));
	    }
	    if(rc < 0)
	    {

	    	inputSettings->tstats.tNumConnectionErrors++;
	    	LOG("Cannot connect client socket",errno);
	    	LOG(strerror(errno),errno);
	    	rcval = -1;
	    	continue;
	    }
	    inputSettings->tstats.tNumConnections++;
	    //rc = fcntl(inputSettings->mSockFd[i], F_GETFL,0);
		//rc |= O_NONBLOCK;
		//rc = fcntl(inputSettings->mSockFd[i], F_SETFL,rc);

	    ssl[i] = SSL_new(ctx);
    	if(!ssl)
    	{
    	    LOG("could not allocate ssl struct",1);
    	    return -1;
    	}
        SSL_set_fd(ssl[i], inputSettings->mSockFd[i]);

        rc = SSL_connect(ssl[i]);
        if(rc < 0)
        {
        	int errorno = SSL_get_error(ssl[i],rc);

            LOG("Errno no client:",errorno);
		    if((errorno == SSL_ERROR_WANT_READ) || (errorno == SSL_ERROR_WANT_WRITE))
		    {
		    	LOG("Non blocking ssl error",inputSettings->mSockFd[i]);
		    	connInfo->sslPend = 0;


		    }
		    else
		    {
		    	char error[200];
				LOG(ERR_error_string(ERR_get_error(),error),SSL_get_error(ssl[i],rc));
				inputSettings->tstats.tNumConnectionErrors++;
                SSL_free(ssl[i]);
				rcval = -1;
				continue;

		    }
        }
        fdInfoMap.insert(std::make_pair(inputSettings->mSockFd[i],connInfo));
        if(connInfo->sslPend == 0)
        inputSettings->tstats.tNumSecureConnections++;
        connInfo++;
        usleep((inputSettings->delay)*1000);
	    //sleep(inputSettings->delay/100);

	}
	initFdInfo(fileBuf, file_head, file_tail);
	end = clock();
	connectTime = (double)(end-start)/CLOCKS_PER_SEC;
	pthread_mutex_lock(&statslock);
	g_cStats.tNumConnectionErrors += inputSettings->tstats.tNumConnectionErrors;
	g_cStats.tNumSecureConnections += inputSettings->tstats.tNumSecureConnections;
	g_cStats.tNumConnections += inputSettings->tstats.tNumConnections;
	if(connectTime)
		     g_cStats.tconnectionRate = (double)g_cStats.tNumConnections/connectTime;
	pthread_mutex_unlock(&statslock);
	return rcval;
}

int TLSClient::process()
{
    unsigned short int i;
    unsigned long packetId=0;

    struct timeval packetTime;
	//char* readAt = tBuf;
	int readBytes;
#ifdef DEBUG
	unsigned short int packetThreadId = (unsigned short)returnTlsNum();
	LOG("Thread ID: ",packetThreadId);
#endif
    u_int16_t currenLen=0;
    u_int64_t totLen=0;
    u_int64_t totrLen=0;
    u_int64_t avg;
    struct pollfd fds;

    int rc;
    srand(time(NULL));

    struct itimerval it;
    int len[MAX_SOCKET_FD] = {0};
    u_int16_t rlen[MAX_SOCKET_FD] = {0};
    int timeout = 0;
    struct sigaction sa;
    SSL_SESSION *session;
	int err;

       if(inputSettings->flags & MASK_CLIENT_RECONNECT)
       {
          /*if reconnect test then shutdown and connect with session id
           * compare ssl struct for testing*/
    	   for(i =0 ;i< inputSettings->connections;i++)
    	   {
    	       session=SSL_get1_session(ssl[i]);
    	       SSL_shutdown(ssl[i]);
    	       SSL_free(ssl[i]);
    	       close(inputSettings->mSockFd[i]);
    	       inputSettings->mSockFd[i] = INVALID_SOCKET;
    	   }
    	   sleep(0.5);
    	   /*Client Session resumption test*/
    	   rc = Connect();
           if(rc < 0)
           {
               LOG("Second Connect Error",1);
               return -1;
           }   /*compare here to confirm*/

       }
	   if ( inputSettings->flags & MASK_TIME_MODE )
	   {
		    LOG("time mode",1);
		    memset(&sa,0,sizeof(sa));
		    sa.sa_handler = &toolAlarmWrapup;
		    sigaction(SIGALRM,&sa,NULL);
		    memset (&it, 0, sizeof (it));
	   	    it.it_value.tv_sec = (int) (inputSettings->time / 100.0);
	   	    it.it_value.tv_usec = (int) 10000 * (inputSettings->time -
	   	    it.it_value.tv_sec * 100.0);
	   	    err = setitimer( ITIMER_REAL, &it, NULL );
	   	    if ( err != 0 )
	   	    {
	   	        LOG("setitimer",2);
	   	        exit(1);
	   	    }
	   }
	   /*Enter start of report*/

	   do {
		       //int randoomDelay = rand() % 5 + 1; // should randomize the time delay for packet from 1 to 5 secs
		       if((inputSettings->flags & MASK_TIME_MODE) && packetId != 0)
		   	       continue;
		       // Read the next data block from file to buff
	           gettimeofday(&packetTime,NULL);
		       if(inputSettings->Extractor_file != NULL)
		       {
		           //fileBlockCopyToBuffer(readAt,inputSettings);
		       }
	           else
	           {
	        	   LOG("Client::process : File not found",1);
	        	   LOG("Using Default",1);
	        	   //break;
	           }
	           // perform write
		       packetId++;
		       for(i=0;i<inputSettings->connections;i++)
		       {

		    	   fds.fd = inputSettings->mSockFd[i];
		    	   fds.events = POLLIN;
		    	   ifdInfoMap = fdInfoMap.find(inputSettings->mSockFd[i]);
                   len[i] = 0;
                   if(likely(ifdInfoMap != fdInfoMap.end()))
    	    	   {
                       readBytes = ReadDataFileBuffer(ifdInfoMap->second, &tBuf,inputSettings->mBufLen);
                       if(ifdInfoMap->second->sslPend == 1)
					   {
                    	   int timeout = 1;
                    	   sleep(timeout); // will use  DTLS1_get_timeout here somehow the name  DTLS1_get_timeout cannot be resolved right now
                       }
                       if(readBytes)
    				   {
                           len[i] = SSL_write( ssl[i], tBuf, readBytes );
    				   }
					   if ( len[i] <= 0 )
					   {
						   LOG("Client::process : Failure in write(process)",errno);
						   LOG("Len read",len[i]);
						   if (SSL_get_error(ssl[i],len[i]) ==
								   SSL_ERROR_WANT_READ || (SSL_get_error(ssl[i],len[i]) ==
										   SSL_ERROR_WANT_WRITE))
						   {
							   LOG("WANT WRITE ERROR continue",1);
							   continue;
						   }
						   else if(len[i] < 0)
						   {

							   LOG("ERROR in write not SSL_WANT_READ",1);
							   fdInfoMap.erase(inputSettings->mSockFd[i]);
							   continue;
						   }
						   else
							   continue;

					   }

					   totLen += len[i];
					   avg = totLen/inputSettings->connections;
					   inputSettings->tstats.tDataTransfered++;
					  currenLen = totLen/(inputSettings->connections*packetId);
					   ifdInfoMap->second->fileBufIndex += len[i];
					   if(ifdInfoMap->second->fileBufIndex >= (file_tail-1))
					   {
						  ifdInfoMap->second->fileBufIndex = file_tail;
						  fdInfoMap.erase(inputSettings->mSockFd[i]);
					   }
					   /*Hack to aviod too many TLS handshakes SD fails to handle this*/
					   if(packetId == 1)
						   usleep((inputSettings->delay)*1000); // minimum 1ms(.01) milliseconds
					   pthread_mutex_lock(&statslock);
					   g_cStats.tEDataTransferRate = ((double)totLen*(double)inputSettings->pThread);
					   pthread_mutex_unlock(&statslock);
					  int rc = poll(&fds,1,timeout);
					  if(rc < 0)
					  {
						  continue;
					  }
					  else
					  {
						  if((fds.revents == 0 )||(fds.revents != POLLIN))
						  {

							 continue;
						  }
						  rlen[i] = SSL_read( ssl[i], rBuf, (inputSettings->mBufLen));
						  if(rlen[i])
						  {
							  totrLen += rlen[i];
	#ifdef DEBUG
							  LOG("Read from the Echo server",rlen[i]);
	#endif
						  }
					  }
				   }
	            }
		        /*Have to confirm if the amount is more than file size and for underflow*/
		        if( inputSettings->mAmount >= currenLen ) /*underflow check*/
	            {
	    	        inputSettings->mAmount -= currenLen;
	            }
		        else
	            {
	    	        inputSettings->mAmount = 0;
	            }


	       } while ((!fdInfoMap.empty())/*while (checkTransferComplete(inputSettings)*/||
	    		   (inputSettings->flags & MASK_TIME_MODE));
	    /*Enter end of report*/
	   pthread_mutex_lock(&statslock);
	   g_cStats.tDataTransfered += inputSettings->tstats.tDataTransfered;
	   g_cStats.tAverageData = avg;
	   g_cStats.tTotalDataTransfered += totLen;
	   g_cStats.tTotalDataReceived += totrLen;
	   pthread_mutex_unlock(&statslock);

	   return currenLen;
}


DTLSClient::DTLSClient(config *config):TLSClient(config),t(g_io)
{

	m_dtlsNumid = config->id;
	pthread_mutex_init(&timerLock,NULL);
	pthread_mutex_lock(&liblock);
	SSL_CTX_set_options(ctx, SSL_OP_ALL);
	/* DTLS: partial reads end up discarding unread UDP bytes
	 * Setting read ahead solves this problem.
	 * from apps/s_client.c from OpenSSL source
	*/
	SSL_CTX_set_read_ahead(ctx, 1);
	pthread_mutex_unlock(&liblock);


}

void DTLSClient::cleanupConnectionState( SSL *ssl, int fd )
{
   int result = SSL_shutdown(ssl);
   if(!result)
       result = SSL_shutdown (ssl);
   //SSL_free(ssl) ;
   //sslInfoMap.erase(fd) ;
}

DTLSClient::~DTLSClient()
{
    LOG("Deleted DTLS Client",1);
    pthread_mutex_destroy(&timerLock);
    std::map<int,SSL *>::iterator isslInfoMap;
    /*
    for(isslInfoMap = sslInfoMap.begin(); isslInfoMap != sslInfoMap.end(); isslInfoMap++)
    {
        if(isslInfoMap->second)
        {
        	SSL_free(isslInfoMap->second);
        	//locks required around ssl map
        	sslInfoMap.erase(isslInfoMap->first);
        }
    }
    */
}
/*timer interrupt handler*/
void DTLSClient::timerHandler(const boost::system::error_code &e,boost::asio::deadline_timer* t, int* count)
{


	int rc;

	//FROM : LINUX DEVICE DRIVERS: ALWAYS GET THE LOCKS IN SAME ORDER AVOIDS DEADLOCKS
	pthread_mutex_lock(&timerLock);
	std::map<int,pfdInfo>::iterator ifd = fdInfoMap.find(*count);
    if((ifd !=fdInfoMap.end()) && (ifd->second))
    {
#ifdef DEBUG
    	LOG("Getting in ",ifd->second->Connid);
#endif
    	if( e == boost::asio::error::operation_aborted )
		{
		   LOG("Canceled timer",ifd->second->Connid);

		   if(ifd->second->Connid > 0)
		   {
			   rc = fcntl(ifd->second->Connid, F_GETFL,0);
			   rc |= O_NONBLOCK;
			   rc = fcntl(ifd->second->Connid, F_SETFL,rc);
		   }
		   pthread_mutex_unlock(&timerLock);
		   return;
		} //Do nothing if timer is canceled
		if( e ) {pthread_mutex_unlock(&timerLock);return;} //Do nothing in case of error
    	ifd->second->clientStats.errorEagain += 1;
    	if(ifd->second->clientStats.errorEagain >= 1)
    	{
    		LOG("Calling close and cancel timer",ifd->second->Connid);
    		//the context of this handler is the io_service thread

    		shutdown(ifd->second->Connid,2);
    		rc = close(ifd->second->Connid);
    		if(rc < 0)
    		{
    			if(errno == EINTR )
                	  TEMP_FAILURE_RETRY (close (ifd->second->Connid));
    		}


			memset(&ifd->second->clientStats,0,sizeof (stats));
			fdInfoMap.erase(*count);

			*count = INVALID_SOCKET;
    	}
	}
    pthread_mutex_unlock(&timerLock);
#ifdef DEBUG
    LOG("Socket closed after handshake not complete",*count);
#endif
    return;
}

void DTLSClient::timerHandler_old(const boost::system::error_code &e,boost::asio::deadline_timer* t, int* count)
{


	int rc;
	if( e == boost::asio::error::operation_aborted )
	{
       LOG("Canceled timer",*count);
   	   if(inputSettings->mSockFd[*count] > 0)
   	   {
           rc = fcntl(inputSettings->mSockFd[*count], F_GETFL,0);
   	       rc |= O_NONBLOCK;
   	       rc = fcntl(inputSettings->mSockFd[*count], F_SETFL,rc);
   	   }
   	   return;
	} //Do nothing if timer is canceled
	if( e ) return; //Do nothing in case of error


    SSL_set_shutdown(ssl[*count],SSL_RECEIVED_SHUTDOWN);
	SSL_clear(ssl[*count]);
	SSL_set_fd(ssl[*count], inputSettings->mSockFd[*count]);
	std::map<int,pfdInfo>::iterator ifd = fdInfoMap.find(inputSettings->mSockFd[*count]);
    if(ifd !=fdInfoMap.end() && (ifd->second))
    {

    	ifd->second->clientStats.errorEagain += 1;
    	if(ifd->second->clientStats.errorEagain == 6)
    	{
    		LOG("Calling close and cancel timer",inputSettings->mSockFd[*count]);
    		printf("thread id is 0x%08lx, socket is %d\n",(unsigned long)pthread_self(),inputSettings->mSockFd[*count]);
    		shutdown(inputSettings->mSockFd[*count],2);
    		rc = close(inputSettings->mSockFd[*count]);
    		if(rc < 0)
    		{
                LOG(strerror(errno),1);
    			if(errno == EINTR )
                	  TEMP_FAILURE_RETRY (close (inputSettings->mSockFd[*count]));
    		}

			LOG("Close successfull",inputSettings->mSockFd[*count]);
			fdInfoMap.erase(inputSettings->mSockFd[*count]);
			inputSettings->mSockFd[*count] = INVALID_SOCKET;

    		return;
    	}

        rc = fcntl(inputSettings->mSockFd[*count], F_GETFL,0);
    	rc |= O_NONBLOCK;
    	rc = fcntl(inputSettings->mSockFd[*count], F_SETFL,rc);
    	ifd->second->sslPend = 0;
    }
	rc = SSL_connect(ssl[*count]);
	if(rc < 0)
	{
		int errorno = SSL_get_error(ssl[*count],rc);
		LOG("Errno no client:",errorno);
		LOG("ON fd:",inputSettings->mSockFd[*count]);
		if((errorno == SSL_ERROR_WANT_READ) || (errorno == SSL_ERROR_WANT_WRITE))
		{
			t->expires_from_now(boost::posix_time::seconds(2));
			t->async_wait(boost::bind(&DTLSClient::timerHandler,this,
								boost::asio::placeholders::error, t, count));
		}
		else
		{

			shutdown(inputSettings->mSockFd[*count],2);
			rc = close(inputSettings->mSockFd[*count]);
			if(rc < 0)
			{
				LOG(strerror(errno),1);
				if(errno == EINTR )
					  TEMP_FAILURE_RETRY (close (inputSettings->mSockFd[*count]));
			}
			fdInfoMap.erase(inputSettings->mSockFd[*count]);
			inputSettings->mSockFd[*count] = INVALID_SOCKET;
		}


	}
	//close(inputSettings->mSockFd[*count]);
    //fdInfoMap.erase(inputSettings->mSockFd[*count]);

    LOG("Socket closed after handshake not complete",inputSettings->mSockFd[*count]);
    //t->cancel();

}
/*
 * DTLS class
*/



int DTLSClient::Connect()
{
	int rc;

	int rcval=0;
	int family;
	int i;
    clock_t start,end;
    pfdInfo connInfo;
    pmsgq tempFdQ = fdMessageQ;
    double connectTime;
    struct sigaction sa_timer;
    memset(&sa_timer,0,sizeof(sa_timer));
    fd_set readset;
    struct timeval timeleft;
	configure();
	if((inputSettings->flags) & MASK_ISIPV6)
	{
	    family = AF_INET6;
	}
	else
	{
        family = AF_INET;
	}
	start = clock();
	connInfo = (pfdInfo)calloc(inputSettings->connections,sizeof(fdInfo));


    if(!connInfo)
    {
        LOG("Could not allocate memory for connection Info structures",1);
	    return -1;
    }
	for(i=0;i<inputSettings->connections;i++)
	{
	    /* BEEJ's guide says:
	     * So the correct thing to do is to use AF_INET in your struct sockaddr_in and PF_INET in your call to socket().
	     * But practically speaking, you can use AF_INET everywhere.
	     * And, since that's what W. Richard Stevens does in his book, that's what I'll do here.
	    */

		inputSettings->mSockFd[i] = socket( family, SOCK_DGRAM, 0 );
	    if(inputSettings->mSockFd[i] < 0)
	    {
	        LOG("Cannot create client socket",i);
	        LOG(strerror(errno),errno);
	        LOG("Family:",family);
	        rcval = -1;
	        continue;
	    }
	    int yes = 1;

	    rc = setsockopt(inputSettings->mSockFd[i],SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(int));

	    if(!in6_isAddrZero(&(inputSettings->clientAddr)))
	    {
	        if((inputSettings->flags) & MASK_CLIENT_ISV6)
	        {
	            rc = bind(inputSettings->mSockFd[i],(struct sockaddr *) &inputSettings->clientV6,
	                		     sizeof(inputSettings->clientV6));
	        }
	        else
	        {
	            rc = bind(inputSettings->mSockFd[i],(struct sockaddr *) &inputSettings->clientV4,
	                		     sizeof(inputSettings->clientV4));

	        }
	    }

	    /*TODO Set socket options*/
	    if((inputSettings->flags) & MASK_ISIPV6)
	    {
	        rc = connect(inputSettings->mSockFd[i],(struct sockaddr *) &inputSettings->peerV6,
	    		             sizeof(inputSettings->peerV6));
	    }
	    else
	    {
	        rc = connect(inputSettings->mSockFd[i],(struct sockaddr *) &inputSettings->peerV4,
	    		             sizeof(inputSettings->peerV4));
	    }
	    if(rc < 0)
	    {

	    	inputSettings->tstats.tNumConnectionErrors++;
	    	LOG("Cannot connect client socket",errno);
	    	LOG(strerror(errno),errno);
	    	rcval = -1;
	    	continue;
	    }
	    //TODO fix
	    if(!(inputSettings->flags & MASK_CLOSE_WAIT))
	    {
	        rc = fcntl(inputSettings->mSockFd[i], F_GETFL,0);
		    rc |= O_NONBLOCK;
		    rc = fcntl(inputSettings->mSockFd[i], F_SETFL,rc);
		    if(rc < 0)
			{
			   LOG("blocking error",1);
			   return -1;
			}
	    }

	    inputSettings->tstats.tNumConnections++;
	    ssl[i] = SSL_new(ctx);
    	if(!ssl)
    	{
    	    LOG("could not allocate ssl struct",1);
    	    return -1;
    	}
        SSL_set_fd(ssl[i], inputSettings->mSockFd[i]);
        connInfo->state = state_created;
        connInfo->Connid = inputSettings->mSockFd[i];
        pthread_mutex_lock(&timerLock); //insert and delete should be atomic pthread_atomic functions
        std::pair<std::map<int,pfdInfo>::iterator,bool> itt;
        itt = fdInfoMap.insert(std::make_pair(inputSettings->mSockFd[i],connInfo));
        if(!itt.second)
           LOG("inserting failed:",itt.second);
        pthread_mutex_unlock(&timerLock);
connect:

        //t(g_io); //can cause a crash because of t getting out of scope

        if((inputSettings->flags & MASK_CLOSE_WAIT))
        {
        	LOG("Starting timer",inputSettings->mSockFd[i]);
            //okay a potential race condition here i i getting updated before cancel provide local var index here
        	t.expires_from_now(boost::posix_time::seconds(1));
        	//index = i;
        	t.async_wait(boost::bind(&DTLSClient::timerHandler,this,
        	        boost::asio::placeholders::error, &t, &inputSettings->mSockFd[i]));

        	//handlers as class members need the this pointer
        }

        rc = SSL_connect(ssl[i]);
#ifdef DEBUG
        LOG("returned SSL",inputSettings->mSockFd[i]);
#endif
        if(rc < 0)
        {
        	int errorno = SSL_get_error(ssl[i],rc);

            LOG("Errno no client:",errorno);
		    if((errorno == SSL_ERROR_WANT_READ) || (errorno == SSL_ERROR_WANT_WRITE))
		    {

				DTLSv1_get_timeout(ssl[i],&timeleft);
				struct timeval *ptimeout = &timeleft;

				FD_ZERO(&readset);
				FD_SET(inputSettings->mSockFd[i], &readset);

				int result = select(2, &readset, NULL, NULL, ptimeout);
				if ((SSL_version(ssl[i]) == DTLS1_VERSION) && DTLSv1_handle_timeout(ssl[i]) > 0)
				{
					LOG("TIMEOUT occured\n",0);
				}

		    	LOG("Non blocking ssl error",inputSettings->mSockFd[i]);
		    	connInfo->sslPend = 1;


		    }
		    else
		    {
		    	char error[200];
				LOG(ERR_error_string(ERR_get_error(),error),SSL_get_error(ssl[i],rc));
				inputSettings->tstats.tNumConnectionErrors++;
                SSL_free(ssl[i]);
				rcval = -1;

				continue;

		    }
        }


        connInfo->state = state_connected;
        connInfo->state = state_data_send;
        LOG("Total connections:",inputSettings->tstats.tNumConnections);
        LOG("Cancel timer",inputSettings->mSockFd[i]);
        t.cancel();

        if(connInfo->sslPend == 0)
            inputSettings->tstats.tNumSecureConnections++;

        pthread_mutex_lock(&tempFdQ->msgqLock);
        pthread_mutex_init(g_mutex_alloc,NULL);
        g_mutexHash.insert(std::make_pair(inputSettings->mSockFd[i],g_mutex_alloc));
        g_mutex_alloc++;
        sslInfoMap.insert(std::make_pair(inputSettings->mSockFd[i],ssl[i]));
        if((inputSettings->flags & MASK_ECHO_TEST) && connInfo->sslPend == 0)
        {

#ifdef DEBUG
#endif


            tempFdQ->fdQueue.push(inputSettings->mSockFd[i]);
    	    if(tempFdQ->signalPush == 0)
    	    {
    		    tempFdQ->signalPush = 1;
    	    }

        }
        pthread_mutex_unlock(&tempFdQ->msgqLock);
        connInfo++;
        usleep((inputSettings->delay)*1000);
	    //sleep(inputSettings->delay/100);

	}
	initFdInfo(fileBuf, file_head, file_tail);
	READ_START_BROADCAST;
	end = clock();
	connectTime = (double)(end-start)/CLOCKS_PER_SEC;
	pthread_mutex_lock(&statslock);
	g_cStats.tNumConnectionErrors += inputSettings->tstats.tNumConnectionErrors;
	g_cStats.tNumSecureConnections += inputSettings->tstats.tNumSecureConnections;
	g_cStats.tNumConnections += inputSettings->tstats.tNumConnections;
	if(connectTime)
		     g_cStats.tconnectionRate = (double)g_cStats.tNumConnections/connectTime;
	pthread_mutex_unlock(&statslock);
	inputSettings->tstats.tNumSecureConnections = 0;
	//complete work here

	return rcval;

}
int DTLSClient::process()
{
    unsigned short int i;
    unsigned long packetId=0;

    char *readBuf=NULL;
    encapsHeader *pHeader;
    pmsgq tempFdQ = fdMessageQ;
    int result;
	int readBytes;

    u_int16_t currenLen=0;
    u_int64_t totLen=0;
    u_int64_t avg;
    struct timeval timeleft;
    fd_set readset;
    int rc;
    int len[MAX_SOCKET_FD] = {0};
    mutexHash::iterator imutex;
    struct sigaction sa;

	int err;
	dtls_data_state STATE;


	struct timeval *timeout_s;

   do {

	       if(inputSettings->flags & MASK_TIME_MODE)
	   	       continue;
	       readBuf = tBuf+sizeof(encapsHeader);

	       pHeader = (encapsHeader *)tBuf;
	       char **pa = &readBuf;
		   packetId++;
		   for(i=0;i<inputSettings->connections;i++)
		   {
			   ifdInfoMap = fdInfoMap.find(inputSettings->mSockFd[i]);
			   len[i] = 0;
			   readBytes = 0;
			   if(likely(ifdInfoMap != fdInfoMap.end()) && (ifdInfoMap->second != NULL))
			   {
				   /*fill the buffer for the connection*/
				  // fprintf(fd,"readBuf is %p address : 0x%08x at loop : %d, fd :%lx Header size : %u\n",readBuf,&readBuf,i,m_dtlsNumid,
					//	    sizeof(encapsHeader));
				   STATE = (dtls_data_state)ifdInfoMap->second->state;
				   /*The DTLS data send state machine continues here*/
                   if(STATE == state_data_send)
                   {
					   pHeader->connectionId = htonl(inputSettings->mSockFd[i]);
					   pHeader->packetId = htonl(packetId);
					   pHeader->len = htons(sizeof(encapsHeader));
					   //fprintf(fd,"pHeader is %p len : %u at loop : %d, fd :%lu\n",pHeader,htons(pHeader->len),i,m_dtlsNumid);

					   readBytes = ReadDataFileBuffer(ifdInfoMap->second, &readBuf,inputSettings->mBufLen);
					   if(readBytes > 0)
					   {
						   /*calculate the digest and update the head*/

						   MD5((unsigned char*)readBuf,readBytes,pHeader->md5sum);
						   imutex = g_mutexHash.find(inputSettings->mSockFd[i]);
						   if(imutex != g_mutexHash.end() && (imutex->second))
						       pthread_mutex_lock(imutex->second);
						   len[i] = SSL_write( ssl[i], tBuf,  (readBytes+sizeof(encapsHeader)) );
						   if(imutex != g_mutexHash.end() && (imutex->second))
						       pthread_mutex_unlock(imutex->second);

					   }
					   if ( len[i] <= 0 )
					   {
						   LOG("Client::process : Failure in write(process)",errno);

						   char error[200];
						   LOG(ERR_error_string(ERR_get_error(),error),SSL_get_error(ssl[i],len[i]));
						   //call get error once
						   if (SSL_get_error(ssl[i],len[i]) ==
								   SSL_ERROR_WANT_READ || (SSL_get_error(ssl[i],len[i]) ==
										   SSL_ERROR_WANT_WRITE))
						   {

								 if(ifdInfoMap->second->sslPend == 1)
								 {
									DTLSv1_get_timeout(ssl[i],&timeleft);
									struct timeval *ptimeout = &timeleft;
									ptimeout->tv_sec = 3;
									FD_ZERO(&readset);
									FD_SET(inputSettings->mSockFd[i], &readset);
									int result = select(2, &readset, NULL, NULL, ptimeout);
									if ((SSL_version(ssl[i]) == DTLS1_VERSION) && DTLSv1_handle_timeout(ssl[i]) > 0)
									{
										LOG("TIMEOUT occured\n",2);
									}
									if(result <= 0)
									{
										ifdInfoMap->second->sslPend = 1;

									}
									continue;

						        }
							    else
							       continue;

						   }
						   else if(len[i] < 0)
						   {
							   LOG("ERROR in write not SSL_WANT_READ",1);
							   fdInfoMap.erase(inputSettings->mSockFd[i]);
							   continue;
						   }
						   else
							   continue;

					   }

					   if(ifdInfoMap->second->sslPend == 1)
					   {
						   ifdInfoMap->second->sslPend = 0;
						   inputSettings->tstats.tNumSecureConnections++;
						   if((inputSettings->flags & MASK_ECHO_TEST))
						   {

				   #ifdef DEBUG
							   LOG("Pushing to table after handshake complete",ifdInfoMap->second->sslPend);
				   #endif
							pthread_mutex_lock(&tempFdQ->msgqLock);

							tempFdQ->fdQueue.push(inputSettings->mSockFd[i]);
							if(tempFdQ->signalPush == 0)
							{
								tempFdQ->signalPush = 1;
							}
							pthread_mutex_unlock(&tempFdQ->msgqLock);
						   }
						   ifdInfoMap->second->sslPend = 0;

					   }
					   totLen += len[i];
					   //avg = totLen/inputSettings->connections;
					   avg = totLen/inputSettings->tstats.tNumConnections;
					   inputSettings->tstats.tDataTransfered++;
					  currenLen = totLen/(inputSettings->connections*packetId);
					   ifdInfoMap->second->fileBufIndex += len[i];
					   if(ifdInfoMap->second->fileBufIndex >= (file_tail-1))
					   {
						   ifdInfoMap->second->fileBufIndex = file_tail;
						   /*chage state to end*/
						   LOG("Wrote last data bytes",len[i]);
						   ifdInfoMap->second->state = state_end;
					   }

					   pthread_mutex_lock(&statslock);

						   g_cStats.tEDataTransferRate = ((double)totLen*(double)inputSettings->pThread);
						   pthread_mutex_unlock(&statslock);
						   //usleep((inputSettings->delay)*1000);

				   }
				   else if(STATE == state_end)
				   {
					   /*Send the last packet with end bit set*/
					   /*At this time we are sending retransmissions*/


					   pHeader->pdata.end = ENDP;
					   LOG("Sending End packet",1);
					   len[i] = SSL_write( ssl[i], tBuf,  sizeof(encapsHeader));
					   /*did not receive ACKEP*/
					   ifdInfoMap->second->state = state_close;
					   LOG("Wrote end packet bytes",len[i]);

				   }
				   else if(STATE == state_close)
				   {
					   LOG("Closing ",inputSettings->mSockFd[i]);
					   fdInfoMap.erase(inputSettings->mSockFd[i]);
					   /*received the ack or reached limit call ssl_shutdown*/
				   }
			   }
			}


	   } while ((!fdInfoMap.empty())||
    		   (inputSettings->flags & MASK_TIME_MODE));
	    /*Enter end of report*/

	   pthread_mutex_lock(&statslock);
	   g_cStats.tDataTransfered += inputSettings->tstats.tDataTransfered;
	   g_cStats.tNumSecureConnections += inputSettings->tstats.tNumSecureConnections;
	   g_cStats.tAverageData = avg;
	   g_cStats.tTotalDataTransfered += totLen;

	   pthread_mutex_unlock(&statslock);

	   return currenLen;
}

int swapMemCmp(void *cmpHost,void *cmpNet,size_t size)
{
   int rc,i;
   if(cmpHost && cmpNet)
   {
        uint8_t *host_byte = (uint8_t *)cmpHost;
        uint8_t *net_byte = (uint8_t *)cmpNet;
        char *writeBuf = (char *)malloc(sizeof(char)*33);
        memset(writeBuf,0,(sizeof(char)*33));
        char *writeBufCmp = (char *)malloc(sizeof(char)*33);
        memset(writeBufCmp,0,(sizeof(char)*33));
        for(i =0; i< 16; i++)
	    {

		    snprintf(&writeBuf[i*2],16*2,"%02x",(unsigned int)host_byte[i]);
		    snprintf(&writeBufCmp[i*2],16*2,"%02x",(unsigned int)net_byte[i]);

	    }
	    LOG(writeBuf,1);
	    LOG(writeBufCmp,1);
	    if(!memcmp(host_byte,net_byte,size))
	       return 0;
	    else
	    	return -1;
   }
   return -2;
}

int DTLSClient::readProcess(int fd)
{
	int currLen;
	int rc;

	encapsHeader *pHeader;
	mutexHash::iterator im;
	int compare=0;
	std::map<int, char *>::iterator iechoFilenameMap;
	std::map<int, SSL *>::iterator isslInfoMap;
	iechoFilenameMap = echoFilenameMap.find(fd);
	ifdInfoMap = fdInfoMap.find(fd);
	isslInfoMap = sslInfoMap.find(fd);
	im = g_mutexHash.find(fd);

    do
    {
    	if(likely(isslInfoMap != sslInfoMap.end()))
    	{

    		if(rBuf)
    		{
    			if(im != g_mutexHash.end() &&(im->second))
    				pthread_mutex_lock(im->second);
    			currLen = SSL_read( isslInfoMap->second, rBuf, (inputSettings->mBufLen)*2);
    			if(im != g_mutexHash.end() &&(im->second))
    			    pthread_mutex_unlock(im->second);
    		}
    		else
    			LOG("NULL rBuf",(inputSettings->mBufLen)*2);
    		if(currLen <= 0)
			{

				int errorno = SSL_get_error(isslInfoMap->second,currLen);

				if((errorno != SSL_ERROR_WANT_READ) ||
						(errorno != SSL_ERROR_WANT_WRITE))
				{

					LOG("Error in(not EWOULDBLOACK)receive on:",fd);
					LOG(strerror(errno),1);
					rc = -1;
					break;
				}
				rc = 0;
				break;
			}
			if(likely(iechoFilenameMap != echoFilenameMap.end()))
			{
				 inputSettings->tstats.tTotalDataReceived += currLen;
				 inputSettings->tstats.tDataReceived++;




				 if(inputSettings->flags & MASK_FILECREATE)
				 {
					 getTestFile(iechoFilenameMap->second,(rBuf+sizeof(encapsHeader))
							 ,(currLen-sizeof(encapsHeader)), g_testFileSize);
				 }
				 else
				 {
					 /*For DTLS if we are not creating files we get checksum per packet*/
					 if(ifdInfoMap != fdInfoMap.end() && (ifdInfoMap->second)) //sanity check for connInfo
					 {
						 LOG("Found the connection",ifdInfoMap->second->Connid);
						 ifdInfoMap->second->connStats.tTotalDataReceived += currLen;
						 pHeader = (encapsHeader *)rBuf;
						 if (pHeader->pdata.end == ENDP)
						 {
							 LOG("received End packet",1);
							 pHeader->pdata.end = ACKEP;
							 /*send ack packet*/
							 cleanupConnectionState( isslInfoMap->second,fd);
							 ifdInfoMap->second->state = state_end_server_read;
							 rc = -1;
							 break;
						 }

					     unsigned char* md5 = (unsigned char *)rBuf;
					     md5 += sizeof(encapsHeader);
					     MD5(md5,currLen-sizeof(encapsHeader),ifdInfoMap->second->connStats.md5sum);
					     /*caution : we have to understand how we read to x86 from the network */
					     compare = swapMemCmp(ifdInfoMap->second->connStats.md5sum,
				         pHeader->md5sum,MD5_DIGEST_SIZE);
					 }
				  if(compare)
				  {

					  g_md5MatchFail =1;
					  LOG("FAILED MD5SUM MATCH",fd);
					  print_buffer((uint8_t *)(rBuf+sizeof(encapsHeader)),currLen-sizeof(encapsHeader),__FILE__, __LINE__);
					  inputSettings->tstats.tcompareFail++;
				  }

				  else
				  {
					   inputSettings->tstats.tcomparePass++;
				  }

				 }
			}

        }


    }while(0);

    if(currLen == 0)
    {
    	rc = -1;
    	LOG("calling ssl_shutdown on ",fd);
    	cleanupConnectionState(isslInfoMap->second,fd);
    }
    return rc;
}

int DTLSClient::readPoll()
{
	int rc;
	pmsgq tempFdread = fdMessageQ;
    struct epoll_event event;
    struct epoll_event *events;
    char *filename;
    static bool checkEmpty=false;

    int i;
    int currentSize = 0;
    int newFd,fd;
    int efd;
    int timeout = 3*1000;

    efd = epoll_create(1000);
    pfdInfo connInfo = (pfdInfo)calloc(100000,sizeof(fdInfo));

    if(efd == -1)
    {
        LOG("Server::EPoll():create1 errno:",errno);
        LOG(strerror(errno),1);
        return -1;
    }
    events = (struct epoll_event*)calloc(MAX_SOCKET_FD,sizeof(events));
    if(!events)
    {
        LOG("Could not allocate events",1);
    	return -1;
    }
/*ONLY start after the first client thread has started*/

    READ_MUTEX_LOCK;
	READ_START_WAIT;
	READ_MUTEX_UNLOCK;
addToTable:
    for(;;)
    {

    	LOG("getting queue :",(tempFdread->fdQueue.empty()?0:1));
    	if(!tempFdread->fdQueue.empty())
    	{
    		checkEmpty=true;

    		pthread_mutex_lock(&tempFdread->msgqLock);
    		newFd = tempFdread->fdQueue.front();
            tempFdread->fdQueue.pop();
            pthread_mutex_unlock(&tempFdread->msgqLock);

#ifdef DEBUG
            LOG("poped and received FD:",newFd);
#endif
            event.data.fd = newFd;
            event.events = EPOLLIN ;

            fd = epoll_ctl(efd,EPOLL_CTL_ADD,newFd,&event);
#ifdef DEBUG
            LOG("FD in epoll table:",event.data.fd);
#endif
            filename = (char *)malloc(FILENAME_SIZE);
            if(!filename)
            {
            	LOG("Could not allocate buffer",1);
            	return -1;
            }
            if((inputSettings->flags) & MASK_PEERB_ISV6)
            {
            	snprintf(filename,20,"EchoTest%d",event.data.fd);

            }
            else
            {
                sockaddr_in echoFileName;
                socklen_t addrlen = sizeof(sockaddr_in);
                getsockname(event.data.fd,(struct sockaddr *)&echoFileName,&addrlen);
            	snprintf(filename,20,"EchoTest%d",ntohs(echoFileName.sin_port));

            }
            if(filename)
            {
            	connInfo->Connid = event.data.fd;
            	//potentially we can have a local thread copy of ssl here and free it from global table
            	echoFilenameMap.insert(std::make_pair(newFd,filename));
            	fdInfoMap.insert(std::make_pair(event.data.fd,connInfo));
            	connInfo++;
            }

    	}
    	else
    	{

    		LOG("empty queued fd",tempFdread->signalPush);
    		break;
    	}

    }
    static int serverTimeout = 0;
    do{

    	if((!checkEmpty)||tempFdread->signalPush == 1)
    	{
#ifdef DEBUG
    		LOG("Getting push request again",tempFdread->signalPush);
#endif
    		pthread_mutex_lock(&tempFdread->msgqLock);
    		tempFdread->signalPush = 0;
    		pthread_mutex_unlock(&tempFdread->msgqLock);
    		if(!tempFdread->fdQueue.empty())
    		    goto addToTable;
    	}

    	currentSize = epoll_wait(efd,events,MAX_SOCKET_FD,timeout);
    	if(currentSize <= 0)
    	{
    		serverTimeout++;
#ifdef DEBUG
    		LOG("Server::EPoll: epoll_wait()",currentSize);
#endif
        	if((!checkEmpty)||tempFdread->signalPush == 1
        			|| (!tempFdread->fdQueue.empty()))
        	{
#ifdef DEBUG
        		LOG("Getting push request again",tempFdread->signalPush);
#endif
        		pthread_mutex_lock(&tempFdread->msgqLock);
        		tempFdread->signalPush = 0;
        		pthread_mutex_unlock(&tempFdread->msgqLock);
        		goto addToTable;
        	}
        	else
        	{
                if(serverTimeout == 5)
                {
                	break;
                }
        	}
    	}
    	for(i = 0; i < currentSize;i++)
        {
            if((events[i].events == 0 )||(events[i].events != POLLIN))
            {
#ifdef DEBUG

                LOG("revent is:",events[i].events);
#endif
            	continue;
            }
#ifdef DEBUG
            LOG("FD is:",events[i].data.fd);

#endif

                rc = readProcess(events[i].data.fd);

            	if(rc < 0)
                {
#ifdef DEBUG
                     LOG("Close FD:",events[i].data.fd);
                     LOG("ALL data or error received on FD",events[i].data.fd);
#endif

                     epoll_ctl(efd,EPOLL_CTL_DEL,events[i].data.fd,NULL);

                }
        }

    }while(1);
    pthread_mutex_lock(&statslock);
    g_cStats.tTotalDataReceived = inputSettings->tstats.tTotalDataReceived;
    g_cStats.tDataReceived = inputSettings->tstats.tDataReceived;
    g_cStats.tcomparePass = inputSettings->tstats.tcomparePass;
    g_cStats.tcompareFail = inputSettings->tstats.tcompareFail;
    pthread_mutex_unlock(&statslock);
    return rc;
}


int UDPClient::Connect()
{
	int rc;
	int retVal;
	int family;
	int i;

    pmsgq tempFdQ = fdMessageQ;
    pfdInfo connInfo;

	if((inputSettings->flags) & MASK_ISIPV6)
	{
	    family = AF_INET6;
	}
	else
	{
        family = AF_INET;
	}
	connInfo = (pfdInfo)calloc(inputSettings->connections,sizeof(fdInfo));
	if(!connInfo)
	{
	    LOG("Could not allocate memory for connection Info structures",1);
	    return -1;
	}
	for(i=0;i<inputSettings->connections;i++)
	{
	    inputSettings->mSockFd[i] = socket( family, SOCK_DGRAM, 0 );
	    int yes = 1;
	    rc = setsockopt(inputSettings->mSockFd[i],SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(int));
	    if(inputSettings->mSockFd[i] < 0)
	    {
	        LOG("Cannot create client socket",i);
	        continue;
	    }

	    if(!in6_isAddrZero(&(inputSettings->clientAddr)))
	    {
	        if((inputSettings->flags) & MASK_CLIENT_ISV6)
	        {
	            rc = bind(inputSettings->mSockFd[i],(struct sockaddr *) &inputSettings->clientV6,
	                		     sizeof(inputSettings->clientV6));
	        }
	        else
	        {
	            rc = bind(inputSettings->mSockFd[i],(struct sockaddr *) &inputSettings->clientV4,
	                		     sizeof(inputSettings->clientV4));
	        }
	    }
	    if(rc < 0)
	    {

	    	inputSettings->tstats.tNumConnectionErrors++;
	    	LOG(strerror(errno),1);
	        retVal = -1;
	    	continue;
	    }
	    else
	    {
            fdInfoMap.insert(std::make_pair(inputSettings->mSockFd[i],connInfo)); /*Use indexed connInfo like connInfo[i]*/
            connInfo++;
            rc = fcntl(inputSettings->mSockFd[i], F_GETFL,0);
            rc |= O_NONBLOCK;
            rc = fcntl(inputSettings->mSockFd[i], F_SETFL,rc);
            if(inputSettings->flags & MASK_ECHO_TEST)
            {

                pthread_mutex_lock(&tempFdQ->msgqLock);
                tempFdQ->fdQueue.push(inputSettings->mSockFd[i]);
	    	    if(tempFdQ->signalPush == 0)
	    	    {
	    		    tempFdQ->signalPush = 1;
	    	    }
	    	    pthread_mutex_unlock(&tempFdQ->msgqLock);
            }
	    }
	    inputSettings->tstats.tNumConnections++;
	    sleep(inputSettings->delay/100);

	}
	//we might need to change the traffic type in the udp world
	initFdInfo(fileBuf, file_head, file_tail);


	READ_START_BROADCAST;

	pthread_mutex_lock(&statslock);
	g_cStats.tNumConnectionErrors += inputSettings->tstats.tNumConnectionErrors;
	g_cStats.tNumConnections += inputSettings->tstats.tNumConnections;

	pthread_mutex_unlock(&statslock);
	return retVal;
}


int UDPClient::readPoll()
{
	int rc;
	pmsgq tempFdread = fdMessageQ;
    struct epoll_event event;
    struct epoll_event *events;
    char *filename;
    static bool checkEmpty=false;

    int i;
    int currentSize = 0;
    int newFd,fd;
    int efd;
    int timeout = inputSettings->timeout*1000;
    if(timeout == 0)
    {
    	timeout = 10*1000;
    }
    efd = epoll_create(1000);
    if(efd == -1)
    {
        LOG("Server::EPoll():create1 errno:",errno);
        LOG(strerror(errno),1);
        return -1;
    }
    events = (struct epoll_event*)calloc(MAX_SOCKET_FD,sizeof(events));
    if(!events)
    {
        LOG("Could not allocate events",1);
    	return -1;
    }
/*ONLY start after the first client thread has started*/

    READ_MUTEX_LOCK;
	READ_START_WAIT;
	READ_MUTEX_UNLOCK;
addToTable:
    for(;;)
    {

    	if(!tempFdread->fdQueue.empty())
    	{
    		checkEmpty=true;
    		pthread_mutex_lock(&tempFdread->msgqLock);
    		newFd = tempFdread->fdQueue.front();
            tempFdread->fdQueue.pop();
            pthread_mutex_unlock(&tempFdread->msgqLock);
            if(newFd > 0)
            {
                rc = fcntl(newFd, F_GETFL,0);
                rc |= O_NONBLOCK;
                rc = fcntl(newFd, F_SETFL,rc);

                if(rc < 0)
                {
                   LOG("blocking error",1);
                   return -1;
                }

            }
#ifdef DEBUG
            LOG("poped and received FD:",newFd);
#endif
            event.data.fd = newFd;
            event.events = EPOLLIN | EPOLLET;

            fd = epoll_ctl(efd,EPOLL_CTL_ADD,newFd,&event);
#ifdef DEBUG
            LOG("FD in epoll table:",event.data.fd);
#endif
            filename = (char *)malloc(FILENAME_SIZE);
            if(!filename)
            {
            	LOG("Could not allocate buffer",1);
            	return -1;
            }
            if((inputSettings->flags) & MASK_PEERB_ISV6)
            {
            	snprintf(filename,20,"EchoTest%d",event.data.fd);

            }
            else
            {
                sockaddr_in echoFileName;
                socklen_t addrlen = sizeof(sockaddr_in);
                getsockname(event.data.fd,(struct sockaddr *)&echoFileName,&addrlen);
            	snprintf(filename,20,"EchoTest%d",ntohs(echoFileName.sin_port));

            }
            if(filename)
            {
            	echoFilenameMap.insert(std::make_pair(newFd,filename));
            }

    	}

    	else
    	{

    		pthread_mutex_lock(&tempFdread->msgqLock);
    		tempFdread->signalPush = 0;
    		pthread_mutex_unlock(&tempFdread->msgqLock);
    		break;
    	}

    }
    do{

    	if((!checkEmpty)||tempFdread->signalPush == 1)
    	{
#ifdef DEBUG
    		LOG("Getting push request again",tempFdread->signalPush);
#endif
    		pthread_mutex_lock(&tempFdread->msgqLock);
    		tempFdread->signalPush = 0;
    		pthread_mutex_unlock(&tempFdread->msgqLock);
    		goto addToTable;
    	}

    	currentSize = epoll_wait(efd,events,MAX_SOCKET_FD,timeout);
    	if(currentSize <= 0)
    	{
#ifdef DEBUG
    		LOG("Server::EPoll: epoll_wait()",1);
#endif
        	if((!checkEmpty)||tempFdread->signalPush == 1)
        	{
#ifdef DEBUG
        		LOG("Getting push request again",tempFdread->signalPush);
#endif
        		pthread_mutex_lock(&tempFdread->msgqLock);
        		tempFdread->signalPush = 0;
        		pthread_mutex_unlock(&tempFdread->msgqLock);
        		goto addToTable;
        	}
        	else
                break;
    	}
    	for(i = 0; i < currentSize;i++)
        {
            if((events[i].events == 0 )||(events[i].events != POLLIN))
            {
#ifdef DEBUG

                LOG("revent is:",events[i].events);
#endif
            	continue;
            }
#ifdef DEBUG
            LOG("FD is:",events[i].data.fd);

#endif
                rc = readProcess(events[i].data.fd);
            	if(rc < 0)
                {
#ifdef DEBUG
                     LOG("Close FD:",events[i].data.fd);
                     LOG("ALL data or error received on FD",events[i].data.fd);
#endif
                     epoll_ctl(efd,EPOLL_CTL_DEL,events[i].data.fd,NULL);

                }
        }

    }while(1);
    pthread_mutex_lock(&statslock);
    g_cStats.tTotalDataReceived = inputSettings->tstats.tTotalDataReceived;
    g_cStats.tDataReceived = inputSettings->tstats.tDataReceived;
    pthread_mutex_unlock(&statslock);
    return rc;

}

int UDPClient::readProcess(int fd)
{
    int rc;
    int currLen = 0;
    std::map<int, char *>::iterator iechoFilenameMap;
    iechoFilenameMap = echoFilenameMap.find(fd);
    encapsHeader *pHeader;
    unsigned int sockaddrLen = 0;
    int compare; // init it
    do
    {

        if(!((inputSettings->flags) & MASK_CLIENT_ISV6))
        {
        	// Based on reading of beej socket guide
        	// initialize fromlen to be the size of from or struct sockaddr
        	sockaddrLen = sizeof(inputSettings->peerV4);
        	currLen = recvfrom( fd, rBuf,
        		      (inputSettings->mBufLen)*2,0,(struct sockaddr *)&inputSettings->peerV4,
				         &sockaddrLen);
        }
        else
        {
        	sockaddrLen = sizeof(inputSettings->peerV6);
        	currLen = recvfrom( fd, rBuf,
        	        		      (inputSettings->mBufLen)*2,0,(struct sockaddr *)&inputSettings->peerV6,
        					         &sockaddrLen);
        }

        if(currLen <= 0)
        {
        	if((errno != EWOULDBLOCK)||(errno != EAGAIN))
            {
                LOG("Error in(not EWOULDBLOACK)receive on:",fd);
                LOG(strerror(errno),errno);
                LOG("Len returned:",currLen);
            	rc = -1;
                return rc;
            }
        	rc = 0;
            break;
        }
        if(likely(iechoFilenameMap != echoFilenameMap.end()) )
        {
        	inputSettings->tstats.tTotalDataReceived += currLen;
			inputSettings->tstats.tDataReceived++;


			 if(inputSettings->flags & MASK_FILECREATE)
			 {
				 getTestFile(iechoFilenameMap->second,(rBuf+sizeof(encapsHeader))
						 ,(currLen-sizeof(encapsHeader)), g_testFileSize);
			 }
			 else
			 {
				 /*For DTLS if we are not creating files we get checksum per packet*/
				 pHeader = (encapsHeader *)rBuf;

				 unsigned char* md5 = (unsigned char *)rBuf;
				 md5 += sizeof(encapsHeader);
			     MD5(md5,currLen-sizeof(encapsHeader),ifdInfoMap->second->connStats.md5sum);
			     /*caution : we have to understand how we read to x86 from the network */
			     compare = swapMemCmp(ifdInfoMap->second->connStats.md5sum,
		         pHeader->md5sum,MD5_DIGEST_SIZE);

				  if(compare)
				  {
					  g_md5MatchFail =1;
					  LOG("FAILED MD5SUM MATCH",fd);
				  }
#ifdef DEBUG
				  else
				  {
					   LOG("MATCH MD5 DATA",fd);
				  }
#endif
			 }
        }

    }while(0);

    if(currLen == 0)
    	rc = -1;
    return rc;
}


int UDPClient::process()
{

   unsigned  int i;
   unsigned long packetId=0;
   long int currenLen=0;
   unsigned long int totLen=0;
   unsigned long int totrLen=0;
   unsigned int avg;

   int len[MAX_SOCKET_FD] = {0};

   int readBytes;


   do {


	   char *readBuf = tBuf;
	   encapsHeader *pHeader = (encapsHeader *)tBuf;
	   printf("address of readBuf Before is %p\n",readBuf);
	   readBuf += sizeof(encapsHeader);
	   packetId++;
	   for(i=0;i<(unsigned int)inputSettings->connections;i++)
	   {
		   ifdInfoMap = fdInfoMap.find(inputSettings->mSockFd[i]);
		   len[i] = 0;

		   if(likely(ifdInfoMap != fdInfoMap.end()))
		   {


               //update the header fields
           	   pHeader->connectionId = htonl(inputSettings->mSockFd[i]);
			   pHeader->packetId = htonl(packetId);
			   //I am not sure right now if we need the struct to be packed attribute
			   pHeader->len = htons(sizeof(encapsHeader));
			   readBytes = ReadDataFileBuffer(ifdInfoMap->second, &readBuf,inputSettings->mBufLen);
			   /*calculate the digest and update the header*/

			   MD5((unsigned char*)readBuf,readBytes,pHeader->md5sum);
			   if(readBytes)
			   {

			        if((inputSettings->flags) & MASK_ISIPV6)
					{
			        	len[i] = sendto( inputSettings->mSockFd[i], tBuf, (readBytes+sizeof(encapsHeader)),0
			        			         ,(struct sockaddr *) &inputSettings->peerV6,
										 sizeof(inputSettings->peerV6));
					}
					else
					{
						len[i] = sendto( inputSettings->mSockFd[i], tBuf,  (readBytes+sizeof(encapsHeader)),0,
								         (struct sockaddr *) &inputSettings->peerV4,
								         sizeof(inputSettings->peerV4));

					}

			   }
			   if (len[i] < 0)
			   {

				   if(unlikely((errno != EWOULDBLOCK)||(errno != EAGAIN)))
				   {
					   LOG(strerror(errno),errno);
					   break;
				   }
				   else
				   {
#ifdef DEBUG
					   LOG(strerror(errno),errno);
#endif
					   ifdInfoMap->second->connStats.errorEagain++;
					   continue;
				   }
			   }
			   totLen += len[i];
			   inputSettings->tstats.tTotalDataTransfered = totLen;
			   avg = (unsigned int)totLen/inputSettings->connections;
			   inputSettings->tstats.tDataTransfered++;
			  ifdInfoMap->second->connStats.tTotalDataTransfered += len[i];
			  currenLen = totLen/(inputSettings->connections*packetId);
			  if(!(inputSettings->flags & MASK_ECHO_TEST))
			   {

			   }

			   ifdInfoMap->second->fileBufIndex += len[i];
			   if(ifdInfoMap->second->fileBufIndex >= (file_tail-1))
			   {
				  ifdInfoMap->second->fileBufIndex = file_tail;
				  fdInfoMap.erase(inputSettings->mSockFd[i]);
			   }
		   }
		}
		/*Have to confirm if the amount is more than file size and for underflow*/
		if( inputSettings->mAmount >= (u_int64_t)currenLen ) /*underflow check*/
		{
			inputSettings->mAmount -= currenLen;
		}
		else
		{
			inputSettings->mAmount = 0;
		}

	   pthread_mutex_lock(&statslock);
	   g_cStats.tEDataTransferRate = ((double)totLen*(double)inputSettings->pThread);
	   pthread_mutex_unlock(&statslock);
   } while ((!fdInfoMap.empty())||(inputSettings->flags & MASK_TIME_MODE));
   pthread_mutex_lock(&statslock);
   g_cStats.tDataTransfered += inputSettings->tstats.tDataTransfered;
   g_cStats.tAverageData = avg;
   g_cStats.tTotalDataTransfered += totLen;
   if(!(inputSettings->flags & MASK_ECHO_TEST))
   {
	   g_cStats.tTotalDataReceived += totrLen;
   }
   pthread_mutex_unlock(&statslock);

   return currenLen;

}
void *client_spawn( void *inputConfig ) {
	Client *theClient = NULL;
    config *inputSettings = (config *)inputConfig;
    int rc;
    //start up the client
    if(inputSettings->clientType == DEFAULT)
    {
        theClient = new Client( inputSettings );
    }
    else if(inputSettings->clientType == PROTOCOL_TCP)
    {
    	theClient = new TcpClient( inputSettings );
    }
    else if(inputSettings->clientType == PROTOCOL_TLS)
    {
    	theClient = new TLSClient( inputSettings );
    }
    else if(inputSettings->clientType == PROTOCOL_UDP)
    {
    	theClient = new UDPClient( inputSettings );
    }
    else if(inputSettings->clientType == PROTOCOL_DTLS)
    {
    	theClient = new DTLSClient( inputSettings );
    }
    if(theClient == NULL)
    {
    	LOG("New client could not be created",1);
    	//goto does not look good but it improves the flow here.
    	goto exit;
    }
    // Run the test
    g_clientThread = 1;
    rc = theClient->Connect();
    if(rc < 0)
    {
    	LOG("could not create all connections",1);
    	//goto exit;
    }
    rc = theClient->process();
    if(rc < 0)
    {
#ifdef DEBUG
       LOG("client_spawn : Problem in process",rc);
#endif

    }
    if(inputSettings->flags & MASK_ECHO_TEST)
    {
        READ_FINISH_MUTEX_LOCK;
        READ_THREAD_FIN_WAIT;
        READ_FINISH_MUTEX_UNLOCK;
    }
exit:
if(theClient != NULL)
{
	delete theClient;
    theClient = NULL;

    LOG("Deleted a Client Thread",1);


}
return 0;
}

void *client_read_spawn(void *inputConfig)
{
 /*
  * Spawn the read thread for the client
  * epoll the FDs coming into the table
  * process data on each FD save it to file
  * send message to main client threads to exit
  * */

	int rc;
	Client  *theClient = NULL;
	config *inputSettings = (config *)inputConfig;
	if(inputSettings->clientType == PROTOCOL_TCP)
	{

		TcpClient *theClient = NULL;
		theClient = new TcpClient( inputSettings );
	}
    else if(inputSettings->clientType == PROTOCOL_UDP)
    {
    	UDPClient *theClient = NULL;
    	theClient = new UDPClient( inputSettings );
    }
    else if(inputSettings->clientType == PROTOCOL_DTLS)
    {

    	theClient = new DTLSClient( inputSettings );
    }
    if(theClient == NULL)
    {
    	LOG("New client could not be created",1);
    	//goto does not look good but it improves the flow here.
    	return 0;
    }
	g_clientReadThread = 1;
	rc = theClient->readPoll();
    if(rc < 0)
    {
#ifdef DEBUG
    	LOG("client_spawn : Problem in process of read",rc);
#endif
    }
    READ_FINISH_MUTEX_LOCK;
    READ_THREAD_FIN_BROADCAST;
    READ_FINISH_MUTEX_UNLOCK;
    if(theClient != NULL)
    {
    	delete theClient;
        theClient = NULL;

        LOG("Deleted a Client Thread",1);
    }
    return 0;
}
/*
 * Copy the data from where the head for the
 * connection is pointing to the tempbuf
 * if the head is not at the tail
*/
int Client::ReadDataFileBuffer(pfdInfo fdInfo, char **tempBuf,int size)
{

	if(fdInfo && (fdInfo->fileBufIndex != file_tail)) /*fileTail is a fixed pointer to the end of buffer*/
	{
	    if(*tempBuf)
	    {
	    	if(fdInfo->fileBufIndex+ size < file_tail)
	    	    memcpy(*tempBuf,fdInfo->fileBufIndex,size);
	    	else
	    	{
	    		size  = file_tail-fdInfo->fileBufIndex-1;
	    		memcpy(*tempBuf,fdInfo->fileBufIndex,size);
	    		//fdInfo->fileBufIndex = file_tail;
	    	}
	    }
	    else
	    {
	    	LOG("tempBuf not allocated",fdInfo->Connid);
	    	size = 0;
	    }
	}
	else
	{
	    size = 0;
#ifdef DEBUG
	    if(fdInfo->fileBufIndex == file_tail)

		    LOG("Reached the end of file for connection",1);
#endif
	}

    return size;
}

int Client::initFdInfo(char *buf, uint8_t *&head, uint8_t *&tail)
{
    int rc=0;
    if(buf)
    {
        head = (uint8_t *)buf;
        tail = (uint8_t *)buf+g_testFileSize+1;

    	for(ifdInfoMap=fdInfoMap.begin();ifdInfoMap !=fdInfoMap.end();ifdInfoMap++)
        {
    		ifdInfoMap->second->fileBufIndex = head;
        }

        return rc;
    }

    LOG("No buffer allocated",1);
    return -1;
}

int Client::checkIndTransferComplete(config *inputSettings)
{
	unsigned int completeCount=0;
	for(ifdInfoMap=fdInfoMap.begin();ifdInfoMap !=fdInfoMap.end();ifdInfoMap++)
	{
	   if(ifdInfoMap->second->fileBufIndex >= file_tail)
	   {
		   completeCount++;
	   }
	}


    if(completeCount == inputSettings->tstats.tNumConnections)
    {
    	LOG("Server::checkIndTransferComplete:Transfer Complete",completeCount);
    	return 0;
    }
    return 1;
}

int checkTransferComplete(config *inputSettings)
{
	if(inputSettings->Extractor_file != NULL)
    {
          if((!feof(inputSettings->Extractor_file) )
        		  &&(inputSettings->mAmount >0)) //CX03 amount should only be greater than 0 rather than >=
          {
              return 1;
          }
    }
	else
	{
		if(inputSettings->mAmount >0)
			return 1;
	}
    return 0;
}
