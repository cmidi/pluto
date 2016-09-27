/*Server.cpp file
 * definitions for server class
 * changes there for centos5.5
 * */

#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include <iostream>
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
#include <sys/epoll.h>
#include <pthread.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <map>
#include <utility>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <boost/crc.hpp>
#include <iostream>
#include <sstream>
#include <fstream>
#include "Misc.h"
#include "Server.h"
#include "ServerAPI.h"

using namespace std;
int g_checkwritestop=0;
//Server *theServer = NULL;
extern "C"
{
    stats g_stats = {0};
    int g_stopReport = 0;
    long int g_filesize;
    static int coreCounter = 0;

    pthread_mutex_t socketAcceptMutex;
    pthread_mutex_t coreCounterMutex; 
}

void detailDisplayConnections(const char *filename, Server* theServer);
char *getPrintableMd5(unsigned char *md5raw);


std::map<int,encapsHeader *> packetHeaderMap;
std::map<int,encapsHeader *>::iterator ipacketHeaderMap;

//static std::map<int, char *> filenameMap;
//static std::map<int, char *>::iterator ifilenameMap;
//static std::map<int,pfdInfo> fdInfoMap;

//static pmsgq fdQ;

static int test_ctx_session_id = 2;

static unsigned char dh512_p[] = {
    0xDA,0x58,0x3C,0x16,0xD9,0x85,0x22,0x89,0xD0,0xE4,0xAF,0x75,
    0x6F,0x4C,0xCA,0x92,0xDD,0x4B,0xE5,0x33,0xB8,0x04,0xFB,0x0F,
    0xED,0x94,0xEF,0x9C,0x8A,0x44,0x03,0xED,0x57,0x46,0x50,0xD3,
    0x69,0x99,0xDB,0x29,0xD7,0x76,0x27,0x6B,0xA2,0xD3,0xD4,0x12,
    0xE2,0x18,0xF4,0xDD,0x1E,0x08,0x4C,0xF6,0xD8,0x00,0x3E,0x7C,
    0x47,0x74,0xE8,0x33,
};

static unsigned char dh512_g[]={
    0x02,
};

DH* get_dh512(const unsigned char *dh512_p,const unsigned char *dh512_g)
{
    DH *dh=NULL;
    if ((dh=DH_new()) == NULL) return(NULL);
    dh->p=BN_bin2bn(dh512_p,sizeof(dh512_p),NULL);
    dh->g=BN_bin2bn(dh512_g,sizeof(dh512_g),NULL);
    if ((dh->p == NULL) || (dh->g == NULL))
        return(NULL);
    return(dh);

	return dh;
}

Server::Server(config *config)
{
    long int size;
    int cl;

    cl = configCopyClientSettings(config, &serverSettings);
    if (cl < 0) {
      delete config;
      LOG("Error allocating the ServerSettings",config->coreId);
      return;
    }

#if 0
    cl = configServerInitialize(serverSettings);
    if (cl < 0) {
      LOG("Could not init the Server", config->coreId);
      return;
    }
#endif

    m_num = config->id;
    tempBuf = new char[(serverSettings->mBufLen)*2];
    if(!tempBuf) {
        LOG("buffer could not be allocated",m_num);
	return;
    }
    memset(tempBuf,0,(serverSettings->mBufLen));
    if(serverSettings->mFileName) {
        //serverSettings->ExtractorFile has fd open, and returns filesize in size
        fileInitialize (serverSettings->mFileName,serverSettings,&size);
        pthread_mutex_lock(&statslock);
        g_filesize = size;
        pthread_mutex_unlock(&statslock);
        fileBuf = (char *)malloc(sizeof(char)*g_filesize);
        if(!fileBuf)
        {
        	printf("Could not allocate buffer exiting..");
        	exit(1);
        }
        int rc = CompleteFileMemCopy(fileBuf,serverSettings,g_filesize);
        if(rc > 0)
        {
            file_head = (uint8_t *)fileBuf;
            file_tail = (uint8_t *)fileBuf+g_filesize+1;
            MD5(file_head,g_filesize,serverSettings->tstats.md5sumcmp);
        }
        else
        	LOG("Could not copy file",1);
    }
    connections_accepted = 0;
#if 0
	fdQ = new msgq;
    pthread_mutex_init(&fdQ->msgqLock,NULL);
    pthread_cond_init(&fdQ->msgqCond,NULL);
#endif
}

Server::~Server()
{

    if(tempBuf)
    {
        delete tempBuf;
        tempBuf = NULL;
    }

	for(int i = 0;i < serverSettings->connections;i++)
	{
	    if ( serverSettings->mSockFd[i] != INVALID_SOCKET ) {
        shutdown(serverSettings->mSockFd[i],1);
	    close( serverSettings->mSockFd[i] );
	    serverSettings->mSockFd[i] = INVALID_SOCKET;
	    }
	}
    if(serverSettings->lSock)
    {
        close(serverSettings->lSock);
    }
	if(fileBuf)
	{
	    free(fileBuf);
	    fileBuf = NULL;
	}
#if 0
    pthread_mutex_destroy(&fdQ->msgqLock);
    pthread_cond_destroy(&fdQ->msgqCond);
    if(fdQ)
    {
    	delete fdQ;
    	fdQ = NULL;
    }
#endif
}

void Server::SaveClass(Server *theServer) 
{
    serverSettings->serverClass = (void *)theServer;
}

config * Server::GetServerSettings(void)
{
    return(serverSettings);
}

int Server::Listen()
{
    int rc;
    int family;
    int yes = 1;
    if((serverSettings->flags) & MASK_SERVER_ISV6)
    {
    	family = AF_INET6;
    }
    else
    {
        family = AF_INET;
    }

    // OPEN LISTENING SOCKET
    serverSettings->lSock = socket( family, SOCK_STREAM, 0 );
    if(serverSettings->lSock < 0)
    {
        LOG("Cannot create server socket",serverSettings->mSockFd[0]);
        return ERR_SERVER_SOCKET;
    }
    //set socket options to be reused
    rc = setsockopt(serverSettings->lSock,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(int));
    /*Set TCP window size if requested*/
    if(serverSettings->flags & MAASK_TCP_WINDOW)
    {
      	//rc = setTcpWindow(serverSettings->lSock, (serverSettings->tcpWindow*2));
    	//rc = setsockopt(serverSettings->lSock,SOL_SOCKET,TCP_WINDOW_CLAMP,&serverSettings->tcpWindow,sizeof(serverSettings->tcpWindow));
        LOG("Trying to set window size to",rc);
    }
    if(rc < 0)
    {
    	LOG("Server::Listen: could not set options on listening socket:",serverSettings->lSock);
    	LOG(strerror(errno),serverSettings->lSock);
    	return -1;
    }
    if(!in6_isAddrZero(&(serverSettings->serverAddr)))
    {
        if(serverSettings->flags & MASK_SERVER_ISV6)
        {
            rc = bind(serverSettings->lSock,(struct sockaddr *) &serverSettings->serverV6,
                		     sizeof(serverSettings->serverV6));
        }
        else
        {
            rc = bind(serverSettings->lSock,(struct sockaddr *) &serverSettings->serverV4,
                		     sizeof(serverSettings->serverV4));
	    printf("Socket Address to bind:%s\n", 
		   inet_ntoa((struct in_addr)(serverSettings->serverV4.sin_addr)));
        }
    }
    if(rc < 0) {
        LOG("cannot bind socket error no: %d",errno);
	LOG(strerror(errno),1);
    	return rc;
    }
    // listen for connections queue set here is 100

        rc = listen( serverSettings->lSock, 100 );
        if(rc < 0)
        {
            LOG("cannot set listening socket error no: %d",errno);
            LOG(strerror(errno),1);
            return ERR_LISTEN;
        }
#ifdef DEBUG
        sockaddr_in test;
        socklen_t addrlen = sizeof(sockaddr_in);
        getsockname(serverSettings->lSock,(struct sockaddr *)&test,&addrlen);
        printf("port:%d\n",ntohs(test.sin_port));
        char ip[50];
        printf("ip:%s\n",inet_ntop(AF_INET,&test.sin_addr,ip,50));
#endif
        return rc;

}

/*this will accept and poll
 *this will not be good for large number of connections
 *Can be used only for testing the Client.
 */



int Server::writePoll()
{

	WRITE_MUTEX_LOCK;
	WRITE_START_WAIT;
	WRITE_MUTEX_UNLOCK;
    sleep (4);
	int i;
    unsigned long packetId=0;
    long int currenLen=0;
    long int totLen=0;
    int readBytes;
	int avg;
	int len[MAX_SOCKET_FD] = {0};
	std::map<int,pfdInfo>::iterator ifdInfoMap;
	char *tBuf = (char *)malloc(sizeof(char)*serverSettings->mBufLen);

	do{
	         packetId++;
	         for(i=0;i<serverSettings->connections;i++)
		     {
		    	ifdInfoMap = fdInfoMap.find(serverSettings->mSockFd[i]);
                /*Check the condition of the fd from the connection table
                * is fd writeable*/
		    	if(likely(ifdInfoMap != fdInfoMap.end()))
		    	{
		    		len[i] = 0;
		    		ifdInfoMap->second->isWriteable = 1;
		    		readBytes = ReadDataFileBuffer(ifdInfoMap->second, &tBuf,serverSettings->mBufLen);
		    		if(readBytes)
		    	    {

			            len[i] = write( serverSettings->mSockFd[i], tBuf, readBytes);

		    	    }
	                if (len[i] < 0)
		    		{

		                if(unlikely((errno != EWOULDBLOCK)||(errno != EAGAIN)))
		    		    {
		    		        LOG(strerror(errno),errno);
		    		        ifdInfoMap->second->connStats.tNumConnectionErrors++;
		    		        break;
		    		    }
		    		    else
		    		    {

		    		        ifdInfoMap->second->isWriteable = 0;
		    		        ifdInfoMap->second->connStats.errorEagain++;
		    		        continue;
		    		    }
		    		}
		    		else
		    		{

		    			ifdInfoMap->second->fileBufIndex += len[i];
		    			if(ifdInfoMap->second->fileBufIndex >= (file_tail-1))
		    			{
		    				ifdInfoMap->second->fileBufIndex = file_tail;
		    			}
		    		}
		            totLen += len[i];
		    	    avg = totLen/serverSettings->connections;
		            serverSettings->tstats.tDataTransfered++;
		            ifdInfoMap->second->connStats.tTotalDataTransfered += len[i];
		    	}
		   }
	    }while(checkIndTransferComplete(serverSettings));
	    /*stats*/
	    for(ifdInfoMap=fdInfoMap.begin();ifdInfoMap !=fdInfoMap.end();ifdInfoMap++)
		{
		   if(ifdInfoMap->second->fileBufIndex >= file_tail)
		   {
			   MD5(file_head,ifdInfoMap->second->fileBufIndex - file_head-1,ifdInfoMap->second->connStats.md5sumwrite);
		   }
		}
	    g_stats.tTotalDataTransfered = totLen;
	    g_stats.tDataTransfered = serverSettings->tstats.tDataTransfered;
	    WRITE_MUTEX_LOCK;
	    WRITE_START_BROADCAST;
	    WRITE_MUTEX_UNLOCK;
	    g_checkwritestop=1;
        LOG("Exiting Write Thread",1);
	return currenLen;
}

/* 
 * Method: EPoll
 *
 * Description: The following steps are performed by this method
 *  1.- Create an epoll instance (file decriptor)
 *  2.- Registers the listening socket to this epoll instance, and
 *      associates an event to the listening socket with attributes
 *      EPOLLIN (file is available for read) and EPOLLET (Edge Trigger)
 *  3.- Loop with epoll_wait to wait for events on the epoll instance.
 *      Epoll_wait returns the number of events to be processed, with the
 *      "events" array containing user data for each event. This loop may
 *      also exit on a configured timeout.
 *  4.- Lastly, Stats are collected.
 *     
 *  Note each connection "Accept" is locked, as this critical code section
 *  is shared by all servers epolling on the listening socket. 
 */
int Server::EPoll()
{
    int g_stopReport = 0;
	int rc;
    socklen_t addrlen;
    int i;
    static int j=0;
    int currentSize = 0;
    int newFd,fd;
    int efd;
    volatile int endServer = 0;
    int timeout = serverSettings->timeout*1000;
    struct epoll_event event;
    struct epoll_event *events;
    char *filename;
    encapsHeader *packetHeader = NULL;
    std::map<int,pfdInfo>::iterator ifdInfoMap;
    /*At this point, Listening socket has already been created. So just tie
     *epoll event to the listening socket
     */

    // CREATE EPOLL PROCEDURE
    efd = epoll_create(1000);
    if(efd == -1)
    {
        LOG("Server::EPoll():create1 errno:",errno);
        LOG(strerror(errno),1);
        return -1;
    }
    memset(&event,0,sizeof(event));
    event.data.fd = serverSettings->lSock;
    event.events = EPOLLIN | EPOLLET;
    fd = epoll_ctl(efd,EPOLL_CTL_ADD,serverSettings->lSock,&event);
    if(fd == -1)
    {
        LOG("Server::EPoll():_epoll_ctl errno:",errno);
        LOG(strerror(errno),1);
        return -1;
    }
    //init events;

    events = (struct epoll_event*)calloc(MAX_SOCKET_FD,sizeof(events));
    if(!events)
    {
        LOG("Could not allocate events",1);
    	return -1;
    }
    pfdInfo connInfo = (pfdInfo)calloc(MAX_SOCKET_FD,sizeof(fdInfo));
    pfdInfo savePointer = connInfo;
    if(!connInfo)
    {
        LOG("Could not allocate connInfo",1);
        return -1;
    }

    //LOOP FOREVER
    do
    {
        /*call poll() wait*/
    	currentSize = epoll_wait(efd,events,MAX_SOCKET_FD,timeout);
    	if(currentSize <= 0)
    	{
    		LOG("Server::EPoll: epoll_wait() failed",1);
    		break;
    	}
    	for(i = 0; i < currentSize;i++)
        {
            if((events[i].events == 0 ))
            {
            	continue;
            }
            if(events[i].data.fd == serverSettings->lSock)
            {

	        /*TODO: Perform some load balancing here. If this thread has already accepted a lot of
		 *      connections, let the other epoll threads catchup.
		 */ 
	        newFd = 0;
	        while((newFd != -1)) /* && (connections_accepted < MAX_NUM_OF_ACCEPTED_CONNS_PER_THREAD))*/
            	{
		    //ACCEPT CONNECTION
		    MUTEX_SOCKET_ACCEPT_LOCK;
		    if((serverSettings->flags) & MASK_PEERB_ISV6) {
		        addrlen = sizeof(serverSettings->peerBV6);
			newFd = accept(serverSettings->lSock,(struct sockaddr *) &serverSettings->peerBV6,
				       &addrlen);
                    }
                    else {
		        addrlen = sizeof(serverSettings->peerBV4);
			newFd = accept(serverSettings->lSock,(struct sockaddr *)&serverSettings->peerBV4,
				       &addrlen);
                    }
		    MUTEX_SOCKET_ACCEPT_UNLOCK;

                    if(newFd < 0) {

		        if((errno != EWOULDBLOCK)||(errno !=EAGAIN)) {
                            serverSettings->tstats.tNumConnectionErrors++;
			    LOG("Server::Poll:accept failed on FD errno:",errno);
                            LOG(strerror(errno),1);
                            endServer = 1;
			}
			break;
		    }

		    //Make the new connection NonBlocking
		    rc = fcntl(newFd, F_GETFL,0);
		    rc |= O_NONBLOCK;
		    rc = fcntl(newFd, F_SETFL,rc);

		    if(serverSettings->flags & MAASK_TCP_WINDOW){
		        //	rc = setTcpWindow(newFd, serverSettings->tcpWindow);
		        LOG("Trying to set window size to",rc);
		    }
		    if(rc < 0) {
		        LOG("blocking error",1);
			break;
		    }

		    //COLLECT SOME STATS
		    serverSettings->connections++;
		    serverSettings->tstats.tNumConnections++;

		    /*INSERT the new fd in the shared socket array*/
		    serverSettings->mSockFd[j] = newFd;

		    /*create a per connection fd table for this connection
		     * and insert it on the map
		     * */
		    connInfoInit(connInfo,newFd,
				 connInfo->tempbuffer,
				 connInfo->fileBufWriteIndex,
				 connInfo->fileBufReadIndex,connInfo->fileBufTail,
				 connInfo->fileBufIndex,file_head);

                    	fdInfoMap.insert(std::make_pair(newFd,connInfo));

                    	  filename = (char *)malloc(FILENAME_SIZE);
                          if((serverSettings->flags) & MASK_PEERB_ISV6)
                          {
                         	snprintf(filename,20,"Test%d",ntohs(serverSettings->peerBV6.sin6_port));
                    	  }
                    	  else
                    	  {
                    	    snprintf(filename,20,"Test%d",ntohs(serverSettings->peerBV4.sin_port));
                    	  }
                    	  if(filename)
                    	  {
                    	   	filenameMap.insert(std::make_pair(newFd,filename));
                    	  }

#if 0
                        pthread_mutex_lock(&fdQ->msgqLock);
                        fdQ->fdQueue.push(serverSettings->mSockFd[j]);
        	    	    if(fdQ->signalPush == 0)
        	    	    {
        	    	    	fdQ->signalPush = 1;
        	    	    }
        	    	    pthread_mutex_unlock(&fdQ->msgqLock);
#endif
                    	j++;
                    	connInfo++;

#if 0
		    event.data.fd = newFd;
                    event.events = EPOLLIN | EPOLLET;
                    fd = epoll_ctl(efd,EPOLL_CTL_ADD,newFd,&event);
#endif

		    // ADD NEW FD to the monitor polling list
                    event.data.fd = newFd;
                    /*Level triggered no EPOLLET*/
                    event.events = EPOLLIN;
                    fd = epoll_ctl(efd,EPOLL_CTL_ADD,newFd,&event);

		    connections_accepted++; 

                    WRITE_MUTEX_LOCK;
                	WRITE_START_BROADCAST;
                	WRITE_MUTEX_UNLOCK;

            	}
            }
            else
            {
                /*receive data from a new socket
                 * process for validation
                 * * close on no data*/

				if  (events[i].events & EPOLLIN)
				{
					rc = readProcess(events[i].data.fd);
					if(rc < 0)
					{
						epoll_ctl(efd,EPOLL_CTL_DEL,events[i].data.fd,NULL);
					}
					/*Fall through*/
				}

				if((serverSettings->flags & MASK_ECHO_TEST)
								&& (g_verbose == 0))
				{
				   writePoll_echo(events[i].data.fd);
				}



            }

    	}

	// STATS COLLECTION
        pthread_mutex_lock(&statslock);
        g_stats.tDataReceived += serverSettings->tstats.tDataReceived;
        g_stats.tNumConnectionErrors += serverSettings->tstats.tNumConnectionErrors;
        g_stats.tNumConnections += serverSettings->tstats.tNumConnections;
        g_stats.tTotalDataReceived += serverSettings->tstats.tTotalDataReceived;
        pthread_mutex_unlock(&statslock);

	// Clear out internal stats.
	serverSettings->tstats.tDataReceived = 0;
	serverSettings->tstats.tNumConnectionErrors = 0;
	serverSettings->tstats.tNumConnections = 0;
	serverSettings->tstats.tTotalDataReceived = 0;


    }while(endServer != 1);//timer or error will end the server

#ifdef DEBUG
    FILE *error = fopen("errorlog.txt","a");
    fprintf(error,"Connections accepted: %d, cpu: %d, pid: %d, thread id: %u\n",
	   connections_accepted, sched_getcpu(), getpid(), (unsigned int)pthread_self());
#endif
    // Moved to Main.
    //    g_stopReport = 1;
    
    //    AUB: NEEDED to signal report_spawn after setting g_stopReport. May need it back in.
    //    REPORT_THREAD_LOCK;
    //    REPORT_THREAD_WAIT;
    //    REPORT_THREAD_UNLOCK;


    if(!g_checkwritestop && (g_verbose == 1))
    {
        WRITE_MUTEX_LOCK;
        WRITE_START_WAIT;
        WRITE_MUTEX_UNLOCK;
    }

    if((serverSettings->flags & MASK_ECHO_TEST))
        detailDisplayConnections("Stats.txt", this);

    if(events)
    {
        free(events);
        events = NULL;
    }
    /*free from map and erase here */
    if(packetHeader)
    	delete packetHeader;
    /*iterate through the map and free the table buffers calling the destroy function*/
    for(ifdInfoMap=fdInfoMap.begin();ifdInfoMap !=fdInfoMap.end();ifdInfoMap++)
    {
    	connInfoDestroy(ifdInfoMap->second);
    }
    if(savePointer)
    {
    	free(savePointer);
    	connInfo = NULL;
    }
    return rc;
}

/*this would validate the buffers coming in*/
int Server::readProcess(int fd)
{
	int currLen;
	int rc=0;
    int writeLen;
	int fileWrite;
	int compare=0;
	size_t size = (sizeof(char)*10*1024);
	std::map<int,pfdInfo>::iterator ifdInfoMap;
	ifilenameMap = filenameMap.find(fd);
	ifdInfoMap = fdInfoMap.find(fd);
    if(likely(ifdInfoMap != fdInfoMap.end()))
    {

    	ifdInfoMap->second->readEvent = 1;
    	switch(ifdInfoMap->second->isWriteable)
	    {
	        case 0:
	        	break;
	        default:
    	        do{
    	        	if(ifdInfoMap->second->fileBufReadIndex+size >
    	            		  ifdInfoMap->second->fileBufTail)
    	              {
    	        		  /*lock connection*/
    	        	      size = ifdInfoMap->second->fileBufTail-ifdInfoMap->second->fileBufReadIndex;
    	            	  /*unlock*/
    	            	  currLen = read( fd, ifdInfoMap->second->fileBufReadIndex,
    	            			                                              size);
    	              }
    	        	  else
    	        	  {
    	            	  currLen = read( fd, ifdInfoMap->second->fileBufReadIndex,
       			                                                              size);

    	        	  }
    	        	  if(currLen <= 0)
    	              {
    	            	  ifdInfoMap->second->readEvent = 0;

    	            	  if(unlikely((errno != EWOULDBLOCK)||(errno != EAGAIN)))
    	                  {
    	                      LOG("Error in(not EWOULDBLOCK)receive on:",ifdInfoMap->second->Connid);
    	                      LOG(strerror(errno),errno);
    	                	  rc = -1;
    	                      return rc;
    	                  }
    	            	  if(currLen == 0)
    	            	      return -1;
#ifdef DEBUG
    	            	  LOG(strerror(errno),1);
#endif
    	            	  rc = 0;
    	            	  ifdInfoMap->second->connStats.errorEagain++;
    	                  break;
    	             }
    	             else
    	             {
    	            	 ifdInfoMap->second->fileBufReadIndex += currLen;
    	            	 rc = currLen;
    	                 serverSettings->tstats.tTotalDataReceived += currLen;
    	                 serverSettings->tstats.tDataReceived++;
    	                 ifdInfoMap->second->connStats.tTotalDataReceived += currLen;


    	            	 if(ifdInfoMap->second->fileBufReadIndex >= ifdInfoMap->second->fileBufTail)
                         {

    	            		 ifdInfoMap->second->fileBufReadIndex = ifdInfoMap->second->fileBufTail;


    	            		 break;
                         }
    	            	 else if(ifdInfoMap->second->connStats.tTotalDataReceived >= (unsigned long int)g_filesize)
    	            	 {
#ifdef DEBUG
    	            		 LOG("Existing because File Transfer complete on:",ifdInfoMap->second->Connid);
#endif

    	            		 break;
    	            	 }
    	            	 else
    	            	 {

    	            		 continue;
    	            	 }

    	             }
                  }while(1);
    	          if(rc !=0)
    	          {
    	        	  ifdInfoMap->second->isReadable = 1;
    	        	  if(likely(ifilenameMap != filenameMap.end()))
    	              {
    	            	  fileWrite = ifdInfoMap->second->fileBufReadIndex - (uint8_t *)ifdInfoMap->second->tempbuffer;
    	            	  /*Added flag to create files only when user defines it*/
    	            	  if(serverSettings->flags & MASK_FILECREATE)
    	            	      writeLen = getTestFile(ifilenameMap->second,ifdInfoMap->second->tempbuffer,fileWrite, g_filesize);

    	            	  MD5_Update(&ifdInfoMap->second->md5sum,ifdInfoMap->second->tempbuffer,fileWrite);
    	            	  if((ifdInfoMap->second->fileBufReadIndex == ifdInfoMap->second->fileBufTail))
    	            	  {
    	            		  ifdInfoMap->second->fileBufReadIndex = (uint8_t *)ifdInfoMap->second->tempbuffer;
    	            	  }

    	            	  if(ifdInfoMap->second->connStats.tTotalDataReceived >= (unsigned long int)g_filesize)
    	            	  {
    	            		  pthread_mutex_lock(&statslock);
    	            		  g_testFiles++;
    	            		  pthread_mutex_unlock(&statslock);
    	            		  MD5_Final(ifdInfoMap->second->connStats.md5sum,&ifdInfoMap->second->md5sum);
    	            	      /*compare and set the test pass flag*/
    	            	      compare = memcmp(serverSettings->tstats.md5sumcmp,ifdInfoMap->second->connStats.md5sum,MD5_DIGEST_SIZE);
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
    	          }
	              break;
	    }

    }
	return rc;
}

/*Deprecated because we are using index pointers now*/
int Server::Process(int fd)
{

	int currLen;
	int rc=0;
	int writeLen=0;
	struct pollfd fds;
	char *fileBuf = tempBuf;
	//void *echoBuffer = tempBuf;

	ifilenameMap = filenameMap.find(fd);
	int timeout = 10*10;

	fds.fd = fd;
	fds.events = POLLOUT;
    do
    {

        currLen = read( fd, tempBuf,
        		      (serverSettings->mBufLen));

        if(currLen <= 0)
        {
        	if(unlikely((errno != EWOULDBLOCK)||(errno != EAGAIN)))
            {
                LOG("Error in(not EWOULDBLOCK)receive on:",fd);
                LOG(strerror(errno),1);
            	rc = -1;
                return rc;
            }
#ifdef DEBUG
        	LOG(strerror(errno),1);
#endif
        	rc = 0;
            break;
        }
        if(likely(ifilenameMap != filenameMap.end()))
        {

        	getTestFile(ifilenameMap->second,fileBuf,currLen, g_filesize);
            if(serverSettings->flags & MASK_ECHO_TEST)
            {
            	writeLen = write(fd,fileBuf,currLen);
            	if(writeLen < currLen)
            	{
                	if(unlikely(((errno != EWOULDBLOCK)||(errno != EAGAIN))
                			                            && (writeLen < 0)))
                    {
                        LOG(strerror(errno),1);
                    	rc = -1;
                        return rc;
                    }
                	else
                	{
             	        LOG("Error is EWOULDBLOCK or partial write",errno);

                        int prc = poll(&fds,1,timeout);
                        if(unlikely(prc < 0))
                        {
                            LOG("Continue after poll data may get lost",1);
                        	continue;
                        }
                        else
                        {
                        	if((fds.revents == 0 )||(fds.revents != POLLOUT))
                        	{
                        	     LOG("No write Events",1);
                        	     continue;
                        	}
                        	switch(writeLen)
                        	{
                        	    case -1:
                        	    	  writeLen = write( fd, fileBuf, currLen);
                        	    	  LOG("EWOULDBLOCK",errno);
                        	          LOG("Written to socket after unblocked bytes:",writeLen);
                        	          break;
                        	    default:
                        	          writeLen += write(fd, fileBuf+writeLen, (currLen-writeLen));
                        	          LOG("Written to socket after partial write bytes:",writeLen);
                        	          break;
                        	}
                        }
                	}

            	}
            }

        }


        serverSettings->tstats.tTotalDataReceived += currLen;
        serverSettings->tstats.tDataReceived++;
        serverSettings->tstats.tTotalDataTransfered += writeLen;

    }while(1);

    if(currLen == 0)
    	rc = -1;
    return rc;
}

UDPServer::UDPServer(config *config):Server(config)
{
/*create a dgram listening socket*/
    int rc;
    int family;
    int yes = 1;
    if((serverSettings->flags) & MASK_SERVER_ISV6)
    {
    	family = AF_INET6;
    }
    else
    {
        family = AF_INET;
    }

    // OPEN LISTENING SOCKET
    serverSettings->lSock = socket( family, SOCK_DGRAM, 0 );
    if(serverSettings->lSock < 0)
    {
        LOG("Cannot create server socket",serverSettings->mSockFd[0]);
        return;
    }
    //set socket options to be reused
    rc = setsockopt(serverSettings->lSock,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(int));
    if(rc < 0)
    {
    	LOG("Server::Listen: could not set options on listening socket:",serverSettings->lSock);
    	LOG(strerror(errno),serverSettings->lSock);
    	return;
    }
    if(!in6_isAddrZero(&(serverSettings->serverAddr)))
    {
        if(serverSettings->flags & MASK_SERVER_ISV6)
        {
            rc = bind(serverSettings->lSock,(struct sockaddr *) &serverSettings->serverV6,
                		     sizeof(serverSettings->serverV6));
        }
        else
        {
            rc = bind(serverSettings->lSock,(struct sockaddr *) &serverSettings->serverV4,
                		     sizeof(serverSettings->serverV4));
	       printf("Socket Address to bind:%s\n",
		   inet_ntoa((struct in_addr)(serverSettings->serverV4.sin_addr)));
        }
    }
    if(rc < 0) {
        LOG("cannot bind socket error no: %d",errno);
	LOG(strerror(errno),1);
    	return;
    }
    return;

}

UDPServer::~UDPServer()
{
  LOG("Deleted UDP server",1);
}

int UDPServer::EPoll()
{
   int rc;

   socklen_t addrlen;
   int i;
   int fd;
   int currentSize = 0;

   int efd;
   volatile int endServer = 0;
   int timeout = serverSettings->timeout*1000;
   struct epoll_event event;
   struct epoll_event *events;
   char *filename;

   std::map<int,pfdInfo>::iterator ifdInfoMap;


   rc = fcntl(serverSettings->lSock, F_SETFL,O_NONBLOCK);
   if(rc < 0)
   {
      close(serverSettings->lSock);
      return -1;
   }
   efd = epoll_create(1000);
   if(efd == -1)
   {
       LOG("Server::EPoll():create1 errno:",errno);
       LOG(strerror(errno),1);
       return -1;
   }
   memset(&event,0,sizeof(event));
   event.data.fd = serverSettings->lSock;
   event.events = EPOLLIN ;
   fd = epoll_ctl(efd,EPOLL_CTL_ADD,serverSettings->lSock,&event);
   if(fd == -1)
   {
       LOG("Server::EPoll():_epoll_ctl errno:",errno);
       LOG(strerror(errno),1);
       return -1;
   }
   //init events;

   events = (struct epoll_event*)calloc(MAX_SOCKET_FD,sizeof(events));
   if(!events)
   {
       LOG("Could not allocate events",1);
   	return -1;
   }
   pfdInfo connInfo = (pfdInfo)calloc(MAX_SOCKET_FD,sizeof(fdInfo));
   pfdInfo savePointer = connInfo;
   if(!connInfo)
   {
       LOG("Could not allocate connInfo",1);
       return -1;
   }
   do
   {
   	currentSize = epoll_wait(efd,events,1,timeout);
   	if(currentSize <= 0)
   	{
   		LOG("Server::EPoll: epoll_wait() failed",1);
   		break;
   	}
   	for(i = 0; i < currentSize;i++)
       {
            LOG("received event on",events[i].data.fd);
            LOG("Listening socket is",serverSettings->lSock);
   		    rc = Process(events[i].data.fd);
           	if(rc < 0)
            {
           		close(events[i].data.fd);
                //epoll_ctl(efd,EPOLL_CTL_DEL,events[i].data.fd,NULL);
            }

       }
       if(g_checkwritestop)
       endServer = 1;
   	}while(endServer == 0);

   pthread_mutex_lock(&statslock);

   g_stats.tDataReceived = serverSettings->tstats.tDataReceived;
   g_stats.tNumConnectionErrors += serverSettings->tstats.tNumConnectionErrors;
   g_stats.tNumConnections = serverSettings->tstats.tNumConnections;
   g_stats.tTotalDataReceived = serverSettings->tstats.tTotalDataReceived;
   if(g_stats.tNumConnections != 0)
	   g_stats.tAverageDataReceived = g_stats.tTotalDataReceived/g_stats.tNumConnections;
   else
	g_stats.tAverageDataReceived = 0;
   pthread_mutex_unlock(&statslock);
   return rc;

}




int UDPServer::Process(int fd)
{
    LOG("UDPServer::Process Called for ", fd);
	int rc;
	int currLen = 0;
    encapsHeader *pHeader;
    unsigned int sockaddrLen = 0;
    int compare; // init it
    do
    {

        if(!((serverSettings->flags) & MASK_CLIENT_ISV6))
        {
        	// Based on reading of beej socket guide
        	// initialize fromlen to be the size of from or struct sockaddr
        	sockaddrLen = sizeof(serverSettings->peerV4);
        	currLen = recvfrom( fd, tempBuf,
        		      (serverSettings->mBufLen)*2,0,(struct sockaddr *)&serverSettings->peerV4,
				         &sockaddrLen);
        }
        else
        {
        	sockaddrLen = sizeof(serverSettings->peerV6);
        	currLen = recvfrom( fd, tempBuf,
        	        		      (serverSettings->mBufLen)*2,0,(struct sockaddr *)&serverSettings->peerV6,
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
        else
        {
        	if((serverSettings->flags) & MASK_ISIPV6)
			{
				sendto( fd, tempBuf, currLen,0
								 ,(struct sockaddr *) &serverSettings->peerV6,
								 sizeof(serverSettings->peerV6));
			}
			else
			{
				sendto( fd, tempBuf, currLen,0,
								 (struct sockaddr *) &serverSettings->peerV4,
								 sizeof(serverSettings->peerV4));

			}
        }


    }while(0);

    if(currLen == 0)
    	rc = -1;
    return rc;
}


TLSServer::TLSServer(config *config):Server(config)
{
    m_TLSnum = config->id;
    const char *ssl_method;
	pthread_mutex_lock(&liblock);
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    pthread_mutex_unlock(&liblock);
    if(config->serverType == PROTOCOL_TLS)
    	ssl_method = "TLSv1";
    else if(config->serverType == PROTOCOL_DTLS)
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

TLSServer::~TLSServer()
{
#ifdef DEBUG
    LOG("Deleted TLS Server",1);
#endif
    SSL_CTX_free(ctx);
}

int TLSServer::configure()
{
	if(!serverSettings)
	{
		LOG("Can't TLS configure NULL settings",1);
		return -1;
	}
    char *keyfile = serverSettings->keyFile;
    char *ca_list = serverSettings->ca_list;
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
	    if((serverSettings->flags & MASK_CA_VERIFY))
	    {
	        if(!(SSL_CTX_load_verify_locations(ctx,
	        		ca_list,0)))
	        {
	            LOG("Can't read CA list",1);
	            return -1;
	        }
	    }

	switch((serverSettings->flags & MASK_AUTH_FLAGS) >> 12)
    {
#ifdef DEBUG
        LOG("TLSServer::configure:",
        		(serverSettings->flags & MASK_AUTH_FLAGS)>>12);
#endif
        case 0x1:
#ifdef DEBUG
        	LOG("verify request check",1);
#endif
            SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,0);
		    break;
	    case 0x2:
#ifdef DEBUG
		    LOG("verify respond check",1);
#endif
	        SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT,0);
		    break;
		case 0x4:
#ifndef SSL_9_CENTOS_5
			SSL_CTX_set_options(ctx,SSL_OP_NO_TICKET);
#endif
#ifdef DEBUG
			LOG("no verify check",(serverSettings->flags & MASK_AUTH_FLAGS) >> 12);
#endif
			break;
		default:
#ifdef DEBUG
			LOG("default no verify check",(serverSettings->flags & MASK_AUTH_FLAGS) >> 12);
#endif
			break;
    }
	if(serverSettings->ciphers)
    {
		DH *dh = NULL;
		if(strstr(serverSettings->ciphers, "DHE") != NULL)
        {

            dh = get_dh512(dh512_p,dh512_g);
            SSL_CTX_set_tmp_dh(ctx,dh);
        }
        SSL_CTX_set_cipher_list(ctx,serverSettings->ciphers);
		if(!dh)
            DH_free(dh);
    }


	SSL_CTX_set_session_cache_mode(ctx,SSL_SESS_CACHE_BOTH);
    return 0;
}

int TLSServer::EPoll()
{
#ifdef DEBUG
	LOG("Called TLS server",1);
#endif
    int timeout = serverSettings->timeout*1000;
    volatile int endServer = 0;
    struct epoll_event event;
    struct epoll_event *events;
    int rc;
    socklen_t addrlen;
    int i;
    int currentSize = 0;
    int newFd,fd;
    int efd;
    encapsHeader *packetHeader;
    std::map<int,pfdInfo>::iterator ifdInfoMap;
    char *filename;
    unsigned int pending;
    rc = configure();
    if(rc < 0)
    {
    	return -1;
    }
#if 0
    rc = Listen();
    if(rc < 0)
    {
    	return -1;
    }
#endif

    efd = epoll_create(1000);
    if(efd == -1)
    {
        LOG("Server::EPoll():create1 errno:",errno);
        LOG(strerror(errno),1);
        return -1;
    }
    event.data.fd = serverSettings->lSock;
    event.events = EPOLLIN;
    fd = epoll_ctl(efd,EPOLL_CTL_ADD,serverSettings->lSock,&event);
    if(fd == -1)
    {
        LOG("Server::EPoll():_epoll_ctl errno:",errno);
        LOG(strerror(errno),1);
        return -1;
    }
    //init events;
    pfdInfo connInfo = (pfdInfo)calloc(MAX_SOCKET_FD,sizeof(fdInfo));
    pfdInfo savePointer = connInfo;
    if(!connInfo)
    {
        LOG("Could not allocate connInfo",1);
        return -1;
    }
    events = (struct epoll_event*)calloc(MAX_SOCKET_FD,sizeof(events));
    if(!events)
    {
        LOG("Could not allocate events",1);
    	return -1;
    }
    do
    {
        /*call poll()*/

    	currentSize = epoll_wait(efd,events,MAX_SOCKET_FD,timeout);
    	if(currentSize <= 0)
    	{
    		LOG("Server::EPoll: epoll_wait() failed",1);
    		break;
    	}
    	for(i = 0; i < currentSize;i++)
        {
            rc = 0;
    		if((events[i].events == 0 )||(events[i].events != POLLIN))
            {
            	continue;
            }
            if(events[i].data.fd == serverSettings->lSock)
            {
                /*accept all the connections
                 * that are waiting on listen*/
#ifdef DEBUG
            	LOG("POLLIN on Listening socket",serverSettings->lSock);
#endif
            	do
            	{
            		pending = 0;
            		rc = 0;
            		MUTEX_SOCKET_ACCEPT_LOCK;
            		if((serverSettings->flags) & MASK_PEERB_ISV6)
                    {
                		addrlen = sizeof(serverSettings->peerBV6);
                		newFd = accept(serverSettings->lSock,(struct sockaddr *) &serverSettings->peerBV6,
	    		                       &addrlen);
                    }
                	else
                    {
                		addrlen = sizeof(serverSettings->peerBV4);
                		newFd = accept(serverSettings->lSock,(struct sockaddr *)&serverSettings->peerBV4,
                				       &addrlen);
                    }
            		MUTEX_SOCKET_ACCEPT_UNLOCK;
                    if(newFd < 0)
                	{
                		if((errno != EWOULDBLOCK)||(errno !=EAGAIN))
                		{
                            serverSettings->tstats.tNumConnectionErrors++;
                			LOG("Server::Poll:accept failed on FD errno:",errno);
                            LOG(strerror(errno),1);
                            endServer = 1;

                		}
                	    break;
                	}
                    if(newFd > 0)
                    {
                    	serverSettings->connections++;
                    	serverSettings->tstats.tNumConnections++;
                    }
#ifdef DEBUG
                	LOG("new incoming connection FD is:",newFd);
#endif
                    event.data.fd = newFd;
                    event.events = EPOLLIN | EPOLLET;
                    fd = epoll_ctl(efd,EPOLL_CTL_ADD,newFd,&event);
                    rc = fcntl(event.data.fd, F_GETFL,0);
					rc |= O_NONBLOCK;
					rc = fcntl(event.data.fd, F_SETFL,rc);
					if(rc < 0)
					{
						LOG("blocking error",1);
						break;
					}
                    if((rc = TLSAccept(event.data.fd,pending)) >= 0)
                    {

                       	serverSettings->tstats.tNumSecureConnections++;

                        connInfoInit(connInfo,newFd,
                        				 connInfo->tempbuffer,
                        				 connInfo->fileBufWriteIndex,
                        				 connInfo->fileBufReadIndex,connInfo->fileBufTail,
                        				 connInfo->fileBufIndex,file_head);

                        fdInfoMap.insert(std::make_pair(event.data.fd,connInfo));
                        connInfo->sslPend = pending;

                        connInfo++;
                        filename = (char *)malloc(FILENAME_SIZE);
                        if((serverSettings->flags) & MASK_PEERB_ISV6)
                        {
                        	snprintf(filename,20,"Test%d",ntohs(serverSettings->peerBV6.sin6_port));
                        }
                        else
                        {
                            snprintf(filename,20,"Test%d",ntohs(serverSettings->peerBV4.sin_port));
                        }
                        if(filename)
                        {
                        	filenameMap.insert(std::make_pair(event.data.fd,filename));
                        }
                        else
                        {
                        	 LOG("Could not allocate filename",event.data.fd);
                        }
                    }
                    else if(rc == -1)
                    {
                    	 endServer = 1;
                    	 printf("TLS accept error\n");
                    	 LOG("TLS accept error on:",event.data.fd);
                    	 break;
                    }
                    else
                    {
                    	endServer = 1;
                    	serverSettings->tstats.treHanshakeErrors++;
                    	LOG("TLS re-handshake error on:",event.data.fd);
                    	break;
                    }

            	}while(newFd != -1);
            }
            else
            {
#ifdef DEBUG
                for(iSSLMap=SSLMap.begin();iSSLMap !=SSLMap.end();iSSLMap++)
                {
            	    LOG("TLSServer::EPoll:map:",iSSLMap->first);
                }
#endif

                iSSLMap = SSLMap.find(events[i].data.fd);
                if(iSSLMap != SSLMap.end())
                {
					rc = TLSServer::Process(iSSLMap->second,events[i].data.fd);
					if(rc < 0)
					{

						LOG("Close FD:",events[i].data.fd);

						int r = SSL_shutdown(iSSLMap->second);
						if(!r)
						{
							shutdown(events[i].data.fd,1);
							SSL_shutdown(iSSLMap->second);
						}
						SSL_free(iSSLMap->second);
						 SSLMap.erase(events[i].data.fd);
						 shutdown(events[i].data.fd,2);
						 close(events[i].data.fd);
					}
                }
            }

        }
        pthread_mutex_lock(&statslock);
        g_stats.tDataReceived += serverSettings->tstats.tDataReceived;
        g_stats.tNumConnectionErrors += serverSettings->tstats.tNumConnectionErrors;
        g_stats.tNumSecureConnections +=serverSettings->tstats.tNumSecureConnections;
        g_stats.tNumConnections += serverSettings->tstats.tNumConnections;
        g_stats.tTotalDataReceived += serverSettings->tstats.tTotalDataReceived;
        g_stats.treHandshakes += serverSettings->tstats.treHandshakes;
        g_stats.treHanshakeErrors += serverSettings->tstats.treHanshakeErrors;
        pthread_mutex_unlock(&statslock);

	    // Clear out internal stats.
	    serverSettings->tstats.tDataReceived = 0;
	    serverSettings->tstats.tNumConnectionErrors = 0;
	    serverSettings->tstats.tNumConnections = 0;
	    serverSettings->tstats.tTotalDataReceived = 0;
	    serverSettings->tstats.treHandshakes = 0;
	    serverSettings->tstats.treHanshakeErrors = 0;
	    serverSettings->tstats.tNumSecureConnections = 0;

    }while(endServer != 1);//timer to end the server required
    g_stopReport = 1;

#ifdef DEBUG
    for(ipacketHeaderMap=packetHeaderMap.begin();ipacketHeaderMap !=packetHeaderMap.end();ipacketHeaderMap++)
    {
	    cout << "key " <<ipacketHeaderMap->first << "value " << ipacketHeaderMap->second <<endl;
	    cout << " ID: " << ipacketHeaderMap->second->connectionId << endl;
	    cout << " packet ID: " << ipacketHeaderMap->second->packetId << endl;
    }
#endif

    if(events)
        free(events);

    if(savePointer)
    {
    	free(savePointer);
    	connInfo = NULL;
    }
    return rc;
}

int TLSServer::TLSAccept(int fd, unsigned int &pend)
{
	SSL *ssl;
	int rc;

	ssl = SSL_new (ctx);
	if(!ssl)
	{
	    LOG("could not allocate ssl struct",1);
	    return -1;
	}
	SSL_set_session_id_context(ssl,
	                    (const unsigned char *)&fd,
	                     sizeof(fd));
    SSL_set_fd(ssl, fd);

    if((rc = SSL_accept(ssl)) <=0)
    {

         rc = -1;
    	 int errorno = SSL_get_error(ssl,rc);
    	 if(errorno == SSL_ERROR_WANT_READ || errorno == SSL_ERROR_WANT_WRITE)
    	 {

    		 rc = 0;
    		 pend = 1;
    	 }
    	 else
    	 {
    	     char error[200];
             LOG(ERR_error_string(ERR_get_error(),error),SSL_get_error(ssl,rc));
             SSL_free(ssl);
             return rc;
    	 }
    }
    /*Added for REHANDSHAKES TESTS cmidha 08/13/2013*/
    if(serverSettings->flags & SHIFT_REHANDSHAKE)
    {
	    if(((serverSettings->flags & MASK_AUTH_FLAGS) >> 12)
	    		== 0x01)
	    {
    	    LOG("verify respond before REHANDSHAKE",1);
            SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,0);
	    }

        /*Set a different session ID it is required to avoid reconnect to same session id*/
	    SSL_set_session_id_context(ssl,(unsigned char *)&test_ctx_session_id,sizeof(test_ctx_session_id));
        if(SSL_renegotiate(ssl) <= 0)
        {
            LOG("Could not be renegotiated in REHANDSHAKE",1);
            return -2;
        }
        if(SSL_do_handshake(ssl) <= 0)
        {
            LOG("Could not complete handshake in REHANDSHAKE",1);
            return -2;
        }
        //ssl->state = SSL_ST_ACCEPT;
        //LOG("Manually setting state to accept",1);
        /*Second call of handshake is required to stop the client from sending data
         * and complete the handshake first
        */
        if((rc=SSL_do_handshake(ssl)) <= 0)
        {
            LOG("Could not complete handshake in REHANDSHAKE",SSL_get_error(ssl,rc));
            return -2;
        }
        serverSettings->tstats.treHandshakes++;
    }
    /*end REHANDSHAKE*/
    SSLMap.insert(std::make_pair(fd,ssl));
    /*keep in mind to delete the map iterator when this is free*/

    /*set up the session ID for each connection connected */

    return rc;
}

int TLSServer::Process(SSL *ssl,int fd)
{
	int currLen;
	int rc;
	std::map<int,pfdInfo>::iterator ifdInfoMap;
	char *fileBuf = tempBuf;
	int compare;
	//ipacketHeaderMap = packetHeaderMap.find(fd);
	ifdInfoMap = fdInfoMap.find(fd);
	ifilenameMap = filenameMap.find(fd);
    do
    {
    	if(likely(ifdInfoMap != fdInfoMap.end()))
    	{

    		currLen = SSL_read( ssl, tempBuf, (serverSettings->mBufLen));
			if(currLen <= 0)
			{

				int errorno = SSL_get_error(ssl,currLen);

				if((errorno != SSL_ERROR_WANT_READ))
				{
					LOG("Error in(not EWOULDBLOACK)receive on:",fd);
					LOG(strerror(errno),1);
					rc = -1;
					break;
				}
				rc = 0;
				break;
			}
			if(likely(ifilenameMap != filenameMap.end()))
			{
				 serverSettings->tstats.tTotalDataReceived += currLen;
				 serverSettings->tstats.tDataReceived++;
				 ifdInfoMap->second->connStats.tTotalDataReceived += currLen;
				 if(serverSettings->flags & MASK_FILECREATE)
				 {
					 getTestFile(ifilenameMap->second,fileBuf,currLen, g_filesize);
				 }
				 else
				 {
					  MD5_Update(&ifdInfoMap->second->md5sum,fileBuf,currLen);
					  if(ifdInfoMap->second->connStats.tTotalDataReceived >= (unsigned long int)g_filesize)
					  {
						  pthread_mutex_lock(&statslock);
						  g_testFiles++;
						  pthread_mutex_unlock(&statslock);
						  MD5_Final(ifdInfoMap->second->connStats.md5sum,&ifdInfoMap->second->md5sum);
						  /*compare and set the test pass flag*/
						  compare = memcmp(serverSettings->tstats.md5sumcmp,ifdInfoMap->second->connStats.md5sum,MD5_DIGEST_SIZE);
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
			}

        }


    }while(1);

    if(currLen == 0)
    	rc = -1;

    return rc;
}

void initServerMutexes()
{
    MUTEX_SOCKET_ACCEPT_INIT;
    MUTEX_CORE_COUNTER_INIT;
}

void destroyServerMutexes()
{
    MUTEX_SOCKET_ACCEPT_DESTROY;
    MUTEX_CORE_COUNTER_DESTROY;
}

int createListeningSocket(void *inputConfig) 
{
    int rc;
    int family;
    int yes = 1;
    config *inputSettings = (config *)inputConfig;

    if((inputSettings->flags) & MASK_SERVER_ISV6){
    	family = AF_INET6;
    }
    else {
        family = AF_INET;
    }

    // OPEN LISTENING SOCKET
    if(inputSettings->serverType == PROTOCOL_DTLS ||
    		inputSettings->serverType == PROTOCOL_DTLS)
    {

    	inputSettings->lSock = socket( family, SOCK_DGRAM, 0 );
    	LOG("Creating a UDP Listening socket",inputSettings->lSock);
    }
    else
        inputSettings->lSock = socket( family, SOCK_STREAM, 0 );
    if(inputSettings->lSock < 0) {
        LOG("Cannot create server socket",inputSettings->mSockFd[0]);
        return ERR_SERVER_SOCKET;
    }



    // BIND SOCKET
    if(!in6_isAddrZero(&(inputSettings->serverAddr))) {
        if(inputSettings->flags & MASK_SERVER_ISV6) {
            rc = bind(inputSettings->lSock,(struct sockaddr *) &inputSettings->serverV6,
                		     sizeof(inputSettings->serverV6));
        }
        else {
            rc = bind(inputSettings->lSock,(struct sockaddr *) &inputSettings->serverV4,
                		     sizeof(inputSettings->serverV4));
        }
 
	if(rc < 0) {
	    LOG("cannot bind socket error no: %d",errno);
	    LOG(strerror(errno),1);
	    return rc;
	}
    }

    //SET SOCKET OPTIONS to be reused
     rc = setsockopt(inputSettings->lSock,SOL_SOCKET,SO_REUSEADDR,(const char *)&yes,sizeof(int));
     /*Set TCP window size if requested*/

     if(rc < 0) {
     	LOG("Server::Listen: could not set options on listening socket:",inputSettings->lSock);
     	LOG(strerror(errno),inputSettings->lSock);
     	return -1;
     }
    // LISTEN for connections queue set here was 100
    if(inputSettings->serverType == PROTOCOL_DTLS ||
        		inputSettings->serverType == PROTOCOL_DTLS)
    {
    	LOG("Skipping listen step",inputSettings->lSock);
    	rc =1;
    }
    else
        rc = listen(inputSettings->lSock, 2000 );
    if(rc < 0) {
        LOG("cannot set listening socket error no: %d",errno);
	LOG(strerror(errno),1);
	return ERR_LISTEN;
    }

    // SET LISTENING SOCKET A NON-BLOCKING
    rc = fcntl(inputSettings->lSock, F_SETFL,O_NONBLOCK);
    if(rc < 0)
    {
       close(inputSettings->lSock);
       return -1;
    }

#ifdef DEBUG
    sockaddr_in test;
    socklen_t addrlen = sizeof(sockaddr_in);
    getsockname(inputSettings->lSock,(struct sockaddr *)&test,&addrlen);
    printf("port:%d\n",ntohs(test.sin_port));
    char ip[50];
    printf("ip:%s\n",inet_ntop(AF_INET,&test.sin_addr,ip,50));
#endif

    return rc;
}


void *server_spawn( void *inputConfig )
{

    config *inputSettings = (config *)inputConfig;
    int rc, error_res;
    cpu_set_t cpuset;
    Server *theServer = NULL;

    /*Move this thread to an available core. 
     * TODO: 
     * 1.- Check core upper bound. Should not exceed platform max.
     * 2.- Add configuration flag to skip affinity (i.e, Let the OS assign core to this thread) 
     *     for this thread.
     */
    MUTEX_CORE_COUNTER_LOCK;
    CPU_ZERO(&cpuset);
    CPU_SET(coreCounter++, &cpuset); // Add CPU to set.
    error_res = sched_setaffinity(0, sizeof(cpuset), &cpuset);
    MUTEX_CORE_COUNTER_UNLOCK;
    if (error_res < 0) {
      LOG(strerror(errno), 1); 
      return 0;
    }

    //Create an instance of the Server!!!
    if((inputSettings->serverType == PROTOCOL_TCP)||
    		(inputSettings->serverType ==DEFAULT))
        theServer = new Server(inputSettings);
    else if((inputSettings->serverType == PROTOCOL_TLS)||
    		inputSettings->serverType==PROTOCOL_SSL)
    	theServer = new TLSServer(inputSettings);
    else if((inputSettings->serverType == PROTOCOL_UDP))
        	theServer = new UDPServer(inputSettings);
    else if((inputSettings->serverType == PROTOCOL_DTLS))
            	theServer = new DTLSServer(inputSettings);
    /*Add more client types here*/

    if(theServer == NULL) {
    	LOG("New Server could not be created",1);
    	//goto does not look good but it improves the flow here.
    	goto exit;
    }
#ifdef DEBUG
    LOG("server server",inputSettings->serverType);
    if(inputSettings->serverType == PROTOCOL_DTLS)
    {
    	DTLSServer *theDTLSServer = dynamic_cast<DTLSServer *>(theServer);

    	theDTLSServer->testHashgen();
	}
#endif
    theServer->SaveClass(theServer);

    g_serverThread = 1;
    if((inputSettings->flags & MASK_ECHO_TEST)
                		&& (g_verbose == 1))
        create_write_server_thread(inputSettings);

    //create_read_server_thread(inputSettings);

    /* Start Epolling */
    rc = theServer->EPoll();
    if(rc < 0)
    {
        LOG("Server_spawn : Failed in Epoll",rc);
        goto exit;
    }

exit:
    if(theServer != NULL)
    {
    	delete theServer;
    	theServer = NULL;
        LOG("Deleted a Server Thread",1);
    }
    return 0;
}


void *write_server_spawn(void *inputSettings)
{
    config *Settings = (config *)inputSettings;
    Server * theServer = (Server *)(Settings->serverClass);

    theServer->writePoll();
    pthread_join(Settings->id, NULL);
    return 0;
}

void getErrorFromHeaderMap(stats *stats)
{

   unsigned int buffersPerConnection = 0;

   if(stats->tNumConnections)
	   buffersPerConnection = stats->tDataReceived/stats->tNumConnections;
   for(ipacketHeaderMap=packetHeaderMap.begin();ipacketHeaderMap !=packetHeaderMap.end();ipacketHeaderMap++)
   {
       if(ipacketHeaderMap->second->packetId <
    		   (u_int32_t)buffersPerConnection)
       {
           printf("Connection ID:%u did not receive all data PID:%u BUffers:%u\n",ipacketHeaderMap->second->connectionId
        		   ,ipacketHeaderMap->second->packetId,
        		   (u_int32_t)buffersPerConnection);
       }
   }

}

void connInfoInit(fdInfo *connInfo,int newFd,
		char *&buffer,uint8_t *&indexwrite,
		uint8_t *&indexread,uint8_t *&tail, uint8_t *&fileIndex, uint8_t *head)
{
	size_t bufSize=sizeof(char)*10*1024;
	//std::ostringstream stats;
	if(connInfo)
	{
	    connInfo->Connid = newFd;
        if((unsigned long int)g_filesize < bufSize)
        {
        	bufSize = g_filesize;
        }
	    buffer = (char *)calloc(1,bufSize);
	    if(buffer)
	    {
	    	indexread = (uint8_t *)buffer;
	    	fileIndex = head;
	        indexwrite = indexread;
	        tail = indexread+bufSize;
	    }
	    else
	    {
	        LOG("tempBuffer allocation failed on",newFd);
	    }

	    connInfo->isReadable = 0;
	     connInfo->isWriteable = 1;
	     connInfo->readEvent = 0;
	     connInfo->writeEvent = 0;
	     connInfo->sslPend  = 0;
	     memset(&connInfo->connStats,0,sizeof(stats));
	     pthread_mutex_init(&connInfo->connLock,NULL);
	     MD5_Init(&connInfo->md5sum);
	     MD5_Init(&connInfo->md5sumwrite);


	}

}

int Server::checkIndTransferComplete(config *inputSettings)
{

	unsigned int completeCount=0;
	std::map<int,pfdInfo>::iterator ifdInfoMap;
	for(ifdInfoMap=fdInfoMap.begin();ifdInfoMap !=fdInfoMap.end();ifdInfoMap++)
	{
	   if(ifdInfoMap->second->fileBufIndex >= file_tail)
	   {
		   completeCount++;

	   }
	}

    if(completeCount == inputSettings->tstats.tNumConnections)
    {
        LOG("Complete Transfer for num:",inputSettings->tstats.tNumConnections);
    	return 0;
    }
    return 1;
}

int Server::ReadDataFileBuffer(pfdInfo fdInfo, char **tempBuf,int size)
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
	    	LOG("tempBuf not allocated",1);
	}
	else /*Should never go here until there is an issue*/
	{
	    size  = 0;
		if(fdInfo->fileBufIndex == file_tail)
		{
#ifdef DEBUG
		    LOG("Reached the end of file for connection",1);
#endif
		}
	}
    return size;
}

void connInfoDestroy(fdInfo *&connInfo)
{
	if(connInfo)
	{
		pthread_mutex_destroy(&connInfo->connLock);
        if(connInfo->tempbuffer)
        {
            free(connInfo->tempbuffer);
        }
	}
}

/*Detailed per connection stats ouput to a file*/

char *getPrintableMd5(unsigned char *md5raw)
{
	int i;
	char *detailBuf = (char *)malloc(sizeof(char)*33);
	for(i =0; i< 16; i++)
	{
        snprintf(&detailBuf[i*2],16*2,"%02x",(unsigned int)md5raw[i]);
	}
	return detailBuf;
}
void detailDisplayConnections(const char *filename, Server* theServer)
{

	LOG("Detailed level stats",1);
	std::map<int,pfdInfo>::iterator ifdInfoMap;
	FILE* logFile = NULL;
	int i;
	logFile = fopen(filename,"a");
    char *detailBuf = (char *)malloc(sizeof(char)*33);
    char *writeBuf = (char *)malloc(sizeof(char)*33);
    memset(writeBuf,0,(sizeof(char)*32));

    fprintf(logFile,"ID  |Errors  |Data Transferred  |Data Received      |Checksum/md5sum                 |cheksum/md5sum write\n");
    fprintf(logFile,"    |        |           (bytes)|            (bytes)|                                |                     \n");
    fprintf(logFile,"                          --------------------------------------------     \n");

    for(ifdInfoMap = theServer->fdInfoMap.begin();ifdInfoMap != theServer->fdInfoMap.end();ifdInfoMap++)
	{
    	if(ifdInfoMap != theServer->fdInfoMap.end())
    	{
    	    for(i =0; i< 16; i++)
    	    {
    		    snprintf(&detailBuf[i*2],16*2,"%02x",(unsigned int)ifdInfoMap->second->connStats.md5sum[i]);
    		    snprintf(&writeBuf[i*2],16*2,"%02x",(unsigned int)ifdInfoMap->second->connStats.md5sumwrite[i]);
    	    }
    		fprintf(logFile,"%4d|%8u|%18lu|%19lu|%32s|%32s\n",
    	    		ifdInfoMap->second->Connid,
    	    		ifdInfoMap->second->connStats.errorEagain,
    	    		ifdInfoMap->second->connStats.tTotalDataTransfered,
    	    		ifdInfoMap->second->connStats.tTotalDataReceived,
    	    		detailBuf,writeBuf);
        }
    }
    fflush( 0 );
    free(detailBuf);
    free(writeBuf);
    fclose(logFile);

}

int Server::writePoll_echo(int fd)
{

    long int currenLen=0;
    long int totLen=0;
    size_t bufsize=0;
    int avg;
    int len;
    static std::map<int,pfdInfo>::iterator ifdInfoMap;

    do
    {

    	        ifdInfoMap = fdInfoMap.find(fd);
                   /*Check the condition of the fd from the connection table
                    * is fd readable*/
		    	if(ifdInfoMap != fdInfoMap.end())
		    	{
		    	   if(ifdInfoMap->second->fileBufReadIndex <= ifdInfoMap->second->fileBufWriteIndex )
		    		   bufsize = ifdInfoMap->second->fileBufTail - ifdInfoMap->second->fileBufWriteIndex;
		    	   else
		    	       bufsize =  ifdInfoMap->second->fileBufReadIndex-ifdInfoMap->second->fileBufWriteIndex;
		    	   if(!(ifdInfoMap->second->isReadable) ||
		    			   (!bufsize) )
		    	   {
		    	       break;
		    	   }

		    	   else
		    	   {
		    	      /*now the fd is readble i.e. the readindex is moved and != writeindex
		    	       * currently this thread does not know how much to write could be <=
		    	       * buffer size. Get the index difference and write to the connection
		    	       * remember it has to be atomic*/
		    		  LOG("Came to write",ifdInfoMap->second->Connid);
		    		  len = write(ifdInfoMap->second->Connid,ifdInfoMap->second->fileBufWriteIndex,bufsize);
		              if (len < 0)
		              {

		            	   if(unlikely((errno != EWOULDBLOCK)||(errno != EAGAIN)))
		            	   {
		            	       LOG(strerror(errno),ifdInfoMap->second->Connid);
		                       //We need to stop reading at this time
		            	       break;
		            	   }
		            	   else
		            	   {
		            		   LOG(strerror(errno),errno);
		            		   ifdInfoMap->second->isWriteable = 0;
		            		   ifdInfoMap->second->connStats.errorEagain++;
		            		   break;
		            	   }
		               }
		               else
		               {
		            	   /*update flags and buffer index but before we make any decision we
		            	    * have to figure out how much bytes were written*/

		            	   ifdInfoMap->second->fileBufWriteIndex += len;
                           if((ifdInfoMap->second->fileBufWriteIndex
                        				   >= ifdInfoMap->second->fileBufTail))
                           {

                        	   ifdInfoMap->second->fileBufWriteIndex = ifdInfoMap->second->fileBufTail;
                        	   break;
                           }
                           ifdInfoMap->second->isWriteable = 1;
		            	   ifdInfoMap->second->connStats.tDataTransfered += len;
		               }
		    	   }
		    	   totLen += len;
		    	   avg = totLen/serverSettings->connections;
		    	   serverSettings->tstats.tDataTransfered++;
		    	   ifdInfoMap->second->connStats.tTotalDataTransfered += len;
		    	}

        }while(bufsize);
        if(ifdInfoMap->second->fileBufWriteIndex == ifdInfoMap->second->fileBufTail)
        	ifdInfoMap->second->fileBufWriteIndex = (uint8_t *)ifdInfoMap->second->tempbuffer;
	    /*stats*/
	    g_stats.tTotalDataTransfered = totLen;
		g_stats.tDataTransfered = serverSettings->tstats.tDataTransfered;
	return currenLen;
}

DTLSServer::DTLSServer(config *config):TLSServer(config)
{
	m_DTLSnum = config->id;
	SSL_CTX_set_options(ctx, SSL_OP_ALL);
	/* DTLS: partial reads end up discarding unread UDP bytes
	 * Setting read ahead solves this problem.
	 * from apps/s_client.c from OpenSSL source
	*/
	SSL_CTX_set_read_ahead(ctx, 1);
}

void DTLSServer::cleanupConnectionState( SSL *ssl, int fd )
{
   int result = SSL_shutdown(ssl);
   if(!result)
       result = SSL_shutdown (ssl);
   SSL_free(ssl) ;

}

DTLSServer::~DTLSServer()
{
    LOG("Deleted DTLS Server",1);
}

/*
 * First version for server process we
 * would like to queue the packets for better performance
 * in a list per connection
*/
int DTLSServer::Process(SSL *s,int fd)
{
	int currLen;
	LOG("Processing event on fd",fd);
	int rc;
    std::map<int,pfdInfo>::iterator ifdInfoMap;
	encapsHeader *pHeader;
	ifdInfoMap = fdInfoMap.find(fd);
	SSL *ssl;
	struct timeval timeleft;
	struct timeval *timeout_s;
	int compare;
    do
    {
        if(ifdInfoMap != fdInfoMap.end())
        {
        	ssl = ifdInfoMap->second->cSSL;
        	currLen = SSL_read( ssl, tempBuf, (serverSettings->mBufLen));
			if(currLen <= 0)
			{

				int errorno = SSL_get_error(ssl,currLen);
				if ((errorno == SSL_ERROR_WANT_READ ||
						(errorno == SSL_ERROR_WANT_WRITE)) && (ifdInfoMap->second->sslPend))
				{
					DTLSv1_get_timeout(ssl,&timeleft);
					timeout_s = &timeleft;
					usleep(timeout_s->tv_usec);
                    usleep(timeout_s->tv_sec*1000000);
					if ( DTLSv1_handle_timeout(ssl) > 0)
					{
						LOG("TIMEOUT occured\n",2);
					}
				}
				if((errorno != SSL_ERROR_WANT_READ))
				{
					LOG("Error in(not EWOULDBLOACK)receive on:",fd);
					LOG(strerror(errno),1);
					rc = -1;
					break;
				}
				rc = 0;
				break;
			}
			if(likely(ifilenameMap != filenameMap.end()))
			{
				 if(ifdInfoMap->second->sslPend)
					 ifdInfoMap->second->sslPend = 0;
				 serverSettings->tstats.tTotalDataReceived += currLen;
				 serverSettings->tstats.tDataReceived++;
				 ifdInfoMap->second->connStats.tTotalDataReceived += currLen;
				 if(serverSettings->flags & MASK_FILECREATE)
				 {
					 getTestFile(ifilenameMap->second,(tempBuf+sizeof(encapsHeader))
							 ,(currLen-sizeof(encapsHeader)), g_testFileSize);
				 }
				 else
				 {
					 /*For DTLS if we are not creating files we get checksum per packet*/
					 if(ifdInfoMap != fdInfoMap.end() && (ifdInfoMap->second)) //sanity check for connInfo
					 {
						 LOG("Found the connection",ifdInfoMap->second->Connid);
						 ifdInfoMap->second->connStats.tTotalDataReceived += currLen;
						 pHeader = (encapsHeader *)tempBuf;
						 if (pHeader->pdata.end == ENDP)
						 {
							 LOG("received End packet",1);
							 pHeader->pdata.end = ACKEP;
							 /*send ack packet*/
							 cleanupConnectionState( ssl,fd);
							 ifdInfoMap->second->state = state_end_server_read;
							 rc = -1;
							 break;
						 }

					     unsigned char* md5 = (unsigned char *)tempBuf;
					     md5 += sizeof(encapsHeader);
					     MD5(md5,currLen-sizeof(encapsHeader),ifdInfoMap->second->connStats.md5sum);
					     /*caution : we have to understand how we read to x86 from the network */
					     compare = memcmp(ifdInfoMap->second->connStats.md5sum,
				         pHeader->md5sum,MD5_DIGEST_SIZE);
					 }
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


        }

    }while(1);

    if(currLen == 0)
    	rc = -1;

    return rc;
}


int DTLSServer::TLSAccept(int hash, unsigned int &pend)
{
	SSL *ssl;
	int rc;
    tSSLMap::iterator iSSL;
    iSSL = connMap.find (hash);
    ssl = iSSL->second;
    struct timeval timeleft;
    memset(&timeleft,0,sizeof timeleft);
	if(!ssl)
	{
	    LOG("could not allocate ssl struct",1);
	    return -1;
	}

    if((rc = SSL_accept(ssl)) <=0)
    {

         rc = -1;
    	 int errorno = SSL_get_error(ssl,rc);
    	 if(errorno == SSL_ERROR_WANT_READ || errorno == SSL_ERROR_WANT_WRITE)
    	 {

    		rc = 0;
    		pend = 1;
			DTLSv1_get_timeout(ssl,&timeleft);

			struct timeval *timeout_s = &timeleft;
            LOG("Timeout is : ",timeout_s->tv_usec);
            LOG("Timeout is : ",timeout_s->tv_sec);
			//usleep(timeout_s->tv_usec);
			usleep(1000000);

			if ( DTLSv1_handle_timeout(ssl) > 0)
			{
				LOG("TIMEOUT occured\n",1);
			}
    	 }
    	 else
    	 {
    	     char error[200];
             LOG(ERR_error_string(ERR_get_error(),error),SSL_get_error(ssl,rc));
             SSL_free(ssl);
             return rc;
    	 }
    }

   // SSLMap.insert(std::make_pair(fd,ssl));
    /*keep in mind to delete the map iterator when this is free*/

    /*set up the session ID for each connection connected */

    return rc;

}

SSL* DTLSServer::initSSL()
{
	SSL *ssl;
	hashkey_t hash  = hashing_fun();
	LOG("First time hash key init ssl at Hash:",hash);
	ssl = SSL_new (ctx);
	if(ssl)
	{
		connMap.insert(std::make_pair(hash,ssl));
		LOG("Making ssl pair with hash:",hash);
		return ssl;
	}
	return NULL;
}

uint32_t DTLSServer::hashing_fun()
{
    /*TODO maybe use hw crc*/
	boost::crc_ccitt_type result;
	uint32_t hash=0;
	char  *crcBuf = (char *)malloc(50*sizeof(char));
	memset(crcBuf,0,50);
    socklen_t addrlen;
    uint32_t *ip_sav = (uint32_t *)malloc(sizeof(uint32_t));
    memset(ip_sav,0,4);
    uint32_t *ip ;
    int i;


    if(serverSettings->flags & MASK_SERVER_ISV6)
    {
    	addrlen = sizeof serverSettings->peerV6;
        snprintf(crcBuf,6,"%d",ntohs(serverSettings->peerV6.sin6_port));

        ip = &serverSettings->peerV6.sin6_addr.s6_addr32[3];
        //memcpy(ip,&serverSettings->peerV6.sin6_addr.s6_addr32[3],sizeof(uint32_t));

    }
    else
    {
    	addrlen = sizeof serverSettings->peerV4;
    	uint16_t port = ntohs(serverSettings->peerV4.sin_port);
    	LOG("Port is",port);
    	snprintf(crcBuf,6,"%d",port);
    	ip = (uint32_t *)&serverSettings->peerV4.sin_addr.s_addr;

    	//memcpy(ip,&serverSettings->peerV4.sin_addr.s_addr,sizeof(uint32_t));

    }
    LOG("value to copy is",*ip);
    LOG("HASHING the specified connection",*ip);

    uint8_t *copyip = (uint8_t *)ip;
    for(i=0;i<sizeof(uint32_t);i++)
	{
		crcBuf[6+i] = *(uint8_t *)&copyip[sizeof(uint32_t)-i-1];
		copyip++;

	}
    LOG(crcBuf,hash);
    result.process_bytes( crcBuf, 11 );
    hash = result.checksum();
    free(ip_sav);
    free(crcBuf);
    LOG("calculated HASH value is :",hash);
	return hash;
}

int DTLSServer::UDPAccept(int fd,struct sockaddr * addr,
		   socklen_t * addr_len,void *sockBuf)
{
    if(!sockBuf)
    	return -1;
	int childfd = -1;
    int error = 1;
    socklen_t localLen,peerLen;

    int family;
    struct sockaddr_in6        *local6;
    struct sockaddr_in         *local4;
    struct sockaddr_in            temp;
    memset(&temp,0,sizeof(struct sockaddr));
    size_t maxLen = 65535;
    localLen = sizeof(temp);
    getsockname(fd,(struct sockaddr *)&temp,&localLen);
    family = temp.sin_family;
    LOG("UDP family in accept is",family);
    hashkey_t hash;
    tfdMap::iterator ifdMap;
    do
    {
		childfd = socket(family,SOCK_DGRAM,0);
	    //SET SOCKET OPTIONS to be reused
		//This part is important even if the parent fd is resuing address if tthis option is not set we
		//will have bind failure
		int yes = 1;
	    error = setsockopt(childfd,SOL_SOCKET,SO_REUSEADDR,(const char *)&yes,sizeof(int));
	   // error = getsockopt(childfd,SOL_TCP,SO_REUSEADDR,(const char *)&yes,sizeof(int));
	     /*Set TCP window size if requested*/

	    if(error < 0) {
	     	LOG("Server::Listen: could not set options on listening socket:",childfd);
	     	LOG(strerror(errno),childfd);
	     	break;
	    }
		if(childfd <= 0)
		{
			break;
		}
		if(family == AF_INET6)
		{
			local6 = (sockaddr_in6 *)&temp;

			error = recvfrom( fd, sockBuf,
					maxLen,MSG_PEEK,(struct sockaddr *)&serverSettings->peerV6,
							         &peerLen);

			hash = hashing_fun();
			ifdMap = hashToFD.find(hash);
			if(ifdMap != hashToFD.end())
			{
				childfd = 0;
				LOG("FD already present in table skipping UDP accept",childfd);
				//I am hoping that the child fd queue has copied data
				recvfrom( fd, sockBuf,
									maxLen,0,(struct sockaddr *)&serverSettings->peerV6,
											         &peerLen);
				LOG("Let us empty listen recv queue",1);

				break;
			}
			error = bind(childfd,(struct sockaddr *)local6,sizeof serverSettings->peerV6);
			if(error < 0)
			{
				LOG("Failed in bind child socket",childfd);
				LOG(strerror(errno),1);
				break;

			}
			error = connect(childfd,(struct sockaddr *)&serverSettings->peerV6,peerLen);
			if(error < 0)
			{
				LOG("Failed in connect child socket",childfd);
				LOG(strerror(errno),1);

				break;

			}
		}
		else
		{
			local4 = &temp;
			recvfrom( fd, sockBuf,
								maxLen,MSG_PEEK,(struct sockaddr *)&serverSettings->peerV4,
										         &peerLen);
			hash = hashing_fun();
			ifdMap = hashToFD.find(hash);
			if(ifdMap != hashToFD.end())
			{

				LOG("Found childfd at hash:",childfd);
				childfd = 0;
				LOG("FD already present in table skipping UDP accept",childfd);
				//I am hoping that the child fd queue has copied data
				recvfrom( fd, sockBuf,
									maxLen,0,(struct sockaddr *)&serverSettings->peerV6,
													 &peerLen);
				LOG("Let us empty listen recv queue",1);
				LOG("hash is:",hash);
				break;
			}
			error = bind(childfd,(struct sockaddr *)local4,sizeof serverSettings->peerV4);
			if (error < 0)
			{
				LOG("Failed in bind child socket",childfd);
				LOG(strerror(errno),1);
				break;
			}
			error = connect(childfd,(struct sockaddr *)&serverSettings->peerV4,peerLen);
			if (error < 0)
			{
				LOG("Failed in connect child socket",childfd);
				LOG(strerror(errno),1);
				break;
			}

		}

      hashToFD.insert(std::make_pair(hash,childfd));
      LOG("Build pair",hash);
      LOG("Build fd",childfd);
      error = 0;
    }while(0);
    if(addr != NULL && addr_len != NULL)
    {
    	*addr_len = peerLen;
    	if (family == AF_INET6)
    		memcpy(addr,&serverSettings->peerV6,sizeof(sockaddr_in6));
    	else
    		memcpy(addr,&serverSettings->peerV4,sizeof(sockaddr_in));
    }

	if(error)
	{
		if(childfd > 0)
		{
			close(childfd);
		}
		childfd = 0;
	}

    return childfd;
}

SSL* DTLSServer::findSSL(int fd)
{
	tSSLMap::iterator iSSL;
	SSL *ssl;

	hashkey_t hash = hashing_fun();
	unsigned int pend;
	iSSL = connMap.find(hash);
	int rc;
	if(iSSL != connMap.end())
	{
		LOG("Found SSL at hash:",hash);
		return iSSL->second;

	}
	else
	{
	   /*
	    * First time entry for connection
	    * initialize by adding it to the map
	    * and call ssl_accept to initiate the handshake
	   */
	   ssl = initSSL();
	   LOG("Setting fd to ssl:",fd);
	   SSL_set_fd(ssl, fd);
	   if ((ssl) && ((rc = TLSAccept(hash,pend)) >= 0))
	   {
		   LOG("Handshake done",1);
	   }
	   return ssl;
	}
}


int DTLSServer::EPoll()
{
#ifdef DEBUG
	LOG("Called DTLS server",1);
#endif
    int timeout = serverSettings->timeout*1000;
    volatile int endServer = 0;
    struct epoll_event event;
    struct epoll_event *events;
    int rc;
    socklen_t addrlen;
    int i;
    int currentSize = 0;
    int newFd,fd;
    int efd;
    encapsHeader *packetHeader;
    std::map<int,pfdInfo>::iterator ifdInfoMap;
    char *filename;
    unsigned int pending;
    SSL *tempSSL;
    rc = configure();
    if(rc < 0)
    {
    	return -1;
    }
    efd = epoll_create(1000);
    if(efd == -1)
    {
        LOG("Server::EPoll():create1 errno:",errno);
        LOG(strerror(errno),1);
        return -1;
    }
    event.data.fd = serverSettings->lSock;
    int yes = 1;
    setsockopt(serverSettings->lSock,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(int));
    event.events = EPOLLIN;
    fd = epoll_ctl(efd,EPOLL_CTL_ADD,serverSettings->lSock,&event);
    if(fd == -1)
    {
        LOG("Server::EPoll():_epoll_ctl errno:",errno);
        LOG(strerror(errno),1);
        return -1;
    }
    //init events;
    pfdInfo connInfo = (pfdInfo)calloc(MAX_SOCKET_FD,sizeof(fdInfo));
    pfdInfo savePointer = connInfo;
    if(!connInfo)
    {
        LOG("Could not allocate connInfo",1);
        return -1;
    }
    events = (struct epoll_event*)calloc(MAX_SOCKET_FD,sizeof(events));
    if(!events)
    {
        LOG("Could not allocate events",1);
    	return -1;
    }
    do
    {
        /*call poll()*/

    	currentSize = epoll_wait(efd,events,MAX_SOCKET_FD,timeout);
    	if(currentSize <= 0)
    	{
    		LOG("Server::EPoll: epoll_wait() failed",1);
    		break;
    	}
    	for(int j = 0; j < currentSize;j++)
    	{
    		if((events[j].events == 0 )||(events[j].events != POLLIN))
			{
				continue;
			}
    		else
    		{
    			LOG("Event on following fds:",events[j].data.fd);
    		}
    	}
    	for(i = 0; i < currentSize;i++)
        {
            rc = 0;
    		if((events[i].events == 0 )||(events[i].events != POLLIN))
            {
            	continue;
            }
            if(events[i].data.fd == serverSettings->lSock)
            {

       	        newFd = 0;
       	        int count = 0;
       	        while((newFd != -1)) /* && (connections_accepted < MAX_NUM_OF_ACCEPTED_CONNS_PER_THREAD))*/
                {
       		    //ACCEPT CONNECTION

       	          char *sockTempBuf = (char *)malloc(sizeof(char)*65535);
       		      MUTEX_SOCKET_ACCEPT_LOCK;
       		      if((serverSettings->flags) & MASK_PEERB_ISV6) {
       		          addrlen = sizeof(serverSettings->peerBV6);

       			      newFd = UDPAccept(serverSettings->lSock,(struct sockaddr *) &serverSettings->peerBV6,
       				       &addrlen,sockTempBuf);
                  }
				  else {
       		           addrlen = sizeof(serverSettings->peerBV4);
       			        newFd = UDPAccept(serverSettings->lSock,(struct sockaddr *)&serverSettings->peerBV4,
       				       &addrlen,sockTempBuf);
                  }
       		      free(sockTempBuf);
       		      MUTEX_SOCKET_ACCEPT_UNLOCK;

                  if(newFd <= 0) {

       		        if(newFd == 0 && count <= 10)
       		            break;
       		        else
       		        	break;
                	if((errno != EWOULDBLOCK)||(errno !=EAGAIN)) {
                                   serverSettings->tstats.tNumConnectionErrors++;
       			    LOG("Server::Poll:accept failed on FD errno:",errno);
                                   LOG(strerror(errno),1);
                                   endServer = 1;
       			    }
       		        break;
                  }


				 serverSettings->connections++;
                 serverSettings->tstats.tNumConnections++;
                 count +=1;

#ifdef DEBUG
              	LOG("new incoming connection FD is:",newFd);
#endif
                  event.data.fd = newFd;
                  event.events = EPOLLIN ;
                  fd = epoll_ctl(efd,EPOLL_CTL_ADD,newFd,&event);
                  rc = fcntl(event.data.fd, F_GETFL,0);
				  rc |= O_NONBLOCK;
				  rc = fcntl(event.data.fd, F_SETFL,rc);
				 if(rc < 0)
				 {
					LOG("blocking error",1);
					break;
				 }
                  if((tempSSL = findSSL(event.data.fd)) != NULL) //We hope we are just creating the new ssl object here
                  {

                      serverSettings->tstats.tNumSecureConnections++;


                      connInfoInit(connInfo,newFd,
                      				 connInfo->tempbuffer,
                      				 connInfo->fileBufWriteIndex,
                      				 connInfo->fileBufReadIndex,connInfo->fileBufTail,
                      				 connInfo->fileBufIndex,file_head);

                      fdInfoMap.insert(std::make_pair(event.data.fd,connInfo));
                      connInfo->cSSL = tempSSL;
                      connInfo->sslPend = 1;

                      connInfo++;
                      filename = (char *)malloc(FILENAME_SIZE);
                      if((serverSettings->flags) & MASK_PEERB_ISV6)
                      {
                      	snprintf(filename,20,"Test%d",ntohs(serverSettings->peerBV6.sin6_port));
                      }
                      else
                      {
                          snprintf(filename,20,"Test%d",ntohs(serverSettings->peerBV4.sin_port));
                      }
                      if(filename)
                      {
                      	filenameMap.insert(std::make_pair(event.data.fd,filename));
                      }
                      else
                      {
                      	 LOG("Could not allocate filename",event.data.fd);
                      }
                  }

                  else
                  {
                  	endServer = 1;
                  	serverSettings->tstats.treHanshakeErrors++;
                  	LOG("TLS re-handshake error on:",event.data.fd);
                  	break;
                  }


                }

            }
            else
            {

            	rc = Process(NULL,events[i].data.fd);
            	if(rc < 0)
                {
#ifdef DEBUG
                     LOG("Close FD:",events[i].data.fd);
                     LOG("ALL data or error received on FD",events[i].data.fd);
#endif

                     epoll_ctl(efd,EPOLL_CTL_DEL,events[i].data.fd,NULL);

                }
            }
        }
        pthread_mutex_lock(&statslock);
        g_stats.tDataReceived += serverSettings->tstats.tDataReceived;
        g_stats.tNumConnectionErrors += serverSettings->tstats.tNumConnectionErrors;
        g_stats.tNumSecureConnections +=serverSettings->tstats.tNumSecureConnections;
        g_stats.tNumConnections += serverSettings->tstats.tNumConnections;
        g_stats.tTotalDataReceived += serverSettings->tstats.tTotalDataReceived;
        g_stats.treHandshakes += serverSettings->tstats.treHandshakes;
        g_stats.treHanshakeErrors += serverSettings->tstats.treHanshakeErrors;
        pthread_mutex_unlock(&statslock);

	    // Clear out internal stats.
	    serverSettings->tstats.tDataReceived = 0;
	    serverSettings->tstats.tNumConnectionErrors = 0;
	    serverSettings->tstats.tNumConnections = 0;
	    serverSettings->tstats.tTotalDataReceived = 0;
	    serverSettings->tstats.treHandshakes = 0;
	    serverSettings->tstats.treHanshakeErrors = 0;
	    serverSettings->tstats.tNumSecureConnections = 0;
    }while(endServer != 1);
	return 0;
}

void *read_server_spawn(void *inputSettings)
{
    return 0;
}
#ifdef DEBUG
void DTLSServer::testHashgen()
{

	serverSettings->peerBV4.sin_addr.s_addr = 1234;
	serverSettings->peerBV4.sin_port = 1234;
	LOG("Ruuning Test for hash ",serverSettings->peerBV4.sin_port);
	hashing_fun();

	serverSettings->peerBV4.sin_addr.s_addr = 4321;
	serverSettings->peerBV4.sin_port = 1234;
	LOG("Ruuning Test for hash ",serverSettings->peerBV4.sin_addr.s_addr);
	hashing_fun();

	serverSettings->peerBV4.sin_addr.s_addr = 1234;
	serverSettings->peerBV4.sin_port = 4321;

	hashing_fun();

	serverSettings->peerBV4.sin_addr.s_addr = 4321;
	serverSettings->peerBV4.sin_port = 4321;
	LOG("Ruuning Test for hash",serverSettings->peerBV4.sin_addr.s_addr);
	hashing_fun();
}
#endif

#if 0
	theServer->readPoll();
	return 0;
}

void testMapEntries(pfdInfo testfdInfoMap, uint8_t *head)
{

                    	std::ostringstream stats;
                    	int sizesave = stats.tellp();
                    	stats << "----------BEGIN DETAILED STATS----------\n";


                            stats << testfdInfoMap->Connid << " |";

                    		printf("tempbuffer:%p | \n",testfdInfoMap->tempbuffer) ;
                    		if(head)
                    		    printf("head: %p\n",head);
                            printf("BufIndex: %p\n",testfdInfoMap->fileBufIndex);
                    		printf("tail:%p | ",testfdInfoMap->fileBufTail) ;
                    		printf("Windex:%p | ",testfdInfoMap->fileBufWriteIndex) ;
                    		printf("Rindex:%p | \n",testfdInfoMap->fileBufReadIndex) ;



                    		printf("readable:%u \n",testfdInfoMap->isReadable);
                    		printf("writable:%u \n",testfdInfoMap->isWriteable);
                    		printf("writeE:%u \n",testfdInfoMap->writeEvent);
                    		printf("readE:%u \n",testfdInfoMap->readEvent);
                    	    stats << "\n" ;
                    	    stats << "----------END STATS----------\n";
                    	    printf("%s",stats.str().c_str());


                    	/*fwrite the buffer*/

}

int Server::readPoll()
{
    int rc;
    socklen_t addrlen;
    int i;
    int currentSize = 0;
    int newFd,fd;
    int efd;
    int timeout = serverSettings->timeout*1000;
    volatile int endServer = 0;
    struct epoll_event event;
    struct epoll_event *events;
    pmsgq tempFdread = fdQ;
    static bool checkEmpty=false;
    /*create a epoll fd*/
    efd = epoll_create(1000);
    if(efd == -1)
    {
        LOG("Server::EPoll():create1 errno:",errno);
        LOG(strerror(errno),1);
        return -1;
    }
    memset(&event,0,sizeof(event));
    events = (struct epoll_event*)calloc(MAX_SOCKET_FD,sizeof(events));
    if(!events)
    {
        LOG("Could not allocate events",1);
    	return -1;
    }
    /*Add to epoll table after poping from the queue
     * update queue*/
addToTable:
    checkEmpty=true;
    for(;;)
    {

        	if(!tempFdread->fdQueue.empty())
        	{

        		pthread_mutex_lock(&tempFdread->msgqLock);
        		newFd = tempFdread->fdQueue.front();
                tempFdread->fdQueue.pop();
                pthread_mutex_unlock(&tempFdread->msgqLock);
#ifdef DEBUG
                LOG("poped and received FD:",newFd);
#endif
                event.data.fd = newFd;
                /*Level triggered no EPOLLET*/
                event.events = EPOLLIN;

                fd = epoll_ctl(efd,EPOLL_CTL_ADD,newFd,&event);
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

        /*Add to table*/
    	if((!checkEmpty)||tempFdread->signalPush == 1)
    	{
#ifdef DEBUG
    		LOG("Getting push request again",tempFdread->signalPush);
#endif
    		goto addToTable;
    	}

    	currentSize = epoll_wait(efd,events,MAX_SOCKET_FD,timeout);
    	if(currentSize <= 0)
    	{
        	if((!checkEmpty)||tempFdread->signalPush == 1)
        	{
#ifdef DEBUG
        		LOG("Getting push request again",tempFdread->signalPush);
#endif
        		goto addToTable;
        	}
        	else
                break;

    	}
    	for(i = 0; i < currentSize;i++)
        {
            if((events[i].events == 0 )||(events[i].events != POLLIN))
            {

            	continue;
            }

                rc = readProcess(events[i].data.fd);
            	if(rc < 0)
                {
#ifdef DEBUG
                  	 LOG("Close FD:",events[i].data.fd);

#endif
                  	shutdown(events[i].data.fd,0);
                  	close(events[i].data.fd);


                }
        }

    }while(1);
    return rc;
}
#endif
