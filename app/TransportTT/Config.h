#ifndef _CONFIGH
#define _CONFIGH
/*
 *  This file has the following declarations
 *  structure config which is the thread Configuration structure.
 *  structure declarations for reporting mechanism.
 *  Miscellaneous #defines
*/
#include <openssl/md5.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#ifdef __cplusplus
extern "C"
{
#endif
extern pthread_mutex_t mutexLog;
extern pthread_mutex_t statslock;
extern pthread_mutex_t reportMutex;
extern pthread_cond_t  reportCond;
extern pthread_mutex_t replayMutex;
extern pthread_cond_t  replayCond;
extern pthread_mutex_t liblock;
extern pthread_mutex_t readFinishMutex;
extern pthread_cond_t  readFinishCond;
extern pthread_cond_t  writeStart;
extern pthread_mutex_t writeStartMutex;
extern pthread_mutex_t readStartMutex;
extern pthread_cond_t  readStart;
extern pthread_mutex_t socketAcceptMutex;
extern pthread_mutex_t coreCounterMutex;

extern int g_clientThread;
extern int g_clientReadThread;
extern int g_serverThread;
extern long int g_testFileSize;
extern int g_verbose;
extern int g_md5MatchFail;
extern unsigned int g_testFiles;
#define LOG(msg,error) \
  warn_errno(msg,error,__FILE__,__LINE__)

#define MAX_BUFFER_LEN 3000
#define MIN_BUFFER_LEN 1
#define MAX_FILE_SIZE (1024*1024*20)
#define MIN_AMOUNT_SENT 1000
#define MAX_SERVER_THREAD 4
#define ENCAPS_HEADER_PROTO 3003
/*These defines are for proper client thread type*/
#define DEFAULT       0
#define PROTOCOL_SSL  0
#define PROTOCOL_TLS  1
#define PROTOCOL_DTLS 2
#define PROTOCOL_TCP  IPPROTO_TCP
#define PROTOCOL_UDP  IPPROTO_UDP
#define ENDP  1509
#define ACKEP 3003
/*end*/
#define MAX_SOCKET_FD    80000
#define MAX_THREAD       500
#define INVALID_SOCKET   -1
#define DEFAULT_PORT     5001
#define MAX_PORT_NUMBER  65335
#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN   0x8100
#endif

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6  0x86dd
#endif

#define MD5_DIGEST_SIZE  16
#define CLIENT_ONLY      1
#define SERVER_ONLY      2
#define DUAL_TEST        3
/*Error defines*/
#define MUTEX_WRITE_START_INIT      pthread_mutex_init(&writeStartMutex,NULL)
#define COND_WRITE_START_INIT       pthread_cond_init(&writeStart, NULL)
#define MUTEX_WRITE_START_DESTROY   pthread_mutex_destroy(&writeStartMutex)
#define COND_WRITE_START_DESTROY    pthread_cond_destroy(&writeStart)
#define WRITE_START_WAIT            pthread_cond_wait(&writeStart, &writeStartMutex)
#define WRITE_START_BROADCAST       pthread_cond_broadcast(&writeStart)
#define WRITE_MUTEX_LOCK            pthread_mutex_lock(&writeStartMutex)
#define WRITE_MUTEX_UNLOCK          pthread_mutex_unlock(&writeStartMutex)

#define MUTEX_READ_START_INIT      pthread_mutex_init(&readStartMutex,NULL)
#define COND_READ_START_INIT       pthread_cond_init(&readStart, NULL)
#define MUTEX_READ_START_DESTROY   pthread_mutex_destroy(&readStartMutex)
#define COND_READ_START_DESTROY    pthread_cond_destroy(&readStart)
#define READ_START_WAIT            pthread_cond_wait(&readStart, &readStartMutex)
#define READ_START_BROADCAST       pthread_cond_broadcast(&readStart)
#define READ_MUTEX_LOCK            pthread_mutex_lock(&readStartMutex)
#define READ_MUTEX_UNLOCK          pthread_mutex_unlock(&readStartMutex)

#define MUTEX_LOG_INIT      		pthread_mutex_init(&mutexLog,NULL)
#define MUTEX_GLOBAL_STATS_INIT     pthread_mutex_init(&statslock,NULL)
#define MUTEX_GLOBAL_STATS_DESTROY	pthread_mutex_destroy(&statslock)
#define MUTEX_LOG_DESTROY   		pthread_mutex_destroy(&mutexLog)
#define MUTEX_LIBLOCK_INIT          pthread_mutex_init(&liblock,NULL)
#define MUTEX_LIBLOCK_DESTROY       pthread_mutex_destroy(&liblock)
#define COND_REPORT_EXIT_INIT       pthread_cond_init(&reportCond, NULL)
#define COND_REPORT_EXIT_DESTROY    pthread_cond_destroy(&reportCond)
#define MUTEX_REPLAY_INIT           pthread_mutex_init(&reportMutex, NULL)
#define MUTEX_COND_REPLAY_INIT      pthread_cond_init(&replayCond, NULL)
#define MUTEX_REPLAY_EXIT           pthread_mutex_destroy(&reportMutex)
#define MUTEX_COND_REPLAY_EXIT      pthread_cond_destroy(&replayCond)
#define REPORT_THREAD_WAIT          pthread_cond_wait(&reportCond, &reportMutex)
#define REPORT_THREAD_BROADCAST     pthread_cond_broadcast(&reportCond)
#define REPORT_THREAD_LOCK          pthread_mutex_lock(&reportMutex)
#define REPORT_THREAD_UNLOCK        pthread_mutex_unlock(&reportMutex)

#define REPLAY_THREAD_WAIT          pthread_cond_wait(&replayCond, &replayMutex)
#define REPLAY_THREAD_BROADCAST     pthread_cond_broadcast(&replayCond)

#define READ_FINISH_MUTEX_INIT      pthread_mutex_init(&readFinishMutex,NULL)
#define READ_FINISH_MUTEX_DESTROY   pthread_mutex_destroy(&readFinishMutex)
#define READ_FINISH_COND_INIT       pthread_cond_init(&readFinishCond, NULL)
#define READ_FINISH_COND_DESTROY    pthread_cond_destroy(&readFinishCond)
#define READ_FINISH_MUTEX_LOCK      pthread_mutex_lock(&readFinishMutex)
#define READ_FINISH_MUTEX_UNLOCK    pthread_mutex_unlock(&readFinishMutex)
#define READ_THREAD_FIN_BROADCAST   pthread_cond_broadcast(&readFinishCond)
#define READ_THREAD_FIN_WAIT        pthread_cond_wait(&readFinishCond,&readFinishMutex)

#define MUTEX_SOCKET_ACCEPT_INIT    pthread_mutex_init(&socketAcceptMutex, NULL)
#define MUTEX_SOCKET_ACCEPT_LOCK    pthread_mutex_lock(&socketAcceptMutex)
#define MUTEX_SOCKET_ACCEPT_UNLOCK  pthread_mutex_unlock(&socketAcceptMutex)
#define MUTEX_SOCKET_ACCEPT_DESTROY pthread_mutex_destroy(&socketAcceptMutex)

#define MUTEX_CORE_COUNTER_INIT    pthread_mutex_init(&coreCounterMutex, NULL)
#define MUTEX_CORE_COUNTER_LOCK    pthread_mutex_lock(&coreCounterMutex)
#define MUTEX_CORE_COUNTER_UNLOCK  pthread_mutex_unlock(&coreCounterMutex)
#define MUTEX_CORE_COUNTER_DESTROY pthread_mutex_destroy(&coreCounterMutex)

/*FLAGS*/
#define MASK_BUFLENSET          0x00000001
#define MASK_ISIPV6             0x00000002
#define MASK_FILEINPUT          0x00000004
#define MASK_TIME_MODE          0x00000008
#define MASK_PROTODEFINED       0x00000010
#define MASK_CLIENT_ISV6        0x00000020
#define MASK_SERVER_ISV6        0x00000040
#define MASK_PEERB_ISV6         0x00000080
#define MASK_SERVER_PROTOCOL    0x00000100
#define MASK_CA_VERIFY          0x00000200
#define MASK_CLIENT_RECONNECT   0x00000400
#define MASK_AUTH_FLAGS         0x00007000
#define MASK_REHANDSHAKE        0x00008000
#define MAASK_TCP_WINDOW        0x00010000
#define MASK_ECHO_TEST          0x00020000
#define MASK_CLIENT_NODELAY     0x00040000
#define MASK_VERBOSE            0x00080000
#define MASK_FILECREATE         0x00100000
#define MASK_CLOSE_WAIT         0x00200000
#define MASK_SINGLE_CORE        0x00400000
/*END FLAGS*/

/*SHIFTS FLAGS*/
#define setIPV6(settings)          settings->flags |= MASK_ISIPV6
#define setFileInput(settings)     settings->flags |= MASK_FILEINPUT
#define SHIFT_BUFLENSET            1 << 0
#define SHIFT_TIME_MODE            1 << 3
#define SHIFT_PROTOCOL             1 << 4
#define SHIFT_CLIENT_ISV6          1 << 5
#define SHIFT_SERVER_ISV6          1 << 6
#define SHIFT_PEERB_ISV6           1 << 7
#define SHIFT_SERVER_PROTOCOL      1 << 8
#define SHIFT_CA_VERIFY            1 << 9
#define SHIFT_CLIENT_RECONNECT     1 << 10
#define SHIFT_PEER_VERIFY          1 << 12
#define SHIFT_PEER_RESPOND         1 << 13
#define SHIFT_NO_VERIFY            1 << 14
#define SHIFT_REHANDSHAKE          1 << 15
#define SHIFT_WINDOW_SET           1 << 16
#define SHIFT_ECHO_TEST            1 << 17
#define SHIFT_CLIENT_NODELAY       1 << 18
#define SHIFT_VERBOSE              1 << 19
#define SHIFT_FILECREATE           1 << 20
#define SHIFT_CLOSE_WAIT           1 << 21
#define SHIFT_SINGLE_CORE          1 << 22
/*end SHIFT FLAGS*/

/*ERROR DEFINES*/
#define ERROR_CONFIGURATION_NOT_COMPLETE                               100
#define ERROR_SPECIFY_PROTOCOL                                         101
#define ERROR_SPECIFY_FILE                                             102
#define ERROR_IP_PORT_ADDRESS                                          103
#define ERROR_CONNECTIONS_NOT_CREATED                                  200
#define ERROR_PORT_ALREADY_IN_USE                                      201
#define ERROR_ACCEPT_FAILED                                            202
#define ERROR_HANDSHAKE_COMPLETE                                       203
#define ERROR_DATA_NOT_RECEIVED                                        300
#define ERROR_ALL_PACKETS_NOT_RECEIVED                                 301
/*END ERROR DEFINES*/

#define MAX_NUMBER_OF_CORES              20 // Just picked a large number.

#define FILENAME_SIZE                    20
typedef struct stats
{
    unsigned int        tNumConnections;
    unsigned int        tNumSecureConnections;
    unsigned int        tNumConnectionErrors;
    unsigned int        tDataTransfered;
    unsigned int        tDataReceived;
    double              tDataTransferRate;
    double              tDataReceiveRate;
    double              tEDataTransferRate;
    double              tconnectionRate;
    unsigned long int   tTotalDataTransfered;
    unsigned long int   tTotalDataReceived;
    unsigned int        tAverageData;
    unsigned int        tAverageDataReceived;
    unsigned int        treHandshakes;
    unsigned long int   tcomparePass;
    unsigned long int   tcompareFail;
    unsigned int        treHanshakeErrors;
    double              tjitter;
    unsigned int        errorEagain;
    unsigned char       md5sum[MD5_DIGEST_SIZE];
    unsigned char       md5sumwrite[MD5_DIGEST_SIZE];
    unsigned char       md5sumcmp[MD5_DIGEST_SIZE];
}stats, *pStats;


typedef struct config
{
    char*                      mFileName;                  /*Input file*/
    char*                      ciphers;
    char*                      keyFile;
    char*                      ca_list;
    int                        mBufLen;                    /*Size of write buffer*/
    int                        connections;                /*Number of connections per thread*/
    u_int64_t                  mAmount;                    /*Amount in bytes to be sent out to server*/
    double                     time;                       /*Time to continue test does not send anything out*/
    double                     delay;                      /*Delay between connects for a thread*/
    int                        clientType;                 /*Derived from protocol*/
    int                        serverType;
    char                       protocol[10];               /*Client type TCP|TLS|UDP*/
    int                        pThread;                    /*Number of client threads*/
    struct in6_addr            clientAddr;                 /*Client IP address*/
    u_int16_t                  clientPort;                 /*Client port*/
    struct in6_addr            serverAddr;                 /*Server IP address*/
    u_int16_t                  serverPort;                 /*Server port*/
    struct in6_addr            peerAddr;                   /*Peer address server|client*/
    u_int16_t                  peerPort;                   /*Peer port*/
    struct in6_addr            peerBAddr;                  /*Peer address server|client*/
    u_int16_t                  peerBPort;                  /*Peer port*/
    u_int16_t                  timeout;                    /*Server timeout*/
    FILE*                      Extractor_file;             /*File for input*/
    unsigned short             testType;                   /*1=CLIENT_ONLY 2=SERVER_ONLY 3=DUAL_TEST*/
    int                        flags;                      /* --->>flags for configuration<<--- */

    unsigned int               tcpWindow;                 /*TCP window size option*/
    int                        mSockFd[MAX_SOCKET_FD];     /*number of connections per thread*/

    int                        lSock;                      /*Listening socket for server threads*/
    stats                      tstats;                     /*thread stats*/
    struct sockaddr_in6        peerV6;                     /*peer information for connection*/
    struct sockaddr_in         peerV4;
    struct sockaddr_in6        peerBV6;                    /*peer information for connection*/
    struct sockaddr_in         peerBV4;
    struct sockaddr_in6        serverV6;                    /*server information for connection*/
    struct sockaddr_in         serverV4;
    struct sockaddr_in6        clientV6;                   /*client information for connection*/
    struct sockaddr_in         clientV4;
    pthread_t                  id;                         /*Thread Id*/
    int                        coreId;
    void                       *serverClass;
}config, *pConfig;

typedef struct connectionInfo
{
	int                Connid;
	char              *tempbuffer;

	/*Index on read and write parts*/
	uint8_t           *fileBufIndex;
    uint8_t           *fileBufWriteIndex;
    uint8_t           *fileBufReadIndex;
    uint8_t           *fileBufTail;

    /*Event Flags*/
    unsigned int       isReadable:1;
    unsigned int       isWriteable:1;
    unsigned int       readEvent:1; /*checking if read events happen after partial reads for level triggered logic*/
    unsigned int       writeEvent:1;
    pthread_mutex_t    connLock;
    unsigned int       sslPend:1;

    /*per connection stats on server*/
    stats              connStats;
    stats              clientStats;
    MD5_CTX            md5sum;
    MD5_CTX            md5sumwrite;
    SSL                *cSSL;
    int                state;

}fdInfo,*pfdInfo;

/*Forward declarations*/
void warn_errno( const char *inMessage, int error,const char *inFile, int inLine );
void crashHandler(int signum);
void fileInitialize ( const char *fileName, config *inputSettings, long int *size);
int  fileBlockCopyToBuffer(char *readData,config *inputSettings);
int  in6_pton(char *addr, struct in6_addr *in6_addr);
int  in6_isAddrV6(struct in6_addr *in6_addr);
void in6_zeroAddr(struct in6_addr *in6_addr);
int in6_isAddrZero(struct in6_addr *in6_addr);
int  configParseCommandLine( int argc, char **argv, config* Settings );
int  configCopyClientSettings(config *inputSettings,config **outputSettings);
int  configClientInitialize(config *inputSettings);
void *client_spawn( void *inputSettings );

void *report_spawn(void *);
void *client_read_spawn(void *inputSettings);
void create_client_read_thread(config* inputSettings);
//void create_server_thread(config* inputSettings);
pthread_t create_server_thread(config* inputSettings);
void createReportThread(void *inputSettings);
void create_client_thread(config* inputSettings);
int configServerInitialize(config *inputSettings);

void toolWrapup();
void toolAlarmWrapup(int signum);
void printConfig(const char *function,config *inputSettings);
int getTestFile(char *filename,char *buf,int size, long compareSize);
void getErrorFromHeaderMap(stats *stats);
int setTcpWindow(int socket, unsigned int size);
void print_buffer(uint8_t *buffer, uint16_t bufferLen, const char *file, int line);
int CompleteFileMemCopy(char *readData,config *inputSettings, long int size);
void print_results(config *config,int type);
//void detailDisplayConnections(const char *filename);
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
#include <boost/asio.hpp>
extern boost::asio::io_service g_io;
void connInfoInit(fdInfo *connInfo,int newFd,
		char *&buffer,uint8_t *&indexwrite,
		uint8_t *&indexread,uint8_t *&tail, uint8_t *&fileIndex, uint8_t *head);
void connInfoDestroy(fdInfo *&connInfo);
void testMapEntries(fdInfo *connInfo, uint8_t *head);
#endif
#endif
