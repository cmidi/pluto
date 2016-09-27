/*Test Configuration file*/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include "Config.h"
#include <unistd.h>
extern stats g_stats;
extern stats g_cStats;
extern int g_stopReport;

static const char usage[] =
        "Transport_Test [options]\n"
        "\t--pra      [x]\t Peer(SD server address) IPv4/IPv6 address\n"
        "\t--prp      [x]\t Peer(SD server port) port\n"
        "\t--pbra     [x]\t Peer(SD client address) IPv4/IPv6 address\n"
        "\t--pbrp     [x]\t Peer(SD client port) port\n"
        "\t--cla      [x]\t client IPv4/IPv6 address\n"
        "\t--clp      [x]\t client port\n"
        "\t--sra      [x]\t server IPv4/IPv6 address\n"
        "\t--srp      [x]\t server port\n"
        "\t--proto    [x]\t Protocol for client \n"
        "\t--len      [x]\t Length of buffer\n"
        "\t--time     [x]\t Time for running tests\n"
        "\t--interval [x]\t Delay between connections\n"
        "\t--type     [x]\t Test type Client|Server|Dual\n"
       	"\t--tmo      [x]\t Timeout(in secs)\n"
		"\t--wait\n"
		"\t--create      \t Create test files\n"
        "\t--help        \t Usage\n"
        "\n"
        "\t-f    [x]\t  Input file name(location)\n"
        "\t-i    [x]\t  Interval between each connection to be made\n"
        "\t-t    [x]\t  Time to send connections out for(no traffic)\n"
        "\t-l    [x]\t  Buffer length for each data to be sent out\n"
        "\t-a    [x]\t  amount of data on each connection to be sent out\n"
        "\t-n    [x]\t  Number of connections per thread\n"
        "\t-P    [x]\t  Number of threads of clients\n"
        "\t-S    [x]\t  Single thread server\n"
        "\t-p    [x]\t  Client type TCP|TLS|UDP|DTLS\n"
		"\t-s    [x]\t  Server type TCP|TLS|UDP|DTLS\n"
        "\t-k    [x]\t  Input key file name(location)\n"
        "\t-c    [x]\t  Input CA LIST file name(location)\n"
        "\t-C    [x]\t  Cipher List\n"
        "\t-r       \t  Client Reconnect option flag set\n"
        "\t-R       \t  Server re-handshake option set\n"
        "\t-v       \t  Server verify request flag\n"
        "\t-V       \t  Server verify respond flag\n"
        "\t-x       \t  Server no verify flag\n"
		"\t-e       \t  Server Echos read traffic\n"
		"\t-d       \t  Socket no delay set\n"
        "\t-h       \t  Help\n";

void crashHandler(int signum)
{
    void *crashDump[10];
    size_t size;
    size = backtrace(crashDump,10);
    fprintf(stdout,"Segmentation fault : %d trace:\n",signum);
    backtrace_symbols_fd(crashDump,size,STDOUT_FILENO);
    fprintf(stdout,"=====REACHED FAULT======");
    exit(1);
}

void warn_errno( const char *inMessage, int error,const char *inFile, int inLine )
{
/*Dont create a errorlog file for embtest version*/
#ifndef EMBTEST
    const char* log = "errorlog.txt";
    FILE* logFile = NULL;
    char timeBuf[100];
    time_t now;
    struct tm *logtime1;

    time(&now);
    logtime1 = localtime(&now);
    strftime(timeBuf,sizeof(timeBuf),"[%Y-%m-%d %H:%M:%S]",logtime1);
    pthread_mutex_lock(&mutexLog);
    logFile = fopen(log,"a");
    if(logFile != NULL)
    {
    	fflush( 0 );
        fprintf(logFile, "%s\t%s %d at (%s:%d)(%lx)\n",timeBuf,
	    inMessage, error,inFile, inLine,(unsigned long)pthread_self());
        fclose(logFile);
    }
    pthread_mutex_unlock(&mutexLog);
#endif


}

void print_buffer(uint8_t *buffer, uint16_t bufferLen, const char *file, int line)
{
    int i;
    uint8_t *print_ptr = buffer;
    if(!print_ptr)
    	return;
    FILE* headerFile = NULL;
    pthread_mutex_lock(&mutexLog);
    headerFile = fopen ("Header.txt","a");
    if(!headerFile)
    	return;
    fprintf(headerFile,"\n -----------FAILED MEM-COMPARE BUFFER-------- \n");
    fprintf(headerFile,"%s: buf_len = %d, data = %p file :%s %d\n", __FUNCTION__, bufferLen, buffer,file,line);

    for (i = 0; i < (bufferLen); i++)
    {
        if ((i % 16) == 0)
        {
            fprintf(headerFile,"\n%p:  ", (print_ptr+i));
        }
        else if (i%4 == 0)
        {
            fprintf(headerFile," ");
        }
        fprintf(headerFile,"%02x ", *(print_ptr + i));
    }
    fprintf(headerFile,"\n\n");
    fclose(headerFile);
    pthread_mutex_unlock(&mutexLog);
}

int getTestFile(char *filename,char *buf,int size, long compareSize)
{
    int rc = -1;
    struct stat fileStatCode;
    long filesize;
    long difference;
    FILE* testFile = NULL;
    if(buf)
    {
        testFile = fopen(filename,"a");
        if(testFile)
        {
            if (stat(filename, &fileStatCode) == 0)
            {
                filesize = fileStatCode.st_size;
            }
            fflush(0);
            if((filesize+(long)size) <= compareSize)
            {
                rc = fwrite(buf,1,size,testFile);
            }
            else
            {
            	difference = compareSize - filesize;
            	rc = fwrite(buf,1,difference,testFile);
#ifdef DEBUG
                LOG("bytes written:",difference);
#endif
            }
            fclose(testFile);

        }
        else
            LOG("Could not create file",errno);
    }
    else
       LOG("NULL test buffer",1);
    return rc;
}


int in6_pton(char *addr, struct in6_addr *in6_addr)
{
    if(strstr(addr, ".") != NULL)
    {
        in6_addr->s6_addr32[0] = in6_addr->s6_addr32[1] = in6_addr->s6_addr32[2] = 0;
        return inet_pton(AF_INET, addr, &in6_addr->s6_addr32[3]);
    }
    else if(strstr(addr, ":") != NULL)
    {
        return inet_pton(AF_INET6, addr, in6_addr);
    }

    return 0;
}

int in6_isAddrV6(struct in6_addr *in6_addr)
{

	if(in6_addr->s6_addr32[0] != 0 ||
       in6_addr->s6_addr32[1] != 0 ||
       in6_addr->s6_addr32[2] != 0)
    {
        return 1;
    }

    return 0;
}

void in6_zeroAddr(struct in6_addr *in6_addr)
{
    in6_addr->s6_addr32[0] = 0;
    in6_addr->s6_addr32[1] = 0;
    in6_addr->s6_addr32[2] = 0;
    in6_addr->s6_addr32[3] = 0;

}

int in6_isAddrZero(struct in6_addr *in6_addr)
{
    if(in6_addr->s6_addr32[0] == 0 &&
       in6_addr->s6_addr32[1] == 0 &&
       in6_addr->s6_addr32[2] == 0 &&
       in6_addr->s6_addr32[3] == 0)
    {
        return 1;
    }
    return 0;
}

void create_client_thread(config* inputSettings)
{
	if( pthread_create(&inputSettings->id,NULL,client_spawn,(void *)inputSettings ) != 0)
	{
        LOG("could not create client thread",1);
		printf("could not create client thread\n");
		exit(1);
	}

}

void create_client_read_thread(config* inputSettings)
{
    if(pthread_create(&inputSettings->id,NULL,client_read_spawn,(void *)inputSettings) !=0)
    {
        LOG("Could not create client read thread",1);
        printf("Could not create client thread\n");
        exit(1);
    }
}

/*
 * Function: createReportThread
 *
 * Description: Create the main report thread
 *
 * return: none
 *
 */
void createReportThread(void *inputSettings)
{
  if( pthread_create(&(((config *)inputSettings)->id),NULL,report_spawn,(void *)0 ) != 0)
	{
        LOG("could not create client thread",1);
		printf("could not create client thread\n");
		exit(1);
	}

}

/*
 * Parses the args using GNU getopt_log()
 * and passes values to the config structure
 * */
int configParseCommandLine( int argc, char **argv, config* Settings )
{
    int success = 0;
    static struct option long_options[] =
    {
	    {"pra",        required_argument,  0,   0},
	    {"prp",        required_argument,  0,   0},
	    {"pbra",        required_argument,  0,   0},
	    {"pbrp",        required_argument,  0,   0},
	    {"cla",        required_argument,  0,   0},
	    {"clp",        required_argument,  0,   0},
	    {"sra",        required_argument,  0,   0},
	    {"srp",        required_argument,  0,   0},
	    {"proto",      required_argument,  0, 'p'},
	    {"len",        required_argument,  0, 'l'},
	    {"time",       required_argument,  0, 't'},
	    {"interval",   required_argument,  0, 'i'},
	    {"type",       required_argument,  0,   0},
	    {"help",             no_argument,  0, 'h'},
	    {"amt",        required_argument,  0, 'a'},
	    {"tmo" ,        required_argument,  0,  0},
	    {"detail",           no_argument,   0,  0},
	    {"wait",             no_argument,   0,  0},
	    {"create",           no_argument,   0,  0},
	    /*do not remove this*/
	    {0,0,0,0}
    };
    static char * short_options = "f:k:C:c:i:t:l:n:P:hp:a:s:rSRvVxed";
    int opt_index = 0, opt = 0;

    while((opt = getopt_long(argc, argv, short_options, long_options, &opt_index)) != -1)
    {
    	 switch(opt)
         {
             case 'f':
                 setFileInput(Settings);
                 Settings->mFileName = (char*)malloc(sizeof(char)*100);
                 if(Settings->mFileName)
                     strcpy(Settings->mFileName,optarg);
                 break;
             case 'k':
                 Settings->keyFile = (char*)malloc(sizeof(char)*100);
                 if(Settings->keyFile)
                     strcpy(Settings->keyFile,optarg);
                 break;
             case 'c':
                 Settings->flags |= SHIFT_CA_VERIFY;
                 Settings->ca_list = (char*)malloc(sizeof(char)*100);
                 if(Settings->ca_list)
                     strcpy(Settings->ca_list,optarg);
                 break;
             case 'C':
                 Settings->ciphers = (char*)malloc(sizeof(char)*600);
                 if(Settings->ciphers)
                     strcpy(Settings->ciphers,optarg);
                 break;
             case 'a':
                 Settings->mAmount = (u_int64_t)atoi(optarg); //can have function call for Mb,Kb returns
            	 break;
             case 'i':
                 Settings->delay = atof(optarg)*100;
                 if(Settings->delay < 0)
                 {
                	 Settings->delay = 1;
                 }
                 break;
             case 't':
                 Settings->flags |= SHIFT_TIME_MODE; /*time mode flag*/
                 Settings->time =  atof(optarg)*100;
                 break;

             case 'l':
                 Settings->flags |= SHIFT_BUFLENSET;
                 Settings->mBufLen = atoi(optarg);
                 if(Settings->mBufLen > MAX_BUFFER_LEN)
                 {
                	 Settings->mBufLen = MAX_BUFFER_LEN;
                 }
                 if(Settings->mBufLen == 0)
                 {
                	 Settings->mBufLen = MIN_BUFFER_LEN;
                 }
                 break;
             case 'n':
                 Settings->connections = atoi(optarg); /*connections would be set to 1 for default class TCP in client settings*/
                 if(Settings->connections > MAX_SOCKET_FD)
                	 Settings->connections = MAX_SOCKET_FD;
                 break;
             case 'P':
                 Settings->pThread = atoi(optarg);
                 if(Settings->pThread > MAX_THREAD)
                	 Settings->pThread = MAX_THREAD;
                 break;
             case 'S':
            	 Settings->flags |= SHIFT_SINGLE_CORE;
            	 break;
             case 'p':/*0=DEFAULT TCP one connection per thread | TCP | TLS | UDP*/
                 Settings->flags |= SHIFT_PROTOCOL;
                 strncpy(Settings->protocol,optarg,(sizeof(char)*10));
            	 if(strcasecmp(Settings->protocol,"TCP")==0)
            	 {
                     Settings->clientType = PROTOCOL_TCP;
            	 }
            	 else if(strcasecmp(Settings->protocol,"UDP")==0)
            	 {
            		 Settings->clientType = PROTOCOL_UDP;
            	 }
            	 else if(strcasecmp(Settings->protocol,"TLS")==0)
            	 {
            		 Settings->clientType = PROTOCOL_TLS;
            	 }
            	 else if(strcasecmp(Settings->protocol,"DTLS")==0)
            	 {
            		 Settings->clientType = PROTOCOL_DTLS;
            	 }
            	 else
            	 {
            		 Settings->clientType = DEFAULT;
            	 }
                 break;
             case 's':/*0=DEFAULT TCP one connection per thread | TCP | TLS | UDP*/
                 Settings->flags |= SHIFT_SERVER_PROTOCOL;
                 strncpy(Settings->protocol,optarg,(sizeof(char)*10));
            	 if(strcasecmp(Settings->protocol,"TCP")==0)
            	 {
                     Settings->serverType = PROTOCOL_TCP;
            	 }
            	 else if(strcasecmp(Settings->protocol,"UDP")==0)
            	 {
            		 Settings->serverType = PROTOCOL_UDP;
            	 }
            	 else if(strcasecmp(Settings->protocol,"TLS")==0)
            	 {
            		 Settings->serverType = PROTOCOL_TLS;
            	 }
            	 else if(strcasecmp(Settings->protocol,"DTLS")==0)
				 {
					 Settings->serverType = PROTOCOL_DTLS;
				 }
            	 else
            	 {
            		 Settings->serverType = DEFAULT;
            	 }
                 break;
	     /*TLS/SSL FLAGS*/
             case 'r':
                 Settings->flags |= SHIFT_CLIENT_RECONNECT;
                 break;
             case 'R':
	         Settings->flags |=SHIFT_REHANDSHAKE;
                 break;
             case 'v':
                 Settings->flags |= SHIFT_PEER_VERIFY;
                 break;
             case 'V':
                 Settings->flags |= SHIFT_PEER_RESPOND;
                 break;
             case 'x':
                 Settings->flags |= SHIFT_NO_VERIFY;
                 break;
             case 'e':
                 Settings->flags |= SHIFT_ECHO_TEST;
                 break;
             case 'd':
            	 Settings->flags |= SHIFT_CLIENT_NODELAY;
            	 break;
             case 'h':
                 printf("Syntax:\n%s\n",usage);
                 return -2;
                 break;
             case 0:
                 if(strcmp("pra",long_options[opt_index].name)==0)
                 {
                	 if(!in6_pton(optarg, &(Settings->peerAddr)))
                	 {
                	     printf("Unable to process peer address %s!\n",optarg);
                	     return false;
                	 }
                     if(in6_isAddrV6(&(Settings->peerAddr)))
                     {
                         setIPV6(Settings);
                     }
                 }
                 else if(strcmp("prp",long_options[opt_index].name)==0)
                 {
                     Settings->peerPort = (u_int16_t)atoi(optarg);
                     if(Settings->peerPort > MAX_PORT_NUMBER)
                     {
                    	 Settings->peerPort = DEFAULT_PORT;
                     }
                 }
                 else if(strcmp("pbrp",long_options[opt_index].name)==0)
                 {
                     Settings->peerBPort = (u_int16_t)atoi(optarg);
                     if(Settings->peerBPort > MAX_PORT_NUMBER)
                     {
                    	 Settings->peerBPort = DEFAULT_PORT;
                     }
                 }
                 else if(strcmp("tmo",long_options[opt_index].name)==0)
                 {
                     Settings->timeout = (u_int16_t)atoi(optarg);
                 }
                 else if(strcmp("pbra",long_options[opt_index].name)==0)
                 {
                	 if(!in6_pton(optarg, &(Settings->peerBAddr)))
                	 {
                	     printf("Unable to process peer address %s!\n",optarg);
                	     return false;
                	 }
                     if(in6_isAddrV6(&(Settings->peerBAddr)))
                     {
                    	 Settings->flags |= SHIFT_PEERB_ISV6;
                     }
                 }
                 else if(strcmp("cla",long_options[opt_index].name)==0)
                 {
                	 if(!in6_pton(optarg, &(Settings->clientAddr)))
                	 {
                	     printf("Unable to process client address %s!\n",optarg);
                	     return false;
                	 }
                     if(in6_isAddrV6(&(Settings->clientAddr)))
                     {
                    	 Settings->flags |= SHIFT_CLIENT_ISV6;
                     }
                 }
                 else if(strcmp("clp",long_options[opt_index].name)==0)
                 {
                     Settings->clientPort = (u_int16_t)atoi(optarg);
                     if(Settings->clientPort > MAX_PORT_NUMBER)
                     {
                    	 Settings->clientPort = DEFAULT_PORT;
                     }
                 }
                 else if(strcmp("sra",long_options[opt_index].name)==0)
                 {
                	 if(!in6_pton(optarg, &(Settings->serverAddr)))
                	 {
                	     printf("Unable to process peer address %s!\n",optarg);
                	     return false;
                	 }
                     if(in6_isAddrV6(&(Settings->serverAddr)))
                     {
                    	 Settings->flags |= SHIFT_SERVER_ISV6;
                    	 Settings->flags |= SHIFT_PEERB_ISV6;
                     }
                 }
                 else if(strcmp("srp",long_options[opt_index].name)==0)
                 {
                     Settings->serverPort = (u_int16_t)atoi(optarg);
                     if(Settings->serverPort > MAX_PORT_NUMBER)
                     {
                    	 Settings->serverPort = DEFAULT_PORT;
                     }
                 }
                 else if(strcmp("type",long_options[opt_index].name)==0)
                 {
                     Settings->testType = (unsigned short)atoi(optarg);
                 }
                 else if(strcmp("detail",long_options[opt_index].name)==0)
                 {
                	 Settings->flags |= SHIFT_VERBOSE;
                	 g_verbose = 1;
                 }
                 else if(strcmp("create",long_options[opt_index].name)==0)
                 {
                	 Settings->flags |= SHIFT_FILECREATE;
                 }
                 else if(strcmp("wait",long_options[opt_index].name)==0)
                 {
                	 Settings->flags |= SHIFT_CLOSE_WAIT;
                 }
            	 break;
             case ':':
            	 printf("Syntax:\n%s\n",usage);
            	 return -1;
             default:
                 printf("Syntax:\n%s\n",usage);
                 return -1;
         }
#ifdef DEBUG
         if(opt != 0)
             printf("option is:%c \t with value:%s\n",opt,optarg);
         else
             printf("option is:%s with value:%s\n",long_options[opt_index].name,optarg);
#endif
    }

    return success;
}


/*
 * The parsed settings are copied to a config structure
 * this structure is then initialized before it is passed
 * to the client/server thread
 * */
int configCopyClientSettings(config *inputSettings,config **outputSettings)
{
    int success = -1;
    if(inputSettings != NULL)
    {
        *outputSettings = (config *)malloc(sizeof(config));
        if(*outputSettings == NULL)
        {
        	printf("Could not allocate memory to copy client settings\n");
        	LOG("Could not allocate memory to copy client settings",1);
        	return success;
        }
        memcpy(*outputSettings,inputSettings,sizeof(config));
        if ( inputSettings->mFileName != NULL )
        {
            (*outputSettings)->mFileName = malloc(strlen(inputSettings->mFileName) + 1);
            if((*outputSettings)->mFileName == NULL)
            {
               LOG("Buffer sent would be default",1);
               printf("filename could not be created\n");
            }
            strcpy( (*outputSettings)->mFileName, inputSettings->mFileName );
        }
        if((inputSettings->serverType == PROTOCOL_TLS) ||
        		(inputSettings->clientType == PROTOCOL_TLS) ||
        		(inputSettings->clientType == PROTOCOL_DTLS) ||
        		(inputSettings->serverType == PROTOCOL_TLS))
        {
            if ( inputSettings->keyFile != NULL )
            {
                (*outputSettings)->keyFile = malloc(strlen(inputSettings->keyFile) + 1);
                if((*outputSettings)->keyFile == NULL)
                {
                    LOG("key allocate error",1);
                }
                strcpy( (*outputSettings)->keyFile, inputSettings->keyFile );
            }
            if ( inputSettings->ca_list != NULL )
            {
                (*outputSettings)->ca_list = malloc(strlen(inputSettings->ca_list) + 1);
                if((*outputSettings)->ca_list == NULL)
                {
                    LOG("ca_list allocate error",1);
                }
                strcpy( (*outputSettings)->ca_list, inputSettings->ca_list );
            }
            if ( inputSettings->ciphers != NULL )
            {
                (*outputSettings)->ciphers = malloc(strlen(inputSettings->ciphers) + 1);
                if((*outputSettings)->ciphers == NULL)
                {
                   LOG("cipher allocate error",1);
                }
                strcpy( (*outputSettings)->ciphers, inputSettings->ciphers );
            }
        }
        strcpy((*outputSettings)->protocol,inputSettings->protocol);
        if(inputSettings->testType == CLIENT_ONLY)
        	REPLAY_THREAD_BROADCAST;
    	success = 0;
#ifdef DEBUG
    printConfig("configCopySettings",*outputSettings);
#endif
    }
    return success;
}

/*
 * These are the client copied settings
 * This routine should check if all
 * the settings are correct and
 * initialize them accordingly
 * these are the final settings
 * that are passed to the client(s)/server thread
 * */
int configClientInitialize(config *inputSettings)
{
    int success = -1;
    if(inputSettings != NULL)
    {
        if(!(inputSettings->flags & MASK_FILEINPUT))
        {
            printf("Input file not provided\n");
            exit(1);
        }
        if(!(inputSettings->flags & MASK_PROTODEFINED))
        {
            printf("specify protocol using -p\n");
            exit(1);
        }
    	if(inputSettings->clientType == DEFAULT)
        {
        	inputSettings->connections = 1;
        	printf("Specify client Type\n");
        	exit(1);
        }
        if(in6_isAddrZero(&(inputSettings->peerAddr)))
        {
        	LOG("Cannot get peer address",1);
        	printf("Cannot get peer address\n");
        	exit (1);
        }
        if(!(in6_isAddrZero(&(inputSettings->peerAddr))) && (inputSettings->peerPort !=0))
        {
        	if((inputSettings->flags) & MASK_ISIPV6)
        	{
#ifdef DEBUG
        		LOG("initializing V6 address",1);
#endif
        		inputSettings->peerV6.sin6_family = AF_INET6;
                inputSettings->peerV6.sin6_port = htons(inputSettings->peerPort);
                inputSettings->peerV6.sin6_addr = inputSettings->peerAddr;
        	}
        	else
        	{
#ifdef DEBUG
        		LOG("initializing V4 address",1);
#endif
        		inputSettings->peerV4.sin_family = AF_INET;
        	    inputSettings->peerV4.sin_port = htons(inputSettings->peerPort);
                inputSettings->peerV4.sin_addr.s_addr = inputSettings->peerAddr.s6_addr32[3];
        	}
        }
        if(!in6_isAddrZero(&(inputSettings->clientAddr)))
        {
            if((inputSettings->flags) & MASK_CLIENT_ISV6)
            {
            	inputSettings->clientV6.sin6_family = AF_INET6;
                inputSettings->clientV6.sin6_port = htons(inputSettings->clientPort);
                inputSettings->clientV6.sin6_addr = inputSettings->clientAddr;
            }
            else
            {
#ifdef DEBUG
        		LOG("initializing V4 address",1);
#endif
            	inputSettings->clientV4.sin_family = AF_INET;
                inputSettings->clientV4.sin_port = htons(inputSettings->clientPort);
                inputSettings->clientV4.sin_addr.s_addr = inputSettings->clientAddr.s6_addr32[3];

            }
        }

        if(!((inputSettings->flags) & MASK_TIME_MODE) && (inputSettings->mAmount == 0))
        {
        	if(!(inputSettings->flags & MASK_FILEINPUT))
                inputSettings->mAmount = MIN_AMOUNT_SENT;
        	else
        		inputSettings->mAmount = MAX_FILE_SIZE;
        }
        if(inputSettings->mBufLen == 0)
        {
        	inputSettings->mBufLen = MIN_BUFFER_LEN;
        }
        inputSettings->Extractor_file = NULL;
        memset(&(inputSettings->tstats),0,sizeof(stats));
        /*Settings the id to be zero before the thread gets created*/
        inputSettings->id = 0;
     	success = 0;
#ifdef DEBUG
    printConfig("configClientInitialize",inputSettings);
#endif
    }

    return success;
}

int configServerInitialize(config *inputSettings)
{
    int success = -1;
    if(inputSettings->serverType == PROTOCOL_TLS)
    {
        if(!(inputSettings->keyFile))
        {
            printf("key file not provided\n");
            exit(1);
        }
    }
    if(!(inputSettings->flags & MASK_FILEINPUT))
    {
        printf("Input file not provided\n");
        exit(1);
    }
    if(inputSettings != NULL)
    {
        memset(&inputSettings->peerBV4,0,sizeof(inputSettings->peerBV4));
        memset(&inputSettings->peerBV6,0,sizeof(inputSettings->peerBV6));
        if(!in6_isAddrZero(&(inputSettings->serverAddr)))
        {
            if((inputSettings->flags) & MASK_SERVER_ISV6)
            {
            	inputSettings->serverV6.sin6_family = AF_INET6;
                inputSettings->serverV6.sin6_port = htons(inputSettings->serverPort);
                inputSettings->serverV6.sin6_addr = inputSettings->serverAddr;
            }
            else
            {
            	inputSettings->serverV4.sin_family = AF_INET;
                inputSettings->serverV4.sin_port = htons(inputSettings->serverPort);
                inputSettings->serverV4.sin_addr.s_addr = inputSettings->serverAddr.s6_addr32[3];
#ifdef DEBUG
		printf("server port input is %u:  \t output %u:\n",
		       htons(inputSettings->serverPort),
		       inputSettings->serverV4.sin_port);
		char addr[100];
		printf("server IP output is %s: \n",
		       inet_ntop(AF_INET,&(inputSettings->serverV4.sin_addr.s_addr),addr,100));
#endif
            }
        }
        else
        {
            printf("Please Specify Server Address\n");
        	exit(1);
        }
        if(inputSettings->mBufLen == 0)
        {
        	inputSettings->mBufLen = MIN_BUFFER_LEN;
        }
        inputSettings->Extractor_file = NULL;
        memset(&(inputSettings->tstats),0,sizeof(stats));
        /*Settings the id to be zero before the thread gets created*/
        inputSettings->id = 0;
     	success = 0;
#ifdef DEBUG
    printConfig("configServerInitialize",inputSettings);
#endif
    }

    return success;
}


void fileInitialize ( const char *fileName, config *inputSettings,long int *size )
{

	struct stat fileStatCode;
	if(fileName)
	{
	    inputSettings->Extractor_file = fopen (fileName, "rb");
	        if ( (inputSettings->Extractor_file) == NULL )
            {
                 LOG("could not find the file",1);
                 LOG("Using Default",2);
		         return;
            }
	        if(stat(fileName,&fileStatCode) == 0)
	        {
	        	*size = fileStatCode.st_size;
	        }
	}
}

int fileBlockCopyToBuffer(char *readData,config *inputSettings)
{
	int rc;
	if(readData == NULL)
	{
		LOG("Could not find buffer",1);
		return -1;
	}
	if(!(feof(inputSettings->Extractor_file)))
    {
	    rc = fread( readData, 1, inputSettings->mBufLen,
    		    inputSettings->Extractor_file );
        if((rc < inputSettings->mBufLen)&& (!feof(inputSettings->Extractor_file)))
        {
            LOG("fileBlockCopyToBuffer: Not all data was read",1);
        }
    }
#ifdef DEBUG
    LOG("bytes:",rc);
#endif
	return rc;
}

int CompleteFileMemCopy(char *readData,config *inputSettings, long int size)
{
    int rc;
    if((!readData) || (!(inputSettings->Extractor_file)))
    {
        LOG("Could not allocate buffer for reading the file or no file",1);
        return -1;
    }

	if(!(feof(inputSettings->Extractor_file)))
    {
	    rc = fread( readData, 1, size,
    		    inputSettings->Extractor_file );
        if(rc <=0)
        {
            LOG("CompleteFileMemCopy: No data read",1);
            LOG(strerror(errno),errno);
        }
    }

#ifdef DEBUG
    LOG("bytes:",rc);
#endif
    return rc;
}
#ifdef DEBUG
char *print_theread_percentComp(char *buf,config *config)
{
    int totalData = g_testFileSize*config->connections*config->pThread;
    int dataComp = g_cStats.tTotalDataTransfered;
    int avg;
    int i;
    char *temp = (char *)malloc(sizeof(char)*33);
    char *savetemp = temp;
    int ratio;
    if(totalData)
    {
    	avg = (dataComp*100)/totalData;
        ratio = (dataComp*32)/totalData;
    }
    if(ratio > 0 && avg > 0)
    {
		for(i=0;i<ratio;i++)
		{
			snprintf(&temp[i],2,"=");
		}
		for(i = 0;i<(32-ratio);i++)
		{
			snprintf(&temp[i+ratio],2," "); //test the warning issue visible in case of assignment
		}
		snprintf(&buf[0],65,"%3d%%[%32s]\n",avg,temp);
    }
    else
    	snprintf(&buf[0],65,"%3d%%[%32s]\n",0,temp);
    free(temp);
	return buf;
}

void print_results(config *config,int type)
{

	char *buffer = (char *)malloc(sizeof(char)*3096);
	char *temp = (char *)malloc(sizeof(char)*65);
	int i;
	char message[64] = "#####\tTransportTT Client Running\t#####\n";
	strcpy(buffer,message);
	snprintf(temp,64,"Number of Connections:\t%u\n",config->tstats.tNumConnections);
	strcat(buffer,temp);
	snprintf(temp,64,"Number of HandShakes :\t%u\n",config->tstats.treHandshakes);
	strcat(buffer,temp);
	snprintf(temp,64,"Number of Threads :\t%u\n",config->pThread);
	strcat(buffer,temp);
	snprintf(temp,64,"*** \tThread Progress\t ****\n");
	strcat(buffer,temp);
	for(i = 0; i<3;i++)
	{
		print_theread_percentComp(temp,config);
		strcat(buffer,temp);
	}
	snprintf(temp,64,"*** \tThreads\t ****\n");
    strcat(buffer,temp);
	snprintf(temp,64,"############TransportTTV3.003################\n");
    strcat(buffer,temp);
    printf("%s",buffer);
    //goto to start here
    for(i = 0 ; i < 10; i++)
        printf("\033[1A\033[2K"); //could be \033[xA\033[2K
    fflush(stdout);
    free(buffer);
    free(temp);

}
#endif

void *report_spawn(void *config)
{
    int i =0;
	stats getStats;
	static stats oldGetStats;
    memset(&getStats,0,sizeof(stats));
    memset(&oldGetStats,0,sizeof(stats));
    printf("Connections  |HandShakes  |Errors  |Packets Received |Data Received  |Bandwidth\n");
    printf("             |            |        |                 |(bytes)        |(Mbps)\n");
    printf("-------------------------------------------------------------------------------\n");
    for(;;)
    {

       pthread_mutex_lock(&statslock);
 	   getStats.tNumConnections = g_stats.tNumConnections ;
 	   getStats.tNumConnectionErrors = g_stats.tNumConnectionErrors ;
 	   getStats.tNumSecureConnections = g_stats.tNumSecureConnections ;
 	   getStats.tTotalDataReceived = g_stats.tTotalDataReceived ;
 	   getStats.tTotalDataTransfered = g_stats.tTotalDataTransfered ;
 	   getStats.tDataTransfered = g_stats.tDataTransfered;
 	   getStats.tDataReceived = g_stats.tDataReceived;
 	   getStats.tEDataTransferRate = g_cStats.tEDataTransferRate ;
 	   getStats.tDataReceiveRate = (double)((getStats.tTotalDataReceived -oldGetStats.tTotalDataReceived)
 			                        *(double)8)/((double)1048576*(double)5);
 	   getStats.tDataTransferRate = (double)((getStats.tEDataTransferRate -oldGetStats.tEDataTransferRate)
 			                        *(double)8)/((double)1048576*(double)5);
 	   getStats.tjitter = g_stats.tjitter;
       if(getStats.tDataReceiveRate > g_stats.tDataReceiveRate)
    	   g_stats.tDataReceiveRate = getStats.tDataReceiveRate;
       if(getStats.tDataTransferRate > g_cStats.tDataTransferRate)
    	   g_cStats.tDataTransferRate = getStats.tDataTransferRate;
 	   pthread_mutex_unlock(&statslock);
 	   if(i%2 == 0)
 	       printf("%13u|%12u|%8u|%17u|%15lu|%11f\n",
 			       getStats.tNumConnections,
 			       getStats.tNumSecureConnections,
 			       getStats.tNumConnectionErrors,
 			       getStats.tDataReceived,
 			       getStats.tTotalDataReceived,
 			       getStats.tDataReceiveRate);
 	  oldGetStats.tTotalDataReceived = getStats.tTotalDataReceived;
 	 oldGetStats.tEDataTransferRate = getStats.tEDataTransferRate;
 	if(g_stopReport)
 	 	       break;
 	 sleep(5*3);
 	   i++;
    }
    REPORT_THREAD_LOCK;
    REPORT_THREAD_BROADCAST;
    REPORT_THREAD_UNLOCK;
    return 0;
}

void toolAlarmWrapup(int signum)
{
	toolWrapup();
	exit(1);
}

void toolWrapup()
{


    if(g_clientThread)
    {
	    printf("\nCLIENT\n");
	    if(g_cStats.tNumConnections != 0)
	        g_cStats.tAverageDataReceived = (unsigned int)g_stats.tTotalDataReceived/g_cStats.tNumConnections;
	    else
	    	g_cStats.tAverageDataReceived = 0;
	    printf("Successful connections              :%u\n",g_cStats.tNumConnections);
        if(g_cStats.tNumSecureConnections)
	        printf("Secure handshakes completed         :%u\n",g_cStats.tNumSecureConnections);
        printf("Unsuccessful connections            :%u\n",g_cStats.tNumConnectionErrors);
        printf("Packets sent                        :%u\n",g_cStats.tDataTransfered);
        printf("Data sent                           :%lu kbytes\n",(g_cStats.tTotalDataTransfered/1024));
        printf("Data received                       :%lu kbytes\n",g_cStats.tTotalDataReceived/1024);
        printf("Packets received                    :%u\n",g_cStats.tDataReceived);
        printf("Maximum bandwidth transfer          :%f Mbits/s\n",g_cStats.tDataTransferRate);
        printf("Connection Rate                     :%f conn/sec\n",g_cStats.tconnectionRate);
        printf("Average Data(connection)            :%u bytes\n",g_cStats.tAverageData);
        printf("Packets compare pass                :%lu\n",g_cStats.tcomparePass);
        printf("Packets compare fail                :%lu\n",g_cStats.tcompareFail);
    }


    if(g_serverThread)
    {
	printf("\nSERVER\n");
	if(g_stats.tNumConnections != 0)
	    g_stats.tAverageDataReceived = (unsigned int)g_stats.tTotalDataReceived/g_stats.tNumConnections;
	else
		g_stats.tAverageDataReceived = 0;
	printf("Successful connections              :%u\n",g_stats.tNumConnections);
        if(g_stats.tNumSecureConnections)
            printf("Secure handshakes completed         :%u\n",g_stats.tNumSecureConnections);
        if(g_stats.treHandshakes)
	    printf("Secure re-handshakes completed      :%u\n",g_stats.treHandshakes);
	if(g_stats.treHanshakeErrors)
	    printf("Secure re-handshakes completed      :%u\n",g_stats.treHanshakeErrors);
        printf("Unsuccessful connections            :%u\n",g_stats.tNumConnectionErrors);
        printf("Average Data received               :%u bytes\n",g_stats.tAverageDataReceived);
        printf("Packets received                    :%u\n",g_stats.tDataReceived);
        printf("Data received                       :%lu kbytes\n",g_stats.tTotalDataReceived/1024);
        printf("Data sent                           :%lu kbytes\n",(g_stats.tTotalDataTransfered/1024));
        printf("Maximum bandwidth received          :%f Mbits/s\n",g_stats.tDataReceiveRate);
        printf("Packets compare pass                :%lu\n",g_stats.tcomparePass);
        if(g_md5MatchFail)
        {
            printf("Md5sum does not match\n");
            printf("Test Failed\n");
            printf("Virtual test files matched : %u\n",g_testFiles);
        }
        else
        {
            printf("Success data compare\n");
            printf("Virtual test files matched : %u\n",g_testFiles);
        }

    }

    if(g_serverThread && g_clientThread)
    {
        if((!g_cStats.tNumConnectionErrors)
    		    && (!g_stats.tNumConnectionErrors))
        {
            if(g_stats.tTotalDataReceived
			    == g_cStats.tTotalDataTransfered)
	        {
	            printf("\n");
	            if(g_stats.tTotalDataReceived)
		           printf("Success data transfer\n");
	        }
            else
            {
#ifdef DEBUG
            	 getErrorFromHeaderMap(&g_cStats);
#endif
            	 printf("Test Failed\n");
            }
	        if(g_stats.tNumConnections
			    == g_cStats.tNumConnections)
	        {
                printf("\n");
                if(g_stats.tTotalDataReceived)
                    printf("Success creating connections\n");
	        }
            else
            {
        	     printf("Connections Created not equal\n");
        	     printf("Test Failed\n");
            }
	        if((g_stats.tNumSecureConnections
			        == g_cStats.tNumSecureConnections))
	        {
                printf("\n");
                if(g_stats.tNumSecureConnections)
                    printf("Success completing TLS handshakes\n");
	        }
            else
            {
            	printf("Handshakes Created not equal\n");
        	     printf("Test Failed\n");
            }

        }

        else
        {
            printf("\n");
            printf("Error Connection Connections\n");
            printf("Connect errors    :%u\n",g_cStats.tNumConnectionErrors);
            printf("accept errors     :%u\n",g_stats.tNumConnectionErrors);
            printf("Test Failed\n");


        }
    }
    else
    {
        printf("Test Complete\n");
    }
    /*if detailed send detailed report*/

}

/*
 *
 * Test Functions
 * Only Add unit test functions below
*/
#ifdef DEBUG
void printConfig(const char *function,config *inputSettings)
{

    printf("\n%s:\n",function);
    if(inputSettings->mFileName != NULL)
        printf("\tfilename:     \t%s\n",inputSettings->mFileName);
    if(inputSettings->keyFile != NULL)
        printf("\tkeyFile:     \t%s\n",inputSettings->keyFile);
    if(inputSettings->ca_list != NULL)
        printf("\tca_list:     \t%s\n",inputSettings->ca_list);
    if(inputSettings->ciphers != NULL)
        printf("\tciphers:     \t%s\n",inputSettings->ciphers);
    printf("\tbuflen:       \t%d\n",inputSettings->mBufLen);
    printf("\tconnections:  \t%d\n",inputSettings->connections);
    printf("\tmAmount:      \t%u\n",(unsigned int)inputSettings->mAmount);
    printf("\ttime:         \t%f\n",inputSettings->time);
    printf("\tdelay:        \t%f\n",inputSettings->delay);
    printf("\tclientType:   \t%d\n",inputSettings->clientType);
    printf("\tServerType:   \t%d\n",inputSettings->serverType);
    printf("\tprotocol:     \t%s\n",inputSettings->protocol);
    printf("\tflags:        \t0x%08x\n",inputSettings->flags);
    printf("\tWith each flag:\n");
    printf("\t\tflags BUFLENSET:                \t0x%01x\n",((inputSettings->flags&MASK_BUFLENSET )>> 0));
    printf("\t\tflags ISIPV6:                   \t0x%01x\n",((inputSettings->flags&MASK_ISIPV6) >> 1));
    printf("\t\tflags FILEINPUT:                \t0x%01x\n",((inputSettings->flags&MASK_FILEINPUT) >> 2));
    printf("\t\tflags TIME_MODE:                \t0x%01x\n",((inputSettings->flags&MASK_TIME_MODE) >> 3));
    printf("\t\tflags MASK_PROTODEFINED:        \t0x%01x\n",((inputSettings->flags&MASK_PROTODEFINED) >> 4));
    printf("\t\tflags CLIENT_ISV6:              \t0x%01x\n",((inputSettings->flags&MASK_CLIENT_ISV6) >> 5));
    printf("\t\tflags PEERB_ISV6 :              \t0x%01x\n",((inputSettings->flags&MASK_PEERB_ISV6) >> 7));
    printf("\t\tflags SERVER_ISV6:              \t0x%01x\n",((inputSettings->flags&MASK_SERVER_ISV6) >> 6));
    printf("\t\tflags MASK_SERVER_PROTOCOL:     \t0x%01x\n",((inputSettings->flags&MASK_SERVER_PROTOCOL) >> 8));
    printf("\t\tflags MASK_CA_VERIFY:           \t0x%01x\n",((inputSettings->flags&MASK_CA_VERIFY) >> 9));
    printf("\t\tflags MASK_CLIENT_RECONNECT:    \t0x%01x\n",((inputSettings->flags&MASK_CLIENT_RECONNECT) >> 10));
    printf("\t\tflags MASK_AUTH_FLAGS:          \t0x%01x\n",((inputSettings->flags&MASK_AUTH_FLAGS) >> 12));
    printf("\t\tflags MASK_REHANDSHAKE:         \t0x%01x\n",((inputSettings->flags&MASK_REHANDSHAKE) >> 15));
    printf("\taddress output is:\t%d\n",(int)inputSettings);
    printf("\t size            :\t%lu\n",sizeof(config));

}


void testInitClientConfig(config *inputSettings)
{
	configClientInitialize(inputSettings);
}

void testCopyConfig(config *input)
{
	config *output = NULL;
	configCopyClientSettings(input,&output);

}

void testParseArgs(int argc,char* argv[])
{
	config *Settings;
	Settings = (config *)malloc(sizeof(config));
	memset(Settings,0,sizeof(config));
	if(!configParseCommandLine(argc,argv,Settings))
	    testCopyConfig(Settings);
	testInitClientConfig(Settings);
	printf("Final Settings are config is:\n");
		    if(Settings->mFileName != NULL)
		        printf("\tfilename:     \t%s\n",Settings->mFileName);
		    printf("\tbuflen:       \t%d\n",Settings->mBufLen);
		    printf("\tconnections:  \t%d\n",Settings->connections);
		    printf("\tmAmount:      \t%u\n",(unsigned int)Settings->mAmount);
		    printf("\ttime:         \t%f\n",Settings->time);
		    printf("\tdelay:        \t%f\n",Settings->delay);
		    printf("\tclientType:   \t%d\n",Settings->clientType);
		    printf("\tprotocol:     \t%s\n",Settings->protocol);
		    printf("\tflags:        \t0x%08x\n",Settings->flags);
		    printf("\taddress output is:  \t%d\n",(int)Settings);
   free(Settings);
}
#endif
