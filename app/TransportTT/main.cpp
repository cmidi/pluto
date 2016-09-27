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
#include <queue>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include "Config.h"
#include "ServerAPI.h"
#include "Misc.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <boost/asio.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

using namespace std;
extern "C" {
pthread_mutex_t mutexLog;
pthread_mutex_t statslock;
pthread_mutex_t reportMutex;
pthread_cond_t reportCond;
pthread_mutex_t replayMutex;
pthread_cond_t replayCond;
pthread_mutex_t liblock;
pthread_mutex_t readFinishMutex;
pthread_cond_t readFinishCond;
pthread_cond_t writeStart;
pthread_mutex_t writeStartMutex;
pthread_mutex_t readStartMutex;
pthread_cond_t readStart;

int g_clientThread             = 0;
int g_clientReadThread         = 0;
int g_serverThread             = 0;
int g_md5MatchFail             = 0;
unsigned int g_testFiles       = 0;
int g_verbose                  = 0;
long int g_testFileSize;
extern  int g_stopReport;
}
static pthread_mutex_t *lock_cs;
static long *lock_count;
pmsgq fdMessageQ;
pthread_mutex_t *g_mutex_alloc;
boost::asio::io_service g_io;


static const char version[] = "TransportTT version 3.03\n"
		"Features Supported\n\n"
		"\t\tTCP Echo Client/Server\n"
		"\t\tFILE memcpy transfer\n"
		"\t\tMulti server poll support\n"
		"\t\tTLS DHE cipher suite support\n"
		"\t\tDTLS support\n"
		"\t\tOn fly data compare\n"
		"\n";

void pthreads_locking_callback(int mode, int type, char *file, int line) {

	if (mode & CRYPTO_LOCK)
	{
		pthread_mutex_lock(&(lock_cs[type]));
		lock_count[type]++;
	} else {
		pthread_mutex_unlock(&(lock_cs[type]));
	}
}
unsigned long pthreads_thread_id(void) {
	unsigned long ret;

	ret = (unsigned long) pthread_self();
	return (ret);
}

void thread_lock_setup(void) {
	int i;

	lock_cs =
			(pthread_mutex_t *) OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	lock_count = (long int *) OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));
	for (i = 0; i < CRYPTO_num_locks(); i++) {
		lock_count[i] = 0;
		pthread_mutex_init(&(lock_cs[i]), NULL);
	}

	CRYPTO_set_id_callback((unsigned long(*)())pthreads_thread_id);CRYPTO_set_locking_callback
	((void(*)(int, int, const char*, int))pthreads_locking_callback);}

void thread_cleanup(void) {
	int i;

	CRYPTO_set_locking_callback(NULL);
	for (i = 0; i < CRYPTO_num_locks(); i++) {
		pthread_mutex_destroy(&(lock_cs[i]));
	}OPENSSL_free(lock_cs);
	OPENSSL_free(lock_count);

}
int g_stop_timer = 0;
int main(int argc, char **argv) {

	signal(SIGPIPE, SIG_IGN);

	int numCores;
	int cl;

	unsigned long int threadID[MAX_THREAD] = { 0 };
	MUTEX_LOG_INIT;
	MUTEX_GLOBAL_STATS_INIT;
	MUTEX_LIBLOCK_INIT;
	MUTEX_REPLAY_INIT;
	MUTEX_COND_REPLAY_INIT;
	MUTEX_WRITE_START_INIT;
	COND_WRITE_START_INIT;
	MUTEX_READ_START_INIT;
	COND_READ_START_INIT;
    struct sigaction sa;
    struct sigaction sa_crash;
    struct itimerval it;
//
      int check;
//
    memset(&sa,0,sizeof(sa));
    memset(&sa_crash,0,sizeof(sa_crash));
	thread_lock_setup();
	//allocate memory for the external input settings
	config *inputSettings = new config;


	config *serverSettings = NULL;
	config *clientReadSettings = NULL;
	fdMessageQ = new msgq;
	g_mutex_alloc = (pthread_mutex_t *)calloc(100000,sizeof(pthread_mutex_t));
	//init the settings
	memset(inputSettings, 0, sizeof(config));
	//parse the settings from commmand line
	if (argc == 1) {
		char *printVer = (char *) malloc(sizeof(char) * 500);


		char *temp = (char *) malloc(sizeof(char) * 30);
		snprintf(temp, 30, "\nBuilt %s %s\n", __DATE__, __TIME__);


		strcpy(printVer, version);

		strcat(printVer, temp);
		free(temp);
#ifdef DEBUG
		snprintf(printVer,16,"\nDEBUG VERSION\n");
#endif
#ifdef SSL_9_CENTOS_5
		strcat(printVer,"\nOPENSSL 0.9.8e compatible\n");
		strcat(printVer,"Centos5 version\n");
#else
		strcat(printVer, "Centos6 version\n");
#endif
		printf("%s", printVer);
		free(printVer);
		return 0;
	}
	cl = configParseCommandLine(argc, argv, inputSettings);
	if (cl < 0) {
		delete inputSettings;
		if (cl != -2)
			printf("Error Parsing Arguments\n");
		return -1;
	}
	if (inputSettings->flags & MASK_ECHO_TEST)
	{

		if (!fdMessageQ) {
			printf("Could not allocate memory for table\n");
			return -1;
		}
		pthread_mutex_init(&fdMessageQ->msgqLock, NULL);
		pthread_cond_init(&fdMessageQ->msgqCond, NULL);
		fdMessageQ->signalPush = 0;
		READ_FINISH_MUTEX_INIT;
		READ_FINISH_COND_INIT;

	}
	sa.sa_handler = &toolAlarmWrapup;
	sa_crash.sa_handler = &crashHandler;
	sigaction(SIGSEGV,&sa_crash,NULL);
	sigaction(SIGINT,&sa,NULL);

	if (((inputSettings->testType == CLIENT_ONLY) ||
		    (inputSettings->testType == DUAL_TEST))
		    &&(inputSettings->timeout != 0))
	{
		memset (&it, 0, sizeof (it));

		it.it_value.tv_sec = (int) (inputSettings->timeout*10);
		int err = setitimer( ITIMER_REAL, &it, NULL );
		if ( err != 0 )
		{
			LOG("setitimer",2);
			exit(1);
		}
		sigaction(SIGALRM,&sa,NULL);
	}




	atexit(toolWrapup);

    pthread_t serverId[MAX_NUMBER_OF_CORES] = {0};

    if (inputSettings->testType == SERVER_ONLY ||
	    inputSettings->testType == DUAL_TEST) {
    	numCores = sysconf(_SC_NPROCESSORS_ONLN);

	    //Create Server Configuration Settings
	    cl = configCopyClientSettings(inputSettings, &serverSettings);
	    if (cl < 0) {
	      delete inputSettings;
	      return -1;
	    }

	    //Initialize Server Configuration Settings
	    cl = configServerInitialize(serverSettings);
	    if (cl < 0) {
	      printf("Could not init the Server\n");
	      return -1;
	    }

	    // Obtain Platform number of cores

	    //OPEN THE SERVER. This call is blocking.
	    if (openTransportTTServer(serverSettings, numCores,serverId) == -1) {
	        delete inputSettings;
		return -1;
	    }
	}
	//This would give time for the server thread to come up and start listening
	// Also for SD to send CLient connections to Server Ideally a server start message can be used
	// *TODO
	if(inputSettings->testType == DUAL_TEST)
	    sleep(5);
	if (inputSettings->testType == CLIENT_ONLY
			|| inputSettings->testType == DUAL_TEST)
			{
		config *clientSettings[MAX_THREAD];
		for (int i = 0; i < inputSettings->pThread; i++) {
			clientSettings[i] = NULL;
			cl = configCopyClientSettings(inputSettings, &clientSettings[i]);
			if (cl < 0) {
				delete inputSettings;
				printf("Error copy client config for thread %d\n", i);
				return -1;

			}
			cl = configClientInitialize(clientSettings[i]);
			if (cl < 0) {
				delete inputSettings;
				printf("Error init client config for thread %d\n", i);
				return -1;
			}
			create_client_thread(clientSettings[i]);

			threadID[i] = clientSettings[i]->id;
		}
		if (inputSettings->flags & MASK_ECHO_TEST)
		{

			cl = configCopyClientSettings(inputSettings, &clientReadSettings);
			if (cl < 0) {
				delete inputSettings;
				printf("Error copy read client config for thread\n");
				return -1;

			}
			cl = configClientInitialize(clientReadSettings);
			if (cl < 0) {
				delete inputSettings;
				printf("Error init  read client config for thread\n");
				return -1;
			}
			create_client_read_thread(clientReadSettings);
		}
		boost::asio::io_service::work work_(g_io);
		while(1)
		{
			unsigned long my_id = pthreads_thread_id();

            LOG("Starting the io service",1);
			g_io.run();
			LOG("Dispatched io",1);
			g_io.reset();
			if(g_stop_timer)
	            break;
			boost::asio::io_service::work work_(g_io);

		}
		g_io.stop();
		for (int j = 0; j < inputSettings->pThread; j++) {
			if (threadID[j]) {
				pthread_join(threadID[j], NULL);
			}
		}
	}
	if (inputSettings->testType == SERVER_ONLY ||
		    inputSettings->testType == DUAL_TEST) {
	    for (int core=0; core<numCores; core++) {

	    	    if(serverId[core])
		            pthread_join(serverId[core], NULL);
	    	        LOG("Joined server id:",serverId[core]);
	    }
	}
	g_stopReport = 1;
	if (inputSettings->flags & MASK_ECHO_TEST)
	{

		pthread_mutex_destroy(&fdMessageQ->msgqLock);
		pthread_cond_destroy(&fdMessageQ->msgqCond);
		READ_FINISH_MUTEX_DESTROY;
		READ_FINISH_COND_DESTROY;
		delete fdMessageQ;
	}


		// CLOSE THE SERVER
	if (inputSettings->testType == SERVER_ONLY || 
	    inputSettings->testType == DUAL_TEST) {
	    closeTransportTTServer();
	}
exit:
	MUTEX_LOG_DESTROY;
	MUTEX_GLOBAL_STATS_DESTROY;
	MUTEX_LIBLOCK_DESTROY;
	MUTEX_REPLAY_EXIT;
	MUTEX_COND_REPLAY_EXIT;
	MUTEX_WRITE_START_DESTROY;
	COND_WRITE_START_DESTROY;
	MUTEX_READ_START_DESTROY;
	COND_READ_START_DESTROY;
	if(g_mutex_alloc)
	    free(g_mutex_alloc);
	thread_cleanup();

	return 0;
}
