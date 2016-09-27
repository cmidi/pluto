/*Server API file*/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include "Server.h"
#include "Config.h"

void create_read_server_thread(void* inputSettings)
{
  if(pthread_create(&((config *)inputSettings)->id,NULL,read_server_spawn,(void *)inputSettings) != 0)
    {
    	LOG("could not create server thread",1);
        printf("could not create server thread\n");
        exit(1);
    }
}

void create_write_server_thread(void* inputSettings)
{
    if(pthread_create(&((config *)inputSettings)->id,NULL,write_server_spawn,(void *)inputSettings) != 0)
    {
    	LOG("could not create server thread",1);
        printf("could not create server thread\n");
        exit(1);
    }
}

/*
 * Function: createServerThread
 *
 * Description: Create the main server threads
 *
 * return: if successful, thread's pthread_id. The calling function
 *         can use this value to run a pthread_join
 */
pthread_t createServerThread(void* inputSettings)
{
    pthread_t id;

    if(pthread_create(&id, NULL,server_spawn,(void *)inputSettings) != 0)

    {
    	LOG("could not create server thread",1);
        printf("could not create server thread\n");
        exit(1);
    }

    return id;
}


/*
 * Function:  openTransportTTServer
 *
 * Description: Creates and Initializes the TransportTT server
 *              as follows
 *  1.- Create a main Listening Socket where all the client
 *      connections will come to.
 *  2.- Create a number of Server Epoll Threads to pick up and
 *      accept the client connection requests from the listening
 *      socket
 *  3.- Create a report thread to periodically display the 
 *      connections statistics
 *
 *  return:  0 on sucess, -1 on failure
 */	    
int openTransportTTServer(void *serverSettings, int numCores,pthread_t (&id)[MAX_NUMBER_OF_CORES])
{
    int core;
    int cl;
    //Initialize Locks used by Server
    initServerMutexes();
    config *settings[MAX_NUMBER_OF_CORES] = {NULL};
    //Create Server Configuration Settings


    // Create Report Thread
    createReportThread(serverSettings);

    // Create Listening Socket
    if (createListeningSocket(serverSettings) != 0) {
        LOG("Failed to create listening port",1);
	return -1;
    }

    // Create Server Threads
    if (numCores > MAX_NUMBER_OF_CORES) {
        numCores = MAX_NUMBER_OF_CORES;
        LOG("Capping number of Cores to: ", MAX_NUMBER_OF_CORES);
    }

    config *temp = (config *)serverSettings;
    if(temp->flags & MASK_SINGLE_CORE)
    {
    	numCores = 1;
    	LOG("Single core :",numCores);
    }
    LOG("TransportTT will run over cores : \n", numCores);
    for (core=0; core<numCores; core++) {

    	settings[core] = NULL;
    	cl = configCopyClientSettings((config *)serverSettings, &settings[core]);
    		if (cl < 0) {
    		  //delete serverSettings;
    		  return -1;
    		}
    		configServerInitialize(settings[core]);

	    id[core] = createServerThread(settings[core]);
    }
    return 0;
}

/*
 * Function:  closeTransportTTServer
 *
 * Description: Place holder to run all Server tear
 *              down functions.
 *
 */
void closeTransportTTServer()
{
    destroyServerMutexes();

    // Add here any other Server related tear down methods 
}

