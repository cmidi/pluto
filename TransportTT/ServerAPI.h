#ifndef SERVERAPI_H
#define SERVERAPI_H

int openTransportTTServer(void *inputSettings, int cores,pthread_t (&id)[MAX_NUMBER_OF_CORES]);
void closeTransportTTServer(void);
void create_read_server_thread(void* inputSettings);
void create_write_server_thread(void* inputSettings);

#endif
