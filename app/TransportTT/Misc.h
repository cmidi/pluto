#include <queue>
#include <iostream>
#include <assert.h>

#define likely(x) __builtin_expect((x),1)
#define unlikely(x) __builtin_expect((x),0)

//using namespace std;

typedef enum dtls_state
{
	state_created = 0,
	state_connected,
	state_data_send,
	state_end,
	state_end_server_read,
	state_end_client_write,
	state_close
}dtls_data_state;

typedef struct info
{
	u_int16_t clientPort;
	u_int32_t pack_sec;
	u_int32_t pack_usec;
	u_int16_t end;           // final packet needs ack from server to update state to close in the state machine

}pktInfo;

typedef struct encapsHeader
{
    u_int16_t len;           // len of header
    u_int16_t sequence;     //This tells the total number of packets that the client will send
    u_int32_t connectionId;  // connection id filled with fd number
    u_int32_t packetId;      // packet id and incremental sequence
    unsigned char       md5sum[16];  // calculated md5
    pktInfo pdata;
}encapsHeader;


typedef struct messageQueue
{
    std::queue<int> fdQueue;
    pthread_mutex_t msgqLock;
    pthread_cond_t msgqCond;
    int signalPush;

}msgq,*pmsgq;


DH* get_dh512(const unsigned char *dh512_p,const unsigned char *dh512_g);
