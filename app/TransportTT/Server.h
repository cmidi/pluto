#ifndef SERVER_H
#define SERVER_H
/* This is the server declaration file
 * consists of Server class
 * */
#include <map>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "Config.h"

#define ERR_SERVER_SOCKET -1
#define ERR_LISTEN -2
#define MAX_NUM_OF_ACCEPTED_CONNS_PER_THREAD 2000

class Server
{
public:
    /*Constructors*/
    Server(config *config);

    virtual ~Server();
    //create socket,bind and start listening
    int Listen();

    int readPoll();
    int writePoll();
    int writePoll_echo(int fd);
    virtual int EPoll();
    //accept and process the buffer;
    virtual int Process(int fd);
    int readProcess(int fd);
    int ReadDataFileBuffer(pfdInfo fdInfo, char **tempBuf,int size);
    int checkIndTransferComplete(config *inputSettings);
    void SaveClass(Server *theServer);
    config * GetServerSettings(void);

    unsigned long int returnTcpNum() {return m_num;}

    std::map<int, char *> filenameMap;
    std::map<int, char *>::iterator ifilenameMap;
    std::map<int,pfdInfo> fdInfoMap;
protected:
    config   *serverSettings; // Points to User Global Configuration Structure
    char*    tempBuf;         // Holds (-l) BufLen buffer
    char*    fileBuf;         // Holds data from input file (ALL of IT!!...TOO MUCH???)
    uint8_t *file_head;       // Points to top of fileBuf
    uint8_t *file_tail;       // Points to tail of fileBuf
    Server  *theServer;       // Points to itself
private:
    unsigned long int m_num;  // Pthread ID;
    int     connections_accepted;
};

class TLSServer: public Server
{
public:

	TLSServer(config *config);

	virtual ~TLSServer();

	int configure();

	virtual int EPoll();

	virtual int TLSAccept(int fd, unsigned int &pend);

	virtual int Process(SSL *ssl,int fd);

    unsigned long int returnTLSNum() {return m_TLSnum;}
    std::map<int,SSL *> SSLMap;
    std::map<int,SSL *>::iterator iSSLMap;
protected:
#ifdef SSL_9_CENTOS_5
    SSL_METHOD *meth;
#else
    const SSL_METHOD *meth;
#endif
    SSL_CTX *ctx;
private:
    unsigned long int m_TLSnum;
};

class UDPServer : public Server
{
public:
    UDPServer(config *config);
    int Process(int fd);
    int EPoll();
    virtual ~UDPServer();
private:
    unsigned long int m_UDPnum;
};

typedef uint32_t hashkey_t;
typedef std::map<hashkey_t,SSL *> tSSLMap;
typedef std::map<hashkey_t,int> tfdMap;

class DTLSServer : public TLSServer
{
public:
    DTLSServer(config *config);
    int Process(SSL *ssl,int fd);
    virtual int EPoll();
    SSL *findSSL(int fd);
    SSL *initSSL();
    uint32_t hashing_fun();
    virtual int TLSAccept(int fd, unsigned int &pend);
    int UDPAccept(int fd,struct sockaddr * addr,
    		   socklen_t * addr_len,void *sockBuf);
    virtual ~DTLSServer();
    void cleanupConnectionState( SSL *ssl, int fd );
#ifdef DEBUG
    void testHashgen();
#endif
private:
    unsigned long int m_DTLSnum;
	tSSLMap connMap;
	tfdMap hashToFD;
};

/*this class is for the processor thread which will process each coming data in the fd's
 * the number of the processor threads would be based on tests
 * */

#ifdef __cplusplus
extern "C"
{
#endif
/* FUNCTION DEFINITIONS */
void *server_spawn( void *inputSettings );
int  createListeningSocket( void *inputSettings );
void *read_server_spawn(void *inputSettings);
void *write_server_spawn(void *inputSettings);
void initServerMutexes();
void destroyServerMutexes();
#ifdef __cplusplus
}
#endif
#endif
