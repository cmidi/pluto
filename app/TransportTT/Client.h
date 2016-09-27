/*
 *   client.cpp declarations
 *   this file contains object declarations for the client class.
 *   changes there for openssl 0.9.8 centos 5.5
*/

#include "Config.h"
#include <boost/bind.hpp>
#include <boost/asio.hpp>
/*ERROR DEFINES*/

#define ERR_CONNECT_SERVER -1
#define ERR_SOCK_CREATE -2
unsigned long int threadId = 0;
extern pmsgq fdMessageQ;
extern pthread_mutex_t * g_mutex_alloc;
extern int g_stop_timer;
//TODO what should be the default behavior...
class Client
{
public:
    /*Constructors*/
    Client(config *config);

    virtual ~Client();

    /*member functions*/    
    virtual int Connect();
    /* process would send send the data out to the server
     * after connection the implementation of the same is
     * be client dependent*/
    virtual int process();
    virtual int readPoll(){LOG("Base Class read poll",1);return 0;};
    int ReadDataFileBuffer(pfdInfo fdInfo, char **tempBuf,int size);
    int checkIndTransferComplete(config *inputSettings);
    int initFdInfo(char *buf, uint8_t *&head, uint8_t *&tail);
    uint8_t *file_head;
    uint8_t *file_tail;

protected:
    config *inputSettings;
    char*    tBuf;
    char*    rBuf;
    char*    fileBuf;
    std::map<int,pfdInfo> fdInfoMap;

    std::map<int,pfdInfo>::iterator ifdInfoMap;

private:
    unsigned long int m_num;
/*add more declarations here*/
}; //end Client Class

class TcpClient : public Client
{
public:    
    /*TcpClient constructor*/
    TcpClient(config *config): Client(config)
    {
        m_tcpNumid = threadId; // this has to be unique for the object
        threadId++;

    }
    
    int process();
    int Connect();
    virtual int readProcess(int fd);
    int readPoll();

    unsigned long int returnTcpNum() {return m_tcpNumid;}

private:
    unsigned long int m_tcpNumid;
    double connectTime;
    double sendTime;
}; //end tcpClient Class

class TLSClient : public Client
{
public:
    TLSClient(config *config);
    virtual ~TLSClient();

    virtual int configure();

    int Connect();

    int process();

    unsigned long int returnTlsNum() {return m_tlsNumid;}

protected:
#ifdef SSL_9_CENTOS_5
    SSL_METHOD *meth;
#else
    const SSL_METHOD *meth;
#endif

    SSL_CTX          *ctx;
    SSL              *ssl[MAX_SOCKET_FD];

private:
    unsigned long int m_tlsNumid;
};


class UDPClient : public Client
{
public:
    /*UdpClient constructor*/
    UDPClient(config *config): Client(config)
    {
        m_Udpnumid = config->id; // this has to be unique for the object

    }
    int Connect(); //Not really a connect like tcp just binds the socket
    int process(); //Send data
    int readProcess(int fd);
    int readPoll();
    int returnUdpNum() {return m_Udpnumid;}

private:
    unsigned long int m_Udpnumid;
}; //end UdpClient Class


class DTLSClient : public TLSClient
{
public :
	DTLSClient(config *);
	virtual ~DTLSClient();
    int Connect();
    int process();
    int readProcess(int fd);
    int readPoll();
    void cleanupConnectionState( SSL *ssl, int fd );
    unsigned long int returnDTlsNum() {return m_dtlsNumid;}
    void timerHandler(const boost::system::error_code& es,
        boost::asio::deadline_timer* t, int* count);
    void timerHandler_old(const boost::system::error_code &e,boost::asio::deadline_timer* t, int* count);
private:
    unsigned long int m_dtlsNumid;
    boost::asio::deadline_timer t;
    pthread_mutex_t timerLock;

};


int checkTransferComplete(config *inputSettings);

