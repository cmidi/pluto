#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
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
#include <string>
#include <string.h>
#include "IpsecClient.h"
#include <iostream>
#include <libTransport/logger.h>
static const char version[] = "IPSEC TESTER VERSION 1.0.0\n";
using namespace std;
using namespace TT;

tunnel_vec global_vector;

void print_map(tun_map myMap){
	map_iter t;
	for (t = myMap.begin(); t != myMap.end() ; ++t){
	    cout << t->first << " "
	              << t->second << " " << "\n";
	}
}

void init_global_vector(){
	map<string,string> m = {{"interface","eth1"},{"rsa","192.168.1.1"},{"hmac","0x111"},{"key","0x222"},{"algo","aes-128"},{"tun","esp"}};
	map<string,string> m1 = {{"interface","eth2"},{"rsa","192.168.1.2"},{"hmac","0x111"},{"key","0x222"},{"algo","aes-128"},{"tun","esp"}};
	map<string,string> m2 = {{"interface","eth3"},{"rsa","192.168.1.3"},{"hmac","0x111"},{"key","0x222"},{"algo","aes-128"},{"tun","esp"}};
	map<string,string> m3 = {{"interface","eth4"},{"rsa","192.168.1.4"},{"hmac","0x111"},{"key","0x222"},{"algo","aes-128"},{"tun","esp"}};
	map<string,string> m4 = {{"interface","eth5"},{"rsa","192.168.1.5"},{"hmac","0x111"},{"key","0x222"},{"algo","aes-128"},{"tun","esp"}};
	map<string,string> m5 = {{"interface","eth6"},{"rsa","192.168.1.6"},{"hmac","0x111"},{"key","0x222"},{"algo","aes-128"},{"tun","esp"}};
	map<string,string> m7 = {{"interface","eth7"},{"rsa","192.168.1.7"},{"hmac","0x111"},{"key","0x222"},{"algo","aes-128"},{"tun","esp"}};
	global_vector.push_back(m);
	global_vector.push_back(m1);
	global_vector.push_back(m2);
	global_vector.push_back(m3);
	global_vector.push_back(m4);
	global_vector.push_back(m5);
	global_vector.push_back(m7);
}
void print_info(int argc){
	  if(argc == 1){
		  char information[] = "Config will be created Now\n";
		  char print_ver[sizeof(version)+sizeof(information)] = {};
		  strcpy(print_ver, version);
		  strcat(print_ver,information);

	  }
}

int create_config(int argc,Config *conf){
    if (argc == 1){
    	init_global_vector();
    	TT_LOG_DEBUG_CONFIG("sizeof global vec:debug\n");
    	TT_LOG_ERROR_CONFIG("sizeof global vec:error\n");
    	TT_LOG_TRACE_CONFIG("sizeof global vec:error\n");
    	for( unsigned int i = 0; i < global_vector.size();++i){
    		conf->pushTunnelVec(global_vector[i]);
    	}
        conf->writeTunnelstoConfig();
    	return 1;
    }
    else
    	return 0;
}



int main(int argc, char **argv){
  int ret=0;
  signal(SIGPIPE, SIG_IGN);
  TransportLogInterface *logger  = TransportLog::get_logger();

  std::string stdout = "stdout";
  char filename[80] = "ipsec.log";

  TT_LOG_INIT(LOG_TRACE,"config",filename);
  logger->createSink(stdout);
  TT::Config *conf = new TT::Config(JSON);
  print_info(argc);
  ret = create_config(argc,conf);

  if (ret) return ret;
  tunnel_vec tunnels;
  tunnels = conf->getTunnelsFromConfig();
  for(unsigned int i= 0 ; i < tunnels.size(); ++i){
	  print_map(tunnels[i]);
  }

  TT_LOG_STOP();
  delete conf;
  return ret;
}
