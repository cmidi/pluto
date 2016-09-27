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
#include <map>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>

#include <libTransport/logger.h>
#include "IpsecClient.h"

#include "TransportProto/IpsecTransport.pb.h"
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <iostream>
#include <exception>
namespace TT{

using boost::property_tree::ptree;
using boost::property_tree::read_json;
using boost::property_tree::write_json;

typedef std::vector<tun_map>::iterator tun_iter;


ReaderBase::ReaderBase(std::string name):mConfig_name(name){};

ProtoReader::ProtoReader():ReaderBase(".config"){}


ProtoReader::~ProtoReader(){
	pImpl->Clear();
}

void ProtoReader::readInit(){
	pImpl.reset(new IpsecTunnelsContainer());
}


TT_STATUS ProtoReader::writeConfig(std::string config){
	TT_STATUS status=TT_ERR;

	std::fstream output(get_name(), std::ios::out | std::ios::trunc | std::ios::binary);
	if (output){

		if(!(pImpl->SerializeToOstream(&output))){
			status = TT_ERR;
		}
		else
			status = TT_SUCCESS;
        //std::for_each(tunnel_container.begin(),tunnel_container.end(),pImpl->SerializeToOstream(&output));
        if(output.is_open())
        	output.close();

	}
    return status;
}

TT_STATUS ProtoReader::readConfig(tunnel_vec &deTun){
	TT_STATUS status = TT_ERR;
	std::fstream input(get_name(), std::ios::in  | std::ios::binary);
	tun_map push_map;
	pImpl->Clear();
	do{
        if(!input)
        	break;
		if(!pImpl->ParseFromIstream(&input))
        	break;
        for(int i =  (int)0; i < pImpl->ipsec_tunnel_size();++i){
        	const IpsecTunnel& tunnel = pImpl->ipsec_tunnel(i);
            push_map["interface"] =  tunnel.interface();
            push_map["hmac"] = tunnel.hmac();
            push_map["key"] = tunnel.key();
            push_map["algo"] = tunnel.algo();
            push_map["rsa"] = tunnel.rsa();
            push_map["tunnel"] = tunnel.tun();
        	deTun.push_back(push_map);
        }
        status = TT_SUCCESS;
	}while(0);
	return status;
}

TT_STATUS ProtoReader::writeToConfig(tun_map& t_vec){
	TT_STATUS status= TT_ERR;
	IpsecTunnel *tunnel = pImpl->add_ipsec_tunnel();

	if (tunnel){
	    tunnel->set_algo(const_cast<const char*>(t_vec["algo"].c_str()),sizeof("algo"));
        tunnel->set_interface(t_vec["interface"]);
        tunnel->set_hmac(t_vec["hmac"]);
        tunnel->set_key(t_vec["key"]);
        tunnel->set_rsa(t_vec["rsa"]);
        tunnel->set_tun(t_vec["tunnel"]);

	    status = TT_SUCCESS;
	}
	return status;
}

JSONReader::JSONReader():ReaderBase(".config"){}

JSONReader::~JSONReader(){

}
void JSONReader::readInit(){
	pImpl.reset(new boost::property_tree::ptree());
}
TT_STATUS JSONReader::writeToConfig(tun_map& t_vec){
	TT_STATUS status= TT_ERR;
	boost::property_tree::ptree pt;
	for(map_iter it = t_vec.begin();it != t_vec.end();++it){
		pt.put(it->first,it->second);
		status = TT_SUCCESS;
	}
	arr.push_back(std::make_pair("",pt));
	return status;
}

TT_STATUS JSONReader::readConfig(tunnel_vec &deTun){
	TT_STATUS status = TT_ERR;
	pImpl->clear();
	arr.clear();
	std::string filename = get_name();
	tun_map push_map;
	try{
	    read_json(filename,*pImpl);
	    status = TT_SUCCESS;
	}
	catch(std::exception& e){
		std::cout << e.what() << std::endl;
		status = TT_ERR;
		throw;
	}
	if(status == TT_SUCCESS){
		arr = pImpl->get_child("tunnels");
        for(ptree::const_iterator it = arr.begin(); it != arr.end(); ++it){
                push_map["interface"] =  it->second.get<std::string>("interface");
                push_map["hmac"] = it->second.get<std::string>("hmac");
                push_map["key"] = it->second.get<std::string>("key");
                push_map["algo"] = it->second.get<std::string>("algo");
                push_map["rsa"] = it->second.get<std::string>("rsa");
                push_map["tunnel"] = it->second.get<std::string>("tun");
                deTun.push_back(push_map);
        }
	}
	return status;
}

TT_STATUS JSONReader::writeConfig(std::string config){
	TT_STATUS status=TT_SUCCESS;
	pImpl->add_child("tunnels",arr);
	std::string filename = get_name();
	write_json(filename,*pImpl);
	arr.clear();
	pImpl->clear();
	return status;

}

Config::Config():mNum_tunnels(0),
		         config(".config"),
		         type(PROTO)
{
	if (type == PROTO)
	    exp.reset(new ProtoReader());

	if(exp)
	    exp->readInit();
}


Config::Config(CONFIG_TYPE t):mNum_tunnels(0),
		         config(".config"),
		         type(t)
{
	if (type == PROTO)
	    exp.reset(new ProtoReader());
    if (type == JSON)
    	exp.reset(new JSONReader());
	if(exp)
	    exp->readInit();
}

Config::~Config(){
	mNum_tunnels = 0;

	m_vec.clear();
	config.clear();
}

void Config::setConfigType(CONFIG_TYPE t){

	resetConfig();
	if (t == PROTO)
	    exp.reset(new ProtoReader());
    if (t == JSON)
    	exp.reset(new JSONReader());
	if(exp)
	    exp->readInit();

}

tunnelHandle Config::getTunnel(char* ip){
	tunnelHandle tun=NULL;
	return tun;
}

tunnel_vec Config::getTunnelsFromConfig(){
	tunnel_vec vecTunnel;
	exp->readConfig(vecTunnel);
	return vecTunnel;
}


TT_STATUS Config::writeTunnelstoConfig(){
	TT_STATUS status= TT_ERR;
    tun_iter itunnel;
    mNum_tunnels = m_vec.size();
    for(itunnel = m_vec.begin(); itunnel < m_vec.end();++itunnel){
    	//print_map(*itunnel);
    	if((status = exp->writeToConfig(*itunnel)) == TT_ERR ){
    		break;
    	}

    }
    if((status =  exp->writeConfig(this->config)) == TT_ERR)
    	TT_LOG_DEBUG_CONFIG("cannot write to file stream");
	return status;

}

}

