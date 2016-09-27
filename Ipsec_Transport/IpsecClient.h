#ifndef __IPSEC_CLIENT_H__
#define __IPSEC_CLIENT_H__

#include "Ipsec_defs.h"
#include <libTransport/error.h>
#include <boost/scoped_ptr.hpp>
#include <boost/utility.hpp>
#include <boost/property_tree/ptree.hpp>

namespace TT{



typedef std::vector< std::map<std::string,std::string> > tunnel_vec;
typedef std::vector< std::map<std::string,std::string> >::iterator itunnel_vec;
typedef std::map<std::string,std::string> tun_map;
typedef std::map<std::string,std::string>::iterator map_iter;

class Config;

typedef void* tunnelHandle;
class IpsecTunnelsContainer;

class ReaderBase{
public:

	ReaderBase(std::string name);
	virtual ~ReaderBase(){mConfig_name.clear();};
	virtual void readInit() = 0;
	virtual TT_STATUS readConfig(tunnel_vec &deTun) = 0;
	virtual TT_STATUS writeConfig(std::string config)  = 0;
	virtual TT_STATUS writeToConfig(tun_map& t_vec) = 0 ;
	const char* get_name(){return mConfig_name.c_str();}



private:
	std::string mConfig_name;
};



class ProtoReader:virtual public ReaderBase{
public:
	ProtoReader();
	ProtoReader(const ProtoReader&); //copy

	void readInit();
	virtual ~ProtoReader();
	virtual TT_STATUS writeConfig(std::string config);
	virtual TT_STATUS readConfig(tunnel_vec &deTun);
	virtual TT_STATUS writeToConfig(tun_map& t_vec);

private:
	boost::scoped_ptr<TT::IpsecTunnelsContainer> pImpl;
    char *mConfig_type;

};

class JSONReader:virtual public ReaderBase{
public:
	JSONReader();
	JSONReader(const ProtoReader&); //copy

	void readInit();
	virtual ~JSONReader();
	virtual TT_STATUS writeConfig(std::string config);
	virtual TT_STATUS readConfig(tunnel_vec &deTun);
	virtual TT_STATUS writeToConfig(tun_map &t_vec);

private:
	boost::scoped_ptr<boost::property_tree::ptree> pImpl;
	boost::property_tree::ptree arr;
    char *mConfig_type;

};

/*
 * We create a single/non copyable Config object
 * to be used to understand the the configuration
 * of each ipsec client socket to be created
*/


typedef enum{
	PROTO = 0,
	JSON,
    MAX
}CONFIG_TYPE;


class Config :private boost::noncopyable{
public:

	Config(CONFIG_TYPE t);
	Config();
	~Config();

	int getNumTunnels(){ return mNum_tunnels; }
	void resetConfig(void){exp.reset();}

	void setConfigType(CONFIG_TYPE t);

    typedef boost::scoped_ptr<ReaderBase> smartRead;
    TT_STATUS writeTunnelstoConfig();
    tunnel_vec getTunnelsFromConfig();
    tunnelHandle getTunnel(char* ip);
    int pushTunnelVec(std::map<std::string,std::string> tun_map){ m_vec.push_back(tun_map); return (int)TT_SUCCESS;};

private:
    smartRead exp;
    int mNum_tunnels;
    tunnel_vec m_vec;
    std::string config;
    CONFIG_TYPE type;
};

}
#endif
