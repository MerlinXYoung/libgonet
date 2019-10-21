#pragma once
#include "config.h"
#include "ztcp_detail.h"
#include "abstract.h"
#if _GONET_AZMQ_
namespace gonet {

class ztcp : public Protocol
{
public:
    typedef Protocol::endpoint endpoint;
    typedef ztcp_detail::ZTcpServer server;
    typedef ztcp_detail::ZTcpClient client;

    ztcp();
    virtual boost::shared_ptr<ServerBase> CreateServer();
    virtual boost::shared_ptr<ClientBase> CreateClient();

    static ztcp* instance();
};

}//namespace gonet
#endif
