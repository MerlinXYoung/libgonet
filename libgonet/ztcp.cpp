#include "ztcp.h"
#include <boost/make_shared.hpp>
#if _GONET_AZMQ_
namespace gonet {

    ztcp::ztcp()
        : Protocol(::boost::asio::ip::tcp::v4().family(), proto_type::zmq)
    {}

    boost::shared_ptr<ServerBase> ztcp::CreateServer()
    {
        return boost::make_shared<server>();
    }
    boost::shared_ptr<ClientBase> ztcp::CreateClient()
    {
        return boost::make_shared<client>();
    }

    ztcp* ztcp::instance()
    {
        static ztcp obj;
        return &obj;
    }

} //namespace gonet
#endif
