#pragma once
#include "config.h"
#include "option.h"

namespace gonet {

    using namespace ::boost::asio;
    using namespace ::boost::asio::ip;

    enum class tcp_socket_type_t
    {
        tcp,
        ssl,
    };

    enum class handshake_type_t
    {
        client,
        server,
    };


    typedef std::unique_ptr<ssl::context> ssl_context;

    // struct tcp_context {};

    class tcp_socket
    {
    public:
        tcp_socket(io_service& ios/*, tcp_context & ctx*/)
            : type_(tcp_socket_type_t::tcp),socket_(new tcp::socket(ios))
        {

        }

        tcp_socket(io_service& ios, ssl_context & ctx)
            : type_(tcp_socket_type_t::ssl),socket_(new ssl::stream<tcp::socket>(ios, *ctx))
        {

        }

        ~tcp_socket(){
            if (type_ == tcp_socket_type_t::ssl)
                socket_.ssl_.~unique_ptr();
            else
                socket_.tcp_.~unique_ptr();
        }
        static ssl_context create_context(OptionSSL const& ssl_opt)
        {
            std::unique_ptr<ssl::context> ctx(new ssl::context((ssl::context::method)ssl_opt.ssl_version));

            // options
            ssl::context::options opt = ssl::context::default_workarounds
                | ssl::context::single_dh_use;
            if (ssl_opt.disable_compression)
                opt |= ssl::context::no_compression;
            ctx->set_options(opt);

            // password callback
            if (ssl_opt.pwd_callback)
                ctx->set_password_callback(ssl_opt.pwd_callback);

            if (ssl_opt.verify_mode == OptionSSL::verify_mode_t::none) {
                ctx->set_verify_mode(ssl::context::verify_none);
            } else if (ssl_opt.verify_mode == OptionSSL::verify_mode_t::optional) {
                ctx->set_verify_mode(ssl::context::verify_peer);
                ctx->load_verify_file(ssl_opt.verify_file);
            } else { // required
                ctx->set_verify_mode(ssl::context::verify_peer 
                        | ssl::context::verify_fail_if_no_peer_cert);
                ctx->load_verify_file(ssl_opt.verify_file);
            }

            if (ssl_opt.certificate_chain_file.size())
                ctx->use_certificate_chain_file(ssl_opt.certificate_chain_file);
            if (ssl_opt.private_key_file.size())
                ctx->use_private_key_file(ssl_opt.private_key_file, ssl::context::pem);
            if (ssl_opt.tmp_dh_file.size())
                ctx->use_tmp_dh_file(ssl_opt.tmp_dh_file);
            return std::move(ctx);
        }

        // static tcp_context create_context()
        // {
        //     return tcp_context();
        // }


        tcp_socket_type_t type() const
        {
            return type_;
        }

        tcp::socket& native_socket()
        {

            if (type_ == tcp_socket_type_t::ssl)
                return socket_.ssl_->next_layer();

            return *socket_.tcp_;
        }

        tcp::socket::native_handle_type native_handle()
        {
            return native_socket().native_handle();
        }

        boost::system::error_code handshake(handshake_type_t type)
        {
            boost::system::error_code ec;

            if (type_ == tcp_socket_type_t::ssl) {
                return socket_.ssl_->handshake(
                        type == handshake_type_t::client ? ssl::stream_base::client : ssl::stream_base::server,
                        ec);
            }
            return ec;
        }

        boost::system::error_code shutdown(socket_base::shutdown_type type)
        {
            boost::system::error_code ec;

            if (type_ == tcp_socket_type_t::ssl)
                return socket_.ssl_->shutdown(ec);
            return socket_.tcp_->shutdown(type, ec);
        }

        boost::system::error_code close()
        {
            boost::system::error_code ec;

            if (type_ == tcp_socket_type_t::ssl)
                socket_.ssl_->shutdown(ec);

            return native_socket().close(ec);
        }

        template <typename MutableBufferSequence>
            std::size_t read_some(const MutableBufferSequence& buffers,
                    boost::system::error_code& ec)
            {

                if (type_ == tcp_socket_type_t::ssl)
                    return socket_.ssl_->read_some(buffers, ec);

                return socket_.tcp_->read_some(buffers, ec);
            }

        template <typename ConstBufferSequence>
            std::size_t write_some(const ConstBufferSequence& buffers,
                    boost::system::error_code& ec)
            {

                if (type_ == tcp_socket_type_t::ssl)
                    return socket_.ssl_->write_some(buffers, ec);

                return socket_.tcp_->write_some(buffers, ec);
            }

    private:
        tcp_socket_type_t type_;
        union S
        {
            //char placeholder_[sizeof(std::unique_ptr<tcp::socket>)];
            std::unique_ptr<tcp::socket> tcp_;
            std::unique_ptr<ssl::stream<tcp::socket>> ssl_;
            S(tcp::socket* s):tcp_(s){}
            S(ssl::stream<tcp::socket>* s):ssl_(s){}
            ~S(){};
        }socket_;

    };

} //namespace gonet
