/******************************************************************************
 *                       ____    _    _____                                   *
 *                      / ___|  / \  |  ___|    C++                           *
 *                     | |     / _ \ | |_       Actor                         *
 *                     | |___ / ___ \|  _|      Framework                     *
 *                      \____/_/   \_|_|                                      *
 *                                                                            *
 * Copyright (C) 2011 - 2017                                                  *
 * Dominik Charousset <dominik.charousset (at) haw-hamburg.de>                *
 *                                                                            *
 * Distributed under the terms and conditions of the BSD 3-Clause License or  *
 * (at your option) under the terms and conditions of the Boost Software      *
 * License 1.0. See accompanying files LICENSE and LICENSE_ALTERNATIVE.       *
 *                                                                            *
 * If you did not receive a copy of the license files, see                    *
 * http://opensource.org/licenses/BSD-3-Clause and                            *
 * http://www.boost.org/LICENSE_1_0.txt.                                      *
 ******************************************************************************/

#include "caf/io/middleman_actor.hpp"

#include <stdexcept>
#include <tuple>
#include <utility>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "caf/actor.hpp"
#include "caf/actor_proxy.hpp"
#include "caf/actor_system_config.hpp"
#include "caf/logger.hpp"
#include "caf/node_id.hpp"
#include "caf/sec.hpp"
#include "caf/send.hpp"
#include "caf/typed_event_based_actor.hpp"

#include "caf/io/basp_broker.hpp"
#include "caf/io/middleman_actor_impl.hpp"
#include "caf/io/system_messages.hpp"

#include "caf/io/network/default_multiplexer.hpp"
#include "caf/io/network/interfaces.hpp"

#include "caf/openssl/manager.hpp"

namespace caf {
namespace openssl {

namespace {

using native_socket = io::network::native_socket;
using default_mpx = io::network::default_multiplexer;

struct ssl_connection {
  ssl_connection() {
    ctx = SSL_CTX_new(TLSv1_2_method());

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);

    if (!ctx)
      CAF_RAISE_ERROR("cannot create OpenSSL context");

    auto ecdh = EC_KEY_new_by_curve_name(NID_secp384r1);
    if (!ecdh)
      CAF_RAISE_ERROR("cannot get ECDH curve");

    SSL_CTX_set_tmp_ecdh(ctx, ecdh);

    if (!SSL_CTX_set_cipher_list(ctx, "AECDH-AES256-SHA"))
      CAF_RAISE_ERROR("cannot set OpenSSL cipher");

    ssl = SSL_new(ctx);

    if (!ssl)
      CAF_RAISE_ERROR("cannot create SSL session");
  }

  ~ssl_connection() {
    SSL_free(ssl);
    SSL_CTX_free(ctx);
  }

  bool read_some(size_t& result, native_socket fd, void* buf, size_t len) {
    CAF_LOG_TRACE(CAF_ARG(fd) << CAF_ARG(len));

    if (len == 0)
      return 0;

    auto ret = SSL_read(ssl, buf, len);

    if (ret > 0) {
      result = ret;
      return true;
    } else {
      result = 0;
      return handle_ssl_error(ret);
    }
  }

  bool write_some(size_t& result, native_socket fd, const void* buf,
                  size_t len) {
    CAF_LOG_TRACE(CAF_ARG(fd) << CAF_ARG(len));

    if (len == 0)
      return true;

    auto ret = SSL_write(ssl, buf, len);

    if (ret > 0) {
      result = ret;
      return true;
    } else {
      result = 0;
      return handle_ssl_error(ret);
    }
  }

  bool connect(native_socket fd) {
    SSL_set_fd(ssl, fd);
    SSL_set_connect_state(ssl);

    auto ret = SSL_connect(ssl);
    return ret > 0 || handle_ssl_error(ret);
  }

  bool try_accept(native_socket& result, native_socket fd) {
    CAF_LOG_TRACE(CAF_ARG(fd));

    sockaddr_storage addr;
    memset(&addr, 0, sizeof(addr));
    socklen_t addrlen = sizeof(addr);
    result = ::accept(fd, reinterpret_cast<sockaddr*>(&addr), &addrlen);

    CAF_LOG_DEBUG(CAF_ARG(fd) << CAF_ARG(result));

    if (result == io::network::invalid_native_socket) {
      auto err = io::network::last_socket_error();
      if (!io::network::would_block_or_temporarily_unavailable(err))
        return false;
    }

    SSL_set_fd(ssl, result);
    SSL_set_accept_state(ssl);

    auto ret = SSL_accept(ssl);

    if (ret > 0)
      return true;
    else
      return handle_ssl_error(ret);
  }

  bool handle_ssl_error(int ret) {
    auto err = SSL_get_error(ssl, ret);

    switch (err) {
      case SSL_ERROR_WANT_READ: // Try again next time.
      case SSL_ERROR_WANT_WRITE:
        return true;

      case SSL_ERROR_ZERO_RETURN: // Regular remote connection shutdown.
      case SSL_ERROR_SYSCALL:     // Socket connection closed.
        return false;

      default: // Other error.
        // TODO: Log.
        ERR_print_errors_fp(stderr);
        return false;
    }
  }

private:
  SSL_CTX* ctx;
  SSL* ssl;
};

struct ssl_policy {
  ssl_policy(std::shared_ptr<ssl_connection> ssl) : ssl_(ssl) {
  }

  bool read_some(size_t& result, native_socket fd, void* buf, size_t len) {
    return ssl_->read_some(result, fd, buf, len);
  }

  bool write_some(size_t& result, native_socket fd, const void* buf,
                  size_t len) {
    return ssl_->write_some(result, fd, buf, len);
  }

  bool try_accept(native_socket& result, native_socket fd) {
    return ssl_->try_accept(result, fd);
  }

  std::shared_ptr<ssl_connection> ssl_;
};

class scribe_impl : public io::scribe {
public:
  scribe_impl(default_mpx& mpx, native_socket fd,
              std::shared_ptr<ssl_connection> ssl)
      : scribe(io::network::conn_hdl_from_socket(fd)),
        launched_(false),
        stream_(mpx, fd, ssl) {
    // nop
  }

  void configure_read(io::receive_policy::config config) override {
    CAF_LOG_TRACE("");
    stream_.configure_read(config);
    if (!launched_)
      launch();
  }

  void ack_writes(bool enable) override {
    CAF_LOG_TRACE(CAF_ARG(enable));
    stream_.ack_writes(enable);
  }

  std::vector<char>& wr_buf() override {
    return stream_.wr_buf();
  }

  std::vector<char>& rd_buf() override {
    return stream_.rd_buf();
  }

  void stop_reading() override {
    CAF_LOG_TRACE("");
    stream_.stop_reading();
    detach(&stream_.backend(), false);
  }

  void flush() override {
    CAF_LOG_TRACE("");
    stream_.flush(this);
  }

  std::string addr() const override {
    auto x = io::network::remote_addr_of_fd(stream_.fd());
    if (!x)
      return "";
    return *x;
  }

  uint16_t port() const override {
    auto x = io::network::remote_port_of_fd(stream_.fd());
    if (!x)
      return 0;
    return *x;
  }

  void launch() {
    CAF_LOG_TRACE("");
    CAF_ASSERT(!launched_);
    launched_ = true;
    stream_.start(this);
  }

  void add_to_loop() override {
    stream_.activate(this);
  }

  void remove_from_loop() override {
    stream_.passivate();
  }

private:
  bool launched_;
  io::network::stream_impl<ssl_policy> stream_;
};

class doorman_impl : public io::doorman {
public:
  doorman_impl(default_mpx& mx, native_socket fd,
               std::shared_ptr<ssl_connection> ssl)
      : doorman(io::network::accept_hdl_from_socket(fd)),
        acceptor_(mx, fd, ssl),
        ssl_(ssl) {
    // nop
  }

  bool new_connection() override {
    CAF_LOG_TRACE("");
    if (detached())
      // we are already disconnected from the broker while the multiplexer
      // did not yet remove the socket, this can happen if an I/O event
      // causes
      // the broker to call close_all() while the pollset contained
      // further activities for the broker
      return false;
    auto& dm = acceptor_.backend();
    auto sptr =
      make_counted<scribe_impl>(dm, acceptor_.accepted_socket(), ssl_);
    auto hdl = sptr->hdl();
    parent()->add_scribe(std::move(sptr));
    return doorman::new_connection(&dm, hdl);
  }

  void stop_reading() override {
    CAF_LOG_TRACE("");
    acceptor_.stop_reading();
    detach(&acceptor_.backend(), false);
  }

  void launch() override {
    CAF_LOG_TRACE("");
    acceptor_.start(this);
  }

  std::string addr() const override {
    auto x = io::network::local_addr_of_fd(acceptor_.fd());
    if (!x)
      return "";
    return std::move(*x);
  }

  uint16_t port() const override {
    auto x = io::network::local_port_of_fd(acceptor_.fd());
    if (!x)
      return 0;
    return *x;
  }

  void add_to_loop() override {
    acceptor_.activate(this);
  }

  void remove_from_loop() override {
    acceptor_.passivate();
  }

private:
  io::network::acceptor_impl<ssl_policy> acceptor_;
  std::shared_ptr<ssl_connection> ssl_;
};

class middleman_actor_impl : public io::middleman_actor_impl {
public:
  middleman_actor_impl(actor_config& cfg, actor default_broker)
      : io::middleman_actor_impl(cfg, std::move(default_broker)) {
    // nop
  }

protected:
  expected<io::scribe_ptr> connect(const std::string& host,
                                   uint16_t port) override {

    auto fd = io::network::new_tcp_connection(host, port);

    if (!fd)
      return std::move(fd.error());

    auto ssl = std::make_shared<ssl_connection>();

    if (ssl->connect(*fd))
      return make_counted<scribe_impl>(mpx(), *fd, ssl);
    else
      return sec::cannot_connect_to_node;
  }

  expected<io::doorman_ptr> open(uint16_t port, const char* addr,
                                 bool reuse) override {

    auto fd = io::network::new_tcp_acceptor_impl(port, addr, reuse);

    if (!fd)
      return std::move(fd.error());

    auto ssl = std::make_shared<ssl_connection>();

    return make_counted<doorman_impl>(mpx(), *fd, ssl);
  }

private:
  default_mpx& mpx() {
    return static_cast<default_mpx&>(system().middleman().backend());
  }
};

} // namespace <anonymous>

io::middleman_actor make_middleman_actor(actor_system& sys, actor db) {
  return sys.config().middleman_detach_utility_actors ?
           sys.spawn<middleman_actor_impl, detached + hidden>(std::move(db)) :
           sys.spawn<middleman_actor_impl, hidden>(std::move(db));
}

} // namespace openssl
} // namespace caf
