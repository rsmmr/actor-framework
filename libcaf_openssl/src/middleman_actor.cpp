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

enum Side { Client, Server };

static bool wait_for_fd(int fd, unsigned long timeout) {
  fd_set fds;
  int nfds = fd + 1;
  FD_ZERO(&fds);
  FD_SET(fd, &fds);

  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = timeout;

  return (::select(nfds, &fds, nullptr, nullptr, &tv) > 0);
}

struct ssl_state {
  Side side;
  SSL_CTX* ctx;
  SSL* ssl;

  void debug(std::string msg1, std::string msg2 = "") {
#if 0
    std::cerr << (side == Side::Client ? "client" : "server") << ": " << msg1
              << " " << msg2 << std::endl;
#endif
  }

  ssl_state(Side side) : side(side) {
  }

  void init() {
    debug("init");
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
};

static void print_bytes(const char* prefix, const void* buf, size_t size) {
  const char* b = (const char*)buf;
  fprintf(stderr, "%10s (%lu) |", prefix, size);
  while (size--) {
    auto c = *b++;

    if (isprint(c))
      fputc((char)c, stderr);
    else
      fprintf(stderr, "\\x%02x", (unsigned char)c);
  }
  fprintf(stderr, "\n");
}

struct ssl_policy {
  ssl_policy(std::shared_ptr<ssl_state> state) : state_(state) {
  }

  /// Reads up to `len` bytes from an OpenSSL socket.
  bool read_some(size_t& result, native_socket fd, void* buf, size_t len) {
    CAF_LOG_TRACE(CAF_ARG(fd) << CAF_ARG(len));

    state_->debug("read");

    if (len == 0)
      return 0;

    while (true) {
      wait_for_fd(SSL_get_fd(state_->ssl), 1000);
      auto ret = SSL_read(state_->ssl, buf, len);

      if (ret > 0) {
        state_->debug("read", "success");
        result = ret;
        print_bytes("read", buf, len);
        return true;
      }
      auto err = SSL_get_error(state_->ssl, ret);

      switch (err) {
        case SSL_ERROR_WANT_READ:
          state_->debug("read", "wants read");
          continue;

        case SSL_ERROR_WANT_WRITE:
          state_->debug("read", "wants write");
          continue;

        case SSL_ERROR_ZERO_RETURN: // Regular remote connection shutdown.
        case SSL_ERROR_SYSCALL:     // Socket connection closed.
          state_->debug("read", "error A");
          return false;

        default: // Other error.
          // TODO: Log.
          state_->debug(
            "read", std::string("error B") + ERR_error_string(err, nullptr));
          ERR_print_errors_fp(stderr);
          return false;
      }
    }
  }

  bool write_some(size_t& result, native_socket fd, const void* buf,
                  size_t len) {
    CAF_LOG_TRACE(CAF_ARG(fd) << CAF_ARG(len));

    state_->debug("write");

    if (len == 0)
      return true;

    while (true) {
      auto ret = SSL_write(state_->ssl, buf, len);

      if (ret > 0) {
        state_->debug("write", "success");
        result = ret;
        print_bytes("write", buf, result);
        return true;
      }

      auto err = SSL_get_error(state_->ssl, ret);

      switch (err) {
        case SSL_ERROR_WANT_READ:
          state_->debug("write", "wants read");
          continue;

        case SSL_ERROR_WANT_WRITE:
          state_->debug("write", "wants write");
          continue;

        case SSL_ERROR_ZERO_RETURN: // Regular remote connection shutdown.
        case SSL_ERROR_SYSCALL:     // Socket connection closed.
          state_->debug("write", "error A");
          return false;

        default: // Other error.
          // TODO: Log.
          state_->debug(
            "write", std::string("error B") + ERR_error_string(err, nullptr));
          ERR_print_errors_fp(stderr);
          return false;
      }
    }
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

    fprintf(stderr, "accept fd %d\n", result);

    state_->init();
    SSL_set_fd(state_->ssl, result);
    SSL_set_accept_state(state_->ssl);

    while (true) {
      wait_for_fd(SSL_get_fd(state_->ssl), 1000);
      auto ret = SSL_accept(state_->ssl);

      if (ret > 0) {
        state_->debug("accept", "accepted!");
        return true;
      }

      auto err = SSL_get_error(state_->ssl, ret);

      switch (err) {
        case SSL_ERROR_WANT_READ:
          state_->debug("accept", "wants read");
          continue;

        case SSL_ERROR_WANT_WRITE:
          state_->debug("accept", "wants write");
          continue;

        case SSL_ERROR_ZERO_RETURN: // Regular remote connection shutdown.
        case SSL_ERROR_SYSCALL:     // Socket connection closed.
          state_->debug("accept", "error A");
          return false;

        default: // Other error.
          // TODO: Log.
          state_->debug(
            "accept", std::string("error B") + ERR_error_string(err, nullptr));
          ERR_print_errors_fp(stderr);
          return false;
      }
    }

    return true;
  }

private:
  std::shared_ptr<ssl_state> state_;
};

class scribe_impl : public io::scribe {
public:
  scribe_impl(default_mpx& mpx, native_socket fd,
              std::shared_ptr<ssl_state> ssl)
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
               std::shared_ptr<ssl_state> ssl)
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
  std::shared_ptr<ssl_state> ssl_;
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

    std::cerr << "| connect " << host << " " << port << std::endl;

    auto fd = io::network::new_tcp_connection(host, port);

    if (!fd)
      return std::move(fd.error());

    auto state = std::make_shared<ssl_state>(Side::Client);
    state->init();

    fprintf(stderr, "connect fd %d\n", *fd);

    SSL_set_fd(state->ssl, *fd);
    SSL_set_connect_state(state->ssl);

    while (true) {
      auto ret = SSL_connect(state->ssl);

      if (ret > 0) {
        state->debug("connect", "connected!");
        return make_counted<scribe_impl>(mpx(), *fd, state);
      }

      auto err = SSL_get_error(state->ssl, ret);

      switch (err) {
        case SSL_ERROR_WANT_READ:
          state->debug("connect", "wants read");
          wait_for_fd(*fd, 100);
          continue;

        case SSL_ERROR_WANT_WRITE:
          state->debug("connect", "wants write");
          wait_for_fd(*fd, 100);
          continue;

        case SSL_ERROR_ZERO_RETURN: // Regular remote connection shutdown.
        case SSL_ERROR_SYSCALL:     // Socket connection closed.
          state->debug("connect", "error A");
          return sec::cannot_connect_to_node;

        default: // Other error.
          // TODO: Log.
          state->debug("connect",
                       std::string("error B") + ERR_error_string(err, nullptr));
          ERR_print_errors_fp(stderr);
          return sec::cannot_connect_to_node;
      }
    }
  }

  expected<io::doorman_ptr> open(uint16_t port, const char* addr,
                                 bool reuse) override {

    auto fd = io::network::new_tcp_acceptor_impl(port, addr, reuse);

    if (!fd)
      return std::move(fd.error());

    auto state = std::make_shared<ssl_state>(Side::Server);
    state->init();

    return make_counted<doorman_impl>(mpx(), *fd, state);
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
