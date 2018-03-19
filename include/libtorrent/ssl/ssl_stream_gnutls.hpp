#ifndef TORRENT_SSL_SSL_STREAM_GNUTLS_HPP
#define TORRENT_SSL_SSL_STREAM_GNUTLS_HPP

#include <limits>
#include <string>
#include <cstddef>

#include <boost/asio.hpp>
#include <boost/asio/ssl/stream_base.hpp>
#include <boost/system/error_code.hpp>

#include <gnutls/gnutls.h>

namespace libtorrent {

namespace ssl {
namespace gnutls {

class context;

template<typename NextLayer>
class stream : public boost::asio::ssl::stream_base {

	using error_code = boost::system::error_code;

	public:

		using next_layer_type = NextLayer;
		using lowest_layer_type = typename NextLayer::lowest_layer_type;
		using native_handle_type = gnutls_session_t;
		using executor_type = typename NextLayer::executor_type;
		enum verify_mode { verify_none };

		template<typename HandshakeHandler>
		void async_handshake(handshake_type type, HandshakeHandler handler) {
			boost::asio::post([this, type, handler]() {
				error_code ec;
				handshake(type, handler, ec);
				handler(ec);
			});
		}

		template<typename ConstBufferSequence, typename BufferedHandshakeHandler>
		void async_handshake(handshake_type type, const ConstBufferSequence& buffers, BufferedHandshakeHandler handler) {
			boost::asio::post([this, type, &buffers, handler]() {
				error_code ec;
				int bytes_transferred = 0;
				handshake(type, buffers, handler, ec);
			});
		}

		template<typename MutableBufferSequence, typename ReadHandler>
		void async_read_some(const MutableBufferSequence& buffers, ReadHandler handler) {
			boost::asio::post([this, &buffers, handler]() {
				error_code ec;
				auto bytes_read = read_some(buffers, ec);
				handler(ec, bytes_read);
			});
		}

		template<typename ShutdownHandler>
		void async_shutdown(ShutdownHandler handler) {
			boost::asio::post([this, handler]() {
				error_code ec;
				shutdown(ec);
				handler(ec);
			});
		}

		template<typename ConstBufferSequence, typename WriteHandler>
		void async_write_some(const ConstBufferSequence& buffers, WriteHandler handler) {
			boost::asio::post([this, &buffers, handler]() {
				error_code ec;
				size_t bytes_transferred = write_some(buffers, ec);
				// TODO: handler(ec, bytes_transferred);
			});
		}

		boost::asio::io_service& get_io_service() {
			return m_next_layer.lowest_layer().get_io_service();
		}

		void handshake(handshake_type type) {
			error_code ec;
			handshake(type, ec);
		}

		error_code handshake(handshake_type type, error_code& ec) {
			int err;

			do {
				err = gnutls_handshake(m_session);
			} while(err == GNUTLS_E_AGAIN || err == GNUTLS_E_INTERRUPTED);

			if( err != 0 ) {
				// TODO: error
			}
		}

		template<typename ConstBufferSequence>
		void handshake(handshake_type type, const ConstBufferSequence& buffers) {
			error_code ec;
			handshake(type, ec);
			// TODO: error checking
		}

		template<typename ConstBufferSequence>
		error_code handshake(handshake_type type, const ConstBufferSequence& buffers, error_code& ec) {
			handshake(type, ec);
			return ec;
		}

		const lowest_layer_type& lowest_layer() const {
			return m_next_layer.lowest_layer();
		}

		lowest_layer_type& lowest_layer() {
			return m_next_layer.lowest_layer();
		}

		gnutls_session_t native_handle() {
            return m_session;
		}

		const next_layer_type& next_layer() const {
			return m_next_layer;
		}

		next_layer_type& next_layer() {
			return m_next_layer;
		}

		template<typename MutableBufferSequence>
		size_t read_some(const MutableBufferSequence& buffers) {
			error_code ec;
			auto bytes_read = read_some(buffers, ec);
			// TODO: exception
			return bytes_read;
		}

		template<typename MutableBufferSequence>
		size_t read_some(const MutableBufferSequence& buffers, error_code& ec) {
			using boost::asio::buffer_cast;
			using boost::asio::buffer_size;
			// TODO: err handling
			int err = gnutls_record_recv(m_session, buffer_cast<char*>(buffers), buffer_size(buffers));
		}

		template<typename VerifyCallback>
		void set_verify_callback(VerifyCallback callback) {
			error_code ec;
			set_verify_callback(callback, ec);
			// TODO: error handling
		}

		template<typename VerifyCallback>
		error_code set_verify_callback(VerifyCallback callback, error_code& ec) {
			// TODO: have cred somewhere
			// This function convert callback output to int so as to match verify_function prototype
			//gnutls_certificate_set_verify_function(cred, [](gnutls_session_t session) {
			//	if(!callback(session))
			//		return 0;
			//	return 1
			//});
			//// TODO: what to do with error_code ?
			return ec;
		}

		void set_verify_depth(int depth) {
			// XXX: what to do ?
			// note: gnutls_certificate_set_verify_limits allows to customize the default verification
			// function limits parameters but we might push our own function
			error_code ec;
			set_verify_depth(depth, ec);
		}

		error_code set_verify_depth(int depth, error_code& ec) {
			// XXX: sign check ?
			//gnutls_certificate_set_verify_limits(
			m_depth = depth;
		}

		void set_verify_mode(verify_mode v) {
			error_code ec;
			set_verify_mode(v, ec);
			// TODO: error check
		}

		error_code set_verify_mode(verify_mode v, error_code& ec) {
			// TODO: store mode, gnutls_certificate_verify_flags
			// TODO: gnutls_certificate_set_verify_flags <= doesn't seem to be the right function
		}

		void shutdown() {
			error_code ec;
			shutdown(ec);
			// TODO: error check
		}

		error_code shutdown(error_code& ec) {
			int err;
			do {
				err = gnutls_bye(m_session, GNUTLS_SHUT_RDWR);
			} while(err == GNUTLS_E_AGAIN || err == GNUTLS_E_INTERRUPTED);
			//TODO: error_handling
            return ec;
		}

		stream(boost::asio::io_service& service, gnutls::context session)
			: m_next_layer(service)
		{
			gnutls_transport_set_ptr(m_session, this);
			gnutls_transport_set_push_function(m_session, push_func);
			gnutls_transport_set_pull_function(m_session, pull_func);
			//gnutls_transport_set_lowat(m_session, 0);
		}

		template<typename ConstBufferSequence>
		std::size_t write_some(const ConstBufferSequence& buffers) {
			error_code ec;
			auto byte_sent = write_some(buffers, ec);
			// TODO: error_handling
			return byte_sent;
		}

		template<typename ConstBufferSequence>
		std::size_t write_some(const ConstBufferSequence& buffers, error_code& ec) {
			using boost::asio::buffer_size;
			using boost::asio::buffer_cast;
			int bytes_sent;
			do {
				// TODO: bytes_sent = gnutls_record_send(m_session, buffer_cast<const char*>(buffers), buffer_size(buffers));
			} while(bytes_sent == GNUTLS_E_AGAIN || bytes_sent == GNUTLS_E_INTERRUPTED);

			if(bytes_sent > 0)
				return bytes_sent;

			// TODO: err handling
			return -1;
		}

		~stream() {

		}
	private:

		static ssize_t pull_func(void* s, void* buffer, std::size_t size) {
			// TODO not complete, read data
			//return static_cast<NextLayer*>(s)->next_layer();
			return 0;
		}

		static ssize_t push_func(void* s, const void* buffer, std::size_t length) {
			// TODO not complete, write data
			//return static_cast<NextLayer*>(s)->next_layer();
			return 0;
		}

		//static int verify_func(gnutls_session_t session) {
		//	// TODO: switch on verify_mode
		//}

		//static int post_client_hello_func(gnutls_session_t session) {
		//	// TODO: check SNI : here or elsewhere ? let gnutls dispatch ?
		//	// TODO: should be in a separated class (not in boost interface)
		//}

		gnutls_session_t m_session;
		NextLayer m_next_layer;
		unsigned int m_depth = std::numeric_limits<unsigned int>::max();
        unsigned int m_verifyMode;
};

}
}
}


#endif
