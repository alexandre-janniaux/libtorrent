#ifndef TORRENT_SSL_SSL_STREAM_GNUTLS_HPP
#define TORRENT_SSL_SSL_STREAM_GNUTLS_HPP

#include <limits>

namespace libtorrent {

namespace gnutls {

template<typename Stream>
class Stream {

	public:

		typedef typename sock_type::next_layer_type next_layer_type;
		typedef typename Stream::lowest_layer_type lowest_layer_type;
		enum handshake_type { TEST };

		template<typename HandshakeHandler>
		void async_handshake(handshake_type type,HandshakeHandler handler) {

		}

		template<typename ConstBufferSequence, typename BufferedHandshakeHandler>
		void async_handshake(handshake_type type, const ConstBufferSequence& buffers, BufferedHandshakeHandler handler) {

		}

		template<typename MutableBufferSequence, typename ReadHandler>
		void async_read_some(const MutableBufferSequence& buffers, ReadHandler handler) {

		}

		template<typename ShutdownHandler>
		void async_shutdown(ShutdownHandler handler) {

		}

		template<typename ConstBufferSequence, typename WriteHandler>
		void async_write_some(const ConstBufferSequence& buffers, WriteHandler handler) {

		}

		boost::asio::io_service& get_io_service() {
			return m_socket.lowest_layer().get_io_service();
		}

		void handshake(handshake_type type) {
			boost::system::error_code ec;
			handshake(type, ec);
		}

		boost::system::error_code handshake(handshake_type type, boost::system::error_code& ec) {
			int err = gnutls_handshake(m_session);
			if( err != 0 ) {

			}
		}

		template<typename ConstBufferSequence>
		void handshake(handshake_type type, const ConstBufferSequence& buffers) {

		}

		template<typename ConstBufferSequence>
		boost::system::error_code handshake(handshake_type type, const ConstBufferSequence& buffers, boost::system::error_code& ec) {

		}

		const lowest_layer_type& lowest_layer() const {
			return m_next_layer.lowest_layer();
		}

		lowest_layer_type& lowest_layer() {
			return m_next_layer.lowest_layer();
		}

		gnutls_session_t native_handle() {

		}

		const next_layer_type& next_layer() const {
			return m_next_layer;
		}

		next_layer_type& next_layer() {
			return m_next_layer;
		}

		template<typename MutableBufferSequence>
		std::size_t read_some(const MutableBufferSequence& buffers) {
		}

		template<typename MutableBufferSequence>
		std::size_t read_some(const MutableBufferSequence& buffers, boost::system::error_code& ec) {
			using boost::asio::buffer_type;
			using boost::asio::buffer_size;
			// TODO: err handling
			int err = gnutls_record_recv(m_session, buffer_type<char*>(buffers), buffer_size(buffers));
		}

		template<typename VerifyCallback>
		void set_verify_callback(VerifyCallback callback) {

		}

		template<typename VerifyCallback>
		boost::system::error_code set_verify_callback(VerifyCallback callback, ,boost::system::error_code& ec) {

		}

		void set_verify_depth(int depth) {

		}

		boost::system::error_code set_verify_depth(int depth, boost::system::error_code& ec) {
			m_depth = depth;
		}

		void set_verify_mode(verify_mode v) {
			boost::system::error_code ec;
			set_verify_mode(v, ec);
			// TODO: error check
		}

		boost::system::error_code set_verify_mode(verify_mode v, boost::system::error_code& ec) {
			// TODO: store mode
		}

		void shutdown() {
			boost::system::error_code ec;
			shutdown(ec);
			// TODO: error check
		}

		boost::system::error_code shutdown(boost::system::error_code& ec) {
			int err = gnutls_bye(m_session, GNUTLS_SHUT_RDWR);
		}

		template<typename Arg>
		Stream(Arg& arg, gnutls_session_t session) {
			gnutls_transport_set_ptr(m_session, this);
			gnutls_transport_set_push_function(m_session, push_func);
			gnutls_transport_set_pull_function(m_session, pull_func);
			gnutls_transport_set_lowat(m_session, 0);
		}

		template<typename ConstBufferSequence>
		std::size_t write_some(const ConstBufferSequence& buffers) {
			boost::system::error_code ec;
			write_some(buffers, ec);
		}

		template<typename ConstBufferSequence>
		std::size_t write_some(const ConstBufferSequence& buffers, boost::system::error_code& ec) {
			using boost::asio::buffer_size;
			using boost::asio::buffer_cast;
			int err = gnutls_record_send(m_session, buffer_cast<const char*>(buffers), buffer_size(buffers));
			// TODO: err handling
		}

		~Stream() {

		}

	private:

		static std::ssize_t pull_func(void* stream, void* buffer, std::size_t size) {
			// TODO not complete
			return static_cast<Stream*>(stream)->next_layer();
		}

		static std::ssize_t push_func(void* stream, const void* buffer, std::size_t length) {
			return static_cast<Stream*>(stream)->next_layer();
		}

		static int verify_func(gnutls_session_t session) {
			// TODO: switch on verify_mode
		}

		static int post_client_hello_func(gnutls_session_t session) {
			// TODO: check SNI : here or elsewhere ? let gnutls dispatch ?
		}

		gnutls_session_t m_session;
		Stream m_next_layer;
		unsigned int m_depth = std::numeric_limits<unsigned int>::max();


};


#endif
