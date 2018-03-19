#ifndef TORRENT_SSL_SSL_CONTEXT_HPP
#define TORRENT_SSL_SSL_CONTEXT_HPP

#include <limits>
#include <string>
#include <cstddef>

#include "libtorrent/aux_/disable_warnings_push.hpp"
#include <boost/asio.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/system/error_code.hpp>
#include "libtorrent/aux_/disable_warnings_pop.hpp"

#include <gnutls/gnutls.h>

namespace libtorrent {
namespace ssl {

namespace gnutls {
class context
{
public:

	using error_code = boost::system::error_code;
	using const_buffer = boost::asio::const_buffer;
	using native_handle_type = gnutls_session_t;

	static constexpr int sslv23 = 42;
	static constexpr int sslv23_client = 42;

	enum verify_mode {
		verify_none,
		verify_peer,
		verify_peer_cert
	};

		// # typedefs
		// file_format
		// method
		// native_handle_type
		// options
		// password_purpose

		void add_certificate_authority(const const_buffer& ca) {
			error_code ec;
			add_certificate_authority(ca, ec);
			// TODO: error check
		}

	error_code add_certificate_authority(const const_buffer& ca, error_code& ec) {
		return ec;
	}

	void add_verify_path(const std::string& path) {
		error_code ec;
		add_verify_path(path, ec);
		// TODO: error check
	}

	error_code add_verify_path(const std::string& path, error_code& ec) {
		return ec;
	}

	//void clear_options(options o) {
	//    error_code ec;
	//    clear_options(o, ec);
	//    // TODO: check errors
	//}

	explicit context(const int& m) {
	}

	context(const context& other) {
		// FIXME: invalid
		m_session = other.m_session;
	}

	context(context&& other) {
		// TODO: un-own the other side
		m_session = other.m_session;
	}

	//void load_verify_file(const std::string& filename) {
	//    error_code ec;
	//    load_verify_file(filename, ec);
	//}

	//error_code load_verify_file(const std::string& filename, error_code& ec) {

	//}

	native_handle_type native_handle() {

	}

	context& operator=(context&& other) {

	}

	//void set_default_verify_paths() {
	//    error_code ec;
	//    set_default_verify_paths(ec);
	//}

	//void set_default_verify_paths(error_code& ec) {

	//}

	//void set_options(options o) {
	//    error_code ec;
	//    set_options(o, ec);
	//}

	//template<typename PasswordCallback>
	//void set_password_callback(PasswordCallback callback) {
	//    error_code ec;
	//    set_password_callback(callback, ec);
	//}

	//template<typename PasswordCallback>
	//void set_password_callback(PasswordCallback& callback, error_code& ec) {

	//}

	//template<typename VerifyCallback>
	//void set_verify_callback(VerifyCallback& callback) {
	//    error_code ec;
	//    set_verify_callback(callback, ec);
	//}

	//template<typename VerifyCallback>
	//void set_verify_callback(VerifyCallback& callback, error_code& ec) {

	//}

	//void set_verify_depth(int depth) {
	//    error_code ec;
	//    set_verify_depth(depth, ec);
	//}

	//void set_verify_depth(int depth, error_code& ec) {

	//}

	void set_verify_mode(verify_mode v) {
	    error_code ec;
	    set_verify_mode(v, ec);
	}

	void set_verify_mode(verify_mode v, error_code& ec) {

	}
	//
	//    void use_certificate(const const_buffer& certificate, file_format format) {
	//        error_code ec;
	//        use_certificate(certificate, format, ec);
	//    }
	//
	//    void use_certificate(const const_buffer& certificate, file_format format, error_code& ec) {
	//
	//    }
	//
	//    void use_certificate_chain(const const_buffer& chain) {
	//        error_code ec;
	//        use_certificate_chain(chain, ec);
	//    }
	//
	//    void use_certificate_chain(const const_buffer& chain, error_code& ec) {
	//
	//    }
	//
	//    void use_certificate_chain_file(const std::string& filename) {
	//        error_code ec;
	//        use_certificate_chain_file(filename, ec);
	//    }
	//
	//    void use_certificate_chain_file(const std::string& filename, error_code& ec) {
	//
	//    }
	//
	//    void use_certificate_file(const std::string& filename, file_format format) {
	//        error_code ec;
	//        use_certificate_file(filename, format, ec);
	//    }
	//
	//    void use_certificate_file(const std::string& filename, file_format format, error_code& ec) {
	//
	//    }
	//
	//    void use_private_key(const const_buffer& private_key, file_format format) {
	//        error_code ec;
	//        use_private_key(private_key, format, ec);
	//    }
	//
	//    void use_private_key(const const_buffer& private_key, file_format format, error_code ec) {
	//
	//    }
	//
	//    void use_private_key_file(const std::string& filename, file_format format) {
	//        error_code ec;
	//        use_private_key_file(filename, file_format, ec);
	//    }
	//
	//    void use_private_key_file(const std::string& filename, file_format format, error_code& ec) {
	//
	//    }
	//
	//    void use_rsa_private_key(const const_buffer& private_key, file_format format) {
	//        error_code ec;
	//        use_rsa_private_key(private_key, format, ec);
	//    }
	//
	//    void use_rsa_private_key(const const_buffer& private_key, file_format format, error_code& ec) {
	//
	//    }
	//
	//    void use_rsa_private_key_file(const std::string& filename, file_format format) {
	//        error_code ec;
	//        use_rsa_private_key_file(filename, file_format, ec);
	//    }
	//
	//    void use_rsa_private_key_file(const std::string& filename, file_format format, error_code& ec) {
	//
	//    }
	//
	//    void use_tmp_dh(const const_buffer& dh) {
	//        error_code ec;
	//        use_tmp_dh(dh, ec);
	//    }
	//
	//    void use_tmp_dh(const const_buffer& dh, error_code& ec) {
	//
	//    }
	//
	//    void use_tmp_dh_file(const std::string& filename) {
	//        error_code ec;
	//        use_tmp_dh_file(filename, ec);
	//    }
	//
	//    void use_tmp_dh_file(const std::string& filename, error_code& ec) {
	//
	//    }
	//
	//    ~context() {
	//
	//    }
	//
	//    // XXX: can't use std::string for unicode
	//    std::string get_servername() {
	//        // Torrent hash are 40 characters wide
	//        char buffer[41];
	//        size_t length;
	//        unsigned int type;
	//        int err = gnutls_server_name_get(m_session, buffer, &length, GNUTLS_NAME_DNS, 0);
	//        if( err != GNUTLS_E_SUCCESS ) return "";
	//        return { buffer, length }
	//    }
	//
	//    void set_servername(const std::string& name) {
	//        gnutls_server_name_set(m_session, GNUTLS_NAME_DNS, name.c_str(), name.size());
	//    }

private:

	//TODO: reference counting
	gnutls_session_t m_session;
};

} // gnutls
} // ssl
} // libtorrent

#endif
