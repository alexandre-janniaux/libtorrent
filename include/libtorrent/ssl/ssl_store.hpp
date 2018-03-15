#ifndef TORRENT_SSL_SSL_STORE_HPP
#define TORRENT_SSL_SSL_STORE_HPP

#ifdef LIBTORRENT_USE_GNUTLS
#include <gnutls/gnutls.h>
#endif

namespace libtorrent {
namespace ssl {

#ifdef TORRENT_USE_OPENSSL
namespace openssl {
class store {
	public:
		store() {
			m_store.reset(X509_STORE_new());
			if(!m_store) {
				// TODO: throw exception
			}
		}

		void add_cert(certificate& cert) {
			X509_STORE_add_cert(m_store, certificate.native_handle());
		}

	private:
		std::unique_ptr<X509_STORE, X509_STORE_free> m_store;
};
}
#endif

#ifdef TORRENT_USE_GNUTLS
namespace gnutls {
class store {
	public:
		store() {
			m_cred_init = gnutls_certificate_allocate_credentials(&m_cred);
			if(m_crend_init != GNUTLS_E_SUCCESS) {
				// throw
			}
		}

		~store() {
			gnutls_certificate_free_credentials(m_cred);
		}

		void add_cert(certificate& cert) {

		}

	private:

	gnutls_credential_t m_cred;
	int m_cred_init = -1;
	int m_gnutls_init = -1;
};
}
#endif

#if defined TORRENT_USE_OPENSSL
#error openssl::SSLStore Not implemented
using openssl::store;
#elif defined TORRENT_USE_GNUTLS
using gnutls::store;
#endif

} // namespace ssl
} // namespace libtorrent

#endif
