#ifndef TORRENT_SSL_SSL_CERTIFICATE_HPP
#define TORRENT_SSL_SSL_CERTIFICATE_HPP

namespace libtorrent {


namespace gnutls {

class SSLCertificate {

    public:

    SSLCertificate() {
        gnutls_certificate_allocate_credentials(&m_cred);
        gnutls_certificate_set_x509_system_trust(m_cred);
    }

    gnutls_certificate_credentials_t get_native_handle() {
        return m_cred;
    }

    private:

    gnutls_certificate_credentials_t m_cred;
};

}

#ifdef TORRENT_USE_OPENSSL
using openssl::SSLCertificate;
#elif TORRENT_USE_GNUTLS
using gnutls::SSLCertificate;
#endif

}

#endif
