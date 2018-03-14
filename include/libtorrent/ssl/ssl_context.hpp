#ifndef TORRENT_SSL_SSL_CONTEXT_HPP
#define TORRENT_SSL_SSL_CONTEXT_HPP

namespace libtorrent {

namespace openssl {
class SSLContext{
    public:

    SSLContext_openssl() {
        m_context = 
    }

};
}


namespace gnutls {
class SSLContext {
    public:

    SSLContext_gnutls() {
        // Thread safe global init
        gnutls_global_init();
        gnutls_init(&m_session);
    }

    ~SSLContext_gnutls() {
        gnutls_deinit(&m_session);
        // TODO: thread safe global deinit
    }

    void add_certificate(SSLCertificate& certificate) {
        gnutls_credentials_set(&m_session, certificate.get_native_handle());
    }

    void set_verify_cert(const std::string& hostname) {
        gnutls_session_set_verify_cert(&m_session, hostname.c_str(), hostname.size());
    }

    <truc> init_transport(sd) {
        gnutls_transport_set_int(&m_session, sd);
    }

    // XXX: can't use std::string for unicode
    std::string get_servername() {
        // Torrent hash are 40 characters wide
        char buffer[41];
        size_t length;
        unsigned int type;
        int err = gnutls_server_name_get(m_session, buffer, &length, GNUTLS_NAME_DNS, 0);
        if( err != GNUTLS_E_SUCCESS ) return "";
        return { buffer, length }
    }

    void set_servername(const std::string& name) {
        gnutls_server_name_set(m_session, GNUTLS_NAME_DNS, name.c_str(), name.size());
    }

    private:

    gnutls_session_t m_session;
};

}

#if defined TORRENT_USE_OPENSSL
using openssl::SSLContext;
#elif defined TORRENT_USE_GNUTLS
using gnutls::SSLContext;
#endif


}

#endif
