#ifndef TORRENT_SSL_SSL_STORE_HPP
#define TORRENT_SSL_SSL_STORE_HPP

namespace libtorrent {

namespace gnutls {
class SSLStore {
    public:
    SSLStore_gnutls(){}

    private:


};
}

#if defined TORRENT_USE_OPENSSL
#error openssl::SSLStore Not implemented
using openssl::SSLStore;
#elif defined TORRENT_USE_GNUTLS
using gnutls::SSLStore;
#endif

}

#endif
