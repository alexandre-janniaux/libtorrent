#ifndef TORRENT_SSL_SSL_CONTEXT_HPP
#define TORRENT_SSL_SSL_CONTEXT_HPP

namespace libtorrent {

namespace gnutls {
class Context {
    public:

    using error_code = boost::system::error_code;

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

    error_code add_certificate_authority(const buffer& ca, error_code& ec) {

    }

    void add_verify_path(const std::string& path) {
        error_code ec;
        add_verify_path(path, ec);
        // TODO: error check
    }

    error_code add_verify_path(const std::string& path, error_code& ec) {

    }

    void clear_options(options o) {
        error_code ec;
        clear_options(o, ec);
        // TODO: check errors
    }

    explicit Context(method m) {

    }

    Context(Conntext&& other) {

    }

    void load_verify_file(const std::string& filename) {
        error_code ec;
        load_verify_file(filename, ec);
    }

    error_code load_verify_file(const std::string& filename, error_code& ec) {

    }

    native_handle_type native_handle() {

    }

    Context& operator=(Context&& other) {

    }

    void set_default_verify_paths() {
        error_code ec;
        set_default_verify_paths(ec);
    }

    void set_default_verify_paths(error_code& ec) {

    }

    void set_options(options o) {
        error_code ec;
        set_options(o, ec);
    }

    template<typename PasswordCallback>
    void set_password_callback(PasswordCallback callback) {
        error_code ec;
        set_password_callback(callback, ec);
    }

    template<typename PasswordCallback>
    void set_password_callback(PasswordCallback& callback, error_code& ec) {

    }

    template<typename VerifyCallback>
    void set_verify_callback(VerifyCallback& callback) {
        error_code ec;
        set_verify_callback(callback, ec);
    }

    template<typename VerifyCallback>
    void set_verify_callback(VerifyCallback& callback, error_code& ec) {

    }

    void set_verify_depth(int depth) {
        error_code ec;
        set_verify_depth(depth, ec);
    }

    void set_verify_depth(int depth, error_code& ec) {

    }

    void set_verify_mode(verify_mode v) {
        error_code ec;
        set_verify_mode(v, ec);
    }

    void set_verify_mode(verify_mode v, error_code& ec) {

    }

    void use_certificate(const const_buffer& certificate, file_format format) {
        error_code ec;
        use_certificate(certificate, format, ec);
    }

    void use_certificate(const const_buffer& certificate, file_format format, error_code& ec) {

    }

    void use_certificate_chain(const const_buffer& chain) {
        error_code ec;
        use_certificate_chain(chain, ec);
    }

    void use_certificate_chain(const const_buffer& chain, error_code& ec) {

    }

    void use_certificate_chain_file(const std::string& filename) {
        error_code ec;
        use_certificate_chain_file(filename, ec);
    }

    void use_certificate_chain_file(const std::string& filename, error_code& ec) {

    }

    void use_certificate_file(const std::string& filename, file_format format) {
        error_code ec;
        use_certificate_file(filename, format, ec);
    }

    void use_certificate_file(const std::string& filename, file_format format, error_code& ec) {

    }

    void use_private_key(const const_buffer& private_key, file_format format) {
        error_code ec;
        use_private_key(private_key, format, ec);
    }

    void use_private_key(const const_buffer& private_key, file_format format, error_code ec) {

    }

    void use_private_key_file(const std::string& filename, file_format format) {
        error_code ec;
        use_private_key_file(filename, file_format, ec);
    }

    void use_private_key_file(const std::string& filename, file_format format, error_code& ec) {

    }

    void use_rsa_private_key(const const_buffer& private_key, file_format format) {
        error_code ec;
        use_rsa_private_key(private_key, format, ec);
    }

    void use_rsa_private_key(const const_buffer& private_key, file_format format, error_code& ec) {

    }

    void use_rsa_private_key_file(const std::string& filename, file_format format) {
        error_code ec;
        use_rsa_private_key_file(filename, file_format, ec);
    }

    void use_rsa_private_key_file(const std::string& filename, file_format format, error_code& ec) {

    }

    void use_tmp_dh(const const_buffer& dh) {
        error_code ec;
        use_tmp_dh(dh, ec);
    }

    void use_tmp_dh(const const_buffer& dh, error_code& ec) {

    }

    void use_tmp_dh_file(const std::string& filename) {
        error_code ec;
        use_tmp_dh_file(filename, ec);
    }

    void use_tmp_dh_file(const std::string& filename, error_code& ec) {

    }

    ~Context() {

    }


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
