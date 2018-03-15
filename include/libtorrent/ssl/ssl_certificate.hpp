#ifndef TORRENT_SSL_SSL_CERTIFICATE_HPP
#define TORRENT_SSL_SSL_CERTIFICATE_HPP

namespace libtorrent {

namespace openssl {

class certificate {

	public:
	certificate() {}

	static certificate from_mem_pem(string_view cert_data) {
		certificate cert;

		// wrap the PEM certificate in a BIO
		auto bp = std::unique_ptr<BIO, BIO_free>(BIO_new_mem_buf(
			const_cast<void*>(static_cast<void const*>(cert_data.data()))
			, static_cast<int>(cert_data.size())));

		// parse the certificate into OpenSSL's internal representation
		cert.reset(PEM_read_bio_X509_AUX(bp, nullptr, nullptr, nullptr));

		// we don't need the BIO anymore
		bp.reset();

		return std::move(cert);
	}

	X509* native_handle() {
		return m_cert.get();
	}

	class general_names_t {

		general_names_t(GENERAL_NAMES* names) {

		}

		friend general_names_t certificate::get_general_names();

		public:
		general_name_iterator begin() {

		}

		const_general_name_iterator begin() {

		}
	}

	general_names_t get_subject_alt_names() {
		auto* gens = static_cast<GENERAL_NAMES*>(
			X509_get_ext_d2i(m_cert, NID_subject_alt_name, nullptr, nullptr));
		return { gens };
	}

	private:
	std::unique_ptr<X509, X509_free> m_cert;
};
}

namespace gnutls {

class certificate {

	public:
	using cert_type = gnutls_x509_crt_t;

	~certificate() {
		gnutls_x509_crt_deinit(m_cert);
	}

	static certificate read_mem_pem(string_view cert_data) {
		certificate cert;
		// TODO: use gnutls_x509_crt_import(cert, datum*, fmt)
		return cert;
	}

	cert_type native_handle() {
    }

	subject_alt_names_t get_subject_alt_names() {
		// TODO: use gnutls_x509_crt_get_subject_alt_name
		subject_alt_names_t names(m_cert);
		return std::move(names);
	}

	// TODO: iterators
	subject_names_t get_subject_name() {
	}

    private:

	certificate() {
		int ret = gnutls_x509_crt_init(&m_cert);
		if(ret != GNUTLS_E_SUCCESS) {
		}
	}

	gnutls_x509_crt_t m_cert;
};

}

#ifdef TORRENT_USE_OPENSSL
using openssl::SSLCertificate;
#elif TORRENT_USE_GNUTLS
using gnutls::SSLCertificate;
#endif

}

#endif
