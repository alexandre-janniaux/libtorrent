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

	/*
	 * Wrapper around X509 general names properties
	 */
	class GeneralName {
		public:
			struct {
				std::string_view get_dns_name() {
					assert(get_type() == GEN_DNS);
					auto domain = m_name->d.dNSName;
					if(domain->type != V_ASN1_IA5STRING || !domain->data || !domain.length)
						return "";
					return reinterpret_cast<const char*>(domain->data);
				}
			};
			int get_type() {
				return m_name->type;
			}

			

		private:
			GENERAL_NAME* m_name;
	};

	/*
	 * Iterator on the general names registered in the X509 certificate
	 */
	class general_names_iterator_t {
		friend class general_names_t;
		general_names_iterator_t(GENERAL_NAMES* names, std::size_t index) {
			m_names = names;
			m_index = index;
		}

		public:
		using value_type = GeneralName;
		using difference_type = std::ssize_t;
		using reference = GeneralName&;

		general_names_iterator_t operator++() {
			general_names_iterator_t other = *this;
			m_index++;
			return other;
		}

		GeneralName operator*() {
			auto name = aux::openssl_general_name_value(m_names, m_index)
			return {
				.type = name->type,
				.data = name->data
			};
		}

		private:
		GENERAL_NAMES* m_names;
		std::size_t m_index;
	};

	/*
	 * Proxy class for the general names stored in X509 certificates
	 */
	class general_names_t {

		friend general_names_t certificate::get_general_names();
		general_names_t(GENERAL_NAMES* names) {
			m_names = names;
		}

		public:
		general_name_iterator begin() {
			return general_names_iterator(m_names, 0);
		}

		const_general_name_iterator begin() {

		}

		private:
		GENERAL_NAMES* m_names;
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
