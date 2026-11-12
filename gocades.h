#ifndef GOCADES_H
#define GOCADES_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cp_buf {
    unsigned char *data;
    size_t len;
} cp_buf;

void cp_buf_free(cp_buf b);

/* Store: location 1 = LocalMachine, 2 = CurrentUser. */
int32_t cp_store_open(int32_t location, const char *name, void **out);
void    cp_store_close(void *hStore);
int32_t cp_store_find_cert_sha1(void *hStore, const unsigned char *sha1,
                                size_t len, void **out);
int32_t cp_store_find_cert_subject(void *hStore, const char *subject, void **out);

typedef struct cp_cert_list {
    void **items;
    size_t len;
} cp_cert_list;

int32_t cp_store_enum_certs(void *hStore, cp_cert_list *out);
void    cp_cert_list_free(cp_cert_list l);

void    cp_cert_free(void *hCert);
void   *cp_cert_dup(void *hCert);
int32_t cp_cert_has_private_key(void *hCert);

int32_t cp_cert_subject(void *hCert, cp_buf *out);
int32_t cp_cert_issuer(void *hCert, cp_buf *out);
int32_t cp_cert_serial(void *hCert, cp_buf *out);
int32_t cp_cert_thumbprint(void *hCert, cp_buf *out);
int32_t cp_cert_export_der(void *hCert, cp_buf *out);
int32_t cp_cert_import_der(void **out, const unsigned char *der, size_t len);

int32_t cp_cert_set_pin(void *hCert, const char *pin);

/* 1 when the key container of the certificate has the default (empty) PIN. */
int32_t cp_cert_is_default_pin(void *hCert, int32_t *out);

/*
 * Certificates a signing call embeds in the CMS
 * (CAPICOM_CERTIFICATE_INCLUDE_OPTION). The chain options build the chain
 * without revocation checks and network retrieval; `hChainStore` (may be
 * NULL) is searched for intermediate certificates.
 */
#define CP_INCLUDE_CHAIN_EXCEPT_ROOT 0
#define CP_INCLUDE_WHOLE_CHAIN       1
#define CP_INCLUDE_END_ENTITY_ONLY   2
#define CP_INCLUDE_NONE              0x100

/* One CMS attribute value for signing (CRYPT_ATTRIBUTE). */
typedef struct cp_attr {
    const char *oid;
    const unsigned char *value;
    size_t value_len;
} cp_attr;

typedef struct cp_attr_list {
    const cp_attr *items;
    size_t len;
} cp_attr_list;

/*
 * Detached CAdES signature over `data`.
 * `cades_type` is CADES_BES (0x1), CADES_T (0x5) or CADES_X_LONG_TYPE_1 (0x5D).
 * `hash_oid` may be NULL; default is GOST R 34.11-2012 256.
 * `tsa_url` may be NULL/empty for BES.
 * `check_cert` non-zero sets CADES_CHECK_CERT_REQ (CadesSigner.CheckCertificate).
 * `auth`/`unauth` may be empty; they become cAuthAttr/cUnauthAttr.
 */
int32_t cp_sign_detached(void *hCert, int32_t include, void *hChainStore,
                         int32_t check_cert, cp_attr_list auth,
                         cp_attr_list unauth, int32_t cades_type,
                         const char *hash_oid, const char *tsa_url,
                         const unsigned char *data, size_t len, cp_buf *out);

int32_t cp_sign_hash(void *hCert, int32_t include, void *hChainStore,
                     int32_t check_cert, cp_attr_list auth, cp_attr_list unauth,
                     int32_t cades_type, const char *hash_oid,
                     const char *tsa_url, const unsigned char *hash,
                     size_t hash_len, cp_buf *out);

/*
 * Returns the HRESULT of the verification call and stores the ADES_VERIFY_*
 * status in *status (-1 when CAdES produced no verification info). A failed
 * check may report its reason in either of them, or in both.
 */
int32_t cp_verify_detached(const unsigned char *sig, size_t sig_len,
                           int32_t cades_type, const unsigned char *data,
                           size_t len, int32_t *status);

int32_t cp_enhance(const unsigned char *sig, size_t sig_len,
                   int32_t cades_type, const char *tsa_url, cp_buf *out);

/* ------------------------------------------------------------------ */
/* Certificates: metadata, extensions, keys                            */
/* ------------------------------------------------------------------ */

typedef struct cp_str_list {
    char **items;
    size_t len;
} cp_str_list;

void cp_str_list_free(cp_str_list l);
void cp_free(void *p);

int32_t cp_cert_valid_from(void *hCert, int64_t *unix_seconds);
int32_t cp_cert_valid_to(void *hCert, int64_t *unix_seconds);
int32_t cp_cert_version(void *hCert, int32_t *version);
int32_t cp_cert_info(void *hCert, int32_t info_type, cp_buf *out);

typedef struct cp_key_usage {
    int32_t present;
    int32_t critical;
    uint32_t bits;
} cp_key_usage;

int32_t cp_cert_key_usage(void *hCert, cp_key_usage *out);

int32_t cp_cert_eku(void *hCert, cp_str_list *out, int32_t *critical,
                    int32_t *present);

int32_t cp_cert_extension_count(void *hCert, size_t *n);
int32_t cp_cert_extension_at(void *hCert, size_t i, cp_buf *oid,
                             int32_t *critical, cp_buf *value);

typedef struct cp_basic_constraints {
    int32_t present;
    int32_t critical;
    int32_t is_ca;
    int32_t path_len_present;
    uint32_t path_len;
} cp_basic_constraints;

int32_t cp_cert_basic_constraints(void *hCert, cp_basic_constraints *out);

int32_t cp_cert_public_key(void *hCert, cp_buf *encoded_key,
                           cp_buf *encoded_params, char **algorithm_oid,
                           int32_t *bit_length);

typedef struct cp_key_prov_info {
    int32_t present;
    char *container;
    char *unique_container;
    char *provider;
    uint32_t provider_type;
    uint32_t key_spec;
} cp_key_prov_info;

int32_t cp_cert_key_prov_info(void *hCert, cp_key_prov_info *out);

/* Revocation modes for cp_cert_is_valid. at_unix == 0 means "now";
 * url_timeout_ms == 0 keeps the CryptoAPI default. */
#define CP_REVOCATION_ONLINE     0
#define CP_REVOCATION_CACHE_ONLY 1
#define CP_REVOCATION_NONE       2

int32_t cp_cert_is_valid(void *hCert, void *hAdditionalStore, int32_t revocation,
                         int64_t at_unix, uint32_t url_timeout_ms,
                         int32_t *valid, uint32_t *policy_error,
                         uint32_t *chain_status);

/* Certificate store mutation. */
int32_t cp_store_add_cert(void *hStore, void *hCert);
int32_t cp_store_remove_cert(void *hStore, void *hCert);
int32_t cp_store_add_crl(void *hStore, const unsigned char *der, size_t len);

/*
 * PFXImportCertStore. With hStore NULL, *out receives the memory store of the
 * PFX; otherwise its certificates (with their key links) are added to hStore
 * and *out is left untouched.
 */
int32_t cp_store_import_pfx(void *hStore, const unsigned char *pfx, size_t len,
                            const wchar_t *password, uint32_t flags,
                            void **out);

/* CRL fields. next_update is 0 when the CRL has none; auth_key_id is empty
 * without an authorityKeyIdentifier keyIdentifier. */
typedef struct cp_crl_info {
    cp_buf issuer;
    int64_t this_update;
    int64_t next_update;
    cp_buf thumbprint;
    cp_buf auth_key_id;
} cp_crl_info;

int32_t cp_crl_info_get(const unsigned char *der, size_t len, cp_crl_info *out);
void    cp_crl_info_free(cp_crl_info i);

/* CSP version. */
typedef struct cp_csp_version {
    uint32_t major;
    uint32_t minor;
    uint32_t build;
} cp_csp_version;

int32_t cp_csp_version_info(const char *name, uint32_t prov_type,
                            cp_csp_version *out);
int32_t cp_csp_name(uint32_t prov_type, cp_buf *out);

/* CAdES type of signer 0 of a CMS (CadesMsgIsType). */
int32_t cp_msg_is_type(const unsigned char *msg, size_t len,
                       uint32_t cades_type, int32_t *result);
int32_t cp_msg_get_type(const unsigned char *msg, size_t len,
                        uint32_t *cades_type);

typedef struct cp_buf_list {
    cp_buf *items;
    size_t len;
} cp_buf_list;

void cp_buf_list_free(cp_buf_list l);

/*
 * DER certificates carried by a CMS: the certificates field, the
 * certificate-values attribute of every signer and the TSA certificates of
 * the signature, CAdES-C and archive timestamps. Duplicates are kept.
 */
int32_t cp_msg_certificates(const unsigned char *msg, size_t len,
                            cp_buf_list *out);

/* revocation-values of a signer (CAdES-X Long): DER CRLs and BasicOCSPResponses. */
int32_t cp_msg_revocation_values(const unsigned char *msg, size_t len,
                                 uint32_t signer, cp_buf_list *crls,
                                 cp_buf_list *ocsps);

/* OID info lookup. */
int32_t cp_oid_info(const char *oid, cp_buf *out);

/* ------------------------------------------------------------------ */
/* Verification with signer information                                */
/* ------------------------------------------------------------------ */

typedef struct cp_verify_info {
    int32_t status;
    void *signer_cert; /* owns a PCCERT_CONTEXT; free with cp_cert_free */
    int64_t signing_time;
    int64_t signature_ts_time;
    int64_t cades_c_ts_time;
    int64_t archive_ts_time;
} cp_verify_info;

/*
 * cp_verify_message and cp_verify_hash fill *out whenever CAdES returned
 * verification info, also when the signature is invalid and the call fails:
 * the caller owns out->signer_cert in both cases. out->status is -1 when no
 * info was produced.
 */
int32_t cp_verify_message(const unsigned char *sig, size_t sig_len,
                          int32_t cades_type, int32_t detached,
                          const unsigned char *content, size_t content_len,
                          int32_t signer_index, void *hStore,
                          cp_verify_info *out);

int32_t cp_verify_hash(const unsigned char *sig, size_t sig_len,
                       int32_t cades_type, const char *hash_oid,
                       const unsigned char *hash, size_t hash_len,
                       int32_t signer_index, void *hStore,
                       cp_verify_info *out);

/* ------------------------------------------------------------------ */
/* Attached CAdES, plain CMS and co-signing                            */
/* ------------------------------------------------------------------ */

int32_t cp_sign_cades(void *hCert, int32_t include, void *hChainStore,
                      int32_t check_cert, cp_attr_list auth, cp_attr_list unauth,
                      int32_t cades_type, const char *hash_oid,
                      const char *tsa_url, const unsigned char *data,
                      size_t len, int32_t detached, cp_buf *out);

/* `hash_oid` may be NULL; default is GOST R 34.11-2012 256. */
int32_t cp_sign_cms(void *hCert, int32_t include, void *hChainStore,
                    cp_attr_list auth, cp_attr_list unauth,
                    const char *hash_oid, int32_t detached,
                    const unsigned char *data, size_t len, cp_buf *out);

int32_t cp_cosign_hash(void *hCert, int32_t include, void *hChainStore,
                       int32_t check_cert, cp_attr_list auth,
                       cp_attr_list unauth, int32_t cades_type,
                       const char *hash_oid, const char *tsa_url,
                       const unsigned char *sig, size_t sig_len,
                       const unsigned char *hash, size_t hash_len, cp_buf *out);

/*
 * Adds a CMS signer (CryptMsg*, no CAdES type) to an existing signature.
 * `content` is the signed content of a detached signature and is ignored
 * when `detached` is 0. `hash_oid` may be NULL; default is GOST R 34.11-2012
 * 256. CADES has no plain-CMS mode for CadesAddHashSignature: PKCS7_TYPE is
 * rejected with E_INVALIDARG.
 */
int32_t cp_cosign_cms(void *hCert, int32_t include, void *hChainStore,
                      cp_attr_list auth, cp_attr_list unauth,
                      const char *hash_oid, const unsigned char *sig,
                      size_t sig_len, int32_t detached,
                      const unsigned char *content, size_t content_len,
                      cp_buf *out);

/* ------------------------------------------------------------------ */
/* Certificate search by CAPICOM criteria                              */
/* ------------------------------------------------------------------ */

/* Change the key container PIN (PP_CHANGE_PASSWORD). */
int32_t cp_change_pin(void *hCert, int32_t key_spec, const char *old_pin,
                      const char *new_pin);

/* ------------------------------------------------------------------ */
/* Provider algorithm enumeration                                      */
/* ------------------------------------------------------------------ */

typedef struct cp_alg_info {
    char *name;
    char *long_name;
    uint32_t alg_id;
    uint32_t default_bits;
    uint32_t min_bits;
    uint32_t max_bits;
    uint32_t protocols;
} cp_alg_info;

typedef struct cp_alg_list {
    cp_alg_info *items;
    size_t len;
} cp_alg_list;

int32_t cp_provider_algorithms(cp_alg_list *out);
void    cp_alg_list_free(cp_alg_list l);

/* ------------------------------------------------------------------ */
/* Hashing                                                             */
/* ------------------------------------------------------------------ */

/* alg is CAPICOM_HASH_ALGORITHM (0..6, 100..102). HMAC is built in Go. */
int32_t cp_hash(int32_t alg, const unsigned char *data, size_t len,
                cp_buf *out);

/* ------------------------------------------------------------------ */
/* Raw signature over a digest                                         */
/* ------------------------------------------------------------------ */

/* The digest algorithm follows the certificate key (GOST R 34.10-2001,
 * 34.10-2012 256/512), and hash_len must be its exact digest size. */
int32_t cp_raw_sign_hash(void *hCert, const unsigned char *hash,
                         size_t hash_len, cp_buf *out);
int32_t cp_raw_verify_hash(void *hCert, const unsigned char *hash,
                           size_t hash_len, const unsigned char *sig,
                           size_t sig_len);

/* ------------------------------------------------------------------ */
/* Symmetric algorithm                                                 */
/* ------------------------------------------------------------------ */

void    *cp_sym_new(void);
void     cp_sym_free(void *h);
int32_t cp_sym_generate(void *h, int32_t alg, uint32_t bits);
int32_t cp_sym_set_mode(void *h, uint32_t mode);
int32_t cp_sym_set_padding(void *h, uint32_t padding);
int32_t cp_sym_get_iv(void *h, cp_buf *out);
int32_t cp_sym_set_iv(void *h, const unsigned char *iv, size_t len);
int32_t cp_sym_encrypt(void *h, const unsigned char *data, size_t len,
                       cp_buf *out);
int32_t cp_sym_decrypt(void *h, const unsigned char *data, size_t len,
                       cp_buf *out);

/* Export/import the session key protected by a recipient certificate. */
int32_t cp_sym_export_key(void *h, void *hCert, cp_buf *out);
int32_t cp_sym_import_key(void *h, void *hCert, const unsigned char *blob,
                          size_t len);

/* ------------------------------------------------------------------ */
/* Enroll: CSP containers and keys (X509Enrollment.CCspInformation)    */
/* ------------------------------------------------------------------ */

typedef struct cp_enroll_container {
    char *fqcn;
    char *unique_name;
    char *name;
    char *media;
    char *reader;
} cp_enroll_container;

typedef struct cp_enroll_container_list {
    cp_enroll_container *items;
    size_t len;
} cp_enroll_container_list;

void cp_enroll_container_list_free(cp_enroll_container_list l);

/* Resolves CryptEnumProviders by name; *prov_type receives the type. */
int32_t cp_enroll_resolve_prov(const char *name, uint32_t *prov_type);

/* Enumerates containers of the provider (CRYPT_FQCN for GOST CSPs). */
int32_t cp_enroll_enum_containers(const char *prov_name, uint32_t prov_type,
                                  cp_enroll_container_list *out);

/* Fills UniqueName/FQCN/Name/Media/Reader for one container name or FQCN. */
int32_t cp_enroll_container_info(const char *container, const char *prov_name,
                                 uint32_t prov_type, int32_t silent,
                                 cp_enroll_container *out);

int32_t cp_enroll_container_delete(const char *container, const char *prov_name,
                                   uint32_t prov_type, int32_t silent);

typedef struct cp_enroll_key {
    int32_t is_exportable;
    int32_t has_certificate;
    uint32_t type; /* AT_KEYEXCHANGE / AT_SIGNATURE */
    int64_t expiration; /* Unix seconds; 0 if unknown */
    char *kp_fp;
    uint32_t kp_algid;
    void *certificate; /* PCCERT_CONTEXT; free with cp_cert_free */
    char *pubkey_oid;
    cp_buf pubkey_key;
    cp_buf pubkey_params;
    int32_t pubkey_bits;
} cp_enroll_key;

typedef struct cp_enroll_key_list {
    cp_enroll_key *items;
    size_t len;
} cp_enroll_key_list;

void cp_enroll_key_list_free(cp_enroll_key_list l);

int32_t cp_enroll_container_keys(const char *container, const char *prov_name,
                                 uint32_t prov_type, int32_t silent,
                                 cp_enroll_key_list *out);

/* CX509Enrollment subset: create/open a key container and encode PKCS#10. */

/* Creates a new key container + key pair. *out_container / *out_unique are
 * malloc'd; free with free(). container may be NULL/"" for a CSP-chosen name. */
int32_t cp_enroll_create_key(const char *prov_name, uint32_t prov_type,
                             const char *container, uint32_t key_spec,
                             int32_t exportable, int32_t silent, const char *pin,
                             char **out_container, char **out_unique);

typedef struct cp_enroll_pkcs10_params {
    const char *prov_name;   /* NULL = default for prov_type */
    uint32_t prov_type;
    const char *container;   /* required: existing container name / FQCN */
    uint32_t key_spec;       /* AT_KEYEXCHANGE / AT_SIGNATURE; 0 → AT_KEYEXCHANGE */
    int32_t silent;
    const char *pin;         /* optional; PP_*_PIN before Sign */
    const char *subject;     /* X.500 string for CertStrToName, required */
    const char *sign_oid;    /* signature OID; NULL → GOST-2012-256 sign */
    uint32_t key_usage;      /* CERT_KEY_USAGE bits; 0 = omit extension */
} cp_enroll_pkcs10_params;

/* Encodes a DER PKCS#10 request for an existing key container. */
int32_t cp_enroll_create_pkcs10(const cp_enroll_pkcs10_params *p, cp_buf *out_req);

/* Installs a DER/base64-decoded certificate into hStore (NULL → CurrentUser/My)
 * and binds it to the key container via CERT_KEY_PROV_INFO_PROP_ID. */
int32_t cp_enroll_install_cert(const char *prov_name, uint32_t prov_type,
                               const char *container, uint32_t key_spec,
                               int32_t silent, const char *pin,
                               const unsigned char *cert, size_t cert_len,
                               void *hStore);

/* ------------------------------------------------------------------ */
/* Enveloped (CMS) data                                                */
/* ------------------------------------------------------------------ */

int32_t cp_envelope_encrypt(void **certs, size_t n, int32_t alg,
                            const unsigned char *data, size_t len,
                            cp_buf *out);
int32_t cp_envelope_decrypt(void *hStore, const unsigned char *data,
                            size_t len, cp_buf *out);

/* ------------------------------------------------------------------ */
/* XMLDSig / XAdES                                                     */
/* ------------------------------------------------------------------ */

typedef struct cp_xades_info {
    int32_t status;
    int32_t xades_type;
    void *signer_cert; /* owns a PCCERT_CONTEXT; free with cp_cert_free */
    int64_t signing_time;
    int64_t signature_ts_time;
    int64_t sig_and_refs_ts_time;
} cp_xades_info;

typedef struct cp_xades_info_array {
    cp_xades_info *items;
    size_t len;
} cp_xades_info_array;

/* xades_type is XADES_DEFAULT/BES/T/X_LONG_TYPE_1/A/XMLDSIG. */
int32_t cp_xades_sign(void *hCert, int32_t xades_type, const char *digest_method,
                      const char *signature_method, const char *tsa_url,
                      const char *xpath, const unsigned char *data,
                      size_t len, int32_t detached, cp_buf *out);

int32_t cp_xades_verify(void *hStore, const char *xpath,
                        const unsigned char *data, size_t len,
                        cp_xades_info_array *out);

void cp_xades_info_array_free(cp_xades_info_array a);

#ifdef __cplusplus
}
#endif

#endif /* GOCADES_H */
