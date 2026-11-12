/*
 * C layer between cgo and the CryptoPro CAdES C API (cades.h) plus the CryptoAPI
 * emulation in libcapi20.
 *
 * The ABI exposed to Go is plain C: opaque void*, int32_t HRESULT-like
 * codes and cp_buf. No C++, no boost, no VARIANT.
 */

#define CRYPT_SIGN_MESSAGE_PARA_HAS_CMS_FIELDS
#define CMSG_SIGNER_ENCODE_INFO_HAS_CMS_FIELDS
#define CMSG_SIGNED_ENCODE_INFO_HAS_CMS_FIELDS
#define CADES_PARA_HAS_EXTRA_FIELDS
#define CADES_PARA_HAS_EXTRA_TIME_FIELDS
#define CERT_CHAIN_PARA_HAS_EXTRA_FIELDS

/* Standard headers first: cades.h uses va_list in the CadesFormatMessage
 * prototype but does not include <stdarg.h> itself. On macOS that definition
 * leaks in through another header; on Linux (glibc) it does not. */
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "cades.h"
#include "xades.h"
#include "gocades.h"

#ifndef HRESULT_FROM_WIN32
#define HRESULT_FROM_WIN32(x)                                                \
    ((int32_t)(x) <= 0                                                       \
         ? (int32_t)(x)                                                      \
         : (int32_t)(((x) & 0x0000FFFFu) | (7u << 16) | 0x80000000u))
#endif

#define CP_OID_GOST3411_2012_256 "1.2.643.7.1.1.2.2"
#define CP_E_OUTOFMEMORY ((int32_t)0x8007000E)
#define CP_E_FAIL        ((int32_t)0x80004005)
#define CP_E_INVALIDARG  ((int32_t)0x80070057)
#define CP_NTE_BAD_HASH  ((int32_t)0x80090002)
#define CP_NTE_BAD_ALGID ((int32_t)0x80090008)

/*
 * CryptoAPI takes buffer lengths as DWORD: a larger size_t would be truncated
 * and only part of the data signed, hashed or encrypted. The margin keeps
 * size arithmetic such as the cipher padding in cp_sym_encrypt in range.
 */
#define CP_MAX_LEN ((size_t)0xFFFFFFFFu - 64)
#define CP_CHECK_LEN(n)                                                      \
    do {                                                                     \
        if ((size_t)(n) > CP_MAX_LEN) {                                      \
            return CP_E_INVALIDARG;                                          \
        }                                                                    \
    } while (0)

static int32_t cp_last_error(void)
{
    DWORD e = GetLastError();
    return e ? HRESULT_FROM_WIN32(e) : CP_E_FAIL;
}

static int32_t cp_copy(const void *p, size_t n, cp_buf *out)
{
    out->data = (unsigned char *)malloc(n ? n : 1);
    if (!out->data) {
        return CP_E_OUTOFMEMORY;
    }
    if (n) {
        memcpy(out->data, p, n);
    }
    out->len = n;
    return 0;
}

void cp_buf_free(cp_buf b)
{
    free(b.data);
}

/* ------------------------------------------------------------------ */
/* Store / certificate                                                 */
/* ------------------------------------------------------------------ */

int32_t cp_store_open(int32_t location, const char *name, void **out)
{
    HCERTSTORE h;
    switch (location) {
    case 0:
        h = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
        break;
    case 1:
        h = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
                          CERT_SYSTEM_STORE_LOCAL_MACHINE, name);
        break;
    case 2:
        h = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
                          CERT_SYSTEM_STORE_CURRENT_USER, name);
        break;
    default:
        return CP_E_INVALIDARG;
    }
    if (!h) {
        return cp_last_error();
    }
    *out = h;
    return 0;
}

void cp_store_close(void *hStore)
{
    if (hStore) {
        CertCloseStore((HCERTSTORE)hStore, 0);
    }
}

int32_t cp_store_find_cert_sha1(void *hStore, const unsigned char *sha1,
                                size_t len, void **out)
{
    CP_CHECK_LEN(len);
    if (!hStore) {
        return CP_E_INVALIDARG;
    }
    CRYPT_HASH_BLOB blob;
    blob.cbData = (DWORD)len;
    blob.pbData = (BYTE *)sha1;

    PCCERT_CONTEXT c = CertFindCertificateInStore(
        (HCERTSTORE)hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
        CERT_FIND_SHA1_HASH, &blob, NULL);
    if (!c) {
        return cp_last_error();
    }
    *out = (void *)c;
    return 0;
}

int32_t cp_store_find_cert_subject(void *hStore, const char *subject, void **out)
{
    if (!hStore) {
        return CP_E_INVALIDARG;
    }
    PCCERT_CONTEXT c = CertFindCertificateInStore(
        (HCERTSTORE)hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
        CERT_FIND_SUBJECT_STR_A, subject, NULL);
    if (!c) {
        return cp_last_error();
    }
    *out = (void *)c;
    return 0;
}

int32_t cp_store_enum_certs(void *hStore, cp_cert_list *out)
{
    if (!hStore) {
        return CP_E_INVALIDARG;
    }
    out->items = NULL;
    out->len = 0;

    HCERTSTORE h = (HCERTSTORE)hStore;
    PCCERT_CONTEXT c = NULL;
    size_t cap = 16;
    size_t n = 0;
    void **items = (void **)malloc(cap * sizeof(void *));
    if (!items) {
        return CP_E_OUTOFMEMORY;
    }

    while ((c = CertEnumCertificatesInStore(h, c)) != NULL) {
        PCCERT_CONTEXT dup = CertDuplicateCertificateContext(c);
        if (!dup) {
            continue;
        }
        if (n == cap) {
            size_t ncap = cap * 2;
            void **grown = (void **)realloc(items, ncap * sizeof(void *));
            if (!grown) {
                CertFreeCertificateContext(dup);
                for (size_t i = 0; i < n; i++) {
                    CertFreeCertificateContext((PCCERT_CONTEXT)items[i]);
                }
                free(items);
                return CP_E_OUTOFMEMORY;
            }
            items = grown;
            cap = ncap;
        }
        items[n++] = (void *)dup;
    }

    out->items = items;
    out->len = n;
    return 0;
}

void cp_cert_list_free(cp_cert_list l)
{
    free(l.items);
}

void cp_cert_free(void *hCert)
{
    if (hCert) {
        CertFreeCertificateContext((PCCERT_CONTEXT)hCert);
    }
}

void *cp_cert_dup(void *hCert)
{
    if (!hCert) {
        return NULL;
    }
    return (void *)CertDuplicateCertificateContext((PCCERT_CONTEXT)hCert);
}

int32_t cp_cert_has_private_key(void *hCert)
{
    DWORD cb = 0;
    if (!hCert) {
        return 0;
    }
    /* Returns FALSE with ERROR_MORE_DATA when the property exists. A key
     * imported with PKCS12_NO_PERSIST_KEY has only the key context. */
    (void)CertGetCertificateContextProperty((PCCERT_CONTEXT)hCert,
                                            CERT_KEY_PROV_INFO_PROP_ID, NULL, &cb);
    if (cb == 0) {
        (void)CertGetCertificateContextProperty((PCCERT_CONTEXT)hCert,
                                                CERT_KEY_CONTEXT_PROP_ID, NULL, &cb);
    }
    return cb > 0 ? 1 : 0;
}

/* Defined in the generic helpers section below. */
static char *cp_wide_to_utf8(const wchar_t *w);

static int32_t cp_cert_name(void *hCert, DWORD type, cp_buf *out)
{
    PCCERT_CONTEXT c = (PCCERT_CONTEXT)hCert;

    /* The ANSI variant returns the local 8-bit code page (CP1251 for Russian),
     * so go through the wide API and convert to UTF-8. */
    DWORD n = CertGetNameStringW(c, type, 0, NULL, NULL, 0);
    if (n <= 1) {
        out->data = NULL;
        out->len = 0;
        return 0;
    }

    wchar_t *wbuf = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
    if (!wbuf) {
        return CP_E_OUTOFMEMORY;
    }

    DWORD got = CertGetNameStringW(c, type, 0, NULL, wbuf, n);

    int32_t rc;
    if (got > 1) {
        char *utf8 = cp_wide_to_utf8(wbuf);
        if (!utf8) {
            rc = CP_E_OUTOFMEMORY;
        } else {
            rc = cp_copy(utf8, strlen(utf8), out);
            free(utf8);
        }
    } else {
        out->data = NULL;
        out->len = 0;
        rc = 0;
    }

    free(wbuf);
    return rc;
}

int32_t cp_cert_subject(void *hCert, cp_buf *out)
{
    if (!hCert) {
        return CP_E_INVALIDARG;
    }
    return cp_cert_name(hCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, out);
}

int32_t cp_cert_issuer(void *hCert, cp_buf *out)
{
    if (!hCert) {
        return CP_E_INVALIDARG;
    }
    return cp_cert_name(
        hCert, CERT_NAME_SIMPLE_DISPLAY_TYPE | CERT_NAME_ISSUER_FLAG, out);
}

int32_t cp_cert_thumbprint(void *hCert, cp_buf *out)
{
    if (!hCert) {
        return CP_E_INVALIDARG;
    }
    PCCERT_CONTEXT c = (PCCERT_CONTEXT)hCert;
    BYTE buf[64];
    DWORD n = sizeof(buf);
    if (!CertGetCertificateContextProperty(c, CERT_SHA1_HASH_PROP_ID, buf, &n)) {
        return cp_last_error();
    }

    static const char hex[] = "0123456789abcdef";
    char *s = (char *)malloc((size_t)n * 2);
    if (!s) {
        return CP_E_OUTOFMEMORY;
    }
    for (DWORD i = 0; i < n; i++) {
        s[i * 2]     = hex[buf[i] >> 4];
        s[i * 2 + 1] = hex[buf[i] & 0x0F];
    }
    int32_t rc = cp_copy(s, (size_t)n * 2, out);
    free(s);
    return rc;
}

int32_t cp_cert_serial(void *hCert, cp_buf *out)
{
    if (!hCert) {
        return CP_E_INVALIDARG;
    }
    PCCERT_CONTEXT c = (PCCERT_CONTEXT)hCert;
    if (!c->pCertInfo) {
        return CP_E_FAIL;
    }

    DWORD n = c->pCertInfo->SerialNumber.cbData;
    const BYTE *p = c->pCertInfo->SerialNumber.pbData;

    static const char hex[] = "0123456789abcdef";
    char *s = (char *)malloc((size_t)n * 2);
    if (!s) {
        return CP_E_OUTOFMEMORY;
    }
    /* CERT_INFO stores the serial in little-endian; display big-endian. */
    for (DWORD i = 0; i < n; i++) {
        BYTE b = p[n - 1 - i];
        s[i * 2]     = hex[b >> 4];
        s[i * 2 + 1] = hex[b & 0x0F];
    }
    int32_t rc = cp_copy(s, (size_t)n * 2, out);
    free(s);
    return rc;
}

int32_t cp_cert_export_der(void *hCert, cp_buf *out)
{
    if (!hCert) {
        return CP_E_INVALIDARG;
    }
    PCCERT_CONTEXT c = (PCCERT_CONTEXT)hCert;
    return cp_copy(c->pbCertEncoded, c->cbCertEncoded, out);
}

int32_t cp_cert_import_der(void **out, const unsigned char *der, size_t len)
{
    CP_CHECK_LEN(len);
    PCCERT_CONTEXT c =
        CertCreateCertificateContext(X509_ASN_ENCODING, der, (DWORD)len);
    if (!c) {
        return cp_last_error();
    }
    *out = (void *)c;
    return 0;
}

/* ------------------------------------------------------------------ */
/* PIN                                                                 */
/* ------------------------------------------------------------------ */

/* cp_cert_set_pin unlocks a key container and attaches the provider to the
 * certificate context with CERT_KEY_CONTEXT_PROP_ID, so that CryptoAPI reuses
 * it instead of acquiring a fresh context and prompting for the PIN again.
 *
 * The property is set without CERT_STORE_NO_CRYPT_RELEASE_FLAG, so it owns
 * hProv: CryptoAPI releases it when the property is replaced or the last
 * reference to the context is freed. Contexts duplicated with
 * CertDuplicateCertificateContext share the property, so hProv must never be
 * released here once the property is set. */
int32_t cp_cert_set_pin(void *hCert, const char *pin)
{
    PCCERT_CONTEXT c = (PCCERT_CONTEXT)hCert;
    DWORD cb = 0;

    if (!c || !pin) {
        return CP_E_INVALIDARG;
    }

    if (!CertGetCertificateContextProperty(c, CERT_KEY_PROV_INFO_PROP_ID, NULL,
                                           &cb)) {
        DWORD e = GetLastError();
        if (e != ERROR_MORE_DATA) {
            return HRESULT_FROM_WIN32(e);
        }
    }
    if (cb == 0) {
        return CP_E_FAIL;
    }

    CRYPT_KEY_PROV_INFO *kpi = (CRYPT_KEY_PROV_INFO *)malloc(cb);
    if (!kpi) {
        return CP_E_OUTOFMEMORY;
    }
    if (!CertGetCertificateContextProperty(c, CERT_KEY_PROV_INFO_PROP_ID, kpi,
                                           &cb)) {
        int32_t rc = cp_last_error();
        free(kpi);
        return rc;
    }

    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContextW(&hProv, kpi->pwszContainerName,
                              kpi->pwszProvName, kpi->dwProvType,
                              CRYPT_SILENT)) {
        int32_t rc = cp_last_error();
        free(kpi);
        return rc;
    }

    /* AT_KEYEXCHANGE == 1, AT_SIGNATURE == 2. */
    DWORD pin_id = (kpi->dwKeySpec == 1) ? PP_KEYEXCHANGE_PIN : PP_SIGNATURE_PIN;

    if (!CryptSetProvParam(hProv, pin_id, (const BYTE *)pin, 0)) {
        int32_t rc = cp_last_error();
        CryptReleaseContext(hProv, 0);
        free(kpi);
        return rc;
    }

    /* Containers that hold both keys get both unlocked; for single-key
     * containers the second call simply fails and is ignored. */
    CryptSetProvParam(hProv, pin_id == PP_SIGNATURE_PIN ? PP_KEYEXCHANGE_PIN
                                                       : PP_SIGNATURE_PIN,
                      (const BYTE *)pin, 0);

    /* Attach the unlocked provider to the certificate so that the signing
     * functions use it rather than acquiring a new context (which would ask
     * for the PIN interactively). */
    CERT_KEY_CONTEXT keyctx;
    memset(&keyctx, 0, sizeof(keyctx));
    keyctx.cbSize = sizeof(keyctx);
    keyctx.hCryptProv = hProv;
    keyctx.dwKeySpec = kpi->dwKeySpec;
    if (!CertSetCertificateContextProperty(c, CERT_KEY_CONTEXT_PROP_ID, 0,
                                           &keyctx)) {
        int32_t rc = cp_last_error();
        CryptReleaseContext(hProv, 0);
        free(kpi);
        return rc;
    }

    free(kpi);
    return 0;
}

/* ------------------------------------------------------------------ */
/* CAdES                                                               */
/* ------------------------------------------------------------------ */

static wchar_t *cp_ascii_to_wide(const char *s)
{
    size_t n = strlen(s);
    wchar_t *w = (wchar_t *)malloc((n + 1) * sizeof(wchar_t));
    if (!w) {
        return NULL;
    }
    for (size_t i = 0; i < n; i++) {
        w[i] = (wchar_t)(unsigned char)s[i];
    }
    w[n] = 0;
    return w;
}

/* The certificates a signing call embeds in the CMS; items point into chain
 * or at the signer certificate itself. */
typedef struct cp_msg_certs {
    PCCERT_CONTEXT *items;
    DWORD n;
    PCCERT_CHAIN_CONTEXT chain;
} cp_msg_certs;

static void cp_msg_certs_free(cp_msg_certs *mc)
{
    free(mc->items);
    if (mc->chain) {
        CertFreeCertificateChain(mc->chain);
    }
    memset(mc, 0, sizeof(*mc));
}

/*
 * Collects the certificates for `include` (CP_INCLUDE_*). Unlike CAdESCOM,
 * which refuses to sign when the chain has any trust error, whatever part of
 * the chain could be built is embedded: trust is the verifier's decision, and
 * a signature must not fail for an unreachable CRL. The root is the last
 * element only when it is self-signed; a partial chain has no root to drop.
 */
static int32_t cp_msg_certs_build(PCCERT_CONTEXT cert, int32_t include,
                                  HCERTSTORE extra, cp_msg_certs *mc)
{
    memset(mc, 0, sizeof(*mc));
    switch (include) {
    case CP_INCLUDE_NONE:
        return 0;
    case CP_INCLUDE_END_ENTITY_ONLY:
        mc->items = (PCCERT_CONTEXT *)malloc(sizeof(PCCERT_CONTEXT));
        if (!mc->items) {
            return CP_E_OUTOFMEMORY;
        }
        mc->items[0] = cert;
        mc->n = 1;
        return 0;
    case CP_INCLUDE_CHAIN_EXCEPT_ROOT:
    case CP_INCLUDE_WHOLE_CHAIN:
        break;
    default:
        return CP_E_INVALIDARG;
    }

    CERT_CHAIN_PARA para;
    memset(&para, 0, sizeof(para));
    para.cbSize = sizeof(para);
    if (!CertGetCertificateChain(NULL, cert, NULL, extra, &para,
                                 CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL, NULL,
                                 &mc->chain)) {
        mc->chain = NULL;
        return cp_last_error();
    }
    if (mc->chain->cChain == 0 || mc->chain->rgpChain[0]->cElement == 0) {
        cp_msg_certs_free(mc);
        return (int32_t)CERT_E_CHAINING;
    }

    PCERT_SIMPLE_CHAIN sc = mc->chain->rgpChain[0];
    DWORD n = sc->cElement;
    if (include == CP_INCLUDE_CHAIN_EXCEPT_ROOT && n > 1 &&
        (sc->rgpElement[n - 1]->TrustStatus.dwInfoStatus &
         CERT_TRUST_IS_SELF_SIGNED)) {
        n--;
    }
    mc->items = (PCCERT_CONTEXT *)malloc(n * sizeof(PCCERT_CONTEXT));
    if (!mc->items) {
        cp_msg_certs_free(mc);
        return CP_E_OUTOFMEMORY;
    }
    /* Element 0 is the signer itself; keep the caller's context there, it is
     * the one with the key link. */
    mc->items[0] = cert;
    for (DWORD i = 1; i < n; i++) {
        mc->items[i] = sc->rgpElement[i]->pCertContext;
    }
    mc->n = n;
    return 0;
}

/* Builds CRYPT_ATTRIBUTE arrays for signing. Caller frees with cp_attrs_free. */
typedef struct cp_crypt_attrs {
    CRYPT_ATTRIBUTE *items;
    CRYPT_ATTR_BLOB *blobs;
    DWORD n;
} cp_crypt_attrs;

static void cp_attrs_free(cp_crypt_attrs *a)
{
    if (!a) {
        return;
    }
    free(a->items);
    free(a->blobs);
    a->items = NULL;
    a->blobs = NULL;
    a->n = 0;
}

static int32_t cp_attrs_build(cp_attr_list src, cp_crypt_attrs *out)
{
    memset(out, 0, sizeof(*out));
    if (!src.items || src.len == 0) {
        return 0;
    }
    CP_CHECK_LEN(src.len);
    out->items = (CRYPT_ATTRIBUTE *)calloc(src.len, sizeof(CRYPT_ATTRIBUTE));
    out->blobs = (CRYPT_ATTR_BLOB *)calloc(src.len, sizeof(CRYPT_ATTR_BLOB));
    if (!out->items || !out->blobs) {
        cp_attrs_free(out);
        return CP_E_OUTOFMEMORY;
    }
    for (size_t i = 0; i < src.len; i++) {
        if (!src.items[i].oid || !*src.items[i].oid) {
            cp_attrs_free(out);
            return CP_E_INVALIDARG;
        }
        out->blobs[i].pbData = (BYTE *)(uintptr_t)src.items[i].value;
        out->blobs[i].cbData = (DWORD)src.items[i].value_len;
        out->items[i].pszObjId = (LPSTR)(uintptr_t)src.items[i].oid;
        out->items[i].cValue = 1;
        out->items[i].rgValue = &out->blobs[i];
    }
    out->n = (DWORD)src.len;
    return 0;
}

static void cp_fill_sign_para(CADES_SIGN_PARA *cp, CRYPT_SIGN_MESSAGE_PARA *csp,
                              PCCERT_CONTEXT cert, const cp_msg_certs *mc,
                              int32_t cades_type, const char *oid,
                              const char *tsa_url,
                              CADES_SERVICE_CONNECTION_PARA *tsa,
                              wchar_t **wtsa, int32_t check_cert,
                              CADES_EXTRA_PARA *extra, const cp_crypt_attrs *auth,
                              const cp_crypt_attrs *unauth)
{
    memset(csp, 0, sizeof(*csp));
    csp->cbSize = sizeof(*csp);
    csp->dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    csp->pSigningCert = cert;
    /* cMsgCert/rgpMsgCert list the certificates to embed in the CMS. Leaving
     * them empty produces a signature that CryptoPro still verifies locally --
     * it finds the certificate in the store -- but that carries no certificate
     * at all. Every other verifier (CryptoARM, Adobe, an EDO backend) then
     * fails with "Certificate is empty". A GOST certificate is ~1.5 KB, so a
     * ~470-byte CMS is the tell-tale sign of this mistake. Only
     * CP_INCLUDE_NONE leaves them empty on purpose. */
    csp->cMsgCert = mc->n;
    csp->rgpMsgCert = mc->n ? mc->items : NULL;
    csp->HashAlgorithm.pszObjId = (LPSTR)oid;
    csp->dwFlags = CRYPT_MESSAGE_SILENT_KEYSET_FLAG;
    if (auth && auth->n) {
        csp->cAuthAttr = auth->n;
        csp->rgAuthAttr = auth->items;
    }
    if (unauth && unauth->n) {
        csp->cUnauthAttr = unauth->n;
        csp->rgUnauthAttr = unauth->items;
    }

    memset(cp, 0, sizeof(*cp));
    cp->dwSize = sizeof(*cp);
    cp->dwCadesType = (DWORD)cades_type;
    cp->pSignerCert = cert;
    cp->szHashAlgorithm = oid;

    /* CadesSigner.CheckCertificate → CADES_CHECK_CERT_REQ, as in libcppcades. */
    if (check_cert && extra) {
        memset(extra, 0, sizeof(*extra));
        extra->dwSize = sizeof(*extra);
        extra->dwFlags = CADES_CHECK_CERT_REQ;
        cp->pCadesExtraPara = extra;
    }

    memset(tsa, 0, sizeof(*tsa));
    *wtsa = NULL;
    if (tsa_url && *tsa_url) {
        *wtsa = cp_ascii_to_wide(tsa_url);
        if (*wtsa) {
            tsa->dwSize = sizeof(*tsa);
            tsa->wszUri = *wtsa;
            cp->pTspConnectionPara = tsa;
        }
    }
}

int32_t cp_sign_cades(void *hCert, int32_t include, void *hChainStore,
                      int32_t check_cert, cp_attr_list auth, cp_attr_list unauth,
                      int32_t cades_type, const char *hash_oid,
                      const char *tsa_url, const unsigned char *data,
                      size_t len, int32_t detached, cp_buf *out)
{
    CP_CHECK_LEN(len);
    if (!hCert) {
        return CP_E_INVALIDARG;
    }
    PCCERT_CONTEXT cert = (PCCERT_CONTEXT)hCert;
    const char *oid =
        (hash_oid && *hash_oid) ? hash_oid : CP_OID_GOST3411_2012_256;

    CRYPT_SIGN_MESSAGE_PARA csp;
    CADES_SIGN_PARA cp;
    CADES_SERVICE_CONNECTION_PARA tsa;
    CADES_EXTRA_PARA extra;
    wchar_t *wtsa = NULL;
    cp_msg_certs mc;
    cp_crypt_attrs aauth, aunauth;

    int32_t rc = cp_msg_certs_build(cert, include, (HCERTSTORE)hChainStore, &mc);
    if (rc) {
        return rc;
    }
    rc = cp_attrs_build(auth, &aauth);
    if (rc) {
        cp_msg_certs_free(&mc);
        return rc;
    }
    rc = cp_attrs_build(unauth, &aunauth);
    if (rc) {
        cp_attrs_free(&aauth);
        cp_msg_certs_free(&mc);
        return rc;
    }
    cp_fill_sign_para(&cp, &csp, cert, &mc, cades_type, oid, tsa_url, &tsa,
                      &wtsa, check_cert, &extra, &aauth, &aunauth);
    if ((tsa_url && *tsa_url) && !wtsa) {
        cp_attrs_free(&aauth);
        cp_attrs_free(&aunauth);
        cp_msg_certs_free(&mc);
        return CP_E_OUTOFMEMORY;
    }

    CADES_SIGN_MESSAGE_PARA smp;
    memset(&smp, 0, sizeof(smp));
    smp.dwSize = sizeof(smp);
    smp.pSignMessagePara = &csp;
    smp.pCadesSignPara = &cp;

    const BYTE *bufs[1];
    DWORD lens[1];
    bufs[0] = data ? data : (const BYTE *)"";
    lens[0] = (DWORD)len;

    CRYPT_DATA_BLOB *blob = NULL;
    BOOL ok = CadesSignMessage(&smp, detached ? TRUE : FALSE, 1, bufs, lens, &blob);

    if (!ok) {
        rc = cp_last_error();
    } else if (!blob) {
        rc = CP_E_FAIL;
    } else {
        rc = cp_copy(blob->pbData, blob->cbData, out);
        CadesFreeBlob(blob);
    }

    free(wtsa);
    cp_attrs_free(&aauth);
    cp_attrs_free(&aunauth);
    cp_msg_certs_free(&mc);
    return rc;
}

int32_t cp_sign_detached(void *hCert, int32_t include, void *hChainStore,
                         int32_t check_cert, cp_attr_list auth,
                         cp_attr_list unauth, int32_t cades_type,
                         const char *hash_oid, const char *tsa_url,
                         const unsigned char *data, size_t len, cp_buf *out)
{
    CP_CHECK_LEN(len);
    if (!hCert) {
        return CP_E_INVALIDARG;
    }
    return cp_sign_cades(hCert, include, hChainStore, check_cert, auth, unauth,
                         cades_type, hash_oid, tsa_url, data, len, 1, out);
}

int32_t cp_sign_hash(void *hCert, int32_t include, void *hChainStore,
                     int32_t check_cert, cp_attr_list auth, cp_attr_list unauth,
                     int32_t cades_type, const char *hash_oid,
                     const char *tsa_url, const unsigned char *hash,
                     size_t hash_len, cp_buf *out)
{
    CP_CHECK_LEN(hash_len);
    if (!hCert) {
        return CP_E_INVALIDARG;
    }
    PCCERT_CONTEXT cert = (PCCERT_CONTEXT)hCert;
    const char *oid =
        (hash_oid && *hash_oid) ? hash_oid : CP_OID_GOST3411_2012_256;

    CRYPT_SIGN_MESSAGE_PARA csp;
    CADES_SIGN_PARA cp;
    CADES_SERVICE_CONNECTION_PARA tsa;
    CADES_EXTRA_PARA extra;
    wchar_t *wtsa = NULL;
    cp_msg_certs mc;
    cp_crypt_attrs aauth, aunauth;

    int32_t rc = cp_msg_certs_build(cert, include, (HCERTSTORE)hChainStore, &mc);
    if (rc) {
        return rc;
    }
    rc = cp_attrs_build(auth, &aauth);
    if (rc) {
        cp_msg_certs_free(&mc);
        return rc;
    }
    rc = cp_attrs_build(unauth, &aunauth);
    if (rc) {
        cp_attrs_free(&aauth);
        cp_msg_certs_free(&mc);
        return rc;
    }
    cp_fill_sign_para(&cp, &csp, cert, &mc, cades_type, oid, tsa_url, &tsa,
                      &wtsa, check_cert, &extra, &aauth, &aunauth);
    if ((tsa_url && *tsa_url) && !wtsa) {
        cp_attrs_free(&aauth);
        cp_attrs_free(&aunauth);
        cp_msg_certs_free(&mc);
        return CP_E_OUTOFMEMORY;
    }

    CADES_SIGN_MESSAGE_PARA smp;
    memset(&smp, 0, sizeof(smp));
    smp.dwSize = sizeof(smp);
    smp.pSignMessagePara = &csp;
    smp.pCadesSignPara = &cp;

    const BYTE *pbHash = hash ? hash : (const BYTE *)"";

    CRYPT_DATA_BLOB *blob = NULL;
    BOOL ok = CadesSignHash(&smp, pbHash, (DWORD)hash_len, szOID_RSA_data, &blob);

    if (!ok) {
        rc = cp_last_error();
    } else if (!blob) {
        rc = CP_E_FAIL;
    } else {
        rc = cp_copy(blob->pbData, blob->cbData, out);
        CadesFreeBlob(blob);
    }

    free(wtsa);
    cp_attrs_free(&aauth);
    cp_attrs_free(&aunauth);
    cp_msg_certs_free(&mc);
    return rc;
}

int32_t cp_verify_detached(const unsigned char *sig, size_t sig_len,
                           int32_t cades_type, const unsigned char *data,
                           size_t len, int32_t *status)
{
    CP_CHECK_LEN(sig_len);
    CP_CHECK_LEN(len);
    *status = -1;

    CRYPT_VERIFY_MESSAGE_PARA cvp;
    memset(&cvp, 0, sizeof(cvp));
    cvp.cbSize = sizeof(cvp);
    cvp.dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

    CADES_VERIFICATION_PARA cpv;
    memset(&cpv, 0, sizeof(cpv));
    cpv.dwSize = sizeof(cpv);
    cpv.dwCadesType = (DWORD)cades_type;

    CADES_VERIFY_MESSAGE_PARA vmp;
    memset(&vmp, 0, sizeof(vmp));
    vmp.dwSize = sizeof(vmp);
    vmp.pVerifyMessagePara = &cvp;
    vmp.pCadesVerifyPara = &cpv;

    const BYTE *bufs[1];
    DWORD lens[1];
    bufs[0] = data ? data : (const BYTE *)"";
    lens[0] = (DWORD)len;

    CADES_VERIFICATION_INFO *info = NULL;
    BOOL ok = CadesVerifyDetachedMessage(&vmp, 0, sig, (DWORD)sig_len, 1, bufs,
                                         lens, &info);

    /* An invalid signature makes the call fail but still yields the info. */
    int32_t rc = ok ? 0 : cp_last_error();
    if (info) {
        *status = (int32_t)info->dwStatus; /* 0 == ADES_VERIFY_SUCCESS */
        CadesFreeVerificationInfo(info);
    } else if (rc == 0) {
        rc = CP_E_FAIL;
    }
    return rc;
}

/* Defined in the generic helpers section below. */
static char *cp_strdup_n(const char *s, size_t n);

/* cp_signer_hash_oid returns the digest algorithm OID of the first signer of
 * a CMS message. The caller frees *oid. */
static int32_t cp_signer_hash_oid(const unsigned char *sig, size_t sig_len,
                                  char **oid)
{
    *oid = NULL;
    HCRYPTMSG msg = CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                         0, 0, 0, NULL, NULL);
    if (!msg) {
        return cp_last_error();
    }

    int32_t rc = 0;
    DWORD cb = 0;
    CMSG_SIGNER_INFO *si = NULL;
    if (!CryptMsgUpdate(msg, sig, (DWORD)sig_len, TRUE) ||
        !CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &cb)) {
        rc = cp_last_error();
    } else if (!(si = (CMSG_SIGNER_INFO *)malloc(cb))) {
        rc = CP_E_OUTOFMEMORY;
    } else if (!CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, si, &cb)) {
        rc = cp_last_error();
    } else if (!si->HashAlgorithm.pszObjId || !*si->HashAlgorithm.pszObjId) {
        rc = CP_NTE_BAD_ALGID;
    } else {
        *oid = cp_strdup_n(si->HashAlgorithm.pszObjId,
                           strlen(si->HashAlgorithm.pszObjId));
        if (!*oid) {
            rc = CP_E_OUTOFMEMORY;
        }
    }

    free(si);
    CryptMsgClose(msg);
    return rc;
}

int32_t cp_enhance(const unsigned char *sig, size_t sig_len,
                   int32_t cades_type, const char *tsa_url, cp_buf *out)
{
    CP_CHECK_LEN(sig_len);
    if (!sig || sig_len == 0) {
        return CP_E_INVALIDARG;
    }

    /* The timestamp imprint uses the signer's own digest algorithm. */
    char *hash_oid = NULL;
    int32_t hrc = cp_signer_hash_oid(sig, sig_len, &hash_oid);
    if (hrc) {
        return hrc;
    }

    CADES_SIGN_PARA cp;
    memset(&cp, 0, sizeof(cp));
    cp.dwSize = sizeof(cp);
    cp.dwCadesType = (DWORD)cades_type;
    cp.szHashAlgorithm = hash_oid;

    CADES_SERVICE_CONNECTION_PARA tsa;
    wchar_t *wtsa = NULL;
    memset(&tsa, 0, sizeof(tsa));
    if (tsa_url && *tsa_url) {
        wtsa = cp_ascii_to_wide(tsa_url);
        if (!wtsa) {
            free(hash_oid);
            return CP_E_OUTOFMEMORY;
        }
        tsa.dwSize = sizeof(tsa);
        tsa.wszUri = wtsa;
        cp.pTspConnectionPara = &tsa;
    }

    CADES_ENHANCE_MESSAGE_PARA emp;
    memset(&emp, 0, sizeof(emp));
    emp.dwSize = sizeof(emp);
    emp.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    emp.pCadesSignPara = &cp;

    CRYPT_DATA_BLOB *blob = NULL;
    BOOL ok = CadesEnhanceMessage(&emp, 0, sig, (DWORD)sig_len, &blob);

    int32_t rc;
    if (!ok) {
        rc = cp_last_error();
    } else if (!blob) {
        rc = CP_E_FAIL;
    } else {
        rc = cp_copy(blob->pbData, blob->cbData, out);
        CadesFreeBlob(blob);
    }

    free(wtsa);
    free(hash_oid);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

void cp_free(void *p)
{
    free(p);
}

void cp_str_list_free(cp_str_list l)
{
    for (size_t i = 0; i < l.len; i++) {
        free(l.items[i]);
    }
    free(l.items);
}

static char *cp_strdup_n(const char *s, size_t n)
{
    char *p = (char *)malloc(n + 1);
    if (!p) {
        return NULL;
    }
    if (n) {
        memcpy(p, s, n);
    }
    p[n] = 0;
    return p;
}

/* Converts a NUL-terminated wchar_t string to UTF-8. */
static char *cp_wide_to_utf8(const wchar_t *w)
{
    if (!w) {
        return NULL;
    }

    size_t n = 0;
    for (const wchar_t *p = w; *p; p++) {
        unsigned int c = (unsigned int)*p;
        if (c < 0x80) {
            n += 1;
        } else if (c < 0x800) {
            n += 2;
        } else if (c < 0x10000) {
            n += 3;
        } else {
            n += 4;
        }
    }

    char *out = (char *)malloc(n + 1);
    if (!out) {
        return NULL;
    }

    char *q = out;
    for (const wchar_t *p = w; *p; p++) {
        unsigned int c = (unsigned int)*p;
        if (c < 0x80) {
            *q++ = (char)c;
        } else if (c < 0x800) {
            *q++ = (char)(0xC0 | (c >> 6));
            *q++ = (char)(0x80 | (c & 0x3F));
        } else if (c < 0x10000) {
            *q++ = (char)(0xE0 | (c >> 12));
            *q++ = (char)(0x80 | ((c >> 6) & 0x3F));
            *q++ = (char)(0x80 | (c & 0x3F));
        } else {
            *q++ = (char)(0xF0 | (c >> 18));
            *q++ = (char)(0x80 | ((c >> 12) & 0x3F));
            *q++ = (char)(0x80 | ((c >> 6) & 0x3F));
            *q++ = (char)(0x80 | (c & 0x3F));
        }
    }
    *q = 0;
    return out;
}

static int32_t cp_filetime_to_unix(const FILETIME *ft, int64_t *out)
{
    if (!ft) {
        *out = 0;
        return 0;
    }

    uint64_t v = ((uint64_t)ft->dwHighDateTime << 32) | (uint64_t)ft->dwLowDateTime;

    /* 100 ns ticks since 1601-01-01; shift to the Unix epoch. */
    const uint64_t epoch = 116444736000000000ULL;
    if (v <= epoch) {
        *out = 0;
        return 0;
    }
    *out = (int64_t)((v - epoch) / 10000000ULL);
    return 0;
}

int32_t cp_cert_valid_from(void *hCert, int64_t *out)
{
    if (!hCert) {
        return CP_E_INVALIDARG;
    }
    PCCERT_CONTEXT c = (PCCERT_CONTEXT)hCert;
    if (!c->pCertInfo) {
        return CP_E_FAIL;
    }
    return cp_filetime_to_unix(&c->pCertInfo->NotBefore, out);
}

int32_t cp_cert_valid_to(void *hCert, int64_t *out)
{
    if (!hCert) {
        return CP_E_INVALIDARG;
    }
    PCCERT_CONTEXT c = (PCCERT_CONTEXT)hCert;
    if (!c->pCertInfo) {
        return CP_E_FAIL;
    }
    return cp_filetime_to_unix(&c->pCertInfo->NotAfter, out);
}

int32_t cp_cert_version(void *hCert, int32_t *out)
{
    if (!hCert) {
        return CP_E_INVALIDARG;
    }
    PCCERT_CONTEXT c = (PCCERT_CONTEXT)hCert;
    if (!c->pCertInfo) {
        return CP_E_FAIL;
    }
    /* CERT_INFO.dwVersion is zero based (CERT_V1 == 0). */
    *out = (int32_t)c->pCertInfo->dwVersion + 1;
    return 0;
}

int32_t cp_cert_info(void *hCert, int32_t info_type, cp_buf *out)
{
    if (!hCert) {
        return CP_E_INVALIDARG;
    }
    DWORD flags;
    switch (info_type) {
    case 0:
        flags = CERT_NAME_SIMPLE_DISPLAY_TYPE;
        break;
    case 1:
        flags = CERT_NAME_SIMPLE_DISPLAY_TYPE | CERT_NAME_ISSUER_FLAG;
        break;
    case 2:
        flags = CERT_NAME_EMAIL_TYPE;
        break;
    case 3:
        flags = CERT_NAME_EMAIL_TYPE | CERT_NAME_ISSUER_FLAG;
        break;
    case 4:
        flags = CERT_NAME_UPN_TYPE;
        break;
    case 5:
        flags = CERT_NAME_UPN_TYPE | CERT_NAME_ISSUER_FLAG;
        break;
    case 6:
        flags = CERT_NAME_DNS_TYPE;
        break;
    case 7:
        flags = CERT_NAME_DNS_TYPE | CERT_NAME_ISSUER_FLAG;
        break;
    default:
        return CP_E_FAIL;
    }

    return cp_cert_name(hCert, flags, out);
}

int32_t cp_cert_key_usage(void *hCert, cp_key_usage *out)
{
    if (!hCert) {
        return CP_E_INVALIDARG;
    }
    memset(out, 0, sizeof(*out));

    PCCERT_CONTEXT c = (PCCERT_CONTEXT)hCert;
    if (!c->pCertInfo) {
        return CP_E_FAIL;
    }

    PCERT_EXTENSION ext =
        CertFindExtension(szOID_KEY_USAGE, c->pCertInfo->cExtension,
                          c->pCertInfo->rgExtension);
    if (!ext) {
        return 0;
    }

    out->present = 1;
    out->critical = ext->fCritical ? 1 : 0;

    PCRYPT_BIT_BLOB bits = NULL;
    DWORD cb = 0;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_KEY_USAGE, ext->Value.pbData,
                             ext->Value.cbData, CRYPT_DECODE_ALLOC_FLAG, NULL,
                             &bits, &cb)) {
        return cp_last_error();
    }
    if (!bits) {
        return CP_E_FAIL;
    }

    /* KeyUsage is a BIT STRING, bit 0 (digitalSignature) first and MSB first. */
    DWORD total = bits->cbData * 8;
    if (bits->cUnusedBits <= total) {
        total -= bits->cUnusedBits;
    }

    uint32_t mask = 0;
    for (DWORD i = 0; i < total && i < 32; i++) {
        unsigned char byte = bits->pbData[i / 8];
        if (byte & (0x80u >> (i % 8))) {
            mask |= (uint32_t)1 << i;
        }
    }
    out->bits = mask;

    LocalFree(bits);
    return 0;
}

int32_t cp_cert_eku(void *hCert, cp_str_list *out, int32_t *critical,
                    int32_t *present)
{
    if (!hCert) {
        return CP_E_INVALIDARG;
    }
    out->items = NULL;
    out->len = 0;
    *critical = 0;
    *present = 0;

    PCCERT_CONTEXT c = (PCCERT_CONTEXT)hCert;
    if (!c->pCertInfo) {
        return CP_E_FAIL;
    }

    PCERT_EXTENSION ext =
        CertFindExtension(szOID_ENHANCED_KEY_USAGE, c->pCertInfo->cExtension,
                          c->pCertInfo->rgExtension);
    if (!ext) {
        return 0;
    }

    *present = 1;
    *critical = ext->fCritical ? 1 : 0;

    PCTL_USAGE usage = NULL;
    DWORD cb = 0;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_ENHANCED_KEY_USAGE,
                             ext->Value.pbData, ext->Value.cbData,
                             CRYPT_DECODE_ALLOC_FLAG, NULL, &usage, &cb)) {
        return cp_last_error();
    }
    if (!usage) {
        return CP_E_FAIL;
    }

    size_t n = usage->cUsageIdentifier;
    char **items = NULL;
    if (n) {
        items = (char **)calloc(n, sizeof(char *));
        if (!items) {
            LocalFree(usage);
            return CP_E_OUTOFMEMORY;
        }
        for (size_t i = 0; i < n; i++) {
            const char *oid = usage->rgpszUsageIdentifier[i];
            items[i] = cp_strdup_n(oid, oid ? strlen(oid) : 0);
            if (!items[i]) {
                for (size_t j = 0; j < i; j++) {
                    free(items[j]);
                }
                free(items);
                LocalFree(usage);
                return CP_E_OUTOFMEMORY;
            }
        }
    }

    LocalFree(usage);
    out->items = items;
    out->len = n;
    return 0;
}

int32_t cp_cert_extension_count(void *hCert, size_t *n)
{
    *n = 0;
    PCCERT_CONTEXT c = (PCCERT_CONTEXT)hCert;
    if (!c) {
        return CP_E_INVALIDARG;
    }
    if (!c->pCertInfo) {
        return CP_E_FAIL;
    }
    *n = c->pCertInfo->cExtension;
    return 0;
}

int32_t cp_cert_extension_at(void *hCert, size_t i, cp_buf *oid,
                             int32_t *critical, cp_buf *value)
{
    oid->data = NULL;
    oid->len = 0;
    value->data = NULL;
    value->len = 0;
    *critical = 0;

    PCCERT_CONTEXT c = (PCCERT_CONTEXT)hCert;
    if (!c) {
        return CP_E_INVALIDARG;
    }
    if (!c->pCertInfo) {
        return CP_E_FAIL;
    }
    if (i >= c->pCertInfo->cExtension) {
        return CP_E_INVALIDARG;
    }
    PCERT_EXTENSION ext = &c->pCertInfo->rgExtension[i];
    const char *id = ext->pszObjId ? ext->pszObjId : "";
    int32_t rc = cp_copy(id, strlen(id), oid);
    if (rc) {
        return rc;
    }
    rc = cp_copy(ext->Value.pbData, ext->Value.cbData, value);
    if (rc) {
        cp_buf_free(*oid);
        oid->data = NULL;
        oid->len = 0;
        return rc;
    }
    *critical = ext->fCritical ? 1 : 0;
    return 0;
}

int32_t cp_cert_basic_constraints(void *hCert, cp_basic_constraints *out)
{
    if (!hCert) {
        return CP_E_INVALIDARG;
    }
    memset(out, 0, sizeof(*out));

    PCCERT_CONTEXT c = (PCCERT_CONTEXT)hCert;
    if (!c->pCertInfo) {
        return CP_E_FAIL;
    }

    PCERT_EXTENSION ext =
        CertFindExtension(szOID_BASIC_CONSTRAINTS2, c->pCertInfo->cExtension,
                          c->pCertInfo->rgExtension);
    if (!ext) {
        return 0;
    }

    out->present = 1;
    out->critical = ext->fCritical ? 1 : 0;

    PCERT_BASIC_CONSTRAINTS2_INFO info = NULL;
    DWORD cb = 0;
    if (CryptDecodeObjectEx(X509_ASN_ENCODING, X509_BASIC_CONSTRAINTS2,
                            ext->Value.pbData, ext->Value.cbData,
                            CRYPT_DECODE_ALLOC_FLAG, NULL, &info, &cb) &&
        info) {
        out->is_ca = info->fCA ? 1 : 0;
        out->path_len_present = info->fPathLenConstraint ? 1 : 0;
        out->path_len = info->dwPathLenConstraint;
        LocalFree(info);
    }

    return 0;
}

int32_t cp_cert_public_key(void *hCert, cp_buf *encoded_key,
                           cp_buf *encoded_params, char **algorithm_oid,
                           int32_t *bit_length)
{
    if (!hCert) {
        return CP_E_INVALIDARG;
    }
    encoded_key->data = NULL;
    encoded_key->len = 0;
    encoded_params->data = NULL;
    encoded_params->len = 0;
    *algorithm_oid = NULL;
    *bit_length = 0;

    PCCERT_CONTEXT c = (PCCERT_CONTEXT)hCert;
    if (!c->pCertInfo) {
        return CP_E_FAIL;
    }

    CERT_PUBLIC_KEY_INFO *spki = &c->pCertInfo->SubjectPublicKeyInfo;

    int32_t rc = cp_copy(spki->PublicKey.pbData, spki->PublicKey.cbData, encoded_key);
    if (rc) {
        return rc;
    }
    rc = cp_copy(spki->Algorithm.Parameters.pbData,
                 spki->Algorithm.Parameters.cbData, encoded_params);
    if (rc) {
        free(encoded_key->data);
        encoded_key->data = NULL;
        encoded_key->len = 0;
        return rc;
    }

    const char *oid = spki->Algorithm.pszObjId ? spki->Algorithm.pszObjId : "";
    *algorithm_oid = cp_strdup_n(oid, strlen(oid));
    if (!*algorithm_oid) {
        free(encoded_key->data);
        free(encoded_params->data);
        encoded_key->data = NULL;
        encoded_params->data = NULL;
        return CP_E_OUTOFMEMORY;
    }

    *bit_length = (int32_t)(spki->PublicKey.cbData * 8) -
                  (int32_t)spki->PublicKey.cUnusedBits;
    return 0;
}

int32_t cp_cert_key_prov_info(void *hCert, cp_key_prov_info *out)
{
    if (!hCert) {
        return CP_E_INVALIDARG;
    }
    memset(out, 0, sizeof(*out));

    PCCERT_CONTEXT c = (PCCERT_CONTEXT)hCert;

    DWORD cb = 0;
    if (!CertGetCertificateContextProperty(c, CERT_KEY_PROV_INFO_PROP_ID, NULL,
                                          &cb)) {
        if (GetLastError() != ERROR_MORE_DATA) {
            return 0; /* no associated key container */
        }
    }
    if (cb == 0) {
        return 0;
    }

    CRYPT_KEY_PROV_INFO *kpi = (CRYPT_KEY_PROV_INFO *)malloc(cb);
    if (!kpi) {
        return CP_E_OUTOFMEMORY;
    }
    if (!CertGetCertificateContextProperty(c, CERT_KEY_PROV_INFO_PROP_ID, kpi,
                                          &cb)) {
        free(kpi);
        return 0;
    }

    out->present = 1;
    out->provider_type = kpi->dwProvType;
    out->key_spec = kpi->dwKeySpec;
    out->container = cp_wide_to_utf8(kpi->pwszContainerName);
    out->provider = cp_wide_to_utf8(kpi->pwszProvName);

    /* The unique container name is a provider parameter, not a property. */
    HCRYPTPROV prov = 0;
    if (CryptAcquireContextW(&prov, kpi->pwszContainerName, kpi->pwszProvName,
                            kpi->dwProvType, CRYPT_SILENT)) {
        DWORD n = 0;
        CryptGetProvParam(prov, PP_UNIQUE_CONTAINER, NULL, &n, 0);
        if (n > 0) {
            BYTE *buf = (BYTE *)malloc(n);
            if (buf) {
                if (CryptGetProvParam(prov, PP_UNIQUE_CONTAINER, buf, &n, 0)) {
                    out->unique_container = cp_wide_to_utf8((const wchar_t *)buf);
                }
                free(buf);
            }
        }
        CryptReleaseContext(prov, 0);
    }

    free(kpi);
    return 0;
}

int32_t cp_cert_is_valid(void *hCert, void *hAdditionalStore, int32_t revocation,
                         int64_t at_unix, uint32_t url_timeout_ms,
                         int32_t *valid, uint32_t *policy_error,
                         uint32_t *chain_status)
{
    if (!hCert) {
        return CP_E_INVALIDARG;
    }
    *valid = 0;
    *policy_error = 0;
    *chain_status = 0;

    DWORD flags;
    switch (revocation) {
    case CP_REVOCATION_ONLINE:
        flags = CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;
        break;
    case CP_REVOCATION_CACHE_ONLY:
        flags = CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT |
                CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY;
        break;
    case CP_REVOCATION_NONE:
        flags = 0;
        break;
    default:
        return CP_E_INVALIDARG;
    }

    CERT_CHAIN_PARA para;
    memset(&para, 0, sizeof(para));
    para.cbSize = sizeof(para);
    para.dwUrlRetrievalTimeout = url_timeout_ms;

    FILETIME ft;
    LPFILETIME pTime = NULL;
    if (at_unix != 0) {
        uint64_t t = (uint64_t)(at_unix * 10000000LL) + 116444736000000000ULL;
        ft.dwLowDateTime = (DWORD)(t & 0xFFFFFFFFu);
        ft.dwHighDateTime = (DWORD)(t >> 32);
        pTime = &ft;
    }

    PCCERT_CHAIN_CONTEXT chain = NULL;
    if (!CertGetCertificateChain(NULL, (PCCERT_CONTEXT)hCert, pTime,
                                (HCERTSTORE)hAdditionalStore, &para, flags,
                                NULL, &chain)) {
        return cp_last_error();
    }
    *chain_status = (uint32_t)chain->TrustStatus.dwErrorStatus;

    CERT_CHAIN_POLICY_PARA ppara;
    memset(&ppara, 0, sizeof(ppara));
    ppara.cbSize = sizeof(ppara);

    CERT_CHAIN_POLICY_STATUS pstatus;
    memset(&pstatus, 0, sizeof(pstatus));
    pstatus.cbSize = sizeof(pstatus);

    BOOL ok = CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_BASE, chain,
                                               &ppara, &pstatus);
    *policy_error = (uint32_t)pstatus.dwError;
    CertFreeCertificateChain(chain);
    if (!ok) {
        return cp_last_error();
    }

    *valid = (pstatus.dwError == 0) ? 1 : 0;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Store mutation                                                      */
/* ------------------------------------------------------------------ */

/* CryptoPro writes a system store back to disk only on CertCloseStore;
 * commit right away so other handles and the chain engine see the change,
 * as with the Windows stores. Memory stores have nothing to commit. */
static int32_t cp_store_commit(HCERTSTORE h)
{
    if (CertControlStore(h, 0, CERT_STORE_CTRL_COMMIT, NULL)) {
        return 0;
    }
    DWORD e = GetLastError();
    if (e == ERROR_CALL_NOT_IMPLEMENTED || e == ERROR_NOT_SUPPORTED) {
        return 0;
    }
    return e ? HRESULT_FROM_WIN32(e) : CP_E_FAIL;
}

int32_t cp_store_add_cert(void *hStore, void *hCert)
{
    if (!hStore || !hCert) {
        return CP_E_INVALIDARG;
    }
    if (!CertAddCertificateContextToStore((HCERTSTORE)hStore,
                                         (PCCERT_CONTEXT)hCert,
                                         CERT_STORE_ADD_ALWAYS, NULL)) {
        return cp_last_error();
    }
    return cp_store_commit((HCERTSTORE)hStore);
}

int32_t cp_store_remove_cert(void *hStore, void *hCert)
{
    if (!hStore || !hCert) {
        return CP_E_INVALIDARG;
    }
    /* Delete the store's own context: CertDeleteCertificateFromStore frees
     * the context it is given, and the caller's one must stay valid. */
    PCCERT_CONTEXT found = CertFindCertificateInStore(
        (HCERTSTORE)hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
        CERT_FIND_EXISTING, hCert, NULL);
    if (!found) {
        return cp_last_error();
    }
    if (!CertDeleteCertificateFromStore(found)) {
        return cp_last_error();
    }
    return cp_store_commit((HCERTSTORE)hStore);
}

int32_t cp_store_add_crl(void *hStore, const unsigned char *der, size_t len)
{
    CP_CHECK_LEN(len);
    if (!hStore) {
        return CP_E_INVALIDARG;
    }
    PCCRL_CONTEXT crl = CertCreateCRLContext(X509_ASN_ENCODING, der, (DWORD)len);
    if (!crl) {
        return cp_last_error();
    }

    int32_t rc = 0;
    if (!CertAddCRLContextToStore((HCERTSTORE)hStore, crl, CERT_STORE_ADD_ALWAYS,
                                 NULL)) {
        rc = cp_last_error();
    }
    CertFreeCRLContext(crl);
    return rc ? rc : cp_store_commit((HCERTSTORE)hStore);
}

int32_t cp_store_import_pfx(void *hStore, const unsigned char *pfx, size_t len,
                            const wchar_t *password, uint32_t flags,
                            void **out)
{
    CP_CHECK_LEN(len);
    if (!pfx || !len || (!hStore && !out)) {
        return CP_E_INVALIDARG;
    }
    CRYPT_DATA_BLOB blob;
    blob.cbData = (DWORD)len;
    blob.pbData = (BYTE *)pfx;
    HCERTSTORE pfxStore =
        PFXImportCertStore(&blob, password ? password : L"", (DWORD)flags);
    if (!pfxStore) {
        return cp_last_error();
    }
    if (!hStore) {
        *out = pfxStore;
        return 0;
    }

    /* The copies keep CERT_KEY_PROV_INFO_PROP_ID, so the certificates in
     * hStore stay linked to the key containers the import created. */
    int32_t rc = 0;
    PCCERT_CONTEXT c = NULL;
    while ((c = CertEnumCertificatesInStore(pfxStore, c)) != NULL) {
        if (!CertAddCertificateContextToStore((HCERTSTORE)hStore, c,
                                             CERT_STORE_ADD_REPLACE_EXISTING,
                                             NULL)) {
            rc = cp_last_error();
            CertFreeCertificateContext(c);
            break;
        }
    }
    CertCloseStore(pfxStore, 0);
    return rc ? rc : cp_store_commit((HCERTSTORE)hStore);
}

static int32_t cp_hex_upper(const BYTE *p, DWORD n, cp_buf *out)
{
    static const char hex[] = "0123456789ABCDEF";
    char *s = (char *)malloc((size_t)n * 2 + 1);
    if (!s) {
        return CP_E_OUTOFMEMORY;
    }
    for (DWORD i = 0; i < n; i++) {
        s[i * 2]     = hex[p[i] >> 4];
        s[i * 2 + 1] = hex[p[i] & 0x0F];
    }
    int32_t rc = cp_copy(s, (size_t)n * 2, out);
    free(s);
    return rc;
}

void cp_crl_info_free(cp_crl_info i)
{
    free(i.issuer.data);
    free(i.thumbprint.data);
    free(i.auth_key_id.data);
}

/* Fields as CPPCadesCPCRLObject reports them: the issuer as an X.500 string
 * (CertNameToStr, CERT_X500_NAME_STR), the SHA-1 thumbprint and the
 * authorityKeyIdentifier keyIdentifier in upper-case hex. */
int32_t cp_crl_info_get(const unsigned char *der, size_t len, cp_crl_info *out)
{
    CP_CHECK_LEN(len);
    memset(out, 0, sizeof(*out));
    if (!der || !len) {
        return CP_E_INVALIDARG;
    }
    PCCRL_CONTEXT crl = CertCreateCRLContext(X509_ASN_ENCODING, der, (DWORD)len);
    if (!crl) {
        return cp_last_error();
    }
    PCRL_INFO ci = crl->pCrlInfo;
    int32_t rc = 0;

    DWORD n = CertNameToStrW(X509_ASN_ENCODING, &ci->Issuer, CERT_X500_NAME_STR,
                             NULL, 0);
    if (n > 1) {
        wchar_t *w = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
        char *utf8 = NULL;
        if (!w) {
            rc = CP_E_OUTOFMEMORY;
        } else {
            CertNameToStrW(X509_ASN_ENCODING, &ci->Issuer, CERT_X500_NAME_STR,
                           w, n);
            utf8 = cp_wide_to_utf8(w);
            rc = utf8 ? cp_copy(utf8, strlen(utf8), &out->issuer)
                      : CP_E_OUTOFMEMORY;
        }
        free(utf8);
        free(w);
    }

    if (rc == 0) {
        cp_filetime_to_unix(&ci->ThisUpdate, &out->this_update);
        cp_filetime_to_unix(&ci->NextUpdate, &out->next_update);

        BYTE hash[64];
        DWORD hn = sizeof(hash);
        if (!CertGetCRLContextProperty(crl, CERT_SHA1_HASH_PROP_ID, hash, &hn)) {
            rc = cp_last_error();
        } else {
            rc = cp_hex_upper(hash, hn, &out->thumbprint);
        }
    }

    PCERT_EXTENSION ext =
        rc ? NULL
           : CertFindExtension(szOID_AUTHORITY_KEY_IDENTIFIER2, ci->cExtension,
                               ci->rgExtension);
    if (ext) {
        DWORD cb = 0;
        void *aki = NULL;
        if (!CryptDecodeObject(X509_ASN_ENCODING, X509_AUTHORITY_KEY_ID2,
                               ext->Value.pbData, ext->Value.cbData, 0, NULL,
                               &cb)) {
            rc = cp_last_error();
        } else if (!(aki = malloc(cb))) {
            rc = CP_E_OUTOFMEMORY;
        } else if (!CryptDecodeObject(X509_ASN_ENCODING, X509_AUTHORITY_KEY_ID2,
                                      ext->Value.pbData, ext->Value.cbData, 0,
                                      aki, &cb)) {
            rc = cp_last_error();
        } else {
            PCERT_AUTHORITY_KEY_ID2_INFO info = (PCERT_AUTHORITY_KEY_ID2_INFO)aki;
            if (info->KeyId.cbData) {
                rc = cp_hex_upper(info->KeyId.pbData, info->KeyId.cbData,
                                  &out->auth_key_id);
            }
        }
        free(aki);
    }

    CertFreeCRLContext(crl);
    if (rc) {
        cp_crl_info_free(*out);
        memset(out, 0, sizeof(*out));
    }
    return rc;
}

/* ------------------------------------------------------------------ */
/* CAdES message type                                                  */
/* ------------------------------------------------------------------ */

static int32_t cp_msg_decode(const unsigned char *msg, size_t len,
                             HCRYPTMSG *out)
{
    *out = NULL;
    HCRYPTMSG h = CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                       0, 0, 0, NULL, NULL);
    if (!h) {
        return cp_last_error();
    }
    if (!CryptMsgUpdate(h, msg, (DWORD)len, TRUE)) {
        int32_t rc = cp_last_error();
        CryptMsgClose(h);
        return rc;
    }
    *out = h;
    return 0;
}

int32_t cp_msg_is_type(const unsigned char *msg, size_t len,
                       uint32_t cades_type, int32_t *result)
{
    CP_CHECK_LEN(len);
    *result = 0;
    if (!msg || !len) {
        return CP_E_INVALIDARG;
    }
    HCRYPTMSG h;
    int32_t rc = cp_msg_decode(msg, len, &h);
    if (rc) {
        return rc;
    }
    BOOL is = FALSE;
    if (!CadesMsgIsType(h, 0, (DWORD)cades_type, &is)) {
        rc = cp_last_error();
    }
    CryptMsgClose(h);
    *result = is ? 1 : 0;
    return rc;
}

/* Strongest type first, as CPPCadesSignedDataObject::GetMsgType does. */
int32_t cp_msg_get_type(const unsigned char *msg, size_t len,
                        uint32_t *cades_type)
{
    static const DWORD order[] = {CADES_A, CADES_X_LONG_TYPE_1, CADES_T,
                                  CADES_BES, PKCS7_TYPE};
    CP_CHECK_LEN(len);
    *cades_type = 0;
    if (!msg || !len) {
        return CP_E_INVALIDARG;
    }
    HCRYPTMSG h;
    int32_t rc = cp_msg_decode(msg, len, &h);
    if (rc) {
        return rc;
    }
    rc = CP_E_INVALIDARG;
    for (size_t i = 0; i < sizeof(order) / sizeof(order[0]); i++) {
        BOOL is = FALSE;
        if (!CadesMsgIsType(h, 0, order[i], &is)) {
            rc = cp_last_error();
            break;
        }
        if (is) {
            *cades_type = (uint32_t)order[i];
            rc = 0;
            break;
        }
    }
    CryptMsgClose(h);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Certificates and revocation values of a CMS                         */
/* ------------------------------------------------------------------ */

void cp_buf_list_free(cp_buf_list l)
{
    for (size_t i = 0; i < l.len; i++) {
        free(l.items[i].data);
    }
    free(l.items);
}

static int32_t cp_buf_list_push(cp_buf_list *l, size_t *cap, const BYTE *p,
                                DWORD n)
{
    if (l->len == *cap) {
        size_t nc = *cap ? *cap * 2 : 8;
        cp_buf *items = (cp_buf *)realloc(l->items, nc * sizeof(cp_buf));
        if (!items) {
            return CP_E_OUTOFMEMORY;
        }
        l->items = items;
        *cap = nc;
    }
    int32_t rc = cp_copy(p, n, &l->items[l->len]);
    if (rc == 0) {
        l->len++;
    }
    return rc;
}

static int32_t cp_buf_list_push_array(cp_buf_list *l, size_t *cap,
                                      PCADES_BLOB_ARRAY a)
{
    for (DWORD i = 0; a && i < a->cValue; i++) {
        int32_t rc = cp_buf_list_push(l, cap, a->rgValue[i].pbData,
                                      a->rgValue[i].cbData);
        if (rc) {
            return rc;
        }
    }
    return 0;
}

/* Adds the signer certificate of every timestamp token in `a`, as
 * CPPCadesSignedDataObject::FillCertificates does with the TSA certificates.
 * A token that does not decode or carries no signer certificate is skipped. */
static int32_t cp_push_tsa_certs(cp_buf_list *l, size_t *cap, PCADES_BLOB_ARRAY a)
{
    for (DWORD i = 0; a && i < a->cValue; i++) {
        HCRYPTMSG t;
        if (cp_msg_decode(a->rgValue[i].pbData, a->rgValue[i].cbData, &t)) {
            continue;
        }
        HCERTSTORE st = CertOpenStore(CERT_STORE_PROV_MSG,
                                      X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                      0, 0, t);
        DWORD cb = 0;
        void *info = NULL;
        PCCERT_CONTEXT c = NULL;
        if (st && CryptMsgGetParam(t, CMSG_SIGNER_CERT_INFO_PARAM, 0, NULL, &cb) &&
            (info = malloc(cb)) != NULL &&
            CryptMsgGetParam(t, CMSG_SIGNER_CERT_INFO_PARAM, 0, info, &cb)) {
            c = CertGetSubjectCertificateFromStore(
                st, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, (PCERT_INFO)info);
        }
        int32_t rc = 0;
        if (c) {
            rc = cp_buf_list_push(l, cap, c->pbCertEncoded, c->cbCertEncoded);
            CertFreeCertificateContext(c);
        } else if (cb && !info) {
            rc = CP_E_OUTOFMEMORY;
        }
        free(info);
        if (st) {
            CertCloseStore(st, 0);
        }
        CryptMsgClose(t);
        if (rc) {
            return rc;
        }
    }
    return 0;
}

/*
 * Mirrors CPPCadesSignedDataObject::FillCertificates. The CAdES attribute
 * getters fail when a signer has no such attribute; that, as in the vendor
 * code, only means there is nothing to add.
 */
int32_t cp_msg_certificates(const unsigned char *msg, size_t len,
                            cp_buf_list *out)
{
    CP_CHECK_LEN(len);
    memset(out, 0, sizeof(*out));
    if (!msg || !len) {
        return CP_E_INVALIDARG;
    }
    HCRYPTMSG h;
    int32_t rc = cp_msg_decode(msg, len, &h);
    if (rc) {
        return rc;
    }
    size_t cap = 0;

    DWORD count = 0;
    DWORD cb = sizeof(count);
    if (!CryptMsgGetParam(h, CMSG_CERT_COUNT_PARAM, 0, &count, &cb)) {
        rc = cp_last_error();
    }
    for (DWORD i = 0; rc == 0 && i < count; i++) {
        DWORD n = 0;
        BYTE *der = NULL;
        if (!CryptMsgGetParam(h, CMSG_CERT_PARAM, i, NULL, &n)) {
            rc = cp_last_error();
        } else if (!(der = (BYTE *)malloc(n ? n : 1))) {
            rc = CP_E_OUTOFMEMORY;
        } else if (!CryptMsgGetParam(h, CMSG_CERT_PARAM, i, der, &n)) {
            rc = cp_last_error();
        } else {
            rc = cp_buf_list_push(out, &cap, der, n);
        }
        free(der);
    }

    DWORD signers = 0;
    cb = sizeof(signers);
    if (rc == 0 && !CryptMsgGetParam(h, CMSG_SIGNER_COUNT_PARAM, 0, &signers, &cb)) {
        rc = cp_last_error();
    }
    for (DWORD i = 0; rc == 0 && i < signers; i++) {
        PCADES_BLOB_ARRAY a = NULL;
        if (CadesMsgGetCertificateValues(h, i, &a)) {
            rc = cp_buf_list_push_array(out, &cap, a);
            CadesFreeBlobArray(a);
        }
        a = NULL;
        if (rc == 0 && CadesMsgGetSignatureTimestamps(h, i, &a)) {
            rc = cp_push_tsa_certs(out, &cap, a);
            CadesFreeBlobArray(a);
        }
        a = NULL;
        if (rc == 0 && CadesMsgGetCadesCTimestamps(h, i, &a)) {
            rc = cp_push_tsa_certs(out, &cap, a);
            CadesFreeBlobArray(a);
        }
        a = NULL;
        if (rc == 0 && CadesMsgGetArchiveTimestamps(h, i, 0, NULL, &a)) {
            rc = cp_push_tsa_certs(out, &cap, a);
            CadesFreeBlobArray(a);
        }
    }

    CryptMsgClose(h);
    if (rc) {
        cp_buf_list_free(*out);
        memset(out, 0, sizeof(*out));
    }
    return rc;
}

int32_t cp_msg_revocation_values(const unsigned char *msg, size_t len,
                                 uint32_t signer, cp_buf_list *crls,
                                 cp_buf_list *ocsps)
{
    CP_CHECK_LEN(len);
    memset(crls, 0, sizeof(*crls));
    memset(ocsps, 0, sizeof(*ocsps));
    if (!msg || !len) {
        return CP_E_INVALIDARG;
    }
    HCRYPTMSG h;
    int32_t rc = cp_msg_decode(msg, len, &h);
    if (rc) {
        return rc;
    }

    PCADES_BLOB_ARRAY c = NULL;
    PCADES_BLOB_ARRAY o = NULL;
    if (CadesMsgGetRevocationValues(h, (DWORD)signer, &c, &o)) {
        size_t cap = 0;
        rc = cp_buf_list_push_array(crls, &cap, c);
        cap = 0;
        if (rc == 0) {
            rc = cp_buf_list_push_array(ocsps, &cap, o);
        }
        if (c) {
            CadesFreeBlobArray(c);
        }
        if (o) {
            CadesFreeBlobArray(o);
        }
    }

    CryptMsgClose(h);
    if (rc) {
        cp_buf_list_free(*crls);
        cp_buf_list_free(*ocsps);
        memset(crls, 0, sizeof(*crls));
        memset(ocsps, 0, sizeof(*ocsps));
    }
    return rc;
}

/* ------------------------------------------------------------------ */
/* CSP version and OID info                                            */
/* ------------------------------------------------------------------ */

/* Opens provider `name` (NULL or "" = the default one) of `prov_type` without
 * a key container, as CAdESCOM About does. */
static int32_t cp_acquire_verify(const char *name, uint32_t prov_type,
                                 HCRYPTPROV *prov)
{
    *prov = 0;
    if (!CryptAcquireContextA(prov, NULL, (name && *name) ? name : NULL,
                              (DWORD)prov_type,
                              CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        return cp_last_error();
    }
    return 0;
}

int32_t cp_csp_name(uint32_t prov_type, cp_buf *out)
{
    out->data = NULL;
    out->len = 0;

    HCRYPTPROV prov;
    int32_t rc = cp_acquire_verify(NULL, prov_type, &prov);
    if (rc) {
        return rc;
    }
    DWORD cb = 0;
    if (!CryptGetProvParam(prov, PP_NAME, NULL, &cb, 0)) {
        rc = cp_last_error();
        CryptReleaseContext(prov, 0);
        return rc;
    }
    char *name = (char *)calloc(1, (size_t)cb + 1);
    if (!name) {
        CryptReleaseContext(prov, 0);
        return CP_E_OUTOFMEMORY;
    }
    if (!CryptGetProvParam(prov, PP_NAME, (BYTE *)name, &cb, 0)) {
        rc = cp_last_error();
    } else {
        rc = cp_copy(name, strlen(name), out);
    }
    free(name);
    CryptReleaseContext(prov, 0);
    return rc;
}

int32_t cp_csp_version_info(const char *name, uint32_t prov_type,
                            cp_csp_version *out)
{
    memset(out, 0, sizeof(*out));

    HCRYPTPROV prov;
    int32_t acq = cp_acquire_verify(name, prov_type, &prov);
    if (acq) {
        return acq;
    }

    DWORD v = 0;
    DWORD cb = sizeof(v);
    BOOL ok = CryptGetProvParam(prov, PP_VERSION, (BYTE *)&v, &cb, 0);
    int32_t rc = ok ? 0 : cp_last_error();

    /* The build number is CryptoPro-specific; providers without
     * PP_VERSION_EX leave it at 0. */
    PROV_PP_VERSION_EX ex;
    memset(&ex, 0, sizeof(ex));
    DWORD cbex = sizeof(ex);
    if (ok && CryptGetProvParam(prov, PP_VERSION_EX, (BYTE *)&ex, &cbex, 0)) {
        out->build = (uint32_t)ex.SKZI_Build;
    }
    CryptReleaseContext(prov, 0);
    if (!ok) {
        return rc;
    }

    DWORD hi = (v >> 16) & 0xFFFF;
    DWORD lo = v & 0xFFFF;

    /* CryptoPro packs the version as (major << 8) | minor in the low word. */
    if (hi == 0 && (lo >> 8) != 0) {
        out->major = (lo >> 8) & 0xFF;
        out->minor = lo & 0xFF;
    } else {
        out->major = hi;
        out->minor = lo;
    }
    return 0;
}

int32_t cp_oid_info(const char *oid, cp_buf *out)
{
    out->data = NULL;
    out->len = 0;
    if (!oid || !*oid) {
        return 0;
    }

    PCCRYPT_OID_INFO info = CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, (void *)oid, 0);
    if (!info || !info->pwszName) {
        return 0;
    }

    char *name = cp_wide_to_utf8(info->pwszName);
    if (!name) {
        return CP_E_OUTOFMEMORY;
    }
    int32_t rc = cp_copy(name, strlen(name), out);
    free(name);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Verification with signer information                                */
/* ------------------------------------------------------------------ */

static void cp_copy_verify_info(CADES_VERIFICATION_INFO *info, cp_verify_info *out)
{
    out->status = (int32_t)info->dwStatus;
    out->signer_cert = NULL;
    out->signing_time = 0;
    out->signature_ts_time = 0;
    out->cades_c_ts_time = 0;
    out->archive_ts_time = 0;

    if (info->pSignerCert) {
        PCCERT_CONTEXT dup = CertDuplicateCertificateContext(info->pSignerCert);
        if (dup) {
            out->signer_cert = (void *)dup;
        }
    }

    cp_filetime_to_unix(info->pSigningTime, &out->signing_time);
    cp_filetime_to_unix(info->pSignatureTimeStampTime, &out->signature_ts_time);
#ifdef CADES_PARA_HAS_EXTRA_TIME_FIELDS
    cp_filetime_to_unix(info->pEarliestCadesCTimeStampTime,
                        &out->cades_c_ts_time);
    cp_filetime_to_unix(info->pLatestArchiveTimeStampTime,
                        &out->archive_ts_time);
#endif
}

/*
 * Converts the outcome of a CadesVerify* call. An invalid signature makes the
 * call fail but still yields the info with the status and the signer
 * certificate, so the info is copied in either case.
 */
static int32_t cp_take_verify_info(BOOL ok, CADES_VERIFICATION_INFO *info,
                                   cp_verify_info *out)
{
    int32_t rc = ok ? 0 : cp_last_error();
    if (info) {
        cp_copy_verify_info(info, out);
        CadesFreeVerificationInfo(info);
    } else {
        out->status = -1;
        if (rc == 0) {
            rc = CP_E_FAIL;
        }
    }
    return rc;
}

static void cp_init_verify_para(CRYPT_VERIFY_MESSAGE_PARA *cvp,
                                CADES_VERIFICATION_PARA *cpv,
                                CADES_VERIFY_MESSAGE_PARA *vmp,
                                int32_t cades_type, void *hStore)
{
    memset(cvp, 0, sizeof(*cvp));
    cvp->cbSize = sizeof(*cvp);
    cvp->dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

    memset(cpv, 0, sizeof(*cpv));
    cpv->dwSize = sizeof(*cpv);
    cpv->dwCadesType = (DWORD)cades_type;
    cpv->hStore = (HCERTSTORE)hStore;

    memset(vmp, 0, sizeof(*vmp));
    vmp->dwSize = sizeof(*vmp);
    vmp->pVerifyMessagePara = cvp;
    vmp->pCadesVerifyPara = cpv;
}

int32_t cp_verify_message(const unsigned char *sig, size_t sig_len,
                          int32_t cades_type, int32_t detached,
                          const unsigned char *content, size_t content_len,
                          int32_t signer_index, void *hStore,
                          cp_verify_info *out)
{
    CP_CHECK_LEN(sig_len);
    CP_CHECK_LEN(content_len);
    memset(out, 0, sizeof(*out));

    CRYPT_VERIFY_MESSAGE_PARA cvp;
    CADES_VERIFICATION_PARA cpv;
    CADES_VERIFY_MESSAGE_PARA vmp;
    cp_init_verify_para(&cvp, &cpv, &vmp, cades_type, hStore);

    CADES_VERIFICATION_INFO *info = NULL;
    BOOL ok;

    if (detached) {
        const BYTE *bufs[1];
        DWORD lens[1];
        bufs[0] = content ? content : (const BYTE *)"";
        lens[0] = (DWORD)content_len;
        ok = CadesVerifyDetachedMessage(&vmp, (DWORD)signer_index, sig,
                                        (DWORD)sig_len, 1, bufs, lens, &info);
    } else {
        ok = CadesVerifyMessage(&vmp, (DWORD)signer_index, sig, (DWORD)sig_len,
                               NULL, &info);
    }

    return cp_take_verify_info(ok, info, out);
}

int32_t cp_verify_hash(const unsigned char *sig, size_t sig_len,
                       int32_t cades_type, const char *hash_oid,
                       const unsigned char *hash, size_t hash_len,
                       int32_t signer_index, void *hStore,
                       cp_verify_info *out)
{
    CP_CHECK_LEN(sig_len);
    CP_CHECK_LEN(hash_len);
    memset(out, 0, sizeof(*out));

    CRYPT_ALGORITHM_IDENTIFIER alg;
    memset(&alg, 0, sizeof(alg));
    alg.pszObjId = (LPSTR)((hash_oid && *hash_oid) ? hash_oid
                                                  : CP_OID_GOST3411_2012_256);

    CRYPT_VERIFY_MESSAGE_PARA cvp;
    CADES_VERIFICATION_PARA cpv;
    CADES_VERIFY_MESSAGE_PARA vmp;
    cp_init_verify_para(&cvp, &cpv, &vmp, cades_type, hStore);

    CADES_VERIFICATION_INFO *info = NULL;
    BOOL ok = CadesVerifyHash(&vmp, (DWORD)signer_index, sig, (DWORD)sig_len,
                              hash, (DWORD)hash_len, &alg, &info);
    return cp_take_verify_info(ok, info, out);
}

/* ------------------------------------------------------------------ */
/* Plain CMS and co-signing                                            */
/* ------------------------------------------------------------------ */

int32_t cp_sign_cms(void *hCert, int32_t include, void *hChainStore,
                    cp_attr_list auth, cp_attr_list unauth,
                    const char *hash_oid, int32_t detached,
                    const unsigned char *data, size_t len, cp_buf *out)
{
    CP_CHECK_LEN(len);
    if (!hCert) {
        return CP_E_INVALIDARG;
    }
    cp_msg_certs mc;
    cp_crypt_attrs aauth, aunauth;
    int32_t rc = cp_msg_certs_build((PCCERT_CONTEXT)hCert, include,
                                    (HCERTSTORE)hChainStore, &mc);
    if (rc) {
        return rc;
    }
    rc = cp_attrs_build(auth, &aauth);
    if (rc) {
        cp_msg_certs_free(&mc);
        return rc;
    }
    rc = cp_attrs_build(unauth, &aunauth);
    if (rc) {
        cp_attrs_free(&aauth);
        cp_msg_certs_free(&mc);
        return rc;
    }

    CRYPT_SIGN_MESSAGE_PARA csp;
    memset(&csp, 0, sizeof(csp));
    csp.cbSize = sizeof(csp);
    csp.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    csp.pSigningCert = (PCCERT_CONTEXT)hCert;
    /* Embed the certificates, see cp_fill_sign_para. */
    csp.cMsgCert = mc.n;
    csp.rgpMsgCert = mc.n ? mc.items : NULL;
    csp.HashAlgorithm.pszObjId =
        (LPSTR)((hash_oid && *hash_oid) ? hash_oid : CP_OID_GOST3411_2012_256);
    csp.dwFlags = CRYPT_MESSAGE_SILENT_KEYSET_FLAG;
    if (aauth.n) {
        csp.cAuthAttr = aauth.n;
        csp.rgAuthAttr = aauth.items;
    }
    if (aunauth.n) {
        csp.cUnauthAttr = aunauth.n;
        csp.rgUnauthAttr = aunauth.items;
    }

    const BYTE *bufs[1];
    DWORD lens[1];
    bufs[0] = data ? data : (const BYTE *)"";
    lens[0] = (DWORD)len;

    BYTE *buf = NULL;
    DWORD cb = 0;
    if (!CryptSignMessage(&csp, detached ? TRUE : FALSE, 1, bufs, lens, NULL, &cb)) {
        rc = cp_last_error();
    } else if (!(buf = (BYTE *)malloc(cb ? cb : 1))) {
        rc = CP_E_OUTOFMEMORY;
    } else if (!CryptSignMessage(&csp, detached ? TRUE : FALSE, 1, bufs, lens,
                                 buf, &cb)) {
        rc = cp_last_error();
    } else {
        rc = cp_copy(buf, cb, out);
    }
    free(buf);
    cp_attrs_free(&aauth);
    cp_attrs_free(&aunauth);
    cp_msg_certs_free(&mc);
    return rc;
}

int32_t cp_cosign_hash(void *hCert, int32_t include, void *hChainStore,
                       int32_t check_cert, cp_attr_list auth,
                       cp_attr_list unauth, int32_t cades_type,
                       const char *hash_oid, const char *tsa_url,
                       const unsigned char *sig, size_t sig_len,
                       const unsigned char *hash, size_t hash_len, cp_buf *out)
{
    CP_CHECK_LEN(sig_len);
    CP_CHECK_LEN(hash_len);
    if (!hCert) {
        return CP_E_INVALIDARG;
    }
    PCCERT_CONTEXT cert = (PCCERT_CONTEXT)hCert;
    const char *oid =
        (hash_oid && *hash_oid) ? hash_oid : CP_OID_GOST3411_2012_256;

    CRYPT_SIGN_MESSAGE_PARA csp;
    CADES_SIGN_PARA cp;
    CADES_SERVICE_CONNECTION_PARA tsa;
    CADES_EXTRA_PARA extra;
    wchar_t *wtsa = NULL;
    cp_msg_certs mc;
    cp_crypt_attrs aauth, aunauth;

    int32_t rc = cp_msg_certs_build(cert, include, (HCERTSTORE)hChainStore, &mc);
    if (rc) {
        return rc;
    }
    rc = cp_attrs_build(auth, &aauth);
    if (rc) {
        cp_msg_certs_free(&mc);
        return rc;
    }
    rc = cp_attrs_build(unauth, &aunauth);
    if (rc) {
        cp_attrs_free(&aauth);
        cp_msg_certs_free(&mc);
        return rc;
    }
    cp_fill_sign_para(&cp, &csp, cert, &mc, cades_type, oid, tsa_url, &tsa,
                      &wtsa, check_cert, &extra, &aauth, &aunauth);
    if ((tsa_url && *tsa_url) && !wtsa) {
        cp_attrs_free(&aauth);
        cp_attrs_free(&aunauth);
        cp_msg_certs_free(&mc);
        return CP_E_OUTOFMEMORY;
    }

    CADES_SIGN_MESSAGE_PARA smp;
    memset(&smp, 0, sizeof(smp));
    smp.dwSize = sizeof(smp);
    smp.pSignMessagePara = &csp;
    smp.pCadesSignPara = &cp;

    CRYPT_DATA_BLOB *blob = NULL;
    BOOL ok = CadesAddHashSignature(&smp, sig, (DWORD)sig_len, hash,
                                    (DWORD)hash_len, &blob);

    if (!ok) {
        rc = cp_last_error();
    } else if (!blob) {
        rc = CP_E_FAIL;
    } else {
        rc = cp_copy(blob->pbData, blob->cbData, out);
        CadesFreeBlob(blob);
    }

    free(wtsa);
    cp_attrs_free(&aauth);
    cp_attrs_free(&aunauth);
    cp_msg_certs_free(&mc);
    return rc;
}

/* Reports whether the decoded message already carries the certificate. */
static int32_t cp_msg_has_cert(HCRYPTMSG msg, PCCERT_CONTEXT cert, int *has)
{
    *has = 0;
    DWORD count = 0;
    DWORD cb = sizeof(count);
    if (!CryptMsgGetParam(msg, CMSG_CERT_COUNT_PARAM, 0, &count, &cb)) {
        return cp_last_error();
    }
    for (DWORD i = 0; i < count && !*has; i++) {
        DWORD n = 0;
        if (!CryptMsgGetParam(msg, CMSG_CERT_PARAM, i, NULL, &n)) {
            return cp_last_error();
        }
        BYTE *der = (BYTE *)malloc(n ? n : 1);
        if (!der) {
            return CP_E_OUTOFMEMORY;
        }
        if (!CryptMsgGetParam(msg, CMSG_CERT_PARAM, i, der, &n)) {
            int32_t rc = cp_last_error();
            free(der);
            return rc;
        }
        *has = n == cert->cbCertEncoded &&
               memcmp(der, cert->pbCertEncoded, n) == 0;
        free(der);
    }
    return 0;
}

int32_t cp_cosign_cms(void *hCert, int32_t include, void *hChainStore,
                      cp_attr_list auth, cp_attr_list unauth,
                      const char *hash_oid, const unsigned char *sig,
                      size_t sig_len, int32_t detached,
                      const unsigned char *content, size_t content_len,
                      cp_buf *out)
{
    CP_CHECK_LEN(sig_len);
    CP_CHECK_LEN(content_len);
    if (!hCert || !sig) {
        return CP_E_INVALIDARG;
    }
    PCCERT_CONTEXT cert = (PCCERT_CONTEXT)hCert;

    cp_msg_certs mc;
    cp_crypt_attrs aauth, aunauth;
    int32_t rc = cp_msg_certs_build(cert, include, (HCERTSTORE)hChainStore, &mc);
    if (rc) {
        return rc;
    }
    rc = cp_attrs_build(auth, &aauth);
    if (rc) {
        cp_msg_certs_free(&mc);
        return rc;
    }
    rc = cp_attrs_build(unauth, &aunauth);
    if (rc) {
        cp_attrs_free(&aauth);
        cp_msg_certs_free(&mc);
        return rc;
    }

    HCRYPTPROV prov = 0;
    DWORD key_spec = 0;
    BOOL caller_free = FALSE;
    if (!CryptAcquireCertificatePrivateKey(
            cert, CRYPT_ACQUIRE_CACHE_FLAG | CRYPT_ACQUIRE_SILENT_FLAG, NULL,
            &prov, &key_spec, &caller_free)) {
        rc = cp_last_error();
        cp_attrs_free(&aauth);
        cp_attrs_free(&aunauth);
        cp_msg_certs_free(&mc);
        return rc;
    }

    HCRYPTMSG msg = CryptMsgOpenToDecode(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        detached ? CMSG_DETACHED_FLAG : 0, 0, 0, NULL, NULL);
    if (!msg) {
        rc = cp_last_error();
        goto out;
    }
    if (!CryptMsgUpdate(msg, sig, (DWORD)sig_len, TRUE)) {
        rc = cp_last_error();
        goto out;
    }
    /* A detached message hashes its content after the signature is read. */
    if (detached &&
        !CryptMsgUpdate(msg, content ? content : (const BYTE *)"",
                        (DWORD)content_len, TRUE)) {
        rc = cp_last_error();
        goto out;
    }

    CMSG_SIGNER_ENCODE_INFO si;
    memset(&si, 0, sizeof(si));
    si.cbSize = sizeof(si);
    si.pCertInfo = cert->pCertInfo;
    si.hCryptProv = prov;
    si.dwKeySpec = key_spec;
    si.HashAlgorithm.pszObjId =
        (LPSTR)((hash_oid && *hash_oid) ? hash_oid : CP_OID_GOST3411_2012_256);
    if (aauth.n) {
        si.cAuthAttr = aauth.n;
        si.rgAuthAttr = aauth.items;
    }
    if (aunauth.n) {
        si.cUnauthAttr = aunauth.n;
        si.rgUnauthAttr = aunauth.items;
    }
    if (!CryptMsgControl(msg, 0, CMSG_CTRL_ADD_SIGNER, &si)) {
        rc = cp_last_error();
        goto out;
    }

    /* Verifiers outside CryptoPro need the signer certificate in the CMS. */
    for (DWORD i = 0; i < mc.n; i++) {
        int has = 0;
        rc = cp_msg_has_cert(msg, mc.items[i], &has);
        if (rc != 0) {
            goto out;
        }
        if (!has) {
            CERT_BLOB blob;
            blob.cbData = mc.items[i]->cbCertEncoded;
            blob.pbData = mc.items[i]->pbCertEncoded;
            if (!CryptMsgControl(msg, 0, CMSG_CTRL_ADD_CERT, &blob)) {
                rc = cp_last_error();
                goto out;
            }
        }
    }

    DWORD n = 0;
    if (!CryptMsgGetParam(msg, CMSG_ENCODED_MESSAGE, 0, NULL, &n)) {
        rc = cp_last_error();
        goto out;
    }
    BYTE *buf = (BYTE *)malloc(n ? n : 1);
    if (!buf) {
        rc = CP_E_OUTOFMEMORY;
        goto out;
    }
    if (!CryptMsgGetParam(msg, CMSG_ENCODED_MESSAGE, 0, buf, &n)) {
        rc = cp_last_error();
    } else {
        rc = cp_copy(buf, n, out);
    }
    free(buf);

out:
    if (msg) {
        CryptMsgClose(msg);
    }
    if (caller_free) {
        CryptReleaseContext(prov, 0);
    }
    cp_attrs_free(&aauth);
    cp_attrs_free(&aunauth);
    cp_msg_certs_free(&mc);
    return rc;
}

/* ------------------------------------------------------------------ */
/* PIN change                                                          */
/* ------------------------------------------------------------------ */

/* Opens the key container of the certificate silently, without the provider
 * cached on the context: no PIN is set on the returned handle. */
static int32_t cp_open_cert_container(PCCERT_CONTEXT c, HCRYPTPROV *prov)
{
    *prov = 0;
    DWORD cb = 0;
    if (!CertGetCertificateContextProperty(c, CERT_KEY_PROV_INFO_PROP_ID, NULL,
                                          &cb)) {
        return cp_last_error();
    }
    CRYPT_KEY_PROV_INFO *kpi = (CRYPT_KEY_PROV_INFO *)malloc(cb ? cb : 1);
    if (!kpi) {
        return CP_E_OUTOFMEMORY;
    }
    int32_t rc = 0;
    if (!CertGetCertificateContextProperty(c, CERT_KEY_PROV_INFO_PROP_ID, kpi,
                                          &cb) ||
        !CryptAcquireContextW(prov, kpi->pwszContainerName, kpi->pwszProvName,
                              kpi->dwProvType, CRYPT_SILENT)) {
        rc = cp_last_error();
        *prov = 0;
    }
    free(kpi);
    return rc;
}

/* PP_PIN_INFO reports CRYPT_PIN_CLEAR for a container whose PIN is not
 * required or still the default one, as CPPCadesCPPrivateKeyObject::
 * get_IsDefaultPin checks. */
int32_t cp_cert_is_default_pin(void *hCert, int32_t *out)
{
    *out = 0;
    if (!hCert) {
        return CP_E_INVALIDARG;
    }
    HCRYPTPROV prov;
    int32_t rc = cp_open_cert_container((PCCERT_CONTEXT)hCert, &prov);
    if (rc) {
        return rc;
    }
    DWORD cb = 0;
    BYTE *info = NULL;
    if (!CryptGetProvParam(prov, PP_PIN_INFO, NULL, &cb, 0)) {
        rc = cp_last_error();
    } else if (cb == 0) {
        rc = CP_E_FAIL;
    } else if (!(info = (BYTE *)malloc(cb))) {
        rc = CP_E_OUTOFMEMORY;
    } else if (!CryptGetProvParam(prov, PP_PIN_INFO, info, &cb, 0)) {
        rc = cp_last_error();
    } else {
        /* CRYPT_PIN_INFO starts with its BYTE type. */
        *out = info[0] == CRYPT_PIN_CLEAR ? 1 : 0;
    }
    free(info);
    CryptReleaseContext(prov, 0);
    return rc;
}

int32_t cp_change_pin(void *hCert, int32_t key_spec, const char *old_pin,
                      const char *new_pin)
{
    if (!hCert) {
        return CP_E_INVALIDARG;
    }
    PCCERT_CONTEXT c = (PCCERT_CONTEXT)hCert;
    if (!c || !new_pin || !*new_pin) {
        return CP_E_INVALIDARG;
    }

    DWORD cb = 0;
    if (!CertGetCertificateContextProperty(c, CERT_KEY_PROV_INFO_PROP_ID, NULL,
                                          &cb)) {
        if (GetLastError() != ERROR_MORE_DATA) {
            return cp_last_error();
        }
    }
    if (cb == 0) {
        return CP_E_FAIL;
    }

    CRYPT_KEY_PROV_INFO *kpi = (CRYPT_KEY_PROV_INFO *)malloc(cb);
    if (!kpi) {
        return CP_E_OUTOFMEMORY;
    }
    if (!CertGetCertificateContextProperty(c, CERT_KEY_PROV_INFO_PROP_ID, kpi,
                                          &cb)) {
        int32_t rc = cp_last_error();
        free(kpi);
        return rc;
    }

    HCRYPTPROV prov = 0;
    if (!CryptAcquireContextW(&prov, kpi->pwszContainerName, kpi->pwszProvName,
                              kpi->dwProvType, CRYPT_SILENT)) {
        int32_t rc = cp_last_error();
        free(kpi);
        return rc;
    }

    /* AT_KEYEXCHANGE == 1, AT_SIGNATURE == 2. */
    DWORD pin_id = (key_spec == 1) ? PP_KEYEXCHANGE_PIN : PP_SIGNATURE_PIN;

    int32_t rc = 0;
    if (old_pin && *old_pin) {
        if (!CryptSetProvParam(prov, pin_id, (const BYTE *)old_pin, 0)) {
            rc = cp_last_error();
        }
    }
    if (rc == 0 &&
        !CryptSetProvParam(prov, PP_CHANGE_PASSWORD, (const BYTE *)new_pin, 0)) {
        rc = cp_last_error();
    }

    CryptReleaseContext(prov, 0);
    free(kpi);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Provider algorithm enumeration                                      */
/* ------------------------------------------------------------------ */

void cp_alg_list_free(cp_alg_list l)
{
    for (size_t i = 0; i < l.len; i++) {
        free(l.items[i].name);
        free(l.items[i].long_name);
    }
    free(l.items);
}

int32_t cp_provider_algorithms(cp_alg_list *out)
{
    out->items = NULL;
    out->len = 0;

    HCRYPTPROV prov = 0;
    if (!CryptAcquireContextW(&prov, NULL, NULL, PROV_RSA_FULL,
                              CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        return cp_last_error();
    }

    size_t cap = 16;
    size_t n = 0;
    cp_alg_info *items = (cp_alg_info *)calloc(cap, sizeof(cp_alg_info));
    if (!items) {
        CryptReleaseContext(prov, 0);
        return CP_E_OUTOFMEMORY;
    }

    DWORD flags = CRYPT_FIRST;
    for (;;) {
        PROV_ENUMALGS_EX info;
        DWORD cb = sizeof(info);
        if (!CryptGetProvParam(prov, PP_ENUMALGS_EX, (BYTE *)&info, &cb, flags)) {
            break;
        }
        flags = 0;

        if (n == cap) {
            size_t ncap = cap * 2;
            cp_alg_info *grown =
                (cp_alg_info *)realloc(items, ncap * sizeof(cp_alg_info));
            if (!grown) {
                for (size_t i = 0; i < n; i++) {
                    free(items[i].name);
                    free(items[i].long_name);
                }
                free(items);
                CryptReleaseContext(prov, 0);
                return CP_E_OUTOFMEMORY;
            }
            memset(grown + cap, 0, (ncap - cap) * sizeof(cp_alg_info));
            items = grown;
            cap = ncap;
        }

        /* The names are length-delimited and may not be NUL terminated. */
        DWORD nameLen = info.dwNameLen;
        if (nameLen > sizeof(info.szName)) {
            nameLen = sizeof(info.szName);
        }
        DWORD longLen = info.dwLongNameLen;
        if (longLen > sizeof(info.szLongName)) {
            longLen = sizeof(info.szLongName);
        }

        items[n].name = cp_strdup_n(info.szName, nameLen);
        items[n].long_name = cp_strdup_n(info.szLongName, longLen);
        items[n].alg_id = (uint32_t)info.aiAlgid;
        items[n].default_bits = info.dwDefaultLen;
        items[n].min_bits = info.dwMinLen;
        items[n].max_bits = info.dwMaxLen;
        items[n].protocols = info.dwProtocols;
        n++;
    }

    CryptReleaseContext(prov, 0);

    out->items = items;
    out->len = n;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Hashing                                                             */
/* ------------------------------------------------------------------ */

static ALG_ID cp_hash_calg(int32_t alg)
{
    switch (alg) {
    case 0:
        return CALG_SHA1;
    case 1:
        return CALG_MD2;
    case 2:
        return CALG_MD4;
    case 3:
        return CALG_MD5;
    case 4:
        return CALG_SHA_256;
    case 5:
        return CALG_SHA_384;
    case 6:
        return CALG_SHA_512;
    case 100:
        return CALG_GR3411;
    case 101:
        return CALG_GR3411_2012_256;
    case 102:
        return CALG_GR3411_2012_512;
    }
    /* HMAC (110..112) is computed in Go on top of the plain digests. */
    return 0;
}

int32_t cp_hash(int32_t alg, const unsigned char *data, size_t len,
                cp_buf *out)
{
    CP_CHECK_LEN(len);
    out->data = NULL;
    out->len = 0;

    ALG_ID calg = cp_hash_calg(alg);
    if (!calg) {
        return CP_E_INVALIDARG;
    }

    HCRYPTPROV prov = 0;
    if (!CryptAcquireContextW(&prov, NULL, NULL, PROV_RSA_FULL,
                              CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        return cp_last_error();
    }

    int32_t rc = 0;
    HCRYPTHASH hHash = 0;

    if (!CryptCreateHash(prov, calg, 0, 0, &hHash)) {
        rc = cp_last_error();
    }

    if (rc == 0 && len > 0) {
        if (!CryptHashData(hHash, data, (DWORD)len, 0)) {
            rc = cp_last_error();
        }
    }

    if (rc == 0) {
        DWORD cb = 0;
        if (!CryptGetHashParam(hHash, HP_HASHVAL, NULL, &cb, 0)) {
            rc = cp_last_error();
        } else {
            BYTE *buf = (BYTE *)malloc(cb ? cb : 1);
            if (!buf) {
                rc = CP_E_OUTOFMEMORY;
            } else {
                if (!CryptGetHashParam(hHash, HP_HASHVAL, buf, &cb, 0)) {
                    rc = cp_last_error();
                } else {
                    rc = cp_copy(buf, cb, out);
                }
                free(buf);
            }
        }
    }

    if (hHash) {
        CryptDestroyHash(hHash);
    }
    CryptReleaseContext(prov, 0);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Raw signature over a digest                                         */
/* ------------------------------------------------------------------ */

/* Acquires the key container of a certificate. The caller must release prov
 * and free kpi. */
static int32_t cp_cert_acquire(PCCERT_CONTEXT c, HCRYPTPROV *prov,
                               CRYPT_KEY_PROV_INFO **kpi_out)
{
    DWORD cb = 0;
    if (!CertGetCertificateContextProperty(c, CERT_KEY_PROV_INFO_PROP_ID, NULL,
                                          &cb)) {
        if (GetLastError() != ERROR_MORE_DATA) {
            return cp_last_error();
        }
    }
    if (cb == 0) {
        return CP_E_FAIL;
    }

    CRYPT_KEY_PROV_INFO *kpi = (CRYPT_KEY_PROV_INFO *)malloc(cb);
    if (!kpi) {
        return CP_E_OUTOFMEMORY;
    }
    if (!CertGetCertificateContextProperty(c, CERT_KEY_PROV_INFO_PROP_ID, kpi,
                                          &cb)) {
        int32_t rc = cp_last_error();
        free(kpi);
        return rc;
    }

    HCRYPTPROV p = 0;
    if (!CryptAcquireContextW(&p, kpi->pwszContainerName, kpi->pwszProvName,
                              kpi->dwProvType, CRYPT_SILENT)) {
        int32_t rc = cp_last_error();
        free(kpi);
        return rc;
    }

    *prov = p;
    *kpi_out = kpi;
    return 0;
}

/* cp_raw_hash_alg picks the digest algorithm that matches the certificate
 * key. HP_HASHVAL reads as many bytes as the algorithm's digest size, so a
 * digest of any other length is rejected rather than over-read or cut. */
static int32_t cp_raw_hash_alg(PCCERT_CONTEXT c, size_t hash_len, ALG_ID *alg)
{
    const char *oid = c->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId;
    size_t want;

    if (!oid) {
        return CP_NTE_BAD_ALGID;
    }
    if (strcmp(oid, szOID_CP_GOST_R3410_12_256) == 0) {
        *alg = CALG_GR3411_2012_256;
        want = 32;
    } else if (strcmp(oid, szOID_CP_GOST_R3410_12_512) == 0) {
        *alg = CALG_GR3411_2012_512;
        want = 64;
    } else if (strcmp(oid, szOID_CP_GOST_R3410EL) == 0) {
        *alg = CALG_GR3411;
        want = 32;
    } else {
        return CP_NTE_BAD_ALGID;
    }
    return hash_len == want ? 0 : CP_NTE_BAD_HASH;
}

int32_t cp_raw_sign_hash(void *hCert, const unsigned char *hash,
                         size_t hash_len, cp_buf *out)
{
    CP_CHECK_LEN(hash_len);
    PCCERT_CONTEXT c = (PCCERT_CONTEXT)hCert;
    if (!c || !c->pCertInfo || !hash) {
        return CP_E_INVALIDARG;
    }

    ALG_ID alg = 0;
    int32_t rc = cp_raw_hash_alg(c, hash_len, &alg);
    if (rc) {
        return rc;
    }

    /* CRYPT_ACQUIRE_CACHE_FLAG returns the provider attached by SetPIN, or
     * acquires one and caches it on the context. Either way the context owns
     * it, so it is never released here. */
    HCRYPTPROV prov = 0;
    DWORD key_spec = 0;
    BOOL caller_free = FALSE;
    if (!CryptAcquireCertificatePrivateKey(
            c, CRYPT_ACQUIRE_CACHE_FLAG | CRYPT_ACQUIRE_SILENT_FLAG, NULL,
            &prov, &key_spec, &caller_free)) {
        return cp_last_error();
    }

    HCRYPTHASH hHash = 0;
    if (!CryptCreateHash(prov, alg, 0, 0, &hHash)) {
        rc = cp_last_error();
    } else if (!CryptSetHashParam(hHash, HP_HASHVAL, hash, 0)) {
        rc = cp_last_error();
    } else {
        DWORD sigLen = 0;
        if (!CryptSignHash(hHash, key_spec, NULL, 0, NULL, &sigLen)) {
            rc = cp_last_error();
        } else {
            BYTE *sig = (BYTE *)malloc(sigLen ? sigLen : 1);
            if (!sig) {
                rc = CP_E_OUTOFMEMORY;
            } else {
                if (!CryptSignHash(hHash, key_spec, NULL, 0, sig, &sigLen)) {
                    rc = cp_last_error();
                } else {
                    rc = cp_copy(sig, sigLen, out);
                }
                free(sig);
            }
        }
    }

    if (hHash) {
        CryptDestroyHash(hHash);
    }
    if (caller_free) {
        CryptReleaseContext(prov, 0);
    }
    return rc;
}

int32_t cp_raw_verify_hash(void *hCert, const unsigned char *hash,
                           size_t hash_len, const unsigned char *sig,
                           size_t sig_len)
{
    CP_CHECK_LEN(hash_len);
    CP_CHECK_LEN(sig_len);
    PCCERT_CONTEXT c = (PCCERT_CONTEXT)hCert;
    if (!c || !c->pCertInfo || !hash || !sig || sig_len == 0) {
        return CP_E_INVALIDARG;
    }

    ALG_ID alg = 0;
    int32_t rc = cp_raw_hash_alg(c, hash_len, &alg);
    if (rc) {
        return rc;
    }

    HCRYPTPROV prov = 0;
    if (!CryptAcquireContextW(&prov, NULL, NULL, PROV_RSA_FULL,
                              CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        return cp_last_error();
    }

    HCRYPTKEY pub = 0;
    HCRYPTHASH hHash = 0;

    if (!CryptImportPublicKeyInfo(prov, X509_ASN_ENCODING,
                                  &c->pCertInfo->SubjectPublicKeyInfo, &pub)) {
        rc = cp_last_error();
    } else if (!CryptCreateHash(prov, alg, 0, 0, &hHash)) {
        rc = cp_last_error();
    } else if (!CryptSetHashParam(hHash, HP_HASHVAL, hash, 0)) {
        rc = cp_last_error();
    } else if (!CryptVerifySignature(hHash, sig, (DWORD)sig_len, pub, NULL, 0)) {
        rc = cp_last_error();
    }

    if (hHash) {
        CryptDestroyHash(hHash);
    }
    if (pub) {
        CryptDestroyKey(pub);
    }
    CryptReleaseContext(prov, 0);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Symmetric algorithm                                                 */
/* ------------------------------------------------------------------ */

typedef struct cp_sym_ctx {
    HCRYPTPROV prov;
    HCRYPTKEY key;
} cp_sym_ctx;

static ALG_ID cp_sym_calg(int32_t alg)
{
    switch (alg) {
    case 0:
        return CALG_RC2;
    case 1:
        return CALG_RC4;
    case 2:
        return CALG_DES;
    case 3:
        return CALG_3DES;
    case 4:
        return CALG_AES_256;
    case 25:
        return CALG_G28147;
    }
    return 0;
}

void *cp_sym_new(void)
{
    return calloc(1, sizeof(cp_sym_ctx));
}

void cp_sym_free(void *h)
{
    cp_sym_ctx *ctx = (cp_sym_ctx *)h;
    if (!ctx) {
        return;
    }
    if (ctx->key) {
        CryptDestroyKey(ctx->key);
    }
    if (ctx->prov) {
        CryptReleaseContext(ctx->prov, 0);
    }
    free(ctx);
}

static int32_t cp_sym_ensure_type(cp_sym_ctx *ctx, DWORD prov_type)
{
    if (ctx->prov) {
        return 0;
    }
    if (!CryptAcquireContextW(&ctx->prov, NULL, NULL, prov_type,
                              CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        return cp_last_error();
    }
    return 0;
}

static int32_t cp_sym_ensure(cp_sym_ctx *ctx)
{
    return cp_sym_ensure_type(ctx, PROV_RSA_FULL);
}

/* GOST session keys and DH key-wrap need a GOST CSP, not PROV_RSA_FULL. */
static DWORD cp_sym_prov_for_calg(ALG_ID calg)
{
    if (calg == CALG_G28147) {
        return PROV_GOST_2012_256;
    }
    return PROV_RSA_FULL;
}

static DWORD cp_sym_prov_for_gost_oid(const char *oid)
{
    if (oid && strcmp(oid, szOID_CP_GOST_R3410_12_512) == 0) {
        return PROV_GOST_2012_512;
    }
    if (oid && strcmp(oid, szOID_CP_GOST_R3410EL) == 0) {
        return PROV_GOST_2001_DH;
    }
    return PROV_GOST_2012_256;
}

int32_t cp_sym_generate(void *h, int32_t alg, uint32_t bits)
{
    if (!h) {
        return CP_E_INVALIDARG;
    }
    cp_sym_ctx *ctx = (cp_sym_ctx *)h;
    if (!ctx) {
        return CP_E_INVALIDARG;
    }

    ALG_ID calg = cp_sym_calg(alg);
    if (!calg) {
        return CP_E_INVALIDARG;
    }

    if (ctx->key) {
        CryptDestroyKey(ctx->key);
        ctx->key = 0;
    }
    /* Re-open when switching between RSA and GOST providers. */
    if (ctx->prov) {
        CryptReleaseContext(ctx->prov, 0);
        ctx->prov = 0;
    }

    int32_t rc = cp_sym_ensure_type(ctx, cp_sym_prov_for_calg(calg));
    if (rc) {
        return rc;
    }

    /* The key size is passed in the high word of dwFlags. */
    DWORD flags = CRYPT_EXPORTABLE;
    if (bits) {
        flags |= (bits & 0xFFFF) << 16;
    }

    if (!CryptGenKey(ctx->prov, calg, flags, &ctx->key)) {
        return cp_last_error();
    }
    return 0;
}

int32_t cp_sym_set_mode(void *h, uint32_t mode)
{
    if (!h) {
        return CP_E_INVALIDARG;
    }
    cp_sym_ctx *ctx = (cp_sym_ctx *)h;
    if (!ctx || !ctx->key) {
        return CP_E_FAIL;
    }

    DWORD m = (DWORD)mode;
    if (!CryptSetKeyParam(ctx->key, KP_MODE, (const BYTE *)&m, 0)) {
        return cp_last_error();
    }
    return 0;
}

int32_t cp_sym_set_padding(void *h, uint32_t padding)
{
    if (!h) {
        return CP_E_INVALIDARG;
    }
    cp_sym_ctx *ctx = (cp_sym_ctx *)h;
    if (!ctx || !ctx->key) {
        return CP_E_FAIL;
    }

    DWORD p = (DWORD)padding;
    if (!CryptSetKeyParam(ctx->key, KP_PADDING, (const BYTE *)&p, 0)) {
        return cp_last_error();
    }
    return 0;
}

int32_t cp_sym_get_iv(void *h, cp_buf *out)
{
    if (!h) {
        return CP_E_INVALIDARG;
    }
    out->data = NULL;
    out->len = 0;

    cp_sym_ctx *ctx = (cp_sym_ctx *)h;
    if (!ctx || !ctx->key) {
        return CP_E_FAIL;
    }

    DWORD cb = 0;
    if (!CryptGetKeyParam(ctx->key, KP_IV, NULL, &cb, 0)) {
        return cp_last_error();
    }

    BYTE *buf = (BYTE *)malloc(cb ? cb : 1);
    if (!buf) {
        return CP_E_OUTOFMEMORY;
    }

    int32_t rc;
    if (!CryptGetKeyParam(ctx->key, KP_IV, buf, &cb, 0)) {
        rc = cp_last_error();
    } else {
        rc = cp_copy(buf, cb, out);
    }
    free(buf);
    return rc;
}

int32_t cp_sym_set_iv(void *h, const unsigned char *iv, size_t len)
{
    CP_CHECK_LEN(len);
    if (!h) {
        return CP_E_INVALIDARG;
    }
    cp_sym_ctx *ctx = (cp_sym_ctx *)h;
    if (!ctx || !ctx->key || !iv || len == 0) {
        return CP_E_INVALIDARG;
    }

    if (!CryptSetKeyParam(ctx->key, KP_IV, iv, 0)) {
        return cp_last_error();
    }
    return 0;
}

int32_t cp_sym_encrypt(void *h, const unsigned char *data, size_t len,
                       cp_buf *out)
{
    CP_CHECK_LEN(len);
    if (!h) {
        return CP_E_INVALIDARG;
    }
    cp_sym_ctx *ctx = (cp_sym_ctx *)h;
    if (!ctx || !ctx->key) {
        return CP_E_FAIL;
    }

    DWORD cap = (DWORD)len + 32;
    BYTE *buf = (BYTE *)malloc(cap ? cap : 1);
    if (!buf) {
        return CP_E_OUTOFMEMORY;
    }
    if (len) {
        memcpy(buf, data, len);
    }

    DWORD outLen = (DWORD)len;
    if (!CryptEncrypt(ctx->key, 0, TRUE, 0, buf, &outLen, cap)) {
        int32_t rc = cp_last_error();
        free(buf);
        return rc;
    }

    int32_t rc = cp_copy(buf, outLen, out);
    free(buf);
    return rc;
}

int32_t cp_sym_decrypt(void *h, const unsigned char *data, size_t len,
                       cp_buf *out)
{
    CP_CHECK_LEN(len);
    if (!h) {
        return CP_E_INVALIDARG;
    }
    cp_sym_ctx *ctx = (cp_sym_ctx *)h;
    if (!ctx || !ctx->key) {
        return CP_E_FAIL;
    }

    DWORD cap = (DWORD)(len ? len : 1);
    BYTE *buf = (BYTE *)malloc(cap);
    if (!buf) {
        return CP_E_OUTOFMEMORY;
    }
    if (len) {
        memcpy(buf, data, len);
    }

    DWORD outLen = (DWORD)len;
    if (!CryptDecrypt(ctx->key, 0, TRUE, 0, buf, &outLen)) {
        int32_t rc = cp_last_error();
        free(buf);
        return rc;
    }

    int32_t rc = cp_copy(buf, outLen, out);
    free(buf);
    return rc;
}

/* Picks ephemeral DH alg, wrap alg and KP_OID for a GOST recipient key. */
static int32_t cp_gost_export_algs(const char *oid, ALG_ID *ephem,
                                   ALG_ID *wrap, const char **param_oid)
{
    if (!oid) {
        return CP_NTE_BAD_ALGID;
    }
    if (strcmp(oid, szOID_CP_GOST_R3410EL) == 0) {
        *ephem = CALG_DH_EL_EPHEM;
        *wrap = CALG_PRO_EXPORT;
        *param_oid = szOID_GostR3410_2001_CryptoPro_XchA_ParamSet;
        return 0;
    }
    if (strcmp(oid, szOID_CP_GOST_R3410_12_256) == 0) {
        *ephem = CALG_DH_GR3410_12_256_EPHEM;
        /* libcppcades default (LegacyPluginSymmetricExport=false) is
         * CALG_PRO_EXPORT, not PRO12. */
        *wrap = CALG_PRO_EXPORT;
        *param_oid = szOID_GostR3410_2001_CryptoPro_XchA_ParamSet;
        return 0;
    }
    if (strcmp(oid, szOID_CP_GOST_R3410_12_512) == 0) {
        *ephem = CALG_DH_GR3410_12_512_EPHEM;
        *wrap = CALG_PRO12_EXPORT;
        *param_oid = szOID_tc26_gost_3410_12_512_paramSetA;
        return 0;
    }
    return CP_NTE_BAD_ALGID;
}

static int32_t cp_export_blob(HCRYPTKEY key, HCRYPTKEY exp, DWORD blob_type,
                              BYTE **out, DWORD *out_len)
{
    DWORD cb = 0;
    if (!CryptExportKey(key, exp, blob_type, 0, NULL, &cb)) {
        return cp_last_error();
    }
    BYTE *buf = (BYTE *)malloc(cb ? cb : 1);
    if (!buf) {
        return CP_E_OUTOFMEMORY;
    }
    if (!CryptExportKey(key, exp, blob_type, 0, buf, &cb)) {
        int32_t rc = cp_last_error();
        free(buf);
        return rc;
    }
    *out = buf;
    *out_len = cb;
    return 0;
}

/* GOST session-key transport as in libcppcades: hex(IV):hex(PUBEX):hex(SIMPLE). */
static int32_t cp_sym_export_gost(cp_sym_ctx *ctx, PCCERT_CONTEXT c, cp_buf *out)
{
    const char *oid = c->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId;
    ALG_ID ephem_alg = 0, wrap_alg = 0;
    const char *param_oid = NULL;
    int32_t rc = cp_gost_export_algs(oid, &ephem_alg, &wrap_alg, &param_oid);
    if (rc) {
        return rc;
    }

    /* Ephemeral DH must live on a GOST CSP that matches the recipient. */
    DWORD want = cp_sym_prov_for_gost_oid(oid);
    HCRYPTKEY ephem = 0;
    if (!CryptGenKey(ctx->prov, ephem_alg, CRYPT_EXPORTABLE | CRYPT_PREGEN,
                     &ephem)) {
        DWORD e = GetLastError();
        if (e != (DWORD)NTE_BAD_TYPE && e != (DWORD)NTE_BAD_ALGID) {
            return cp_last_error();
        }
        /* Session key may sit on the wrong provider; rebuild on a GOST CSP. */
        BYTE *plain = NULL;
        DWORD plain_len = 0;
        rc = cp_export_blob(ctx->key, 0, PLAINTEXTKEYBLOB, &plain, &plain_len);
        if (rc) {
            return HRESULT_FROM_WIN32(e);
        }
        HCRYPTPROV gost = 0;
        if (!CryptAcquireContextW(&gost, NULL, NULL, want,
                                  CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
            free(plain);
            return cp_last_error();
        }
        HCRYPTKEY moved = 0;
        if (!CryptImportKey(gost, plain, plain_len, 0, CRYPT_EXPORTABLE,
                            &moved)) {
            rc = cp_last_error();
            free(plain);
            CryptReleaseContext(gost, 0);
            return rc;
        }
        free(plain);
        CryptDestroyKey(ctx->key);
        CryptReleaseContext(ctx->prov, 0);
        ctx->prov = gost;
        ctx->key = moved;
        if (!CryptGenKey(ctx->prov, ephem_alg, CRYPT_EXPORTABLE | CRYPT_PREGEN,
                         &ephem)) {
            return cp_last_error();
        }
    }
    /* libcppcades sets KP_DHOID (not KP_OID) before KP_X. */
    if (!CryptSetKeyParam(ephem, KP_DHOID, (BYTE *)(uintptr_t)param_oid, 0)) {
        rc = cp_last_error();
        CryptDestroyKey(ephem);
        return rc;
    }
    if (!CryptSetKeyParam(ephem, KP_X, NULL, 0)) {
        rc = cp_last_error();
        /* KP_X with NULL may return a positive Win32 code that is still OK. */
        if ((HRESULT)rc < 0) {
            CryptDestroyKey(ephem);
            return rc;
        }
        rc = 0;
    }

    BYTE *pubex = NULL;
    DWORD pubex_len = 0;
    rc = cp_export_blob(ephem, 0, PUBLICKEYBLOBEX, &pubex, &pubex_len);
    if (rc) {
        CryptDestroyKey(ephem);
        return rc;
    }

    HCRYPTKEY recip_pub = 0;
    if (!CryptImportPublicKeyInfo(ctx->prov, X509_ASN_ENCODING,
                                  &c->pCertInfo->SubjectPublicKeyInfo,
                                  &recip_pub)) {
        rc = cp_last_error();
        free(pubex);
        CryptDestroyKey(ephem);
        return rc;
    }

    BYTE *recip_blob = NULL;
    DWORD recip_len = 0;
    rc = cp_export_blob(recip_pub, 0, PUBLICKEYBLOB, &recip_blob, &recip_len);
    CryptDestroyKey(recip_pub);
    if (rc) {
        free(pubex);
        CryptDestroyKey(ephem);
        return rc;
    }

    HCRYPTKEY agree = 0;
    if (!CryptImportKey(ctx->prov, recip_blob, recip_len, ephem, 0, &agree)) {
        rc = cp_last_error();
        free(recip_blob);
        free(pubex);
        CryptDestroyKey(ephem);
        return rc;
    }
    free(recip_blob);

    if (!CryptSetKeyParam(agree, KP_ALGID, (BYTE *)&wrap_alg, 0)) {
        rc = cp_last_error();
        CryptDestroyKey(agree);
        free(pubex);
        CryptDestroyKey(ephem);
        return rc;
    }

    /* libcppcades reads param 0x68; headers call 0x6c KP_IV_BLOB. Prefer the
     * 8-byte IV blob over an OID string some builds return for 0x68. */
    DWORD iv_param = KP_IV_BLOB;
    DWORD iv_len = 0;
    if (!CryptGetKeyParam(agree, KP_IV_BLOB, NULL, &iv_len, 0) || iv_len == 0) {
        iv_param = 0x68;
        iv_len = 0;
        if (!CryptGetKeyParam(agree, iv_param, NULL, &iv_len, 0)) {
            rc = cp_last_error();
            CryptDestroyKey(agree);
            free(pubex);
            CryptDestroyKey(ephem);
            return rc;
        }
    }
    BYTE *iv = (BYTE *)malloc(iv_len ? iv_len : 1);
    if (!iv) {
        rc = CP_E_OUTOFMEMORY;
        CryptDestroyKey(agree);
        free(pubex);
        CryptDestroyKey(ephem);
        return rc;
    }
    if (!CryptGetKeyParam(agree, iv_param, iv, &iv_len, 0)) {
        rc = cp_last_error();
        free(iv);
        CryptDestroyKey(agree);
        free(pubex);
        CryptDestroyKey(ephem);
        return rc;
    }

    BYTE *simple = NULL;
    DWORD simple_len = 0;
    rc = cp_export_blob(ctx->key, agree, SIMPLEBLOB, &simple, &simple_len);
    CryptDestroyKey(agree);
    CryptDestroyKey(ephem);
    if (rc) {
        free(iv);
        free(pubex);
        return rc;
    }

    cp_buf hex_iv = {0}, hex_pub = {0}, hex_sim = {0};
    rc = cp_hex_upper(iv, iv_len, &hex_iv);
    if (!rc) {
        rc = cp_hex_upper(pubex, pubex_len, &hex_pub);
    }
    if (!rc) {
        rc = cp_hex_upper(simple, simple_len, &hex_sim);
    }
    free(iv);
    free(pubex);
    free(simple);
    if (rc) {
        cp_buf_free(hex_iv);
        cp_buf_free(hex_pub);
        cp_buf_free(hex_sim);
        return rc;
    }

    size_t total = hex_iv.len + 1 + hex_pub.len + 1 + hex_sim.len;
    unsigned char *joined = (unsigned char *)malloc(total ? total : 1);
    if (!joined) {
        cp_buf_free(hex_iv);
        cp_buf_free(hex_pub);
        cp_buf_free(hex_sim);
        return CP_E_OUTOFMEMORY;
    }
    size_t off = 0;
    memcpy(joined + off, hex_iv.data, hex_iv.len);
    off += hex_iv.len;
    joined[off++] = ':';
    memcpy(joined + off, hex_pub.data, hex_pub.len);
    off += hex_pub.len;
    joined[off++] = ':';
    memcpy(joined + off, hex_sim.data, hex_sim.len);
    cp_buf_free(hex_iv);
    cp_buf_free(hex_pub);
    cp_buf_free(hex_sim);
    rc = cp_copy(joined, total, out);
    free(joined);
    return rc;
}

static int cp_hex_nibble(int c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    return -1;
}

static int32_t cp_hex_decode(const char *s, size_t n, BYTE **out, DWORD *out_len)
{
    if (n % 2) {
        return CP_E_INVALIDARG;
    }
    DWORD len = (DWORD)(n / 2);
    BYTE *buf = (BYTE *)malloc(len ? len : 1);
    if (!buf) {
        return CP_E_OUTOFMEMORY;
    }
    for (size_t i = 0; i < len; i++) {
        int hi = cp_hex_nibble((unsigned char)s[i * 2]);
        int lo = cp_hex_nibble((unsigned char)s[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            free(buf);
            return CP_E_INVALIDARG;
        }
        buf[i] = (BYTE)((hi << 4) | lo);
    }
    *out = buf;
    *out_len = len;
    return 0;
}

static int32_t cp_sym_import_gost(cp_sym_ctx *ctx, PCCERT_CONTEXT c,
                                  const unsigned char *blob, size_t len)
{
    /* Split hex(IV):hex(PUBEX):hex(SIMPLE). */
    const char *s = (const char *)blob;
    const char *p1 = memchr(s, ':', len);
    if (!p1) {
        return CP_E_INVALIDARG;
    }
    const char *p2 = memchr(p1 + 1, ':', (size_t)(s + len - (p1 + 1)));
    if (!p2) {
        return CP_E_INVALIDARG;
    }
    BYTE *iv = NULL, *pubex = NULL, *simple = NULL;
    DWORD iv_len = 0, pubex_len = 0, simple_len = 0;
    int32_t rc = cp_hex_decode(s, (size_t)(p1 - s), &iv, &iv_len);
    if (!rc) {
        rc = cp_hex_decode(p1 + 1, (size_t)(p2 - (p1 + 1)), &pubex, &pubex_len);
    }
    if (!rc) {
        rc = cp_hex_decode(p2 + 1, (size_t)(s + len - (p2 + 1)), &simple,
                           &simple_len);
    }
    if (rc) {
        free(iv);
        free(pubex);
        free(simple);
        return rc;
    }

    HCRYPTPROV cert_prov = 0;
    DWORD key_spec = 0;
    BOOL caller_free = FALSE;
    if (!CryptAcquireCertificatePrivateKey(
            c, CRYPT_ACQUIRE_CACHE_FLAG | CRYPT_ACQUIRE_SILENT_FLAG, NULL,
            &cert_prov, &key_spec, &caller_free)) {
        rc = cp_last_error();
        free(iv);
        free(pubex);
        free(simple);
        return rc;
    }

    HCRYPTKEY user_key = 0;
    if (!CryptGetUserKey(cert_prov, key_spec, &user_key)) {
        rc = cp_last_error();
        if (caller_free) {
            CryptReleaseContext(cert_prov, 0);
        }
        free(iv);
        free(pubex);
        free(simple);
        return rc;
    }

    HCRYPTKEY ephem = 0;
    if (!CryptImportKey(cert_prov, pubex, pubex_len, user_key, 0, &ephem)) {
        rc = cp_last_error();
        CryptDestroyKey(user_key);
        if (caller_free) {
            CryptReleaseContext(cert_prov, 0);
        }
        free(iv);
        free(pubex);
        free(simple);
        return rc;
    }
    free(pubex);

    const char *oid = c->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId;
    ALG_ID ephem_alg = 0, wrap_alg = 0;
    const char *param_oid = NULL;
    rc = cp_gost_export_algs(oid, &ephem_alg, &wrap_alg, &param_oid);
    (void)ephem_alg;
    if (rc) {
        CryptDestroyKey(ephem);
        CryptDestroyKey(user_key);
        if (caller_free) {
            CryptReleaseContext(cert_prov, 0);
        }
        free(iv);
        free(simple);
        return rc;
    }
    if (!CryptSetKeyParam(ephem, KP_ALGID, (BYTE *)&wrap_alg, 0)) {
        rc = cp_last_error();
        CryptDestroyKey(ephem);
        CryptDestroyKey(user_key);
        if (caller_free) {
            CryptReleaseContext(cert_prov, 0);
        }
        free(iv);
        free(simple);
        return rc;
    }
    /* IV for PRO_EXPORT unwrap: KP_IV works on CSP 5.0; also try the raw
     * 0x68 id libcppcades uses and KP_IV_BLOB as CRYPT_DATA_BLOB. */
    CRYPT_DATA_BLOB iv_blob;
    iv_blob.pbData = iv;
    iv_blob.cbData = iv_len;
    if (!CryptSetKeyParam(ephem, KP_IV, iv, 0) &&
        !CryptSetKeyParam(ephem, 0x68, iv, 0) &&
        !CryptSetKeyParam(ephem, KP_IV_BLOB, (BYTE *)&iv_blob, 0)) {
        rc = cp_last_error();
        CryptDestroyKey(ephem);
        CryptDestroyKey(user_key);
        if (caller_free) {
            CryptReleaseContext(cert_prov, 0);
        }
        free(iv);
        free(simple);
        return rc;
    }
    free(iv);

    HCRYPTKEY session = 0;
    if (!CryptImportKey(cert_prov, simple, simple_len, ephem, CRYPT_EXPORTABLE,
                        &session)) {
        rc = cp_last_error();
        CryptDestroyKey(ephem);
        CryptDestroyKey(user_key);
        if (caller_free) {
            CryptReleaseContext(cert_prov, 0);
        }
        free(simple);
        return rc;
    }
    free(simple);
    CryptDestroyKey(ephem);
    CryptDestroyKey(user_key);

    /* The session key lives on the recipient provider; adopt that provider.
     * When caller_free is FALSE the provider is owned by CERT_KEY_CONTEXT —
     * take an extra ref so cp_sym_free does not drop the certificate's. */
    if (!caller_free) {
        if (!CryptContextAddRef(cert_prov, NULL, 0)) {
            rc = cp_last_error();
            CryptDestroyKey(session);
            return rc;
        }
    }
    if (ctx->key) {
        CryptDestroyKey(ctx->key);
        ctx->key = 0;
    }
    if (ctx->prov) {
        CryptReleaseContext(ctx->prov, 0);
        ctx->prov = 0;
    }
    ctx->prov = cert_prov;
    ctx->key = session;
    return 0;
}

int32_t cp_sym_export_key(void *h, void *hCert, cp_buf *out)
{
    if (!h || !hCert) {
        return CP_E_INVALIDARG;
    }
    out->data = NULL;
    out->len = 0;

    cp_sym_ctx *ctx = (cp_sym_ctx *)h;
    if (!ctx || !ctx->key) {
        return CP_E_FAIL;
    }

    int32_t rc = cp_sym_ensure(ctx);
    if (rc) {
        return rc;
    }

    PCCERT_CONTEXT c = (PCCERT_CONTEXT)hCert;
    if (!c || !c->pCertInfo) {
        return CP_E_INVALIDARG;
    }

    const char *oid = c->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId;
    if (oid && (strcmp(oid, szOID_CP_GOST_R3410EL) == 0 ||
                strcmp(oid, szOID_CP_GOST_R3410_12_256) == 0 ||
                strcmp(oid, szOID_CP_GOST_R3410_12_512) == 0)) {
        return cp_sym_export_gost(ctx, c, out);
    }

    HCRYPTKEY pub = 0;
    if (!CryptImportPublicKeyInfo(ctx->prov, X509_ASN_ENCODING,
                                  &c->pCertInfo->SubjectPublicKeyInfo, &pub)) {
        return cp_last_error();
    }

    DWORD cb = 0;
    if (!CryptExportKey(ctx->key, pub, SIMPLEBLOB, 0, NULL, &cb)) {
        rc = cp_last_error();
    } else {
        BYTE *buf = (BYTE *)malloc(cb ? cb : 1);
        if (!buf) {
            rc = CP_E_OUTOFMEMORY;
        } else {
            if (!CryptExportKey(ctx->key, pub, SIMPLEBLOB, 0, buf, &cb)) {
                rc = cp_last_error();
            } else {
                rc = cp_copy(buf, cb, out);
            }
            free(buf);
        }
    }

    CryptDestroyKey(pub);
    return rc;
}

int32_t cp_sym_import_key(void *h, void *hCert, const unsigned char *blob,
                          size_t len)
{
    CP_CHECK_LEN(len);
    if (!h || !hCert) {
        return CP_E_INVALIDARG;
    }
    cp_sym_ctx *ctx = (cp_sym_ctx *)h;
    if (!ctx || !blob || len == 0) {
        return CP_E_INVALIDARG;
    }

    PCCERT_CONTEXT c = (PCCERT_CONTEXT)hCert;
    if (!c) {
        return CP_E_INVALIDARG;
    }

    int32_t rc = cp_sym_ensure(ctx);
    if (rc) {
        return rc;
    }

    /* GOST transport from ExportKey is an ASCII "hex:hex:hex" string. */
    if (memchr(blob, ':', len) != NULL) {
        return cp_sym_import_gost(ctx, c, blob, len);
    }

    HCRYPTPROV cert_prov = 0;
    CRYPT_KEY_PROV_INFO *kpi = NULL;
    rc = cp_cert_acquire(c, &cert_prov, &kpi);
    if (rc) {
        return rc;
    }
    free(kpi);

    HCRYPTKEY key = 0;
    if (!CryptImportKey(cert_prov, blob, (DWORD)len, 0, 0, &key)) {
        rc = cp_last_error();
        CryptReleaseContext(cert_prov, 0);
        return rc;
    }

    /* cp_cert_acquire always returns a provider the caller must free. */
    if (ctx->key) {
        CryptDestroyKey(ctx->key);
        ctx->key = 0;
    }
    if (ctx->prov) {
        CryptReleaseContext(ctx->prov, 0);
        ctx->prov = 0;
    }
    ctx->prov = cert_prov;
    ctx->key = key;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Enveloped (CMS) data                                                */
/* ------------------------------------------------------------------ */

static const char *cp_content_oid(int32_t alg)
{
    switch (alg) {
    case 0:
        return "1.2.840.113549.3.2"; /* RC2-CBC */
    case 1:
        return "1.2.840.113549.3.4"; /* RC4 */
    case 2:
        return "1.3.14.3.2.7"; /* DES-CBC */
    case 3:
        return "1.2.840.113549.3.7"; /* 3DES-CBC */
    case 4:
        return "2.16.840.1.101.3.4.1.42"; /* AES-256-CBC */
    case 25:
        return "1.2.643.2.2.21"; /* GOST 28147-89 */
    }
    return NULL;
}

int32_t cp_envelope_encrypt(void **certs, size_t n, int32_t alg,
                            const unsigned char *data, size_t len,
                            cp_buf *out)
{
    CP_CHECK_LEN(len);
    out->data = NULL;
    out->len = 0;

    const char *oid = cp_content_oid(alg);
    if (!oid || !certs || n == 0) {
        return CP_E_INVALIDARG;
    }

    CRYPT_ENCRYPT_MESSAGE_PARA para;
    memset(&para, 0, sizeof(para));
    para.cbSize = sizeof(para);
    para.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    para.ContentEncryptionAlgorithm.pszObjId = (LPSTR)oid;

    PCCERT_CONTEXT *rgs = (PCCERT_CONTEXT *)malloc(n * sizeof(PCCERT_CONTEXT));
    if (!rgs) {
        return CP_E_OUTOFMEMORY;
    }
    for (size_t i = 0; i < n; i++) {
        rgs[i] = (PCCERT_CONTEXT)certs[i];
    }

    DWORD cb = 0;
    if (!CryptEncryptMessage(&para, (DWORD)n, rgs, data, (DWORD)len, NULL,
                             &cb)) {
        int32_t rc = cp_last_error();
        free(rgs);
        return rc;
    }

    BYTE *buf = (BYTE *)malloc(cb ? cb : 1);
    if (!buf) {
        free(rgs);
        return CP_E_OUTOFMEMORY;
    }

    int32_t rc;
    if (!CryptEncryptMessage(&para, (DWORD)n, rgs, data, (DWORD)len, buf, &cb)) {
        rc = cp_last_error();
    } else {
        rc = cp_copy(buf, cb, out);
    }

    free(buf);
    free(rgs);
    return rc;
}

int32_t cp_envelope_decrypt(void *hStore, const unsigned char *data,
                            size_t len, cp_buf *out)
{
    CP_CHECK_LEN(len);
    out->data = NULL;
    out->len = 0;

    if (!hStore || !data || len == 0) {
        return CP_E_INVALIDARG;
    }

    HCERTSTORE h = (HCERTSTORE)hStore;

    CRYPT_DECRYPT_MESSAGE_PARA para;
    memset(&para, 0, sizeof(para));
    para.cbSize = sizeof(para);
    para.dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    para.cCertStore = 1;
    para.rghCertStore = &h;

    DWORD cb = 0;
    if (!CryptDecryptMessage(&para, data, (DWORD)len, NULL, &cb, NULL)) {
        return cp_last_error();
    }

    BYTE *buf = (BYTE *)malloc(cb ? cb : 1);
    if (!buf) {
        return CP_E_OUTOFMEMORY;
    }

    int32_t rc;
    if (!CryptDecryptMessage(&para, data, (DWORD)len, buf, &cb, NULL)) {
        rc = cp_last_error();
    } else {
        rc = cp_copy(buf, cb, out);
    }

    free(buf);
    return rc;
}

/* ------------------------------------------------------------------ */
/* XMLDSig / XAdES                                                     */
/* ------------------------------------------------------------------ */

int32_t cp_xades_sign(void *hCert, int32_t xades_type, const char *digest_method,
                      const char *signature_method, const char *tsa_url,
                      const char *xpath, const unsigned char *data,
                      size_t len, int32_t detached, cp_buf *out)
{
    CP_CHECK_LEN(len);
    if (!hCert) {
        return CP_E_INVALIDARG;
    }
    XADES_SIGN_PARA xp;
    memset(&xp, 0, sizeof(xp));
    xp.dwSize = sizeof(xp);
    xp.dwSignatureType = (DWORD)xades_type;
    xp.pSignerCert = (PCCERT_CONTEXT)hCert;
    if (digest_method && *digest_method) {
        xp.szDigestMethod = digest_method;
    }
    if (signature_method && *signature_method) {
        xp.szSignatureMethod = signature_method;
    }

    XADES_SIGN_MESSAGE_PARA smp;
    memset(&smp, 0, sizeof(smp));
    smp.dwSize = sizeof(smp);
    smp.pXadesSignPara = &xp;

    CADES_SERVICE_CONNECTION_PARA tsa;
    wchar_t *wtsa = NULL;
    memset(&tsa, 0, sizeof(tsa));
    if (tsa_url && *tsa_url) {
        wtsa = cp_ascii_to_wide(tsa_url);
        if (!wtsa) {
            return CP_E_OUTOFMEMORY;
        }
        tsa.dwSize = sizeof(tsa);
        tsa.wszUri = wtsa;
        xp.pTspConnectionPara = &tsa;
    }

    /* No XPath is NULL ("sign the whole document"), not an empty expression. */
    CRYPT_DATA_BLOB *blob = NULL;
    BOOL ok = XadesSign(&smp, (xpath && *xpath) ? xpath : NULL,
                        detached ? TRUE : FALSE, data, (DWORD)len, &blob);

    int32_t rc;
    if (!ok) {
        rc = cp_last_error();
    } else if (!blob) {
        rc = CP_E_FAIL;
    } else {
        rc = cp_copy(blob->pbData, blob->cbData, out);
        XadesFreeBlob(blob);
    }

    free(wtsa);
    return rc;
}

void cp_xades_info_array_free(cp_xades_info_array a)
{
    for (size_t i = 0; i < a.len; i++) {
        if (a.items[i].signer_cert) {
            CertFreeCertificateContext((PCCERT_CONTEXT)a.items[i].signer_cert);
        }
    }
    free(a.items);
}

int32_t cp_xades_verify(void *hStore, const char *xpath,
                        const unsigned char *data, size_t len,
                        cp_xades_info_array *out)
{
    CP_CHECK_LEN(len);
    out->items = NULL;
    out->len = 0;

    XADES_VERIFICATION_PARA vp;
    memset(&vp, 0, sizeof(vp));
    vp.dwSize = sizeof(vp);
    vp.hStore = (HCERTSTORE)hStore;
    vp.bIsDetached = FALSE;

    XADES_VERIFY_MESSAGE_PARA vmp;
    memset(&vmp, 0, sizeof(vmp));
    vmp.dwSize = sizeof(vmp);
    vmp.pXadesVerifyPara = &vp;

    /* As with CAdES, an invalid signature fails the call but still yields
     * the per-signature info, which is returned together with the error. */
    XADES_VERIFICATION_INFO_ARRAY *arr = NULL;
    BOOL ok = XadesVerify(&vmp, (xpath && *xpath) ? xpath : NULL, data,
                          (DWORD)len, &arr);
    int32_t rc = ok ? 0 : cp_last_error();
    if (!arr) {
        return rc ? rc : CP_E_FAIL;
    }

    size_t n = (size_t)arr->cbCount;
    cp_xades_info *items = NULL;

    if (n) {
        items = (cp_xades_info *)calloc(n, sizeof(cp_xades_info));
        if (!items) {
            XadesFreeVerificationInfoArray(arr);
            return CP_E_OUTOFMEMORY;
        }

        for (size_t i = 0; i < n; i++) {
            XADES_VERIFICATION_INFO *vi = &arr->pXadesVerificationInfo[i];

            items[i].status = (int32_t)vi->dwStatus;
            items[i].xades_type = (int32_t)vi->dwVerifiedXadesType;
            items[i].signer_cert = NULL;

            if (vi->pSignerCert) {
                PCCERT_CONTEXT dup =
                    CertDuplicateCertificateContext(vi->pSignerCert);
                if (dup) {
                    items[i].signer_cert = (void *)dup;
                }
            }

            cp_filetime_to_unix(vi->pSigningTime, &items[i].signing_time);
            cp_filetime_to_unix(vi->pSignatureTimeStampTime,
                                &items[i].signature_ts_time);
            cp_filetime_to_unix(vi->pSigAndRefsTimeStampTime,
                                &items[i].sig_and_refs_ts_time);
        }
    }

    XadesFreeVerificationInfoArray(arr);

    out->items = items;
    out->len = n;
    return rc;
}

/* ------------------------------------------------------------------ */
/* Enroll: CSP containers and keys                                     */
/* ------------------------------------------------------------------ */

static char *cp_strdup(const char *s)
{
    if (!s) {
        return NULL;
    }
    return cp_strdup_n(s, strlen(s));
}

static void cp_enroll_container_clear(cp_enroll_container *c)
{
    if (!c) {
        return;
    }
    free(c->fqcn);
    free(c->unique_name);
    free(c->name);
    free(c->media);
    free(c->reader);
    memset(c, 0, sizeof(*c));
}

void cp_enroll_container_list_free(cp_enroll_container_list l)
{
    for (size_t i = 0; i < l.len; i++) {
        cp_enroll_container_clear(&l.items[i]);
    }
    free(l.items);
}

static void cp_enroll_key_clear(cp_enroll_key *k)
{
    if (!k) {
        return;
    }
    free(k->kp_fp);
    free(k->pubkey_oid);
    free(k->pubkey_key.data);
    free(k->pubkey_params.data);
    if (k->certificate) {
        CertFreeCertificateContext((PCCERT_CONTEXT)k->certificate);
    }
    memset(k, 0, sizeof(*k));
}

void cp_enroll_key_list_free(cp_enroll_key_list l)
{
    for (size_t i = 0; i < l.len; i++) {
        cp_enroll_key_clear(&l.items[i]);
    }
    free(l.items);
}

/* FQCN form \\.\READER\NAME → reader, media(=reader), name. */
static void cp_parse_fqcn(const char *fqcn, char **name, char **media,
                          char **reader)
{
    *name = NULL;
    *media = NULL;
    *reader = NULL;
    if (!fqcn || !*fqcn) {
        return;
    }
    if (fqcn[0] == '\\' && fqcn[1] == '\\' && fqcn[2] == '.' &&
        fqcn[3] == '\\') {
        const char *rstart = fqcn + 4;
        const char *slash = strrchr(rstart, '\\');
        if (slash && slash > rstart) {
            *reader = cp_strdup_n(rstart, (size_t)(slash - rstart));
            *media = cp_strdup(*reader);
            *name = cp_strdup(slash + 1);
            return;
        }
    }
    *name = cp_strdup(fqcn);
}

static int32_t cp_enroll_acquire(const char *container, const char *prov_name,
                                 uint32_t prov_type, DWORD flags,
                                 HCRYPTPROV *prov)
{
    *prov = 0;
    if (!CryptAcquireContextA(prov, (container && *container) ? container : NULL,
                              (prov_name && *prov_name) ? prov_name : NULL,
                              (DWORD)prov_type, flags)) {
        return cp_last_error();
    }
    return 0;
}

static int32_t cp_enroll_prov_param_str(HCRYPTPROV prov, DWORD param,
                                        char **out)
{
    *out = NULL;
    DWORD cb = 0;
    if (!CryptGetProvParam(prov, param, NULL, &cb, 0)) {
        DWORD e = GetLastError();
        if (e == ERROR_MORE_DATA) {
            /* some providers set cb and still return FALSE */
        } else if (cb == 0) {
            return cp_last_error();
        }
    }
    if (cb == 0) {
        return 0;
    }
    char *buf = (char *)calloc(1, (size_t)cb + 1);
    if (!buf) {
        return CP_E_OUTOFMEMORY;
    }
    if (!CryptGetProvParam(prov, param, (BYTE *)buf, &cb, 0)) {
        free(buf);
        return cp_last_error();
    }
    buf[cb ? cb - 1 : 0] = 0; /* ensure NUL if provider counted it */
    /* Prefer strlen in case cb included trailing junk. */
    *out = cp_strdup(buf);
    free(buf);
    return *out ? 0 : CP_E_OUTOFMEMORY;
}

int32_t cp_enroll_resolve_prov(const char *name, uint32_t *prov_type)
{
    if (!name || !*name || !prov_type) {
        return CP_E_INVALIDARG;
    }
    *prov_type = 0;
    DWORD idx = 0;
    for (;;) {
        DWORD type = 0;
        DWORD cb = 0;
        if (!CryptEnumProvidersA(idx, NULL, 0, &type, NULL, &cb)) {
            DWORD e = GetLastError();
            if (e == ERROR_NO_MORE_ITEMS || e == ERROR_MORE_DATA) {
                if (e == ERROR_NO_MORE_ITEMS && cb == 0) {
                    break;
                }
            } else if (cb == 0) {
                return cp_last_error();
            }
        }
        if (cb == 0) {
            break;
        }
        char *buf = (char *)malloc(cb ? cb : 1);
        if (!buf) {
            return CP_E_OUTOFMEMORY;
        }
        if (!CryptEnumProvidersA(idx, NULL, 0, &type, buf, &cb)) {
            free(buf);
            return cp_last_error();
        }
        if (strcmp(buf, name) == 0) {
            free(buf);
            *prov_type = (uint32_t)type;
            return 0;
        }
        free(buf);
        idx++;
    }
    return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
}

static int32_t cp_enroll_fill_info(HCRYPTPROV prov, const char *opened_as,
                                   cp_enroll_container *out)
{
    memset(out, 0, sizeof(*out));
    char *fqcn = NULL;
    char *unique = NULL;
    int32_t rc = cp_enroll_prov_param_str(prov, PP_FQCN, &fqcn);
    if (rc) {
        /* PP_FQCN may be missing on non-GOST; fall back to the open name. */
        fqcn = cp_strdup(opened_as);
        rc = 0;
    }
    (void)cp_enroll_prov_param_str(prov, PP_UNIQUE_CONTAINER, &unique);
    out->fqcn = fqcn;
    out->unique_name = unique;
    cp_parse_fqcn(fqcn ? fqcn : opened_as, &out->name, &out->media, &out->reader);
    return 0;
}

int32_t cp_enroll_container_info(const char *container, const char *prov_name,
                                 uint32_t prov_type, int32_t silent,
                                 cp_enroll_container *out)
{
    if (!container || !*container || !out) {
        return CP_E_INVALIDARG;
    }
    memset(out, 0, sizeof(*out));
    DWORD flags = silent ? CRYPT_SILENT : 0;
    HCRYPTPROV prov = 0;
    int32_t rc = cp_enroll_acquire(container, prov_name, prov_type, flags, &prov);
    if (rc) {
        return rc;
    }
    rc = cp_enroll_fill_info(prov, container, out);
    CryptReleaseContext(prov, 0);
    return rc;
}

int32_t cp_enroll_enum_containers(const char *prov_name, uint32_t prov_type,
                                  cp_enroll_container_list *out)
{
    if (!out) {
        return CP_E_INVALIDARG;
    }
    out->items = NULL;
    out->len = 0;

    HCRYPTPROV prov = 0;
    int32_t rc = cp_enroll_acquire(NULL, prov_name, prov_type,
                                   CRYPT_VERIFYCONTEXT | CRYPT_SILENT, &prov);
    if (rc) {
        return rc;
    }

    DWORD flags = 0;
    if (prov_type == PROV_GOST_2001_DH || prov_type == PROV_GOST_2012_256 ||
        prov_type == PROV_GOST_2012_512) {
        flags = CRYPT_FQCN;
    }

    size_t cap = 0;
    size_t n = 0;
    cp_enroll_container *items = NULL;
    DWORD first = CRYPT_FIRST;
    for (;;) {
        DWORD cb = 0;
        if (!CryptGetProvParam(prov, PP_ENUMCONTAINERS, NULL, &cb, first | flags)) {
            DWORD e = GetLastError();
            if (e == ERROR_NO_MORE_ITEMS) {
                break;
            }
            if (e != ERROR_MORE_DATA && cb == 0) {
                rc = cp_last_error();
                break;
            }
        }
        if (cb == 0) {
            break;
        }
        char *name = (char *)calloc(1, (size_t)cb + 1);
        if (!name) {
            rc = CP_E_OUTOFMEMORY;
            break;
        }
        if (!CryptGetProvParam(prov, PP_ENUMCONTAINERS, (BYTE *)name, &cb,
                               first | flags)) {
            DWORD e = GetLastError();
            free(name);
            if (e == ERROR_NO_MORE_ITEMS) {
                break;
            }
            rc = cp_last_error();
            break;
        }
        first = 0;

        if (n == cap) {
            size_t ncap = cap ? cap * 2 : 8;
            cp_enroll_container *ni =
                (cp_enroll_container *)realloc(items, ncap * sizeof(*ni));
            if (!ni) {
                free(name);
                rc = CP_E_OUTOFMEMORY;
                break;
            }
            items = ni;
            cap = ncap;
        }
        memset(&items[n], 0, sizeof(items[n]));

        /* Open the container for UniqueName; keep FQCN even if open fails. */
        HCRYPTPROV cprov = 0;
        if (cp_enroll_acquire(name, prov_name, prov_type, CRYPT_SILENT, &cprov) ==
            0) {
            rc = cp_enroll_fill_info(cprov, name, &items[n]);
            CryptReleaseContext(cprov, 0);
            if (rc) {
                free(name);
                break;
            }
            free(name);
        } else {
            items[n].fqcn = name;
            cp_parse_fqcn(name, &items[n].name, &items[n].media,
                          &items[n].reader);
        }
        n++;
        rc = 0;
    }

    CryptReleaseContext(prov, 0);
    if (rc) {
        cp_enroll_container_list_free(
            (cp_enroll_container_list){.items = items, .len = n});
        return rc;
    }
    out->items = items;
    out->len = n;
    return 0;
}

int32_t cp_enroll_container_delete(const char *container, const char *prov_name,
                                   uint32_t prov_type, int32_t silent)
{
    if (!container || !*container) {
        return CP_E_INVALIDARG;
    }
    DWORD flags = CRYPT_DELETEKEYSET | (silent ? CRYPT_SILENT : 0);
    HCRYPTPROV prov = 0;
    if (!CryptAcquireContextA(&prov, container,
                              (prov_name && *prov_name) ? prov_name : NULL,
                              (DWORD)prov_type, flags)) {
        return cp_last_error();
    }
    /* CRYPT_DELETEKEYSET does not return a usable context. */
    return 0;
}

static int32_t cp_enroll_fill_pubkey(HCRYPTPROV prov, DWORD key_spec,
                                     cp_enroll_key *out)
{
    DWORD cb = 0;
    if (!CryptExportPublicKeyInfo(prov, key_spec, X509_ASN_ENCODING, NULL,
                                  &cb)) {
        return 0; /* optional */
    }
    CERT_PUBLIC_KEY_INFO *info = (CERT_PUBLIC_KEY_INFO *)malloc(cb ? cb : 1);
    if (!info) {
        return CP_E_OUTOFMEMORY;
    }
    if (!CryptExportPublicKeyInfo(prov, key_spec, X509_ASN_ENCODING, info,
                                  &cb)) {
        free(info);
        return 0;
    }
    int32_t rc = cp_copy(info->PublicKey.pbData, info->PublicKey.cbData,
                         &out->pubkey_key);
    if (!rc) {
        rc = cp_copy(info->Algorithm.Parameters.pbData,
                     info->Algorithm.Parameters.cbData, &out->pubkey_params);
    }
    if (!rc) {
        const char *oid =
            info->Algorithm.pszObjId ? info->Algorithm.pszObjId : "";
        out->pubkey_oid = cp_strdup(oid);
        if (!out->pubkey_oid) {
            rc = CP_E_OUTOFMEMORY;
        }
    }
    if (!rc) {
        out->pubkey_bits = (int32_t)(info->PublicKey.cbData * 8) -
                           (int32_t)info->PublicKey.cUnusedBits;
    }
    free(info);
    return rc;
}

static int32_t cp_enroll_fill_key(HCRYPTPROV prov, HCRYPTKEY key, DWORD key_spec,
                                  cp_enroll_key *out)
{
    memset(out, 0, sizeof(*out));
    out->type = (uint32_t)key_spec;

    DWORD perms = 0;
    DWORD cb = sizeof(perms);
    if (CryptGetKeyParam(key, KP_PERMISSIONS, (BYTE *)&perms, &cb, 0)) {
        out->is_exportable = (perms & CRYPT_EXPORT) ? 1 : 0;
    }

    ALG_ID alg = 0;
    cb = sizeof(alg);
    if (CryptGetKeyParam(key, KP_ALGID, (BYTE *)&alg, &cb, 0)) {
        out->kp_algid = (uint32_t)alg;
    }

    FILETIME ft;
    cb = sizeof(ft);
    if (CryptGetKeyParam(key, KP_NOTAFTER, (BYTE *)&ft, &cb, 0)) {
        cp_filetime_to_unix(&ft, &out->expiration);
    }

    cb = 0;
    if (CryptGetKeyParam(key, KP_FP, NULL, &cb, 0) || cb > 0) {
        if (cb > 0) {
            char *fp = (char *)calloc(1, (size_t)cb + 1);
            if (!fp) {
                return CP_E_OUTOFMEMORY;
            }
            if (CryptGetKeyParam(key, KP_FP, (BYTE *)fp, &cb, 0)) {
                out->kp_fp = cp_strdup(fp);
            }
            free(fp);
        }
    }

    cb = 0;
    if (CryptGetKeyParam(key, KP_CERTIFICATE, NULL, &cb, 0) ||
        GetLastError() == ERROR_MORE_DATA) {
        if (cb > 0) {
            BYTE *der = (BYTE *)malloc(cb);
            if (!der) {
                return CP_E_OUTOFMEMORY;
            }
            if (CryptGetKeyParam(key, KP_CERTIFICATE, der, &cb, 0)) {
                PCCERT_CONTEXT c =
                    CertCreateCertificateContext(X509_ASN_ENCODING, der, cb);
                if (c) {
                    out->certificate = (void *)c;
                    out->has_certificate = 1;
                }
            }
            free(der);
        }
    }

    if (out->has_certificate) {
        char *oid = NULL;
        int32_t bits = 0;
        int32_t rc = cp_cert_public_key(out->certificate, &out->pubkey_key,
                                        &out->pubkey_params, &oid, &bits);
        if (rc) {
            return rc;
        }
        out->pubkey_oid = oid;
        out->pubkey_bits = bits;
    } else {
        int32_t rc = cp_enroll_fill_pubkey(prov, key_spec, out);
        if (rc) {
            return rc;
        }
    }
    return 0;
}

int32_t cp_enroll_container_keys(const char *container, const char *prov_name,
                                 uint32_t prov_type, int32_t silent,
                                 cp_enroll_key_list *out)
{
    if (!container || !*container || !out) {
        return CP_E_INVALIDARG;
    }
    out->items = NULL;
    out->len = 0;

    DWORD flags = silent ? CRYPT_SILENT : 0;
    HCRYPTPROV prov = 0;
    int32_t rc = cp_enroll_acquire(container, prov_name, prov_type, flags, &prov);
    if (rc) {
        return rc;
    }

    static const DWORD specs[2] = {AT_KEYEXCHANGE, AT_SIGNATURE};
    cp_enroll_key tmp[2];
    size_t n = 0;
    memset(tmp, 0, sizeof(tmp));

    for (size_t i = 0; i < 2; i++) {
        HCRYPTKEY key = 0;
        if (!CryptGetUserKey(prov, specs[i], &key)) {
            continue;
        }
        rc = cp_enroll_fill_key(prov, key, specs[i], &tmp[n]);
        CryptDestroyKey(key);
        if (rc) {
            for (size_t j = 0; j < n; j++) {
                cp_enroll_key_clear(&tmp[j]);
            }
            CryptReleaseContext(prov, 0);
            return rc;
        }
        n++;
    }
    CryptReleaseContext(prov, 0);

    if (n == 0) {
        return 0;
    }
    cp_enroll_key *items = (cp_enroll_key *)malloc(n * sizeof(*items));
    if (!items) {
        for (size_t j = 0; j < n; j++) {
            cp_enroll_key_clear(&tmp[j]);
        }
        return CP_E_OUTOFMEMORY;
    }
    memcpy(items, tmp, n * sizeof(*items));
    out->items = items;
    out->len = n;
    return 0;
}

/* ------------------------------------------------------------------ */
/* CX509Enrollment: PKCS#10 request                                    */
/* ------------------------------------------------------------------ */

#ifndef szOID_CP_GOST_R3411_12_256_R3410
#define szOID_CP_GOST_R3411_12_256_R3410 "1.2.643.7.1.1.3.2"
#endif
#ifndef szOID_CP_GOST_R3411_12_512_R3410
#define szOID_CP_GOST_R3411_12_512_R3410 "1.2.643.7.1.1.3.3"
#endif
#ifndef szOID_CP_GOST_R3411_R3410EL
#define szOID_CP_GOST_R3411_R3410EL "1.2.643.2.2.3"
#endif

static const char *cp_enroll_default_sign_oid(uint32_t prov_type)
{
    if (prov_type == PROV_GOST_2012_512) {
        return szOID_CP_GOST_R3411_12_512_R3410;
    }
    if (prov_type == PROV_GOST_2001_DH) {
        return szOID_CP_GOST_R3411_R3410EL;
    }
    return szOID_CP_GOST_R3411_12_256_R3410;
}

static int32_t cp_enroll_set_pin(HCRYPTPROV prov, uint32_t key_spec,
                                 const char *pin)
{
    if (!pin || !*pin) {
        return 0;
    }
    DWORD pin_id = (key_spec == AT_KEYEXCHANGE) ? PP_KEYEXCHANGE_PIN
                                                 : PP_SIGNATURE_PIN;
    if (!CryptSetProvParam(prov, pin_id, (const BYTE *)pin, 0)) {
        return cp_last_error();
    }
    /* GOST containers often accept either PIN id; set the other too. */
    DWORD other = (pin_id == PP_SIGNATURE_PIN) ? PP_KEYEXCHANGE_PIN
                                               : PP_SIGNATURE_PIN;
    CryptSetProvParam(prov, other, (const BYTE *)pin, 0);
    return 0;
}

static int32_t cp_enroll_encode_name(const char *subject, CERT_NAME_BLOB *out)
{
    memset(out, 0, sizeof(*out));
    DWORD cb = 0;
    if (!CertStrToNameA(X509_ASN_ENCODING, subject, CERT_X500_NAME_STR, NULL,
                        NULL, &cb, NULL)) {
        return cp_last_error();
    }
    BYTE *buf = (BYTE *)malloc(cb ? cb : 1);
    if (!buf) {
        return CP_E_OUTOFMEMORY;
    }
    if (!CertStrToNameA(X509_ASN_ENCODING, subject, CERT_X500_NAME_STR, NULL,
                        buf, &cb, NULL)) {
        free(buf);
        return cp_last_error();
    }
    out->pbData = buf;
    out->cbData = cb;
    return 0;
}

static int32_t cp_enroll_encode_key_usage_attr(uint32_t key_usage,
                                               CRYPT_ATTR_BLOB *out_blob,
                                               BYTE **owned)
{
    *owned = NULL;
    memset(out_blob, 0, sizeof(*out_blob));
    if (key_usage == 0) {
        return 0;
    }

    BYTE bits[2];
    bits[0] = (BYTE)(key_usage & 0xFF);
    bits[1] = (BYTE)((key_usage >> 8) & 0xFF);
    CRYPT_BIT_BLOB ku;
    memset(&ku, 0, sizeof(ku));
    ku.pbData = bits;
    ku.cbData = bits[1] ? 2 : 1;
    ku.cUnusedBits = 0;

    DWORD cbKU = 0;
    if (!CryptEncodeObject(X509_ASN_ENCODING, X509_KEY_USAGE, &ku, NULL,
                           &cbKU)) {
        return cp_last_error();
    }
    BYTE *encKU = (BYTE *)malloc(cbKU ? cbKU : 1);
    if (!encKU) {
        return CP_E_OUTOFMEMORY;
    }
    if (!CryptEncodeObject(X509_ASN_ENCODING, X509_KEY_USAGE, &ku, encKU,
                           &cbKU)) {
        free(encKU);
        return cp_last_error();
    }

    CERT_EXTENSION ext;
    memset(&ext, 0, sizeof(ext));
    ext.pszObjId = (char *)szOID_KEY_USAGE;
    ext.fCritical = TRUE;
    ext.Value.pbData = encKU;
    ext.Value.cbData = cbKU;

    CERT_EXTENSIONS exts;
    memset(&exts, 0, sizeof(exts));
    exts.cExtension = 1;
    exts.rgExtension = &ext;

    DWORD cb = 0;
    if (!CryptEncodeObject(X509_ASN_ENCODING, X509_EXTENSIONS, &exts, NULL,
                           &cb)) {
        free(encKU);
        return cp_last_error();
    }
    BYTE *enc = (BYTE *)malloc(cb ? cb : 1);
    if (!enc) {
        free(encKU);
        return CP_E_OUTOFMEMORY;
    }
    if (!CryptEncodeObject(X509_ASN_ENCODING, X509_EXTENSIONS, &exts, enc,
                           &cb)) {
        free(enc);
        free(encKU);
        return cp_last_error();
    }
    free(encKU);
    *owned = enc;
    out_blob->pbData = enc;
    out_blob->cbData = cb;
    return 0;
}

int32_t cp_enroll_create_key(const char *prov_name, uint32_t prov_type,
                             const char *container, uint32_t key_spec,
                             int32_t exportable, int32_t silent, const char *pin,
                             char **out_container, char **out_unique)
{
    if (out_container) {
        *out_container = NULL;
    }
    if (out_unique) {
        *out_unique = NULL;
    }
    uint32_t ks = key_spec ? key_spec : AT_KEYEXCHANGE;
    /* CRYPT_SILENT + NEWKEYSET yields NTE_SILENT_CONTEXT on CryptoPro when the
     * CSP would show a PIN UI. Set the PIN first (when provided) instead. */
    (void)silent;
    DWORD acq = CRYPT_NEWKEYSET;
    HCRYPTPROV prov = 0;
    int32_t rc = cp_enroll_acquire(container, prov_name, prov_type, acq, &prov);
    if (rc) {
        return rc;
    }
    rc = cp_enroll_set_pin(prov, ks, pin);
    if (rc) {
        CryptReleaseContext(prov, 0);
        return rc;
    }
    HCRYPTKEY key = 0;
    DWORD gen_flags = exportable ? CRYPT_EXPORTABLE : 0;
    if (!CryptGenKey(prov, ks, gen_flags, &key)) {
        rc = cp_last_error();
        CryptReleaseContext(prov, 0);
        if (container && *container) {
            HCRYPTPROV doomed = 0;
            (void)CryptAcquireContextA(
                &doomed, container,
                (prov_name && *prov_name) ? prov_name : NULL, (DWORD)prov_type,
                CRYPT_DELETEKEYSET | CRYPT_SILENT);
        }
        return rc;
    }
    CryptDestroyKey(key);

    char *cname = NULL;
    char *uname = NULL;
    rc = cp_enroll_prov_param_str(prov, PP_CONTAINER, &cname);
    if (rc) {
        CryptReleaseContext(prov, 0);
        return rc;
    }
    (void)cp_enroll_prov_param_str(prov, PP_UNIQUE_CONTAINER, &uname);
    CryptReleaseContext(prov, 0);
    if (out_container) {
        *out_container = cname;
    } else {
        free(cname);
    }
    if (out_unique) {
        *out_unique = uname;
    } else {
        free(uname);
    }
    return 0;
}

int32_t cp_enroll_create_pkcs10(const cp_enroll_pkcs10_params *p, cp_buf *out_req)
{
    if (!p || !p->subject || !*p->subject || !p->container || !*p->container ||
        !out_req) {
        return CP_E_INVALIDARG;
    }
    out_req->data = NULL;
    out_req->len = 0;

    uint32_t key_spec = p->key_spec ? p->key_spec : AT_KEYEXCHANGE;
    DWORD acq = p->silent ? CRYPT_SILENT : 0;
    HCRYPTPROV prov = 0;
    int32_t rc = cp_enroll_acquire(p->container, p->prov_name, p->prov_type,
                                   acq, &prov);
    if (rc) {
        return rc;
    }

    rc = cp_enroll_set_pin(prov, key_spec, p->pin);
    if (rc) {
        CryptReleaseContext(prov, 0);
        return rc;
    }

    DWORD cbPub = 0;
    if (!CryptExportPublicKeyInfo(prov, key_spec,
                                  X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, NULL,
                                  &cbPub)) {
        rc = cp_last_error();
        CryptReleaseContext(prov, 0);
        return rc;
    }
    PCERT_PUBLIC_KEY_INFO pki =
        (PCERT_PUBLIC_KEY_INFO)calloc(1, cbPub ? cbPub : 1);
    if (!pki) {
        CryptReleaseContext(prov, 0);
        return CP_E_OUTOFMEMORY;
    }
    if (!CryptExportPublicKeyInfo(prov, key_spec,
                                  X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, pki,
                                  &cbPub)) {
        rc = cp_last_error();
        free(pki);
        CryptReleaseContext(prov, 0);
        return rc;
    }

    CERT_NAME_BLOB subject;
    rc = cp_enroll_encode_name(p->subject, &subject);
    if (rc) {
        free(pki);
        CryptReleaseContext(prov, 0);
        return rc;
    }

    CRYPT_ATTR_BLOB kuBlob;
    BYTE *kuOwned = NULL;
    rc = cp_enroll_encode_key_usage_attr(p->key_usage, &kuBlob, &kuOwned);
    if (rc) {
        free(subject.pbData);
        free(pki);
        CryptReleaseContext(prov, 0);
        return rc;
    }

    CRYPT_ATTRIBUTE attr;
    memset(&attr, 0, sizeof(attr));
    CERT_REQUEST_INFO req;
    memset(&req, 0, sizeof(req));
    req.dwVersion = CERT_REQUEST_V1;
    req.Subject = subject;
    req.SubjectPublicKeyInfo = *pki;
    if (kuOwned) {
        attr.pszObjId = (char *)szOID_CERT_EXTENSIONS;
        attr.cValue = 1;
        attr.rgValue = &kuBlob;
        req.cAttribute = 1;
        req.rgAttribute = &attr;
    }

    const char *sign_oid =
        (p->sign_oid && *p->sign_oid) ? p->sign_oid
                                      : cp_enroll_default_sign_oid(p->prov_type);
    CRYPT_ALGORITHM_IDENTIFIER sigAlg;
    memset(&sigAlg, 0, sizeof(sigAlg));
    sigAlg.pszObjId = (char *)sign_oid;

    DWORD cbReq = 0;
    if (!CryptSignAndEncodeCertificate(
            prov, key_spec, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            X509_CERT_REQUEST_TO_BE_SIGNED, &req, &sigAlg, NULL, NULL,
            &cbReq)) {
        rc = cp_last_error();
        free(kuOwned);
        free(subject.pbData);
        free(pki);
        CryptReleaseContext(prov, 0);
        return rc;
    }
    unsigned char *reqBuf = (unsigned char *)malloc(cbReq ? cbReq : 1);
    if (!reqBuf) {
        free(kuOwned);
        free(subject.pbData);
        free(pki);
        CryptReleaseContext(prov, 0);
        return CP_E_OUTOFMEMORY;
    }
    if (!CryptSignAndEncodeCertificate(
            prov, key_spec, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            X509_CERT_REQUEST_TO_BE_SIGNED, &req, &sigAlg, NULL, reqBuf,
            &cbReq)) {
        rc = cp_last_error();
        free(reqBuf);
        free(kuOwned);
        free(subject.pbData);
        free(pki);
        CryptReleaseContext(prov, 0);
        return rc;
    }

    free(kuOwned);
    free(subject.pbData);
    free(pki);
    CryptReleaseContext(prov, 0);

    out_req->data = reqBuf;
    out_req->len = cbReq;
    return 0;
}

int32_t cp_enroll_install_cert(const char *prov_name, uint32_t prov_type,
                               const char *container, uint32_t key_spec,
                               int32_t silent, const char *pin,
                               const unsigned char *cert, size_t cert_len,
                               void *hStore)
{
    if (!container || !*container || !cert || cert_len == 0) {
        return CP_E_INVALIDARG;
    }
    CP_CHECK_LEN(cert_len);
    uint32_t ks = key_spec ? key_spec : AT_KEYEXCHANGE;

    PCCERT_CONTEXT ctx = CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, cert, (DWORD)cert_len);
    if (!ctx) {
        return cp_last_error();
    }

    CRYPT_KEY_PROV_INFO kpi;
    memset(&kpi, 0, sizeof(kpi));
    /* CryptoPro accepts ANSI container/provider names via the A path; the
     * wide KEY_PROV_INFO fields are filled from temporary WCHAR buffers. */
    int wCont = MultiByteToWideChar(CP_UTF8, 0, container, -1, NULL, 0);
    int wProv = 0;
    if (prov_name && *prov_name) {
        wProv = MultiByteToWideChar(CP_UTF8, 0, prov_name, -1, NULL, 0);
    }
    if (wCont <= 0) {
        CertFreeCertificateContext(ctx);
        return CP_E_INVALIDARG;
    }
    wchar_t *wc = (wchar_t *)calloc((size_t)wCont, sizeof(wchar_t));
    wchar_t *wp = NULL;
    if (!wc) {
        CertFreeCertificateContext(ctx);
        return CP_E_OUTOFMEMORY;
    }
    if (MultiByteToWideChar(CP_UTF8, 0, container, -1, wc, wCont) <= 0) {
        free(wc);
        CertFreeCertificateContext(ctx);
        return cp_last_error();
    }
    if (wProv > 0) {
        wp = (wchar_t *)calloc((size_t)wProv, sizeof(wchar_t));
        if (!wp) {
            free(wc);
            CertFreeCertificateContext(ctx);
            return CP_E_OUTOFMEMORY;
        }
        if (MultiByteToWideChar(CP_UTF8, 0, prov_name, -1, wp, wProv) <= 0) {
            free(wc);
            free(wp);
            CertFreeCertificateContext(ctx);
            return cp_last_error();
        }
    }
    kpi.pwszContainerName = wc;
    kpi.pwszProvName = wp;
    kpi.dwProvType = (DWORD)prov_type;
    kpi.dwFlags = 0;
    kpi.dwKeySpec = ks;
    (void)silent;

    if (!CertSetCertificateContextProperty(ctx, CERT_KEY_PROV_INFO_PROP_ID, 0,
                                           &kpi)) {
        int32_t rc = cp_last_error();
        free(wc);
        free(wp);
        CertFreeCertificateContext(ctx);
        return rc;
    }
    free(wc);
    free(wp);

    if (pin && *pin) {
        DWORD flags = silent ? CRYPT_SILENT : 0;
        HCRYPTPROV prov = 0;
        int32_t rc =
            cp_enroll_acquire(container, prov_name, prov_type, flags, &prov);
        if (rc) {
            CertFreeCertificateContext(ctx);
            return rc;
        }
        rc = cp_enroll_set_pin(prov, ks, pin);
        if (rc) {
            CryptReleaseContext(prov, 0);
            CertFreeCertificateContext(ctx);
            return rc;
        }
        CERT_KEY_CONTEXT kc;
        memset(&kc, 0, sizeof(kc));
        kc.cbSize = sizeof(kc);
        kc.hCryptProv = prov;
        kc.dwKeySpec = ks;
        if (!CertSetCertificateContextProperty(ctx, CERT_KEY_CONTEXT_PROP_ID, 0,
                                               &kc)) {
            rc = cp_last_error();
            CryptReleaseContext(prov, 0);
            CertFreeCertificateContext(ctx);
            return rc;
        }
        /* ownership of prov moves to the cert context */
    }

    HCERTSTORE store = (HCERTSTORE)hStore;
    int own_store = 0;
    if (!store) {
        store = CertOpenSystemStoreA(0, "MY");
        if (!store) {
            int32_t rc = cp_last_error();
            CertFreeCertificateContext(ctx);
            return rc;
        }
        own_store = 1;
    }
    if (!CertAddCertificateContextToStore(store, ctx, CERT_STORE_ADD_REPLACE_EXISTING,
                                          NULL)) {
        int32_t rc = cp_last_error();
        CertFreeCertificateContext(ctx);
        if (own_store) {
            CertCloseStore(store, 0);
        }
        return rc;
    }
    CertFreeCertificateContext(ctx);
    if (own_store) {
        (void)CertControlStore(store, 0, CERT_STORE_CTRL_COMMIT, NULL);
        CertCloseStore(store, 0);
    }
    return 0;
}
