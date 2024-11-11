/* Copyright (C) 2023 Gramine contributors
 * SPDX-License-Identifier: BSD-3-Clause */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "secret_prov.h"

#define PORT "4433"
// #define EXPECTED_STRING "MORE"
#define FIRST_SECRET "RA Delegation Process"
#define SECOND_SECRET "42" /* answer to ultimate question of life, universe, and everything */

#define SRV_CRT_PATH "../ssl/server.crt"
#define SRV_KEY_PATH "../ssl/server.key"

//#define CSR_LEN 250
#define printf(...) (void)0 // for evaluation

static EVP_PKEY *ca_pkey = NULL;
static X509 *ca_cert = NULL;

static pthread_mutex_t g_print_lock;

static void hexdump_mem(const void* data, size_t size) {
    uint8_t* ptr = (uint8_t*)data;
    for (size_t i = 0; i < size; i++)
        printf("%02x", ptr[i]);
    printf("\n");
}

void print_bynary(unsigned char *hash, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

EVP_PKEY *generate_key() {
    /* Generate Certification Key */
    EVP_PKEY* ec_delegation_pkey = NULL;
    EVP_PKEY_CTX * pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pkey_ctx)
    {
        //printf("EVP_PKEY_CTX_new_id: %ld\n", ERR_get_error());
        //return SGX_QL_ERROR_UNEXPECTED;
    }
    int pkey_ret = EVP_PKEY_keygen_init(pkey_ctx);
    if (!pkey_ret)
    {
        //printf("EVP_PKEY_keygen_init: %ld\n", ERR_get_error());
        EVP_PKEY_CTX_free(pkey_ctx);
        //return SGX_QL_ERROR_UNEXPECTED;
    }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkey_ctx, NID_secp384r1) <= 0)
    {
        //printf("EVP_PKEY_CTX_set_ec_paramgen_curve_nid: %ld\n", ERR_get_error());
        EVP_PKEY_CTX_free(pkey_ctx);
        //return SGX_QL_ERROR_UNEXPECTED;
    }
    if (EVP_PKEY_keygen(pkey_ctx, &ec_delegation_pkey) <= 0)
    {
        //printf("EVP_PKEY_keygen: %ld\n", ERR_get_error());
        EVP_PKEY_CTX_free(pkey_ctx);
        //return SGX_QL_ERROR_UNEXPECTED;
    }
    EVP_PKEY_CTX_free(pkey_ctx);

    return ec_delegation_pkey;
}

X509 *generate_self_signed_cert(EVP_PKEY *pkey) {
    X509 *x509 = X509_new();
    
    if (!x509) {
        printf("Error: Failed to create X509 object\n");
        return NULL;
    }

    // 証明書のシリアル番号設定
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

    // サブジェクト名（Subject Name）を設定
    X509_NAME *subject_name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(subject_name, "C", MBSTRING_ASC, (unsigned char *)"US", -1, -1, 0);  // 国名
    X509_NAME_add_entry_by_txt(subject_name, "O", MBSTRING_ASC, (unsigned char *)"My Organization", -1, -1, 0);  // 組織名
    X509_NAME_add_entry_by_txt(subject_name, "CN", MBSTRING_ASC, (unsigned char *)"My CA", -1, -1, 0);  // Common Name
    X509_set_subject_name(x509, subject_name);

    // 発行者名（Issuer Name）を設定（CAの場合、自己署名ならサブジェクト名と同じ）
    X509_set_issuer_name(x509, subject_name);

    // 証明書の有効期間設定
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);  // 1年

    //公開鍵を設定
    X509_set_pubkey(x509, pkey);

    // 証明書に署名
    if (!X509_sign(x509, pkey, EVP_sha256())) {
        printf("Error: Failed to sign certificate\n");
        X509_free(x509);
        return NULL;
    }

    return x509;
}

X509 *create_certificate_from_csr(X509_REQ *csr, EVP_PKEY *ca_private_key, X509 *ca_cert, int days) {
    X509 *cert = X509_new();  // 新しい証明書を生成

    if (!cert) {
        printf("Error: Failed to create X509 object\n");
        return NULL;
    }

    // 証明書のバージョンを設定 (v3)
    X509_set_version(cert, 2);  // X509v3 (0-indexed)

    // CSRからサブジェクト名を取得し、証明書に設定
    // X509_NAME *subject_name = X509_REQ_get_subject_name(csr);
    // X509_set_subject_name(cert, subject_name);

    // CA証明書から発行者名を取得し、証明書に設定
    X509_set_issuer_name(cert, X509_get_subject_name(ca_cert));

    // CSRの公開鍵を取得し、証明書に設定
    EVP_PKEY *csr_pubkey = X509_REQ_get_pubkey(csr);
    X509_set_pubkey(cert, csr_pubkey);
    EVP_PKEY_free(csr_pubkey);  // 公開鍵の参照を解放

    // 証明書の有効期間を設定（開始日と終了日）
    X509_gmtime_adj(X509_get_notBefore(cert), 0);  // 現在の時刻を開始日とする
    X509_gmtime_adj(X509_get_notAfter(cert), (long)60 * 60 * 24 * days);  // 有効期間(days日間)

    // 証明書に署名 (CAの秘密鍵を使用)
    if (!X509_sign(cert, ca_private_key, EVP_sha256())) {
        printf("Error: Failed to sign certificate\n");
        X509_free(cert);
        return NULL;
    }

    return cert;
}

/* our own callback to verify SGX measurements during TLS handshake */
static int verify_measurements_callback(const char* mrenclave, const char* mrsigner,
                                        const char* isv_prod_id, const char* isv_svn) {
    assert(mrenclave && mrsigner && isv_prod_id && isv_svn);

    pthread_mutex_lock(&g_print_lock);
    puts("Received the following measurements from the client:");
    printf("  - MRENCLAVE:   "); hexdump_mem(mrenclave, 32);
    printf("  - MRSIGNER:    "); hexdump_mem(mrsigner, 32);
    printf("  - ISV_PROD_ID: %hu\n", *((uint16_t*)isv_prod_id));
    printf("  - ISV_SVN:     %hu\n", *((uint16_t*)isv_svn));
    puts("[ WARNING: In reality, you would want to compare against expected values! ]");
    pthread_mutex_unlock(&g_print_lock);

    return 0;
}

/* this callback is called in a new thread associated with a client; be careful to make this code
 * thread-local and/or thread-safe */
static int communicate_with_client_callback(struct ra_tls_ctx* ctx) {
    int ret;
    X509_REQ* p_x509_req = NULL;
    X509 *cert = NULL;
    
    /* if we reached this callback, the first secret was sent successfully */
    // This secret is simply strings.
    printf("--- Sent secret1 ---\n");

    // listen on csr_len
    uint8_t csr_len_buf[sizeof(int)];
    ret = secret_provision_read(ctx, csr_len_buf, sizeof(csr_len_buf));
    if (ret < 0) {
        if (ret == -ECONNRESET) {
            /* client doesn't want another secret, shutdown communication gracefully */
            return 0;
        }

        fprintf(stderr, "[error] secret_provision_read() returned %d\n", ret);
        return -EINVAL;
    }
    int csr_len;
    memcpy(&csr_len, csr_len_buf, sizeof(int));  // バッファから int にコピー
    printf("--- Received client CSR(DER) length == %d ---\n", csr_len);
    

    /* Prepare to receive next secret (CSR) */
    uint8_t csr[csr_len];
    ret = secret_provision_read(ctx, csr, sizeof(csr));
    if (ret < 0) {
        if (ret == -ECONNRESET) {
            /* client doesn't want another secret, shutdown communication gracefully */
            return 0;
        }

        fprintf(stderr, "[error] secret_provision_read() returned %d\n", ret);
        return -EINVAL;
    }
    printf("--- Received client CSR(DER) ---\n");
    const unsigned char* csr_tmp = (unsigned char*)csr; // for converting d2i
    print_bynary(csr_tmp, sizeof(csr)); // It is convenient to get the size using csr

    p_x509_req = d2i_X509_REQ(NULL, &csr_tmp, sizeof(csr));
    if(p_x509_req == NULL){
        fprintf(stderr, "[error] d2i_X509_REQ() returned %d\n", ret);
        return -EINVAL;
    }

    cert = create_certificate_from_csr(p_x509_req, ca_pkey, ca_cert, 365);
    if(cert == NULL){
        fprintf(stderr, "[error] create_certificate_from_csr() returned %d\n", ret);
        return -EINVAL;
    }

    unsigned char *cert_der = NULL;
    int cert_len = i2d_X509(cert, &cert_der);

    /* tell cert length */
    uint8_t certlenbuffer[sizeof(int)];
    // int のバイト配列を uint8_t 配列にコピー
    memcpy(certlenbuffer, &cert_len, sizeof(int));
    ret = secret_provision_write(ctx, certlenbuffer, sizeof(certlenbuffer));
    if (ret < 0) {
        fprintf(stderr, "[error] secret_provision_write() returned %d\n", ret);
        return -EINVAL;
    }
    printf("--- Sent client cert length == %d ---\n", cert_len);


    // send cert
    ret = secret_provision_write(ctx, (uint8_t*)cert_der, cert_len+1);
    if (ret < 0) {
        fprintf(stderr, "[error] secret_provision_write() returned %d\n", ret);
        return -EINVAL;
    }
    printf("--- Sent client cert(DER)---\n");
    for (int i = 0; i < cert_len; i++) {
        printf("%02X", cert_der[i]);
    }
    printf("\n");

    return 0;
}

int main(void) {
    //署名用の鍵とその証明書の生成
    ca_pkey = generate_key();
    ca_cert = generate_self_signed_cert(ca_pkey);

    int ret = pthread_mutex_init(&g_print_lock, NULL);
    if (ret < 0)
        return ret;
    

    puts("--- Starting the Secret Provisioning server on port " PORT " ---");
    ret = secret_provision_start_server((uint8_t*)FIRST_SECRET, sizeof(FIRST_SECRET),
                                        PORT, SRV_CRT_PATH, SRV_KEY_PATH,
                                        verify_measurements_callback,
                                        communicate_with_client_callback);
    if (ret < 0) {
        fprintf(stderr, "[error] secret_provision_start_server() returned %d\n", ret);
        return 1;
    }

    pthread_mutex_destroy(&g_print_lock);
    return 0;
}
