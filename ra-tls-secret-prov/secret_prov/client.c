/* Copyright (C) 2023 Gramine contributors
 * SPDX-License-Identifier: BSD-3-Clause */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "secret_prov.h"

//#define SEND_STRING "MORE"
#define printf(...) (void)0 //for evaluation

#define CA_CRT_PATH "ca.crt"

void print_hash(unsigned char *hash, size_t length) {
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

unsigned char *generate_csr(EVP_PKEY *pkey, int* csr_len) {
    /* Create CSR */
    X509_REQ* p_x509_req = NULL;
    if (NULL == (p_x509_req = X509_REQ_new())) {
        /* Error */
        printf("X509_REQ_new error\n");
    }

    // X509_NAME *name = X509_REQ_get_subject_name(p_x509_req);
    // X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"US", -1, -1, 0);
    // X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"My Company", -1, -1, 0);
    // X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"www.example.com", -1, -1, 0);

    if (0 >= X509_REQ_set_pubkey(p_x509_req, pkey)) {
        X509_REQ_free(p_x509_req);
        p_x509_req = NULL;
        printf("X509_REQ_set_pubkey error\n");
    }

    int cert_size = X509_REQ_sign(p_x509_req, pkey, EVP_sha256());
    if (0 >= cert_size) {
        X509_REQ_free(p_x509_req);
        p_x509_req = NULL;
        printf("X509_REQ_sign error\n");
    }

    unsigned char *der_tmp = NULL;
    *csr_len = i2d_X509_REQ(p_x509_req, &der_tmp);

    return der_tmp;
}

int main(void) {
    //for evaluation
    struct timeval start, end;
    long seconds, useconds;
    double elapsed;


    int ret;

    uint8_t* secret1 = NULL;
    size_t secret1_size = 0;

    unsigned char *csr_der = NULL;
    int csr_len;

    EVP_PKEY* ec_delegation_pkey = generate_key();
    if (ec_delegation_pkey == NULL) {
        printf("Error: pkey generation failed\n");
        return 1;
    }
    //get CSR of DER shaped and its length
    csr_der = generate_csr(ec_delegation_pkey, &csr_len);
    if (csr_der == NULL) {
        printf("Error: CSR generation failed\n");
        return 1;
    }

    // 開始時刻の取得
    gettimeofday(&start, NULL);

    struct ra_tls_ctx* ctx = NULL;
    ret = secret_provision_start("dummyserver:80;localhost:4433;anotherdummy:4433",
                                 CA_CRT_PATH, &ctx);
    if (ret < 0) {
        fprintf(stderr, "[error] secret_provision_start() returned %d\n", ret);
        //goto out;
    }

    ret = secret_provision_get(ctx, &secret1, &secret1_size);
    if (ret < 0) {
        fprintf(stderr, "[error] secret_provision_get() returned %d\n", ret);
        //goto out;
    }
    if (!secret1_size) {
        fprintf(stderr, "[error] secret_provision_get() returned secret with size 0\n");
        //goto out;
    }
    secret1[secret1_size - 1] = '\0';
    printf("--- Received secret1 = '%s' ---\n", secret1);

    /* tell csr length */
    uint8_t csrlenbuffer[sizeof(int)];
    // int のバイト配列を uint8_t 配列にコピー
    memcpy(csrlenbuffer, &csr_len, sizeof(int));
    ret = secret_provision_write(ctx, csrlenbuffer, sizeof(csrlenbuffer));
    if (ret < 0) {
        fprintf(stderr, "[error] secret_provision_write(csr_len) returned %d\n", ret);
        //goto out;
    }
    printf("--- Sent client CSR(DER) length == %d ---\n", csr_len);


    /* send CSR */
    ret = secret_provision_write(ctx, (uint8_t*)csr_der, csr_len);
    if (ret < 0) {
        fprintf(stderr, "[error] secret_provision_write(csr) returned %d\n", ret);
        //goto out;
    }
    printf("--- Sent client CSR(DER) ---\n");
    for (int i = 0; i < csr_len; i++) {
        printf("%02X", csr_der[i]);
    }
    printf("\n");


    // listen on cert_len
    uint8_t cert_len_buf[sizeof(int)];
    ret = secret_provision_read(ctx, cert_len_buf, sizeof(cert_len_buf));
     if (ret < 0) {
        fprintf(stderr, "[error] secret_provision_read(cert_len) returned %d\n", ret);
        //goto out;
    }
    int cert_len;
    memcpy(&cert_len, cert_len_buf, sizeof(int));  // バッファから int にコピー
    printf("--- Received client CSR(DER) length == %d ---\n", cert_len);

    /* receive cert */
    uint8_t certder[cert_len];
    ret = secret_provision_read(ctx, certder, sizeof(certder));
    if (ret < 0) {
        fprintf(stderr, "[error] secret_provision_read(certder) returned %d\n", ret);
        //goto out;
    }
    //certder[sizeof(cert) - 1] = '\0';
    printf("--- Received certder ---\n");
    print_hash(certder, sizeof(certder));

    // verifying cert with corresponding private key.
    const unsigned char* certder_tmp = (unsigned char*)certder; // for converting d2i
    X509 *p_x509 = NULL;
    p_x509 = d2i_X509(NULL, &certder_tmp, sizeof(certder));
    if(p_x509 == NULL){
        fprintf(stderr, "[error] d2i_X509() returned %d\n", ret);
        //goto out;
    }

    // 終了時刻の取得
    gettimeofday(&end, NULL);

    // 証明書と秘密鍵の検証
    if (X509_check_private_key(p_x509, ec_delegation_pkey)) {
        printf("The certificate and private key match.\n");
    } else {
        printf("The certificate and private key do NOT match.\n");
    }

    // 経過時間を計算（秒とマイクロ秒の差分を合算）
    seconds  = end.tv_sec  - start.tv_sec;
    useconds = end.tv_usec - start.tv_usec;
    elapsed = seconds + useconds / 1000000.0;

    // stderrに結果を出力
    fprintf(stderr, "Elapsed time: %f seconds\n", elapsed);

    ret = 0;
out:
    free(secret1);
    free(csr_der);
    X509_free(p_x509);
    EVP_PKEY_free(ec_delegation_pkey);
    secret_provision_close(ctx);
    return ret == 0 ? 0 : 1;
}
