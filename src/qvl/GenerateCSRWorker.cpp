/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "GenerateCSRWorker.h"
extern "C" {
#include <secret_prov.h>
}

namespace intel::sgx::dcap::qvlwrapper {

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

    void GenerateCSRWorker::Run()  {
        int ret;

        uint8_t* secret1 = NULL;
        size_t secret1_size = 0;

        unsigned char *csr_der = NULL;
        int csr_len;

        EVP_PKEY* ec_delegation_pkey = generate_key();
        if (ec_delegation_pkey == NULL) {
            printf("Error: pkey generation failed\n");
        }
        //get CSR of DER shaped and its length
        csr_der = generate_csr(ec_delegation_pkey, &csr_len);
        if (csr_der == NULL) {
            printf("Error: CSR generation failed\n");
        }

        const char* CA_CRT_PATH = std::getenv("QVS_DELEGATING_ATTESTATION_CERT_FILE");
        fprintf(stderr, "[debug] QVS_DELEGATING_ATTESTATION_CERT_FILE is %s\n", CA_CRT_PATH);
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

        
        const unsigned char* certder_tmp = (unsigned char*)certder; // for converting d2i
        X509 *p_x509 = NULL;
        p_x509 = d2i_X509(NULL, &certder_tmp, sizeof(certder));
        if(p_x509 == NULL){
            fprintf(stderr, "[error] d2i_X509() returned %d\n", ret);
            //goto out;
        }

        // verifying cert with corresponding private key.
        if (X509_check_private_key(p_x509, ec_delegation_pkey)) {
            printf("The certificate and private key match.\n");
        } else {
            printf("The certificate and private key do NOT match.\n");
        }

        //if(X509_REQ_verify(p_x509_req, ec_delegation_pkey) != 1) printf("X509_REQ_verify error\n");

        //Output csr to file
        // FILE *csr_file;
        // csr_file = fopen("delegation.csr", "wb");
        // if(csr_file == NULL) printf("csr_file error\n");
        // if(!PEM_write_X509_REQ(csr_file, p_x509_req)){
        //     printf("PEM_write_X509_REQ error\n");
        // }
        // fclose(csr_file);

        // FILE *key_file;
        // key_file = fopen("delegationkey.pem", "wb");
        // if (!PEM_write_PrivateKey(key_file, ec_delegation_pkey, NULL, NULL, 0, 0, NULL)) {
        //     printf("PEM_write_PrivateKey error\n");
        // }
        // fclose(key_file);

        free(secret1);
        free(csr_der);
        X509_free(p_x509);
        EVP_PKEY_free(ec_delegation_pkey);
        secret_provision_close(ctx);
    }

    void GenerateCSRWorker::OnOK() {
        auto returnObj = Napi::Object::New(Env());
        returnObj.Set("result", result);
        promise.Resolve(returnObj);
    }
}
