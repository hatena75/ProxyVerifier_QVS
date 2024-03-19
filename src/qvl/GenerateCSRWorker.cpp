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

// #include <openssl/ec.h>
// #include <openssl/bn.h>
// #include <openssl/rsa.h>
// #include <openssl/evp.h>
// #include <openssl/err.h>
// #include <openssl/rand.h>
// #include <openssl/x509.h>

namespace intel::sgx::dcap::qvlwrapper {
    void GenerateCSRWorker::Run()  {
        size_t bufSize = 10;
        auto version = std::make_unique<char[]>(bufSize);
        sgxEnclaveAttestationGetVersion(version.get(), bufSize);
        result = std::string(version.get());

    //     /**
    //      * (My function) Create delegation rsa key pair and output it's public key.
    //      * @param delegation_key[OUT] - Pointer to hold the delegation public key.
    //      *
    //      * @return Status code of the operation, one of:
    //      *      - SGX_QL_SUCCESS
    //      *      - SGX_QL_ERROR_INVALID_PARAMETER
    //      **/
    //     quote3_error_t sgx_myqve_get_public_key(
    //         unsigned char* delegation_key, uint32_t delegation_key_size) {
            
    //         // bellow code is cited from sgxssl
    //         // public cript context (ctx) generated
    //         EVP_PKEY_CTX * ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    //         if (!ctx)
    //         {
    //             //printf("EVP_PKEY_CTX_new_id: %ld\n", ERR_get_error());
    //             return SGX_QL_ERROR_UNEXPECTED;
    //         }
    //         int ret = EVP_PKEY_keygen_init(ctx);
    //         if (!ret)
    //         {
    //             //printf("EVP_PKEY_keygen_init: %ld\n", ERR_get_error());
    //             EVP_PKEY_CTX_free(ctx);
    //             return SGX_QL_ERROR_UNEXPECTED;
    //         }
    //         if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp384r1) <= 0)
    //         {
    //             //printf("EVP_PKEY_CTX_set_ec_paramgen_curve_nid: %ld\n", ERR_get_error());
    //             EVP_PKEY_CTX_free(ctx);
    //             return SGX_QL_ERROR_UNEXPECTED;
    //         }
    //         ec_delegation_pkey = NULL; //general structure of asynmetric pair of keys.
    //     #if OPENSSL_VERSION_NUMBER < 0x30000000
    //         if (EVP_PKEY_keygen(ctx, &ec_delegation_pkey) <= 0)
    //     #else //new API EVP_PKEY_generate() since 3.0
    //         if (EVP_PKEY_generate(ctx, &ec_delegation_pkey) <= 0)
    //     #endif
    //         {
    //             //printf("EVP_PKEY_keygen: %ld\n", ERR_get_error());
    //             EVP_PKEY_CTX_free(ctx);
    //             return SGX_QL_ERROR_UNEXPECTED;
    //         }
    //         // public key - string
    //         int len = i2d_PUBKEY(ec_delegation_pkey, NULL);
    //         unsigned char *buf = (unsigned char *) malloc (len + 1);
    //         if (!buf)
    //         {
    //             //printf("Failed in calling malloc()\n");
    //             EVP_PKEY_CTX_free(ctx);
    //             return SGX_QL_ERROR_INVALID_PARAMETER;
    //         }
    //         unsigned char *tbuf = buf;
    //         i2d_PUBKEY(ec_delegation_pkey, &tbuf);

    //         // print public key
    //         //printf ("{\"public\":\"");
    //         // int i;
    //         // for (i = 0; i < len; i++) {
    //         //     //printf("%02x", (unsigned char) buf[i]);
    //         // }
    //         //printf("\"}\n");

    //         //Create CSR
    //         X509_REQ* p_x509_req = NULL;
    //         if (NULL == (p_x509_req = X509_REQ_new())) {
    //             /* Error */
    //             return SGX_QL_ERROR_MESSAGE_PARSING_ERROR;
    //         }

    //         if (0 >= X509_REQ_set_pubkey(p_x509_req, ec_delegation_pkey)) {
    //             X509_REQ_free(p_x509_req);
    //             p_x509_req = NULL;
    //             return SGX_QL_ERROR_STORED_KEY;
    //         }

    //         int cert_size = X509_REQ_sign(p_x509_req, ec_delegation_pkey, EVP_sha256());
    //         if (0 >= cert_size) {
    //             X509_REQ_free(p_x509_req);
    //             p_x509_req = NULL;
    //             return SGX_QL_ERROR_INVALID_PCE_SIG_SCHEME;
    //         }

    //         //Return CSR (now delegation_key → p_x509_req {need to size})
    //         // if (memcpy_s(delegation_key, (size_t)delegation_key_size, buf, (size_t)len) != 0) {
    //         //     return SGX_QL_RESULT_INVALID_SIGNATURE;
    //         // }

    //         EVP_PKEY_CTX_free(ctx);
    //         X509_REQ_free(p_x509_req);
    //         p_x509_req = NULL;
    //         free(buf);

    //         // private key - string
    //         //len = i2d_PrivateKey(ec_delegation_pkey, NULL);
    //         // unsigned char *buf2 = (unsigned char *) malloc (len + 1);
    //         // if (!buf2)
    //         // {
    //             //printf("Failed in calling malloc()\n");
    //             // EVP_PKEY_CTX_free(ctx);
    //             // return SGX_QL_ERROR_UNEXPECTED;
    //         // }
    //         // unsigned char *tbuf2 = buf2;
    //         // i2d_PrivateKey(ec_delegation_pkey, &tbuf2);

    //         // print private key
    //         //printf ("{\"private\":\"");
    //         // for (i = 0; i < len; i++) {
    //         //     //printf("%02x", (unsigned char) buf[i]);
    //         // }
    //         //printf("\"}\n");

    //         //free(buf2);

    //         //EVP_PKEY_free(ec_delegation_pkey);

    //         return SGX_QL_SUCCESS;
    //     }
    }

    void GenerateCSRWorker::OnOK() {
        auto returnObj = Napi::Object::New(Env());
        returnObj.Set("result", result);
        promise.Resolve(returnObj);
    }
}
