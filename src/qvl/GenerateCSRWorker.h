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

#ifndef QUOTEVERIFICATIONLIBRARYWRAPPER_GENERATECSRWORKER_H
#define QUOTEVERIFICATIONLIBRARYWRAPPER_GENERATECSRWORKER_H

#include <napi.h>
#include <iostream>
#include <SgxEcdsaAttestation/QuoteVerification.h>
#include "BaseWorker.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <cstdlib>

namespace intel::sgx::dcap::qvlwrapper {
    class GenerateCSRWorker : public BaseWorker {
    public:
        GenerateCSRWorker(Napi::Env &env, Napi::Promise::Deferred &promise, const std::string& requestId)
                : BaseWorker(env, promise, requestId) {}

        ~GenerateCSRWorker() override = default;

        void Run() override;
        void OnOK() override;

    private:
        std::vector<unsigned char> delegationCert{};
        std::vector<unsigned char> delegationPrivateKey{};
        std::vector<unsigned char> delegationPublicKey{};
    };

}
#endif //QUOTEVERIFICATIONLIBRARYWRAPPER_GENERATECSRWORKER_H
