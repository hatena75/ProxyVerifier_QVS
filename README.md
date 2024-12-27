# ProxyVerifier_QVS
## About

This repository is an implementation of the following paper:
- Takashi Yagawa, Tadanori Teruya, Kuniyasu Suzaki, Hirotake Abe. "Delegating Verification for Remote Attestation using TEE". 7th Workshop on System Software for Trusted Execution (SysTEX 2024). July 8th, 2024.

ProxyVerifier_QVS is based from [Intel® Software Guard Extensions and Intel® Trust Domain Extensions Data Center Attestation Primitives (Intel® SGX and Intel® TDX DCAP) Quote Verification Service](https://github.com/hatena75/ProxyVerifier_QVS/tree/541531b838d17f7418f7d86c16974f98f2fa81b4) (commit 541531b).

We use [Gramine Shielded Containers (gsc)](https://github.com/gramineproject/gsc) to apply SGX.

## Requirements
 - [Docker](https://www.docker.com/) (tested with version 20.10.11)
    - ```$ curl -fsSL https://get.docker.com -o get-docker.sh```
    - ```$ sudo sh ./get-docker.sh```
    - ```$ sudo usermod -aG docker $USER``` and re-login
 - For [gsc](https://github.com/gramineproject/gsc) and gramine sample dependencies (tested with commit e57a501)
    - ```$ sudo apt-get install python3 python3-pip pkg-config libssl-dev```
    - ```$ pip3 install docker jinja2 tomli tomli-w pyyaml```
      - if you have an error of pip3, ```$ sudo apt install python3-docker python3-jinja2 python3-tomli python3-tomli-w python3-yaml```
 - Intel SGX environment
    - Please follow [Intel_SGX_SW_Installation_Guide](https://download.01.org/intel-sgx/latest/linux-latest/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf)
 - gramine
    - Please follow [Gramine installation options](https://gramine.readthedocs.io/en/latest/installation.html#install-gramine-packages)
  

## Environment
Our experimental environment is as follows:

| Software | Version |
| ---- | ---- |
| OS | Ubuntu22.04 |
| kernel | 6.2.0-36-generic |
| SGX SDK | 2.22.100.3 |
| SGX PSW | 1.19.100.3-jammy1 |
| gsc | commit [e57a501](https://github.com/gramineproject/gsc/tree/e57a501fe2e54692742876ac1cc3b81cfa24af86) |
| gramine in gsc and host| [v1.7](https://github.com/gramineproject/gramine/tree/115ffeeb72e13a2a6cab9b11160109f171832c60) |

# How to Build and Run

## Verification Delegater
1\. Change directory into ra-tls-secret-prov:
```
ProxyVerifier_QVS$ cd ra-tls-secret-prov
```
2\. Change Makefile for lines of "--key" for ./enclave.pem:
```
ProxyVerifier_QVS/ra-tls-secret-prov$ sudo vi Makefile
```
3\. Build. (You may have to repeat the process several times until it is complete.) :
```
ProxyVerifier_QVS/ra-tls-secret-prov$ make app dcap RA_TYPE=dcap
```
4\. Change directory into secret_prov :
```
ProxyVerifier_QVS/ra-tls-secret-prov$ cd secret_prov
```
5\. Stand up Verification Delegater (nohup) :
```
ProxyVerifier_QVS/ra-tls-secret-prov/secret_prov$ ./standup_server.sh
```

## Proxy Verifier Container (QVS)
1\. Execute ```./build.sh```. This script will build QVL, QVS.

2\. Change directory into gsc:
```
ProxyVerifier_QVS$ cd gsc
```
3\. Generate the signing key (if you don’t already have a key):
```
ProxyVerifier_QVS/gsc$ openssl genrsa -3 -out enclave-key.pem 3072
```
4\. Generate config file (Copy template):
```
ProxyVerifier_QVS/gsc$ cp config.yaml.template config.yaml
```
5\. Graminize the Python image using `gsc build`:
```
ProxyVerifier_QVS/gsc$ ./gsc build --insecure-args qvs test/generic.manifest
```
6\. Sign the graminized Docker image using `gsc sign-image`:
```
ProxyVerifier_QVS/gsc$ ./gsc sign-image qvs enclave-key.pem
```
7\. Change directory to one level above:
```
ProxyVerifier_QVS/gsc$ cd ..
```
8\. Run graminized qvs:
```
ProxyVerifier_QVS$ ./rungramineQVS.sh
```

# How to Test
1\. As provisioning, QVS must be evaluated with Verification Delegater and received Delegation Certificate:
```
ProxyVerifier_QVS$ curl --cacert ./configuration-default/certificates/qvs-cert.pem -k https://localhost:8799/attestation/sgx/dcap/v1/report/genCSR
```
2\. Now, QVS can be used in the same way as a normal verification service. :
```
ProxyVerifier_QVS$ curl -i -H "Content-Type: application/json" -d '@attested.json' -k https://localhost:8799/attestation/sgx/dcap/v1/report
```

The following response is expected. :
```
$curl -i -H "Content-Type: application/json" -d '@attested.json' -k https://localhost:8799/attestation/sgx/dcap/v1/report
HTTP/1.1 200 OK
Request-ID: 8980e299c5d94784b4508066e965b2fa
X-Delegating-Certificate: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJZVENCNTZBREFnRUNBZ0VBTUFvR0NDcUdTTTQ5QkFNQ01EY3hDekFKQmdOVkJBWVRBbFZUTVJnd0ZnWUQKVlFRS0RBOU5lU0JQY21kaGJtbDZZWFJwYjI0eERqQU1CZ05WQkFNTUJVMTVJRU5CTUI0WERUSTBNVEV6TURFMgpNVFl6TjFvWERUSTFNVEV6TURFMk1UWXpOMW93QURCMk1CQUdCeXFHU000OUFnRUdCU3VCQkFBaUEySUFCSks3CjB6V0Q5dUQ1dS85eTM0TDk1NkNtUmJWU0tpQ1pCOTdJWnVtWlpvRnNPN2xVWExwYkNVVHNyYVNBeGFmVWh5cTkKSmNoME8xcUxBY0UzQjFFQ0xzWS83VHI5M2MvNjFqd1loWDNEb1pmd1lvQ0NRdVZDam9yWGpiM1dSU0tDVXpBSwpCZ2dxaGtqT1BRUURBZ05wQURCbUFqRUFnNEd6ZHlSTGpIMnBMVi9QYmpJL1Z5eUZCaHJnUXpPblV0RkxYWng5ClZZZVorNUx1VnhoYlVrN1p2Qjh1NDZmbEFqRUF6L2ZOTHBBWWlldXYrd2dVT1N2QkgxUU04c01uSkxKQk13c0QKeUpPZkh5Rk5GMklLc1lYSU1KVnY4R1BTT2JDOQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t
X-Delegating-Signature: MGUCMQCHsbZFp2GPwANa1luP8NZD7J/5zKoYDZZeIqTcjjXXi2B2Vf98gXwpYBqSniuWwgwCMG7OlTtuq41jnJkHHqChC039x4oRHPnTK65Iy0wwaJFsmOluWYn2y+sKzNy34Da1gA==
Content-Type: text/plain
Content-Length: 1294
Date: Sat, 30 Nov 2024 16:23:55 GMT
Connection: keep-alive
Keep-Alive: timeout=70

{"id":"317388319492582325445987204621256135619","timestamp":"2024-11-30T16:23:55Z","version":5,"attestationType":"ECDSA","teeType":"SGX_SCALABLE","isvQuoteStatus":"TCB_OUT_OF_DATE_AND_CONFIGURATION_NEEDED","isvQuoteBody":"AwACAAAAAAAKAA8Ak5pyM/ecTKmUCg2zlX8GB9tU0IU6B+k49rX9vuKrm9MAAAAACgwPDv//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABQAAAAAAAADnAAAAAAAAAAJO4ywR4f8g8Yoi0bOJAxMgPRVG3r4CmD7MZmb8bVu3AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACTu/jBiThpRTSjNF6rY41ngyj/eNZhOYLhmVJvTtHJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","tcbEvaluationDataNumber":17,"tcbDate":"2024-11-30T15:25:30Z","nonce":"ABCDEABCDEABCDEABCDEABCDEABCDE12","advisoryURL":"[https://security-center.intel.com](https://security-center.intel.com/)","advisoryIDs":["INTEL-SA-00615","INTEL-SA-00657","INTEL-SA-00730","INTEL-SA-00738","INTEL-SA-00767","INTEL-SA-00828","INTEL-SA-00837","INTEL-SA-00960"],"tcbComponentsOutOfDate":[{"category":"BIOS","type":"Early Microcode Update"},{"category":"OS/VMM","type":"SGX Late Microcode Update"}],"configuration":["DYNAMIC_PLATFORM","SMT_ENABLED"]}
```

You can confirm that the following are included. 
| Element | Description |
| ---- | ---- |
| X-Delegating-Certificate | Verification Certificate |
| X-Delegating-Signature | the hash value of the verification result |
| body | Verification result |

In addition, you can use this information to check the integrity and authenticity of the verification results. ((X-Delegating-Certificate).pem is the public key from X-Delegating-Certificate)
```
$openssl dgst -sha256 -verify (X-Delegating-Certificate).pem -signature (X-Delegating-Signature).bin (Verification result).txt
```