# ProxyVerifier_QVS
### About

This repository is an implementation of the following paper:
- Takashi Yagawa, Tadanori Teruya, Kuniyasu Suzaki, Hirotake Abe. "Delegating Verification for Remote Attestation using TEE". 7th Workshop on System Software for Trusted Execution (SysTEX 2024). July 8th, 2024.

ProxyVerifier_QVS is based from [Intel® Software Guard Extensions and Intel® Trust Domain Extensions Data Center Attestation Primitives (Intel® SGX and Intel® TDX DCAP) Quote Verification Service](https://github.com/hatena75/ProxyVerifier_QVS/tree/541531b838d17f7418f7d86c16974f98f2fa81b4) (commit 541531b).

We use [Gramine Shielded Containers (gsc)](https://github.com/gramineproject/gsc) to apply SGX.

### Requirements
 - [Docker](https://www.docker.com/) (tested with version 20.10.11)
    - ```$ curl -fsSL https://get.docker.com -o get-docker.sh```
    - ```$ sudo sh ./get-docker.sh```
    - ```$ sudo usermod -aG docker $USER``` and re-login
 - For [gsc](https://github.com/gramineproject/gsc/tree/b593a7456d06c7a402a2df9c9899a63007f31616) dependencies (tested with commit b593a74)
    - ```$ sudo apt-get install docker.io python3 python3-pip```
    - ```$ pip3 install docker jinja2 tomli tomli-w pyyaml```
  

### Environment
Our experimental environment is as follows:

| Software | Version |
| ---- | ---- |
| OS | Ubuntu22.04 |
| kernel | 6.2.0-36-generic |
| SGX SDK | 2.22.100.3 |
| SGX PSW | 1.19.100.3-jammy1 |
| gsc | commit [b593a74](https://github.com/gramineproject/gsc/tree/b593a7456d06c7a402a2df9c9899a63007f31616) |
| Gramine | v1.7 ([from gsc](https://gramine.readthedocs.io/projects/gsc/en/stable/index.html#configuration))|

# How to Build and Run

## Normal Container
You can build QVS without SGX protection by following [Quick Setup in Quote Verification Service](https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationService?tab=readme-ov-file#quick-setup) README.

1\. Execute ```./build.sh```. This script will build QVL, QVS and SSS.

2\. Execute ```./runAll.sh```. This script will configure QVS and SSS with autogenerated self-signed certs.

As a result it runs two docker containers: ```qvs``` and ```vcs-sss``` running on ports 8796-8799
 
MTLS connection is established and both services are fully operable.

## SGX Container
You can apply gsc to Normal Container. The method is traced in [the gsc manual](https://gramine.readthedocs.io/projects/gsc/en/latest/#example).

1\. Change directory into gsc:
```
ProxyVerifier_QVS$ cd gsc
```
2\. Generate the signing key (if you don’t already have a key):
```
ProxyVerifier_QVS/gsc$ openssl genrsa -3 -out enclave-key.pem 3072
```
3\. Generate config file (Copy template):
```
ProxyVerifier_QVS/gsc$ cp config.yaml.template config.yaml
```
4\. Graminize the Python image using `gsc build`:
```
ProxyVerifier_QVS/gsc$ ./gsc build --insecure-args qvs test/generic.manifest
```
5\. Sign the graminized Docker image using `gsc sign-image`:
```
ProxyVerifier_QVS/gsc$ ./gsc sign-image qvs enclave-key.pem
```
6\. Change directory to one level above:
```
ProxyVerifier_QVS/gsc$ cd ..
```
7\. Run graminized qvs:
```
ProxyVerifier_QVS$ ./rungramineQVS.sh
```
Note: Since the same port number as the normal container is used by default, the normal container must be stopped beforehand.