# Delegation Cert Issuer

gramineサンプルのサーバを流用し、Delegation Cert Issuerとしている。

These examples use the Secret Provisioning library `secret_prov_attest.so` for
the clients and `secret_prov_verify_epid.so`/`secret_prov_verify_dcap.so` for
the servers. These libraries are installed together with Gramine (but for DCAP
version, you need `meson setup ... -Ddcap=enabled`). For DCAP attestation, the
DCAP software infrastructure must be installed and work correctly on the host.

The current example works with ECDSA (DCAP) remote attestation schemes. For more documentation, refer to https://gramine.readthedocs.io/en/stable/attestation.html.

## Secret Provisioning servers

The servers are supposed to run on trusted machines (not in SGX enclaves). The
servers listen for client connections. For each connected client, the servers
verify the client's RA-TLS certificate and the embedded SGX quote and, if
verification succeeds, sends secrets back to the client (e.g. the master key
for encrypted files in `secret_prov_pf` example).

There are two versions of each server: the EPID one and the DCAP one. Each of
them links against the corresponding EPID/DCAP secret-provisioning library at
build time.

Because this example builds and uses debug SGX enclaves (`sgx.debug` is set
to `true`), we use environment variable `RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE=1`.
Note that in production environments, you must *not* use this option!

Moreover, we set `RA_TLS_ALLOW_OUTDATED_TCB_INSECURE=1`,
`RA_TLS_ALLOW_HW_CONFIG_NEEDED=1` and `RA_TLS_ALLOW_SW_HARDENING_NEEDED=1` to
allow performing the tests when some of Intel's security advisories haven't been
addressed (for example, when the microcode or architectural enclaves aren't
fully up-to-date). Note that in production environments, you must carefully
analyze whether to use these options!

### verify_measurements_callback()

今回ここは無しでも構わないが、丁寧にやるならちゃんと調べて使うとよいだろう。
環境変数で渡される形にしても良い。

### communicate_with_client_callback()

この関数を書き換えることで、以下の流れを実現する。


クライアントが生成した公開鍵を受け取る → 公開鍵に署名鍵で署名する → 署名付き公開鍵と証明書をクライアントに返送する。

## Secret Provisioning clients

今回はこれがProxyVerifierになる。

# Service Start

For all examples, we set the following environment variables:
```sh
export RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE=1
export RA_TLS_ALLOW_OUTDATED_TCB_INSECURE=1
export RA_TLS_ALLOW_HW_CONFIG_NEEDED=1
export RA_TLS_ALLOW_SW_HARDENING_NEEDED=1
```

- Secret Provisioning flows, ECDSA-based (DCAP) attestation:

```sh
make

# listening for Certification Delegation
./server_dcap wrap_key &

# ↓はProxyVerifierでの対応になる。
# gramine-sgx ./client

kill %%
```
