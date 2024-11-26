docker stop gsc-qvs
docker image rm gsc-qvs
./gsc build --insecure-args qvs test/generic.manifest
./gsc sign-image qvs enclave-key.pem