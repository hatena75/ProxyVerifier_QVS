docker stop gsc-qvs
sleep 1
docker image rm gsc-qvs
./gsc build --insecure-args qvs test/generic.manifest && \
./gsc sign-image qvs enclave-key.pem && \
../rungramineQVS.sh