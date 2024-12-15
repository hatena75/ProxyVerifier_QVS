import http from 'k6/http';
import { sleep } from 'k6';

export const options = {
  // A number specifying the number of VUs to run concurrently.
  //vus: 11,
  // A string specifying the total duration of the test run.
  duration: '1m',
  // curl corresponding -k
  insecureSkipTLSVerify: true,
};

// The function that defines VU logic.
//
// See https://grafana.com/docs/k6/latest/examples/get-started-with-k6/ to learn more
// about authoring k6 scripts.
//

//curl -H "Content-Type: application/json" -d '@attested.json' --cacert ./configuration-default/certificates/qvs-cert.pem -k https://localhost:8799/attestation/sgx/dcap/v1/report

const url = 'https://localhost:8799/attestation/sgx/dcap/v1/report';
//const cert = open('../configuration-default/certificates/qvs-cert.pem');
const quote = open('../attested.json');

export default function() {
  http.post(url, quote, { headers: { 'Content-Type': 'application/json' } });
  sleep(1);
}
