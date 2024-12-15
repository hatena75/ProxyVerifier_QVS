import http from 'k6/http';
import { sleep } from 'k6';

export const options = {
  duration: '1m', 
  insecureSkipTLSVerify: true,
};

// The function that defines VU logic.
//
// See https://grafana.com/docs/k6/latest/examples/get-started-with-k6/ to learn more
// about authoring k6 scripts.
//
export default function() {
  let res = http.get('https://localhost:8799/attestation/sgx/dcap/v1/report/genCSR');

  sleep(1); // 各VUsごとに1秒待機（リクエストの間隔を調整）
}