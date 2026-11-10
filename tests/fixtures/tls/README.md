# Test TLS fixture

`localhost-cert.pem` and `localhost-key.pem` are a **self-signed certificate for
`CN=localhost`**, generated for the TLS binding test only.

- Not a credential. It is never loaded by the runtime, only by
  `tests/tls-binding.test.ts`.
- It is committed because the test needs a certificate and the repo has no
  certificate-generation dependency.
- `scripts/pack-release.mjs` exempts this directory explicitly and prints the
  exemption, so the exception is visible rather than implied.

If you are auditing this repository: this key protects nothing. Do not reuse it.
