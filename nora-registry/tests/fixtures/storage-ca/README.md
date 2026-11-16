Test-only TLS material for the object store tests of `[tls] ca_cert` (#1186), made once with
openssl (P-256, valid until 2126):

- `ca.pem`: a private CA;
- `store.pem`, `store-key.pem`: the certificate it signed for `127.0.0.1` and `localhost`, and its key;
- `other-ca.pem`: a CA unrelated to both.

Nothing here is trusted anywhere outside these tests.
