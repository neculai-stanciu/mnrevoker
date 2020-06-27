# A simple ocsp responder in micronaut

All important changes from this project are based [revoker implementation](https://github.com/wdawson/revoker).

## Command to validate OCSP responder

```bash
 openssl ocsp -CAfile chain.pem -url http://localhost:8080 -resp_text -issuer INTERMEDIATE_ROOT.pem -cert intermediate.test.ocsp.pem
```


