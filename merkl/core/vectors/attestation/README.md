# Attestation vectors

Real AWS Nitro Enclaves attestation documents, and the verdict a verifier must
reach on each. Nothing here was produced by Merkl: every document was signed by
the AWS Nitro Attestation PKI on AWS hardware, so a verifier that passes these
agrees with AWS rather than with us.

## Files

| File | What it is |
|---|---|
| `documents.json` | The real documents, base64, with provenance and observed contents. Hand-committed, never regenerated. |
| `cases.json` | Verification cases derived from them, tamper cases included. Generated. |
| `aws-nitro-root-g1.pem` | The published AWS Nitro Attestation PKI root. |
| `not-the-aws-root.pem` | A throwaway P-384 self-signed certificate, so one case can pin an anchor the documents do not chain to. Holds no secret; its private key was destroyed at generation. |

Regenerate and check:

```bash
python -m merkl.core.vectors.attestation.generate
python -m merkl.core.vectors.attestation.generate --check
```

## Provenance

The three documents come from the test data of
[`evervault/attestation-doc-validation`](https://github.com/evervault/attestation-doc-validation)
at commit `10cc232fb0102f8447dfddc0ba6012bf00f48e6a` (Apache-2.0):

| Case name | Upstream path | Produced | Mode |
|---|---|---|---|
| `production` | `test-data/beta/valid-attestation-doc-bytes` | 2022-10-13T08:58:02.136Z | production (PCR0/1/2/8 real) |
| `debug-with-bindings` | `test-data/beta/debug-mode-attestation-doc-bytes` | 2022-10-12T13:50:06.081Z | debug, carries `public_key` and `user_data` |
| `debug-2023` | `test-data/valid-attestation-doc-base64` | 2023-09-18T15:03:30.860Z | debug, different intermediates |

`production` is the reference fixture. Its NSM leaf certificate is valid from
2022-10-13T08:57:59Z to 2022-10-13T11:58:02Z — about three hours, which is what
an NSM certificate's life looks like. Every test pins `now` inside that window;
`merkl.core` reads no clock, so an expired fixture is verifiable forever.

`debug-with-bindings` is the only public document we could find that carries both
a `public_key` and a `user_data`, which are the two fields a receipt binds
itself to. Their contents are a joke (`my super secret key`, `hello, world!`) and
that does not matter: what the vectors need is bytes AWS signed with those fields
populated.

## The root

`aws-nitro-root-g1.pem` is the certificate AWS publishes at
<https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip>.

| | |
|---|---|
| SHA-256 of the published zip | `8cf60e2b2efca96c6a9e71e851d00c1b6991cc09eadbe64a6a1d1b1eb9faff7c` |
| SHA-256 of the certificate (DER) | `641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b` |
| Subject | `C=US, O=Amazon, OU=AWS, CN=aws.nitro-enclaves` |
| Valid | 2019-10-28T13:28:05Z → 2049-10-28T14:28:05Z |

The zip digest is the one AWS documents alongside the download. Re-check it:

```bash
curl -sO https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
shasum -a 256 AWS_NitroEnclaves_Root-G1.zip
```

The same PEM is embedded in `merkl/core/verify/attestation.py` as
`NITRO_ROOT_G1_PEM`, and `tests/core/test_attestation.py` asserts the two are the
same bytes. A verifier that downloads its trust anchor at verification time
trusts whoever answered the request, so the copy in the code is the real one and
this file is the fixture that proves it was not edited.

## Refreshing

Only if a document has to be replaced. Prefer adding to `documents.json` over
replacing: a fixture from a different year is a different chain, and passing both
is what proves a verifier is not hard-coding one.

Do not "refresh" a document to make it current. There is no such thing — an
attestation document is a signed statement about a past moment, and every real
one is expired.
