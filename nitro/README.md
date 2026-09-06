# The Nitro signer

The Merkl policy signer, running inside an AWS Nitro Enclave in **the customer's
own account**. Merkl never holds the key. Nobody holds the key: it is generated
inside the enclave, sealed under a KMS key whose policy names measurements the
customer pinned, and it exists in plaintext only in memory the hypervisor will
not let anything else read.

What that buys, precisely: receipt leaf 3 stops being a promise. It carries an
attestation document signed by AWS hardware saying *this key, under this policy,
inside an enclave measuring these PCRs* — and anyone can check it offline, years
later, with `merkl.core.verify.attestation` and no trusted party.

## What is here

```
nitro/
  Dockerfile.enclave      the measured image: signer + rail codec + policy
  Dockerfile.parent       the relay: HTTP in, vsock out, trusted by nothing
  enclave/main.py         boot, unseal, bind the policy, serve vsock
  parent/proxy.py         relay, sealed-blob store, credential forwarding
  terraform/              enclave-enabled instance, IAM, KMS with PCR conditions
```

Two files are **not** in git and have to be placed by whoever builds the image:

| Path | What | Why not committed |
|---|---|---|
| `nitro/policy.json` | The signed policy document (`SignedPolicy`) for this treasury | It names one treasury's approvers and limits. It is measured into PCR0, which is the point. |
| `nitro/vendor/kmstool_enclave_cli`, `nitro/vendor/libnsm.so` | Built from [`aws-nitro-enclaves-sdk-c`](https://github.com/aws/aws-nitro-enclaves-sdk-c) | A binary in git is a binary nobody reviews. Build it, or use `MERKL_KMS_BACKEND=botocore` and skip both. |

## Build

The enclave image is the security boundary, so build it from a wheel built from
this repo — not from PyPI, so what is measured is what was reviewed.

```bash
# 1. the wheel
uv build --wheel --out-dir dist

# 2. the docker image  (--provenance=false: attestation layers move PCR0)
docker build --provenance=false --file nitro/Dockerfile.enclave \
  --build-arg MERKL_KMS_KEY_ID="$(terraform -chdir=nitro/terraform output -raw kms_key_arn)" \
  --build-arg AWS_REGION=us-east-1 \
  --tag merkl-signer:0.1.1 .

# 3. the enclave image file, and the measurements
nitro-cli build-enclave --docker-uri merkl-signer:0.1.1 --output-file merkl-signer.eif
```

`build-enclave` prints the PCRs. They look like this:

```json
{
  "Measurements": {
    "HashAlgorithm": "Sha384 { ... }",
    "PCR0": "9a7b…",
    "PCR1": "bcdf…",
    "PCR2": "21c0…"
  }
}
```

| PCR | Measures | Moves when |
|---|---|---|
| PCR0 | the whole enclave image | any change at all, including a base-image digest |
| PCR1 | the kernel and bootstrap | the `nitro-cli` version changes |
| PCR2 | the user application | the code changes but the base does not |
| PCR8 | the certificate a *signed* image was signed with | the signing certificate changes — and not on a rebuild, which is why it is the right one to pin if you sign images |

**PCR0 changes on every build.** Two builds of the same source can differ if
anything underneath moved, which is why the base image is pinned by digest and
why the wheel is built locally. If you want an allowlist that survives a rebuild,
sign the image (`nitro-cli build-enclave --signing-certificate …
--private-key …`) and pin PCR8 alone.

An all-zero PCR means the enclave was started with `--debug-mode`. Its
measurements mean nothing and its console is readable from the parent. Never pin
one; `merkl.core.verify.attestation` fails such a document by default and the
Terraform refuses one in `enclave_pcrs`.

## Pin the allowlist

Two places, and they must agree:

```hcl
# nitro/terraform/terraform.tfvars — what KMS will decrypt for
enclave_pcrs = {
  "0" = "9a7b…"   # 96 lowercase hex characters
  "1" = "bcdf…"
  "2" = "21c0…"
}
```

```python
# what a verifier will accept, wherever receipts are checked
from merkl.core.verify.attestation import AttestationTrust

TRUST = AttestationTrust(pcrs={0: "9a7b…", 1: "bcdf…", 2: "21c0…"})
```

The KMS condition stops an unapproved enclave from *getting* the key. The
verifier's allowlist stops an unapproved enclave's receipts from being *believed*.
Different failures, both needed: an attacker who somehow obtained the key still
cannot produce an attestation from an enclave you pinned.

## Deploy

```bash
terraform -chdir=nitro/terraform init
terraform -chdir=nitro/terraform apply   # creates the KMS key, IAM role, instance

# on the instance (aws ssm start-session --target "$(terraform … output -raw instance_id)")
sudo nitro-cli run-enclave --eif-path merkl-signer.eif --cpu-count 2 --memory 1024
nitro-cli describe-enclaves | jq -r '.[0].EnclaveCID'    # → 16, usually

docker run -d --restart=always --network host --device /dev/vsock \
  -v /var/lib/merkl:/var/lib/merkl merkl-parent:0.1.1 \
  --cid 16 --history-provider yourpkg.rail:read_outflows
```

`--history-provider` is `package.module:callable`, taking `(treasury, since)` and
returning `Outflow.to_content()` objects. Reconciliation (plan D17) needs the
rail's validated outflows, reading a ledger needs a network the enclave does not
have, and `XrplSettlementAdapter` is constructed with an *agent wallet* because
its main job is signing transactions — the parent is precisely the process that
must not hold a signing key. So the operator supplies a read-only reader. Without
one the enclave reconciles against nothing, and its `unmatched_outflows` line is
empty because it saw no outflows rather than because there were none.

Then, from the agent's host:

```python
from merkl.adapters.signer_nitro import NitroSignerClient

async with NitroSignerClient(base_url="http://127.0.0.1:8787") as signer:
    await signer.assert_attested(trust=TRUST, now=datetime.now(UTC), policy_hash=POLICY_HASH)
```

`assert_attested` is the moment to find out you are talking to the wrong enclave.
It is not called automatically — see `merkl/adapters/signer_nitro/client.py` for
why — so call it at startup, and again whenever you want to know it is still the
same signer.

## Runbook

**First boot.** The enclave finds no sealed blob, generates a key from NSM
entropy mixed with the process CSPRNG, seals it with `kms:Encrypt`, and hands the
ciphertext to the parent, which writes `/var/lib/merkl/policy-key.sealed`. Back
up that file. Losing it and the KMS key together loses the signer's identity, and
a treasury whose signer list names a key nobody can produce is a treasury that
cannot pay.

**Reconciliation.** At boot and every `MERKL_RECONCILE_SECONDS` (300 by default)
the enclave asks the parent for rail history, parses it into checked `Outflow`
objects, and compares it to state it wrote itself. `UNMATCHED OUTFLOWS` in the
enclave log is the line to alert on: money left the treasury with no
authorization on record. A parent that invents outflows makes its own instance
look like it is leaking; a parent that hides them hides its own alarm. Neither
moves a payment — nothing on that channel reaches the decision path.

**A restart.** The parent hands the blob back, `kms:Decrypt` opens it under the
same measurements, the same public key comes up. Nothing else changes.

**A code change.** New PCR0. The old sealed blob is now unopenable, deliberately.
Sequence: build → read the new PCRs → `terraform apply` with *both* the old and
the new PCR0 allowed → restart the enclave → confirm the new one boots and
`health` reports the same `signer_public_key` → `terraform apply` again with only
the new PCR0. Skipping the overlap is how a deploy becomes an outage.

**A policy change.** `policy_update` (plan D16) changes the policy hash the
enclave attests to, and the next attestation says so — no rebuild needed, because
the policy hash is read through a callable. But the policy *document* is baked
into the image, so a permanent change should be rebuilt and re-pinned; use
`policy_update` for the change entry and the rebuild for the measurement.

**The enclave will not boot.** `nitro-cli console --enclave-id …` (debug builds
only, and a debug build is not one to run a treasury on). More usefully: the
parent logs `enclave unreachable` and returns `503`, which is a signer that
stops signing. Nothing settles. That is the correct failure.

**`AccessDeniedException` on decrypt.** The PCRs in the key policy do not match
the running enclave. Compare `nitro-cli describe-enclaves` measurements against
`terraform output pinned_pcrs`. Almost always a rebuild whose allowlist was not
re-pinned.

## Threat notes

The parent is assumed hostile. That is not a posture, it is the deployment: the
customer's own operators, their CI, and anything that gets root on the instance
are all "the parent".

**What the parent can do.** Refuse to start the enclave. Kill it. Drop, delay or
reorder its traffic. Serve a stale sealed blob. Lie about rail history. Read
every request and every decision that passes through the relay, including
destinations and amounts. All of it is availability and privacy. None of it
produces a payment.

**What the parent cannot do.** Read the policy key — it is sealed under a KMS key
policy that requires an attestation, and the parent has no NSM. Sign with it.
Make the enclave approve something the policy denies — the policy is measured
into PCR0, and a different policy is a different enclave that KMS will not
decrypt for. Produce an attestation document, so it cannot pretend to be the
enclave to a verifier. Roll the state back: a snapshot carries a monotonic
sequence and `SealedStateStore.restore` refuses to move backwards, so replaying
an old snapshot is an error rather than a way to spend a window twice.

**What AWS can do.** Everything, in the sense that they build the hardware and
run the PKI whose root this verifier pins. Nitro's design and its published
attestation are what is being trusted, and that trust is explicit — the root
certificate is embedded in `merkl/core/verify/attestation.py` with its
fingerprint, not fetched at verification time from whoever answers.

**What is outside all of it.** A compromised *agent* can still ask for payments,
and the policy is what refuses them. A compromised settlement adapter can still
produce bytes that encode a different payment, and the rail codec inside the
enclave is what catches that (`docs/SIGNER-RPC.md` section 5). The enclave
protects the key and the decision; it does not make the agent honest.

## What was executed, and what was not

Written on a Mac with no `nitro-cli`, no NSM device and no AWS account. Precisely:

| Artifact | Status |
|---|---|
| `merkl.core.verify.attestation` | **Executed.** Against three attestation documents AWS signed, with `now` pinned inside their validity windows. `tests/core/test_attestation.py`, `merkl/core/vectors/attestation/`. |
| `merkl.core.verify.cbor` | **Executed.** RFC 8949 vectors, property tests, and the real documents. |
| `merkl.adapters.nitro.cms` | **Executed.** Against envelopes `openssl cms -encrypt` produced. `tests/adapters/test_cms.py`. |
| `merkl.signer.vsock` framing | **Executed.** Over `socket.socketpair()`, including that vsock and HTTP answer byte-identically. |
| The parent's blob store, control channel and history provider | **Executed** under pytest, including that a bad provider is refused at startup and a rail that is down is an error rather than a crash. |
| `NitroKeystore` lifecycle | **Executed** against fake NSM and KMS ports: generate, seal, hand over, reopen, derive the state key, attest. |
| KMS request shaping | **Executed** against fakes: what goes out, and every refusal. |
| `Dockerfile.parent` | **Executed.** `docker build` succeeds; the image imports the proxy and the verifier, and refuses `--listen 0.0.0.0`. |
| `terraform/` | **Executed.** `terraform fmt -check` clean, `terraform validate` passes, the four `enclave_pcrs` validation expressions checked in `terraform console`. |
| `Dockerfile.enclave` | **Written, not built.** It needs `nitro/policy.json` and the vendored `kmstool_enclave_cli`, neither of which is in the repo. |
| `nitro-cli build-enclave`, the PCRs | **Written, not run.** No `nitro-cli`. |
| The NSM `ioctl` | **Written, not run.** No `/dev/nsm`. The request number is asserted against the driver's `_IOWR` encoding and the CBOR framing is tested; the syscall is not. |
| The KMS round trip | **Written, not run.** No AWS account. |
| `terraform apply` | **Written, not run.** No AWS account. |
| The parent ↔ enclave vsock hop | **Written, not run.** macOS has no `AF_VSOCK`. |

The first real deployment should expect to find something in the "not run" rows.
The rows above them are the ones a bug would be expensive in.
