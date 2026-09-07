"""Ask the Nitro Secure Module to vouch for this enclave, and for this key.

The NSM is a device the hypervisor exposes to an enclave and to nothing else. It
will sign a document containing the enclave's measurements (PCR0-PCR8) together
with up to three fields the enclave chooses. Merkl uses two of them, and which
two is the whole design:

* ``public_key`` — the policy public key. Without this the document says "some
  approved enclave is running", which is true of every enclave from that image,
  including one that generated a different key.
* ``user_data`` — the policy hash. Without this the document says nothing about
  *which policy* the enclave was enforcing when it signed, and a signer that
  swapped its policy would still attest identically.

Together they turn leaf 3 from "an enclave exists" into "this key, under this
policy, inside an enclave measuring these PCRs". That is the claim
``merkl.core.verify.attestation`` checks, and the three fields have to be the
same three on both sides or the check is theatre.

The transport is one ``ioctl`` on ``/dev/nsm``. That is deliberate: the
alternative is ``aws-nsm-interface`` or the Rust SDK's Python bindings, which
would put a compiled dependency inside the enclave image — the one place where
every byte is measured into PCR0 and has to be justified to whoever reads the
allowlist. The wire format is CBOR, and ``merkl.core.verify.cbor`` already speaks
it, so the whole client is a struct definition and forty lines.

Outside an enclave there is no ``/dev/nsm`` and construction fails loudly rather
than degrading into something that returns a plausible ``None``. A dev signer
uses ``DevKeystore``, whose ``attestation()`` is ``None`` and says so (plan D3).
"""

from __future__ import annotations

import base64
import ctypes
import fcntl
import os
from typing import Any, Final, Protocol

from merkl.core.canonical import JSONObject
from merkl.core.verify import cbor
from merkl.shared.errors import MerklError

NSM_DEVICE: Final = "/dev/nsm"

NSM_IOCTL_MAGIC: Final = 0x0A
NSM_REQUEST_MAX_SIZE: Final = 0x1000
NSM_RESPONSE_MAX_SIZE: Final = 0x3000

_IOC_WRITE: Final = 1
_IOC_READ: Final = 2

ATTESTATION_FORMAT: Final = "aws-nitro"
"""The ``format`` token receipt leaf 3 carries. Frozen with the leaf encoding."""

MAX_FIELD_BYTES: Final = 1024
"""NSM's own cap on ``user_data``, ``nonce`` and ``public_key``."""


class NsmError(MerklError):
    """The Nitro Secure Module is unavailable, or refused the request."""

    error_code = "keystore_error"


class _Iovec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]


class _NsmMessage(ctypes.Structure):
    """``struct nsm_message`` from the Nitro Enclaves kernel driver."""

    _fields_ = [("request", _Iovec), ("response", _Iovec)]


def _iowr(magic: int, number: int, size: int) -> int:
    """Linux ``_IOWR``: direction, size, type and number packed into 32 bits."""
    return ((_IOC_READ | _IOC_WRITE) << 30) | (size << 16) | (magic << 8) | number


NSM_IOCTL: Final = _iowr(NSM_IOCTL_MAGIC, 0, ctypes.sizeof(_NsmMessage))
"""``0xc0200a00`` on 64-bit Linux. Computed rather than pasted, so it stays right."""


class NsmPort(Protocol):
    """What the keystore needs from the enclave's attestation device.

    Two methods, because those are the two things that must come from hardware
    rather than from software: a signed statement about this enclave, and entropy
    the enclave did not have to trust its own userspace for.
    """

    def attest(
        self,
        *,
        public_key: bytes | None = None,
        user_data: bytes | None = None,
        nonce: bytes | None = None,
    ) -> bytes:
        """A COSE_Sign1 attestation document, CBOR bytes."""
        ...

    def random(self, count: int) -> bytes:
        """``count`` bytes of hardware entropy."""
        ...


class NitroSecureModule:
    """The real device. Only constructible inside an enclave."""

    def __init__(self, device: str = NSM_DEVICE) -> None:
        try:
            self._fd = os.open(device, os.O_RDWR | os.O_CLOEXEC)
        except OSError as exc:
            raise NsmError(
                f"cannot open {device}: this process is not running inside a Nitro Enclave, "
                "or the enclave was started without an NSM device"
            ) from exc

    def close(self) -> None:
        if self._fd >= 0:
            os.close(self._fd)
            self._fd = -1

    def __enter__(self) -> NitroSecureModule:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- the port ---------------------------------------------------------- #

    def attest(
        self,
        *,
        public_key: bytes | None = None,
        user_data: bytes | None = None,
        nonce: bytes | None = None,
    ) -> bytes:
        for name, value in (
            ("public_key", public_key),
            ("user_data", user_data),
            ("nonce", nonce),
        ):
            if value is not None and len(value) > MAX_FIELD_BYTES:
                raise NsmError(f"{name} is {len(value)} bytes, over the NSM's {MAX_FIELD_BYTES}")
        response = self._call(
            {
                "Attestation": {
                    "public_key": public_key,
                    "user_data": user_data,
                    "nonce": nonce,
                }
            }
        )
        document = _variant(response, "Attestation").get("document")
        if not isinstance(document, bytes) or not document:
            raise NsmError("the NSM returned an attestation with no document")
        return document

    def random(self, count: int) -> bytes:
        if count <= 0:
            raise NsmError("random() needs a positive byte count")
        collected = b""
        while len(collected) < count:
            response = self._call("GetRandom")
            chunk = _variant(response, "GetRandom").get("random")
            if not isinstance(chunk, bytes) or not chunk:
                raise NsmError("the NSM returned no entropy")
            collected += chunk
        return collected[:count]

    # -- transport --------------------------------------------------------- #

    def _call(self, request: cbor.CborValue) -> dict[int | str, Any]:
        """One ioctl: CBOR in, CBOR out, buffers sized by the driver's limits."""
        encoded = cbor.encode(request)
        if len(encoded) > NSM_REQUEST_MAX_SIZE:
            raise NsmError(f"NSM request is {len(encoded)} bytes, over the driver's limit")
        request_buffer = ctypes.create_string_buffer(encoded, len(encoded))
        response_buffer = ctypes.create_string_buffer(NSM_RESPONSE_MAX_SIZE)
        message = _NsmMessage(
            request=_Iovec(
                ctypes.cast(request_buffer, ctypes.c_void_p), ctypes.c_size_t(len(encoded))
            ),
            response=_Iovec(
                ctypes.cast(response_buffer, ctypes.c_void_p),
                ctypes.c_size_t(NSM_RESPONSE_MAX_SIZE),
            ),
        )
        try:
            fcntl.ioctl(self._fd, NSM_IOCTL, message, True)
        except OSError as exc:
            raise NsmError(f"the NSM ioctl failed: {exc}") from exc
        used = message.response.iov_len
        if used <= 0 or used > NSM_RESPONSE_MAX_SIZE:
            raise NsmError(f"the NSM wrote {used} bytes, which cannot be a response")
        return decode_response(response_buffer.raw[:used])


def decode_response(raw: bytes) -> dict[int | str, Any]:
    """Decode one NSM response, turning its ``Error`` variant into an exception.

    Separate from the ioctl so the wire format can be tested without a device —
    the framing is the part that can be wrong on a laptop, and the ioctl is the
    part that cannot be exercised anywhere but inside an enclave.
    """
    try:
        response = cbor.loads(raw)
    except cbor.CborError as exc:
        raise NsmError(f"the NSM response is not CBOR: {exc}") from exc
    if isinstance(response, str):
        raise NsmError(f"the NSM answered {response!r}, which carries no data")
    if not isinstance(response, dict) or len(response) != 1:
        raise NsmError("an NSM response is a single-variant CBOR map")
    if "Error" in response:
        raise NsmError(f"the NSM refused the request: {response['Error']!r}")
    return response


def _variant(response: dict[int | str, Any], expected: str) -> dict[str, Any]:
    body = response.get(expected)
    if not isinstance(body, dict):
        raise NsmError(f"the NSM answered {sorted(response)!r}, not {expected}")
    return {str(k): v for k, v in body.items()}


def attestation_content(
    document: bytes,
    policy_public_key: str,
    *,
    document_format: str = ATTESTATION_FORMAT,
) -> JSONObject:
    """Receipt leaf 3, from a document the NSM just produced.

    The shape is frozen by ``merkl-receipt-leaf-v1``: ``{format, document,
    policy_public_key}``, with the document base64 of the CBOR. The policy hash
    is not repeated here — it is already in leaf 2 and the envelope, and it is
    bound into the document as ``user_data``, which is what the verifier holds
    the two against.
    """
    return {
        "format": document_format,
        "document": base64.b64encode(document).decode(),
        "policy_public_key": policy_public_key,
    }
