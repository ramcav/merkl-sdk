"""Deployment: the enclave image, the parent proxy, and the Terraform for both.

Not part of the ``merkl-sdk`` wheel (``pyproject.toml`` packages ``merkl`` only).
It is a package so the parts of it that *can* be executed on a laptop — the
parent's blob store and control channel — are importable by the test suite
rather than only readable.
"""
