"""XRPL settlement: multisigned Payments anchored by a memo (plan section 7).

Requires the ``xrpl`` extra (``pip install 'merkl-sdk[xrpl]'``). This is the only
package in the distribution that imports ``xrpl-py``; core, the signer and the
SDK never do.
"""

from merkl.adapters.xrpl.adapter import (
    MAINNET_JSON_RPC,
    MAINNET_WEBSOCKET,
    TESTNET_JSON_RPC,
    TESTNET_WEBSOCKET,
    XrplAdapterError,
    XrplSettlementAdapter,
    currency_code,
    ripple_time,
    signer_address,
    to_xrpl_amount,
)
from merkl.adapters.xrpl.bootstrap import (
    TreasurySetup,
    bootstrap_treasury,
    load_wallets,
    verify_treasury,
)

__all__ = [
    "MAINNET_JSON_RPC",
    "MAINNET_WEBSOCKET",
    "TESTNET_JSON_RPC",
    "TESTNET_WEBSOCKET",
    "TreasurySetup",
    "XrplAdapterError",
    "XrplSettlementAdapter",
    "bootstrap_treasury",
    "currency_code",
    "load_wallets",
    "ripple_time",
    "signer_address",
    "to_xrpl_amount",
    "verify_treasury",
]
