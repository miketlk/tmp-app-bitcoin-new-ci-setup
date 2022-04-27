from bitcoin_client.ledger_bitcoin import Client, AddressType, PolicyMapWallet, BlindedWallet, BlindedMultisigWallet
from bitcoin_client.ledger_bitcoin.exception.errors import IncorrectDataError, NotSupportedError
from bitcoin_client.ledger_bitcoin.exception import DenyError

from test_utils import automation

import hmac
from hashlib import sha256

import pytest

# TODO: add single sig wallet
# TODO: add multisig wallet

# TODO: remove
@automation("automations/register_wallet_accept.json")
@pytest.mark.skip(reason="Non-working")
def test_register_nonblinded_wallet_accept_singlesig_wit(client: Client, speculos_globals):
    # bech32 address (P2WPKH)
    wallet = PolicyMapWallet(
        name="",
        policy_map="wpkh(@0)",
        keys_info=[
            f"[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P/**",
        ],
    )

    wallet_id, wallet_hmac = client.register_wallet(wallet)

    assert wallet_id == wallet.id

    assert hmac.compare_digest(
        hmac.new(speculos_globals.wallet_registration_key, wallet_id, sha256).digest(),
        wallet_hmac,
    )

@automation("automations/register_wallet_accept.json")
@pytest.mark.skip(reason="Not supported yet")
def test_register_blinded_wallet_accept_singlesig_wit(client: Client, speculos_globals):
    # bech32 address (P2WPKH)
    wallet = BlindedWallet(
        name="Cold storage",
        blinding_key="KwdAn3qzU2nLSn9mdYjwfHDcLsSmYRF3zT7Bk5DMxts6Si3NZUXp",
        policy_map="wpkh(@0)",
        keys_info=[
            f"[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P/**",
        ],
    )

    wallet_id, wallet_hmac = client.register_wallet(wallet)

    assert wallet_id == wallet.id

    assert hmac.compare_digest(
        hmac.new(speculos_globals.wallet_registration_key, wallet_id, sha256).digest(),
        wallet_hmac,
    )
