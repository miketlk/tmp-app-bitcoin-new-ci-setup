from bitcoin_client.ledger_bitcoin import Client, AddressType, MultisigWallet, PolicyMapWallet, BlindedWallet, BlindedMultisigWallet
from bitcoin_client.ledger_bitcoin.exception.errors import IncorrectDataError

import random
import string
import json
from pathlib import Path

import pytest

tests_root: Path = Path(__file__).parent

def random_wallet_name() -> str:
    charset = string.ascii_letters+string.digits
    return "wallet_" + ''.join(random.choice(charset) for i in range(random.randint(2, 16-7)))

def test_get_wallet_address_elip150_batch(client: Client, speculos_globals):
    # Ensure the tests are repeatable
    random.seed(1)

    with open(f"{tests_root}/wallets/wallets_elip150.json", "r") as read_file:
        test_data = json.load(read_file)

    # Loop through all test suites with valid vectors
    for test in test_data["valid"]:
        # Test confidential address
        wallet = BlindedWallet(
            name=random_wallet_name(),
            blinding_key=test["blinding_key"],
            policy_map=test["policy_map"],
            keys_info=test["keys_info"]
        )
        res = client.get_wallet_address(wallet, wallet.hmac(speculos_globals.wallet_registration_key), 0,  0, False)
        assert res == test["confidential_address"]

        # Test unconfidential address
        wallet = PolicyMapWallet(
            name=random_wallet_name(),
            policy_map=test["policy_map"],
            keys_info=test["keys_info"]
        )
        res = client.get_wallet_address(wallet, wallet.hmac(speculos_globals.wallet_registration_key), 0,  0, False)
        assert res == test["unconfidential_address"]

    # Loop through all test suites with invalid vectors
    for test in test_data["invalid"]:
        # Test confidential address
        wallet = BlindedWallet(
            name=random_wallet_name(),
            blinding_key=test["blinding_key"],
            policy_map=test["policy_map"],
            keys_info=test["keys_info"]
        )
        with pytest.raises(IncorrectDataError):
            client.get_wallet_address(wallet, wallet.hmac(speculos_globals.wallet_registration_key), 0,  0, False)
