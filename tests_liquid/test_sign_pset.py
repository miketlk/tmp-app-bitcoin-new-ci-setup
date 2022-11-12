import pytest

import threading

import json

from decimal import Decimal

from typing import List

from pathlib import Path

from bitcoin_client.ledger_bitcoin import Client, BlindedWallet, BlindedMultisigWallet, AddressType
from bitcoin_client.ledger_bitcoin.exception.errors import IncorrectDataError, NotSupportedError

from bitcoin_client.ledger_bitcoin.pset import PSET
from bitcoin_client.ledger_bitcoin.wallet import AddressType
from speculos.client import SpeculosClient

from test_utils import has_automation, bip0340, txmaker, mnemonic, SpeculosGlobals

from embit.script import Script
from embit.networks import NETWORKS

from test_utils.speculos import automation

import hmac
from hashlib import sha256

import random
import string

tests_root: Path = Path(__file__).parent


CURRENCY_TICKER = "TEST"


def format_amount(ticker: str, amount: int) -> str:
    """Formats an amounts in sats as shown in the app: divided by 10_000_000, with no trailing zeroes."""
    assert amount >= 0

    return f"{ticker} {str(Decimal(amount) / 100_000_000)}"


def should_go_right(event: dict):
    """Returns true if the current text event implies a "right" button press to proceed."""

    if event["text"].startswith("Review"):
        return True
    elif event["text"].startswith("Amount"):
        return True
    elif event["text"].startswith("Address"):
        return True
    elif event["text"].startswith("Confirm"):
        return True
    elif event["text"].startswith("Fees"):
        return True
    return False


def ux_thread_sign_psbt(speculos_client: SpeculosClient, all_events: List[dict]):
    """Completes the signing flow always going right and accepting at the appropriate time, while collecting all the events in all_events."""

    # press right until the last screen (will press the "right" button more times than needed)

    while True:
        event = speculos_client.get_next_event()
        all_events.append(event)

        if should_go_right(event):
            speculos_client.press_and_release("right")
        elif event["text"] == "Approve":
            speculos_client.press_and_release("both")
        elif event["text"] == "Accept":
            speculos_client.press_and_release("both")
            break


def parse_signing_events(events: List[dict]) -> dict:
    ret = dict()

    # each of these is True if the _previous_ event was matching (so the next text needs to be recorded)
    was_amount = False
    was_address = False
    was_fees = False

    cur_output_index = -1

    ret["addresses"] = []
    ret["amounts"] = []
    ret["fees"] = ""

    for ev in events:
        if ev["text"].startswith("output #"):
            idx_str = ev["text"][8:]

            assert int(idx_str) - 1 == cur_output_index + 1  # should not skip outputs

            cur_output_index = int(idx_str) - 1

            ret["addresses"].append("")
            ret["amounts"].append("")

        if was_address:
            ret["addresses"][-1] += ev["text"]
        if was_amount:
            ret["amounts"][-1] += ev["text"]

        if was_fees:
            ret["fees"] += ev["text"]

        was_amount = ev["text"].startswith("Amount")
        was_address = ev["text"].startswith("Address")
        was_fees = ev["text"].startswith("Fees")

    return ret


def open_pset_from_file(filename: str) -> PSET:
    raw_psbt_base64 = open(filename, "r").read()

    psbt = PSET()
    psbt.deserialize(raw_psbt_base64)

    return psbt


def random_wallet_name() -> str:
    charset = string.ascii_letters+string.digits
    return "wallet_" + ''.join(random.choice(charset) for i in range(random.randint(2, 16-7)))


# Takes quite a long time. It's recommended to enable stdout to see the progress (pytest -s).
@has_automation(f"{tests_root}/automations/sign_with_any_wallet_accept.json")
def test_sign_psbt_batch(client: Client, speculos_globals: SpeculosGlobals):

    client.debug = False
    random.seed(1)

    with open(f"{tests_root}/pset/test_data.json", "r") as read_file:
        test_data = json.load(read_file)

    for _, suite in test_data["valid"].items():
        wallet = BlindedWallet(
            name=random_wallet_name(),
            blinding_key=suite["mbk"],
            policy_map=suite["policy_map"],
            keys_info=suite["keys_info"]
        )

        wallet_hmac = None
        if len(suite["keys_info"]) > 1:
            # Register wallet before multisig tests
            wallet_id, wallet_hmac = client.register_wallet(wallet)
            assert wallet_id == wallet.id
            assert hmac.compare_digest(
                hmac.new(speculos_globals.wallet_registration_key, wallet_id, sha256).digest(),
                wallet_hmac,
            )

        for test in suite["tests"]:
            print("TEST:", suite["description"], test["description"])

            pset = PSET()
            pset.deserialize(test["pset"])
            result = client.sign_psbt(pset, wallet, wallet_hmac)

            for n_input, sigs in test["signatures"].items():
                result_sig = result[int(n_input)].hex()
                assert len(result_sig) >= 100 and len(result_sig) <= 144
                assert result_sig.startswith("304")
                assert result_sig in sigs["final_scriptwitness"]
