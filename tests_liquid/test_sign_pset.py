import pytest

import threading

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


@has_automation(f"{tests_root}/automations/sign_with_default_wallet_accept.json")
def test_sign_psbt_singlesig_wpkh(client: Client, speculos_globals: SpeculosGlobals):

    psbt = open_pset_from_file(f"{tests_root}/pset/singlesig/single_confidential.psbt")

    fpr = speculos_globals.master_key_fingerprint.hex()

    # bech32 address (P2WPKH)
    wallet = BlindedWallet(
        name="",
        blinding_key="L24LLSbccJ52ESXkRvnKxYik3iBJvH2uQHf6X3xnsKZ3sw8RHMmA",
        policy_map="wpkh(@0)",
        keys_info=[
            f"[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P/**",
        ],
    )

    result = client.sign_psbt(psbt, wallet, None)

    # TODO: check with other SIGHASH options
    assert result == {
        0: bytes.fromhex(
            "3044022027f6b1c8afe995cdb43c61ce9bbd7fb21401925b53b7af21c9450f2baf47cb1d02201fd2574926d6ee1a7e364f4ef51a0634e62d442a4747cd3355536cd36d7ae9c501"
        )
    }
