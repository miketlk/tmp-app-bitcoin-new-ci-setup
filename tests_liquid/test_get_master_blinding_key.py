from bitcoin_client.ledger_bitcoin import Client
from .conftest import SpeculosGlobals
from test_utils import mnemonic

def test_get_master_blinding_key(client: Client, speculos_globals: SpeculosGlobals):
    mbk = client.liquid_get_master_blinding_key()
    assert mbk == bytes.fromhex('0c11648c2c6df4f9dacdb4c8d35d6166d94cea2b9ad37833a82210bb7c9f5fb4')
