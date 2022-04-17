from bitcoin_client.ledger_bitcoin import Client
from .conftest import SpeculosGlobals


def test_get_blinding_key(client: Client, speculos_globals: SpeculosGlobals):
    bk = client.liquid_get_blinding_key(bytes.fromhex('001452c16f41d5d8623bceceede0694b1950cb994250'))
    assert bk == bytes.fromhex('1887ea68676fb0804c846a3a818d95957ab86697fe8acc6f14178f9c5e553689')

    # script=0001020304...f8f9fafb - 252 bytes
    bk = client.liquid_get_blinding_key(bytes(range(0, 252)))
    assert bk == bytes.fromhex('81109c9df480f5c7b2b26c9fe168ddf191b9bd5efbeb4a4c579353e8a94c0085')

