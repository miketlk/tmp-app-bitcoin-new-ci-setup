from bitcoin_client.ledger_bitcoin import Client, AddressType, MultisigWallet, PolicyMapWallet, BlindedWallet, BlindedMultisigWallet
from bitcoin_client.ledger_bitcoin.exception.errors import IncorrectDataError

import pytest


def test_get_wallet_address_singlesig_wit(client: Client):
    # bech32 address (P2WPKH)
    wallet = PolicyMapWallet(
        name="",
        policy_map="wpkh(@0)",
        keys_info=[
            f"[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P/**",
        ],
    )

    res = client.get_wallet_address(wallet, None, 0,  0, False)
    assert res == "ert1qzdr7s2sr0dwmkwx033r4nujzk86u0cy6nxw6ml"

    res = client.get_wallet_address(wallet, None, 1, 15, False)
    assert res == "ert1qlrvzyx8jcjfj2xuy69du9trtxnsvjupehr4ewv"


def test_get_wallet_confidential_address_singlesig_wit(client: Client):
    # bech32 address (P2WPKH)
    wallet = BlindedWallet(
        name="",
        blinding_key="KwdAn3qzU2nLSn9mdYjwfHDcLsSmYRF3zT7Bk5DMxts6Si3NZUXp",
        policy_map="wpkh(@0)",
        keys_info=[
            f"[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P/**",
        ],
    )

    res = client.get_wallet_address(wallet, None, 0,  0, False)
    assert res == "el1qqvk6gl0lgs80w8rargdqyfsl7f0llsttzsx8gd4fz262cjnt0uxh6y68aq4qx76ahvuvlrz8t8ey9v04clsf58w045gzmxga3"

    res = client.get_wallet_address(wallet, None, 1, 15, False)
    assert res == "el1qqwfu5kl52jxc05g5nrux3almgt4ryz8eandhsjjnjw3k0jhetd9vp7xcygv093yny5dcf52mc2kxkd8qe9crjknppwuda885y"


def test_get_wallet_address_singlesig_sh_wit(client: Client):
    # wrapped segwit addresses (P2SH-P2WPKH)
    wallet = PolicyMapWallet(
        name="",
        policy_map="sh(wpkh(@0))",
        keys_info=[
            f"[f5acc2fd/49'/1'/0']tpubDC871vGLAiKPcwAw22EjhKVLk5L98UGXBEcGR8gpcigLQVDDfgcYW24QBEyTHTSFEjgJgbaHU8CdRi9vmG4cPm1kPLmZhJEP17FMBdNheh3/**",
        ],
    )

    res = client.get_wallet_address(wallet, None, 0,  0, False)
    assert res == "XHPmTmp4RyhZdQQ4Q5gGSfDdH9NAJf8LFn"

    res = client.get_wallet_address(wallet, None, 1, 15, False)
    assert res == "XUhMv7NnGaC3qgDGdmdTsCj8pnSeDSccur"


def test_get_wallet_confidential_address_singlesig_sh_wit(client: Client):
    # wrapped segwit addresses (P2SH-P2WPKH)
    wallet = BlindedWallet(
        name="",
        blinding_key="KwdAn3qzU2nLSn9mdYjwfHDcLsSmYRF3zT7Bk5DMxts6Si3NZUXp",
        policy_map="sh(wpkh(@0))",
        keys_info=[
            f"[f5acc2fd/49'/1'/0']tpubDC871vGLAiKPcwAw22EjhKVLk5L98UGXBEcGR8gpcigLQVDDfgcYW24QBEyTHTSFEjgJgbaHU8CdRi9vmG4cPm1kPLmZhJEP17FMBdNheh3/**",
        ],
    )

    res = client.get_wallet_address(wallet, None, 0,  0, False)
    assert res == "AzpwWmd4zRxfbpKrQRyTrbz5uzaPtvkYqMo5TTzEwk84fsR8mmymQZcCw2Y8nFh7duqWAp9n8fHaeaQJ"

    res = client.get_wallet_address(wallet, None, 1, 15, False)
    assert res == "AzpwstV1pi7SykboRfjZ5obJDw4hsRSUhsZeaoSZxVoynfZ7Jjkges6ZkVWmx1jrED4wLkrDcP8M4Zzk"


def test_get_wallet_address_singlesig_taproot(client: Client):
    # test for a native taproot wallet (bech32m addresses, per BIP-0086)

    wallet = PolicyMapWallet(
        name="",
        policy_map="tr(@0)",
        keys_info=[
            f"[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U/**",
        ],
    )

    res = client.get_wallet_address(wallet, None, 0, 0, False)
    assert res == "ert1pws8wvnj99ca6acf8kq7pjk7vyxknah0d9mexckh5s0vu2ccy68jsehezqq"

    res = client.get_wallet_address(wallet, None, 0, 9, False)
    assert res == "ert1psl7eyk2jyjzq6evqvan854fts7a5j65rth25yqahkd2a765yvj0q5zjv08"

    res = client.get_wallet_address(wallet, None, 1, 0, False)
    assert res == "ert1pmr60r5vfjmdkrwcu4a2z8h39mzs7a6wf2rfhuml6qgcp940x9cxszp8e36"

    res = client.get_wallet_address(wallet, None, 1, 9, False)
    assert res == "ert1p98d6s9jkf0la8ras4nnm72zme5r03fexn29e3pgz4qksdy84ndpq5clwz5"


def test_get_wallet_confidential_address_singlesig_taproot(client: Client):
    # test for a native taproot wallet (bech32m addresses, per BIP-0086)

    wallet = BlindedWallet(
        name="",
        blinding_key="KwdAn3qzU2nLSn9mdYjwfHDcLsSmYRF3zT7Bk5DMxts6Si3NZUXp",
        policy_map="tr(@0)",
        keys_info=[
            f"[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U/**",
        ],
    )

    res = client.get_wallet_address(wallet, None, 0, 0, False)
    assert res == "el1pqg07ysw3s0n8xvq0q0e8xx2as0d5g88ufegmum5hqlmwcmu7t25hqaqwue8y2t3m4msj0vpur9ducgdd8mw76thjd3d0fq7ec43sf509vzd04meg4245"

    res = client.get_wallet_address(wallet, None, 0, 9, False)
    assert res == "el1pqff2fah8mwpcj9g63jf4w5er6qppmrvf0pstw0ywnlyjhllvr84p4plajfv4yfyyp4jcqemx0f2jhpamf94gxhw4ggpm0v64ma4ggey7dh62hwaz3zpx"

    res = client.get_wallet_address(wallet, None, 1, 0, False)
    assert res == "el1pqgc4kq04mthvlzztfdypdc7nsn82xj9almax9edvacp5xnpdkaw78k8578gcn9kmvxa3et65y00ztk9pam5uj5xn0ehl5q3szt27vtsdr3awklkfsw9d"

    res = client.get_wallet_address(wallet, None, 1, 9, False)
    assert res == "el1pqwzfwa3n70fkcj3gc8uljg70as6tn3aae2s6wnunyfstfw40ve5s52wm4qt9vjll6w8mpt88hu59hngxlznjdx5tnzzs92pdq6g0tx6zjqp5vw2dnc93"

# Multisig

def test_get_wallet_address_multisig_sh_wit(client: Client):
    # test for a wrapped segwit multisig wallet

    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.SH_WIT,
        threshold=2,
        keys_info=[
            f"[f5acc2fd/48'/1'/0'/1']tpubDFAqEGNyad35YgH8zxvxFZqNUoPtr5mDojs7wzbXQBHTZ4xHeVXG6w2HvsKvjBpaRpTmjYDjdPg5w2c6Wvu8QBkyMDrmBWdCyqkDM7reSsY/**",
            f"[42b01983/48'/1'/0'/1']tpubDFjEjEPeyFun4mXBDxjLLx7hSM8jpMYNoSckRMtYygsAh4ZUtXKJtczddeHRKQ1Mzq8B6MWy3iUJyeKmJwiEKDd4rXxazBSjAEHzibDEhVK/**"
        ],
    )
    wallet_hmac = bytes.fromhex(
        "22125dd3bdec5a3c095aed3f1a03ce9337f8422dd33e8235e37f0ffc49d4b5e0"
    )

    res = client.get_wallet_address(wallet, wallet_hmac, 0, 0, False)
    assert res == "XYMYxdKp2nXqk6TVWFRxGMUJrEovELhDvc"


def test_get_wallet_confidential_address_multisig_sh_wit(client: Client):
    # test for a blinded wrapped segwit multisig wallet

    # blinded(slip77(L1XvKmnKWuC4a5sbz3Ez6LCfMCbaXMBCcQk7C62ziN5NjoEgjN5N),sh(wsh(sortedmulti(2,
    #   [f5acc2fd/48h/1h/0h/2h]tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK/{0,1}/*,
    #   [42b01983/48h/1h/0h/2h]tpubDFjEjEPeyFun6FHqS248kK51SwLVx3hVzWdAFwsDXza1Lfjy1KASoBhMiiJMqtJTUAPdM7zbrx3BNgYMQNyGNVwkyNS1Wi82bb2Hwij7K9L/{0,1}/*,
    #   [9860e1eb/48h/1h/0h/2h]tpubDESXi1fi17YeJJA7xAn5sqHPvEBFpPscRv9QEzJpJQw4D7QfAWw8xfXuGdW1wMQvdj9vz8SxCSTVdhcS4Sro5GYdMojR2JYE3GuHBWipnxy/{0,1}/*
    # ))))

    wallet = BlindedMultisigWallet(
        name="Cold storage",
        blinding_key="L1XvKmnKWuC4a5sbz3Ez6LCfMCbaXMBCcQk7C62ziN5NjoEgjN5N",
        address_type=AddressType.SH_WIT,
        threshold=2,
        keys_info=[
            f"[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK/**",
            f"[42b01983/48'/1'/0'/2']tpubDFjEjEPeyFun6FHqS248kK51SwLVx3hVzWdAFwsDXza1Lfjy1KASoBhMiiJMqtJTUAPdM7zbrx3BNgYMQNyGNVwkyNS1Wi82bb2Hwij7K9L/**",
            f"[9860e1eb/48'/1'/0'/2']tpubDESXi1fi17YeJJA7xAn5sqHPvEBFpPscRv9QEzJpJQw4D7QfAWw8xfXuGdW1wMQvdj9vz8SxCSTVdhcS4Sro5GYdMojR2JYE3GuHBWipnxy/**"
        ],
    )
    wallet_hmac = bytes.fromhex(
        "c20ef8b63ce8cdd84bf75bb1c63a041610669c6e3622d84efaa41f631c914858"
    )

    res = client.get_wallet_address(wallet, wallet_hmac, 0, 0, False)
    assert res == "AzppatN1RMEjDYu1dosnD4vB37f8xEcFv5gJiWiUSLKpAvX4XKRrvctNJqQoJUUYJ74MGtyccSNcvJPS"


def test_get_wallet_address_multisig_wit(client: Client):
    # test for a native segwit multisig wallet (bech32 address)

    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.WIT,
        threshold=2,
        keys_info=[
            "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK/**",
            "[42b01983/48'/1'/0'/2']tpubDFjEjEPeyFun6FHqS248kK51SwLVx3hVzWdAFwsDXza1Lfjy1KASoBhMiiJMqtJTUAPdM7zbrx3BNgYMQNyGNVwkyNS1Wi82bb2Hwij7K9L/**",
            "[9860e1eb/48'/1'/0'/2']tpubDESXi1fi17YeJJA7xAn5sqHPvEBFpPscRv9QEzJpJQw4D7QfAWw8xfXuGdW1wMQvdj9vz8SxCSTVdhcS4Sro5GYdMojR2JYE3GuHBWipnxy/**"
        ],
    )
    wallet_hmac = bytes.fromhex(
        "83c29134508da25622a65c66f3a9c45f9d0db81b965c40ab1d255e4e41320c05"
    )

    res = client.get_wallet_address(wallet, wallet_hmac, 0, 0, False)
    assert res == "ert1qm00c95pvkjp97fvswsl09j7pgt75m54srzsu2y87wau7v423q2kqthjx8a"


def test_get_wallet_confidential_address_multisig_wit(client: Client):
    # test for a native segwit multisig wallet (bech32 address)

    # blinded(slip77(L1XvKmnKWuC4a5sbz3Ez6LCfMCbaXMBCcQk7C62ziN5NjoEgjN5N),wsh(sortedmulti(2,
    #   [f5acc2fd/48h/1h/0h/2h]tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK/{0,1}/*,
    #   [42b01983/48h/1h/0h/2h]tpubDFjEjEPeyFun6FHqS248kK51SwLVx3hVzWdAFwsDXza1Lfjy1KASoBhMiiJMqtJTUAPdM7zbrx3BNgYMQNyGNVwkyNS1Wi82bb2Hwij7K9L/{0,1}/*,
    #   [9860e1eb/48h/1h/0h/2h]tpubDESXi1fi17YeJJA7xAn5sqHPvEBFpPscRv9QEzJpJQw4D7QfAWw8xfXuGdW1wMQvdj9vz8SxCSTVdhcS4Sro5GYdMojR2JYE3GuHBWipnxy/{0,1}/*
    # )))

    wallet = BlindedMultisigWallet(
        name="Cold storage",
        blinding_key="L1XvKmnKWuC4a5sbz3Ez6LCfMCbaXMBCcQk7C62ziN5NjoEgjN5N",
        address_type=AddressType.WIT,
        threshold=2,
        keys_info=[
            "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK/**",
            "[42b01983/48'/1'/0'/2']tpubDFjEjEPeyFun6FHqS248kK51SwLVx3hVzWdAFwsDXza1Lfjy1KASoBhMiiJMqtJTUAPdM7zbrx3BNgYMQNyGNVwkyNS1Wi82bb2Hwij7K9L/**",
            "[9860e1eb/48'/1'/0'/2']tpubDESXi1fi17YeJJA7xAn5sqHPvEBFpPscRv9QEzJpJQw4D7QfAWw8xfXuGdW1wMQvdj9vz8SxCSTVdhcS4Sro5GYdMojR2JYE3GuHBWipnxy/**"
        ],
    )
    wallet_hmac = bytes.fromhex(
        "42feebc1aac60c4e6a6030bef8444a631e759d0f10de85ef939a46d7010f0d64"
    )

    res = client.get_wallet_address(wallet, wallet_hmac, 0, 0, False)
    assert res == "el1qqwuytsp6xrqhuku4cqqftdasvf6d6rkxjlrf90ptm3670tx2pkwlfk7lstgzedyztujeqap77t9uzshafhftqx9pc5g0uameue24zq4vcu0n02rjs05c"


# Failure cases for default wallets

def test_get_wallet_address_default_fail_wrongkeys(client: Client):
    # 0 keys info should be rejected
    with pytest.raises(IncorrectDataError):
        client.get_wallet_address(PolicyMapWallet(
            name="",
            policy_map="wpkh(@0)",
            keys_info=[],
        ), None, 0,  0, False)

    # more than 1 key should be rejected
    with pytest.raises(IncorrectDataError):
        client.get_wallet_address(PolicyMapWallet(
            name="",
            policy_map="wpkh(@0)",
            keys_info=[
                f"[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P/**",
                f"[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P/**"
            ],
        ), None, 0,  0, False)

    # wrong BIP44 purpose should be rejected (here using 49' for a P2WPKH address)
    with pytest.raises(IncorrectDataError):
        client.get_wallet_address(PolicyMapWallet(
            name="",
            policy_map="wpkh(@0)",
            keys_info=[
                f"[f5acc2fd/49'/1'/0']tpubDC871vGLAiKPcwAw22EjhKVLk5L98UGXBEcGR8gpcigLQVDDfgcYW24QBEyTHTSFEjgJgbaHU8CdRi9vmG4cPm1kPLmZhJEP17FMBdNheh3/**",
            ],
        ), None, 0,  0, False)

    # mismatching pubkey (claiming key origin "84'/1'/0'", but that's the extended dpubkey for "49'/1'/0'"")
    with pytest.raises(IncorrectDataError):
        client.get_wallet_address(PolicyMapWallet(
            name="",
            policy_map="wpkh(@0)",
            keys_info=[
                f"[f5acc2fd/84'/1'/0']tpubDC871vGLAiKPcwAw22EjhKVLk5L98UGXBEcGR8gpcigLQVDDfgcYW24QBEyTHTSFEjgJgbaHU8CdRi9vmG4cPm1kPLmZhJEP17FMBdNheh3/**",
            ],
        ), None, 0,  0, False)

    # wrong master fingerprint
    with pytest.raises(IncorrectDataError):
        client.get_wallet_address(PolicyMapWallet(
            name="",
            policy_map="wpkh(@0)",
            keys_info=[
                f"[05acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P/**",
            ],
        ), None, 0,  0, False)

    # too large address_index, cannot be done non-silently
    with pytest.raises(IncorrectDataError):
        client.get_wallet_address(PolicyMapWallet(
            name="",
            policy_map="wpkh(@0)",
            keys_info=[
                f"[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P/**",
            ],
        ), None, 0,  100000, False)
