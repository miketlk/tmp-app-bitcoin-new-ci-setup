#!/usr/bin/env python3
# Copyright (c) 2010 ArtForz -- public domain half-a-node
# Copyright (c) 2012 Jeff Garzik
# Copyright (c) 2010-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Bitcoin Object Python Serializations

Support of Elements transactions.

Based on the test/test_framework/mininode.py file from the
Bitcoin repository
"""

import copy
import struct

from .common import (
    hash256,
)
from ._script import (
    is_opreturn,
    is_p2sh,
    is_p2pkh,
    is_p2pk,
    is_witness,
    is_p2wsh,
)
from ._serialize import (
    deser_uint256,
    deser_string,
    deser_string_vector,
    deser_vector,
    Readable,
    ser_uint256,
    ser_string,
    ser_string_vector,
    ser_vector,
    uint256_from_str,
)

from typing import (
    List,
    Optional,
    Union,
    Tuple,
)

from .errors import PSBTSerializationError

from .tx import (
    COutPoint,
    CTxIn,
    CTxOut,
    CScriptWitness,
    CTxInWitness,
    CTxWitness,
    CTransaction
)

# Type for asset and token commitment
Commitment = Union[bytes, int, None]

class AssetIssuance(object):
    def __init__(
        self,
        nonce: Optional[bytes] = None,
        entropy: Optional[bytes] = None,
        amountCommitment: Commitment = None,
        tokenCommitment: Commitment = None
    ) -> None:
        self.nonce = nonce or b"\x00" * 32
        self.entropy = entropy or b"\x00" * 32
        self.amountCommitment = amountCommitment
        self.tokenCommitment = tokenCommitment

    @classmethod
    def _read_commitment(cls, stream: Readable) -> Commitment:
        c = stream.read(1)
        assert len(c) == 1
        if c == b"\x00": # None
            return None
        if c == b"\x01": # unconfidential
            r = stream.read(8)
            assert len(r) == 8
            return int.from_bytes(r, "big")
        # confidential
        r = stream.read(32)
        assert len(r) == 32
        return c + r

    @classmethod
    def _write_commitment(cls, c: Commitment) -> bytes:
        if c is None:
            return b"\x00"
        if isinstance(c, int):
            return b"\x01" + c.to_bytes(8, 'big')
        return c

    def deserialize(self, f: Readable) -> None:
        self.nonce = f.read(32)
        assert len(self.nonce) == 32
        self.entropy = f.read(32)
        assert len(self.entropy) == 32
        self.amountCommitment = self._read_commitment(f)
        self.tokenCommitment = self._read_commitment(f)

    def serialize(self) -> bytes:
        r = b""
        r += self.nonce
        r += self.entropy
        r += self._write_commitment(self.amountCommitment)
        r += self._write_commitment(self.tokenCommitment)
        return r

    def __repr__(self) -> str:
        return "AssetIssuance(nonce=%s entropy=%s amountCommitment=%s tokenCommitment=%s)" % (
            self.nonce,
            self.entropy,
            self.amountCommitment,
            self.tokenCommitment
        )


class CETxIn(CTxIn):
    def __init__(
        self,
        outpoint: Optional[COutPoint] = None,
        scriptSig: bytes = b"",
        nSequence: int = 0,
        isPegin: bool = False,
        assetIssuance: Optional[AssetIssuance] = None
    ) -> None:
        if outpoint is None:
            self.prevout = COutPoint()
        else:
            self.prevout = outpoint
        self.scriptSig = scriptSig
        self.nSequence = nSequence
        self.isPegin = isPegin
        self.assetIssuance = assetIssuance

    def deserialize(self, f: Readable) -> None:
        self.prevout = COutPoint()
        self.prevout.deserialize(f)
        self.scriptSig = deser_string(f)
        self.nSequence = struct.unpack("<I", f.read(4))[0]
        self.isPegin = False
        self.assetIssuance = None
        if self.prevout.n != 0xFFFFFFFF:
            self.isPegin = self.prevout.n & (1 << 30) != 0
            has_issuance = self.prevout.n & (1 << 31) != 0
            if has_issuance:
                self.assetIssuance = AssetIssuance()
                self.assetIssuance.deserialize(f)
            else:
                self.assetIssuance = None
            # Remove issue and pegin flags
            self.prevout.n &= 0x3FFFFFFF

    def serialize(self) -> bytes:
        prevout = self.prevout
        if self.has_issuance:
            prevout.n |= (1 << 31)
        if self.isPegin:
            prevout.n |= (1 << 30)

        r = b""
        r += prevout.serialize()
        r += ser_string(self.scriptSig)
        r += struct.pack("<I", self.nSequence)
        if self.has_issuance:
            r += self.assetIssuance.serialize()
        return r

    @property
    def has_issuance(self) -> bool:
        return self.assetIssuance is not None

    def __repr__(self) -> str:
        return "CETxIn(prevout=%s scriptSig=%s nSequence=%i isPegin=%r assetIssuance=%r)" \
            % (repr(self.prevout), self.scriptSig.hex(),
               self.nSequence, self.isPegin, self.assetIssuance)


class CETxOut(CTxOut):
    def __init__(
        self,
        asset: Optional[bytes] = None,
        nValue: int = 0,
        scriptPubKey: bytes = b"",
        ecdhPubKey: Optional[bytes] = None,
        witness: Optional['CETxOutWitness'] = None
    ) -> None:
        self.asset = asset
        self.nValue = nValue
        self.scriptPubKey = scriptPubKey
        self.ecdhPubKey = ecdhPubKey
        self.witness = witness if witness is not None else CETxOutWitness()

    def deserialize(self, f: Readable) -> None:
        self.asset = f.read(33)
        self.ecdhPubKey = None
        c = f.read(1)
        if c != b"\x01":
            self.nValue = c + f.read(32)
        else:
            self.nValue = struct.unpack("<q", f.read(8))[0]
        c = f.read(1)
        if c != b"\x00":
            self.ecdhPubKey = c + f.read(32)
        self.scriptPubKey = deser_string(f)

    def serialize(self) -> bytes:
        r = b""
        if len(self.asset) == 32:
            r += b"\x01"
        r += self.asset
        if isinstance(self.nValue, int):
            r += b"\x01" + struct.pack("<q", self.nValue)
        else:
            r += self.nValue
        if self.ecdhPubKey:
            r += self.ecdhPubKey
        else:
            r += b"\x00"
        r += ser_string(self.scriptPubKey)
        return r

    def is_opreturn(self) -> bool:
        return is_opreturn(self.scriptPubKey)

    def is_p2sh(self) -> bool:
        return is_p2sh(self.scriptPubKey)

    def is_p2wsh(self) -> bool:
        return is_p2wsh(self.scriptPubKey)

    def is_p2pkh(self) -> bool:
        return is_p2pkh(self.scriptPubKey)

    def is_p2pk(self) -> bool:
        return is_p2pk(self.scriptPubKey)

    def is_witness(self) -> Tuple[bool, int, bytes]:
        return is_witness(self.scriptPubKey)

    def is_blinded(self) -> bool:
        return self.ecdhPubKey is not None

    def __repr__(self) -> str:
        return "CETxOut(asset=%s nValue=%r scriptPubKey=%s ecdhPubKey=%s witness=%r)" \
            % (self.asset.hex(), self.nValue, self.scriptPubKey.hex(),
            self.ecdhPubKey.hex(), self.witness)


class CETxInWitness(CTxInWitness):
    def __init__(
        self,
        amountProof: Optional[bytes] = None,
        tokenProof: Optional[bytes] = None,
        scriptWitness: Optional[CScriptWitness] = None,
        peginWitness: Optional[CScriptWitness] = None
    ) -> None:
        self.amountProof = amountProof if amountProof is not None else b""
        self.tokenProof = tokenProof if tokenProof is not None else b""
        self.scriptWitness = scriptWitness if scriptWitness is not None else CScriptWitness()
        self.peginWitness = peginWitness if peginWitness is not None else CScriptWitness()

    def deserialize(self, f: Readable) -> None:
        self.amountProof = deser_string(f)
        self.tokenProof = deser_string(f)
        self.scriptWitness.stack = deser_string_vector(f)
        self.peginWitness.stack = deser_string_vector(f)

    def serialize(self) -> bytes:
        r = ser_string(self.amountProof)
        r += ser_string(self.tokenProof)
        r += ser_string_vector(self.scriptWitness.stack)
        r += ser_string_vector(self.peginWitness.stack)
        return r

    def __repr__(self) -> str:
        return "CETxInWitness(amountProof=%s tokenProof=%s scriptWitness=%r"\
            " peginWitness=%r)" \
            % (self.amountProof.hex(), self.tokenProof.hex(),
            self.scriptWitness, self.peginWitness)

    def is_null(self) -> bool:
        empty: bool = (
            not self.amountProof and
            not self.tokenProof and
            not self.scriptWitness.is_null() and
            not self.peginWitness.is_null()
        )
        return not empty


class CETxOutWitness(object):
    def __init__(
        self,
        surjectionProof: Optional[bytes] = None,
        rangeProof: Optional[bytes] = None
    ) -> None:
        self.surjectionProof = surjectionProof if surjectionProof is not None else b""
        self.rangeProof = rangeProof if rangeProof is not None else b""

    def deserialize(self, f: Readable) -> None:
        self.surjectionProof = deser_string(f)
        self.rangeProof = deser_string(f)

    def serialize(self) -> bytes:
        return ser_string(self.surjectionProof) + ser_string(self.rangeProof)

    def __repr__(self) -> str:
        return "CETxOutWitness(surjectionProof=%s rangeProof=%s)" \
            % (self.surjectionProof.hex(), self.rangeProof.hex())

    def is_null(self) -> bool:
        empty: bool = (
            not self.surjectionProof and
            not self.rangeProof
        )
        return not empty


class CETxWitness(CTxWitness):
    def __init__(self) -> None:
        self.vtxinwit: List[CETxInWitness] = []
        self.vtxoutwit: List[CETxOutWitness] = []

    def deserialize(self, f: Readable) -> None:
        for i in range(len(self.vtxinwit)):
            self.vtxinwit[i].deserialize(f)
        for i in range(len(self.vtxoutwit)):
            self.vtxoutwit[i].deserialize(f)

    def serialize(self) -> bytes:
        r = b""
        # This is different than the usual vector serialization --
        # we omit the length of the vector, which is required to be
        # the same length as the transaction's vin vector.
        for x in self.vtxinwit:
            r += x.serialize()
        for x in self.vtxoutwit:
            r += x.serialize()
        return r

    def __repr__(self) -> str:
        return "CETxWitness(In=[%s] Out=[%s])" % (
               (','.join([repr(x) for x in self.vtxinwit])),
               (','.join([repr(x) for x in self.vtxoutwit]))
        )

    def is_null(self) -> bool:
        for x in self.vtxinwit:
            if not x.is_null():
                return False
        for x in self.vtxoutwit:
            if not x.is_null():
                return False
        return True

class CETransaction(CTransaction):
    def __init__(self, tx: Optional['CTransaction'] = None) -> None:
        if tx is None:
            self.nVersion = 2
            self.vin: List[CETxIn] = []
            self.vout: List[CETxOut] = []
            self.wit = CETxWitness()
            self.nLockTime = 0
            self.sha256: Optional[int] = None
            self.hash: Optional[bytes] = None
        else:
            self.nVersion = tx.nVersion
            self.vin = copy.deepcopy(tx.vin)
            self.vout = copy.deepcopy(tx.vout)
            self.nLockTime = tx.nLockTime
            self.sha256 = tx.sha256
            self.hash = tx.hash
            self.wit = copy.deepcopy(tx.wit)

    def deserialize(self, f: Readable) -> None:
        self.nVersion = struct.unpack("<i", f.read(4))[0]
        marker = struct.unpack("<B", f.read(1))[0]
        has_witness = False
        if marker == 0x01:
            has_witness = True
        elif marker != 0x00:
            raise PSBTSerializationError("Unsupported transaction marker")

        self.vin = deser_vector(f, CETxIn)
        self.vout = deser_vector(f, CETxOut)
        self.nLockTime = struct.unpack("<I", f.read(4))[0]

        if has_witness:
            self.wit.vtxinwit = [CETxInWitness() for i in range(len(self.vin))]
            self.wit.vtxoutwit = [CETxOutWitness() for i in range(len(self.vout))]
            self.wit.deserialize(f)

        self.sha256 = None
        self.hash = None

    def serialize_without_witness(self) -> bytes:
        r = b""
        r += struct.pack("<i", self.nVersion)
        r += struct.pack("<B", 0x00)
        r += ser_vector(self.vin)
        r += ser_vector(self.vout)
        r += struct.pack("<I", self.nLockTime)
        return r

    # Only serialize with witness when explicitly called for
    def serialize_with_witness(self) -> bytes:
        has_witness = not self.wit.is_null()
        r = b""
        r += struct.pack("<i", self.nVersion)
        r += struct.pack("<B", 0x01 if has_witness else 0x00)
        r += ser_vector(self.vin)
        r += ser_vector(self.vout)
        r += struct.pack("<I", self.nLockTime)
        if has_witness:
            if (len(self.wit.vtxinwit) != len(self.vin)):
                # vtxinwit must have the same length as vin
                self.wit.vtxinwit = self.wit.vtxinwit[:len(self.vin)]
                for _ in range(len(self.wit.vtxinwit), len(self.vin)):
                    self.wit.vtxinwit.append(CETxInWitness())
            if (len(self.wit.vtxoutwit) != len(self.vout)):
                # vtxoutwit must have the same length as vout
                self.wit.vtxoutwit = self.wit.vtxoutwit[:len(self.vout)]
                for _ in range(len(self.wit.vtxoutwit), len(self.vout)):
                    self.wit.vtxoutwit.append(CETxOutWitness())
            r += self.wit.serialize()
        return r

    # Regular serialization is without witness -- must explicitly
    # call serialize_with_witness to include witness data.
    def serialize(self) -> bytes:
        return self.serialize_without_witness()

    # Recalculate the txid (transaction hash without witness)
    def rehash(self) -> None:
        self.sha256 = None
        self.calc_sha256()

    # We will only cache the serialization without witness in
    # self.sha256 and self.hash -- those are expected to be the txid.
    def calc_sha256(self, with_witness: bool = False) -> Optional[int]:
        if with_witness:
            # Don't cache the result, just return it
            return uint256_from_str(hash256(self.serialize_with_witness()))

        if self.sha256 is None:
            self.sha256 = uint256_from_str(hash256(self.serialize_without_witness()))
        self.hash = hash256(self.serialize())
        return None

    def is_null(self) -> bool:
        return len(self.vin) == 0 and len(self.vout) == 0

    def __repr__(self) -> str:
        return "CETransaction(nVersion=%i vin=%s vout=%s wit=%s nLockTime=%i)" \
            % (self.nVersion, repr(self.vin), repr(self.vout), repr(self.wit), self.nLockTime)
