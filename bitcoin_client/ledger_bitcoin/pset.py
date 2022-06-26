# Original version: https://github.com/bitcoin-core/HWI/blob/3fe369d0379212fae1c72729a179d133b0adc872/hwilib/key.py
# Distributed under the MIT License.

"""
PSET Classes and Utilities
**************************
"""

# TODO: Decode proprietary fields specific to PSET
# TODO: Properly initialize input and output classes on creation

import base64
import struct

from io import BytesIO, BufferedReader
from typing import (
    Dict,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Set,
    Tuple,
)

from .key import KeyOriginInfo
from .errors import PSBTSerializationError
from .elements_tx import (
    CETransaction,
    CETxIn,
    CETxInWitness,
    CETxOut
)
from .tx import (
    CTransaction,
)
from ._serialize import (
    deser_compact_size,
    deser_string,
    Readable,
    ser_compact_size,
    ser_string,
    ser_uint256,
    uint256_from_str,
)
from .psbt import (
    DeserializeHDKeypath,
    SerializeHDKeypath,
    PartiallySignedInput,
    PartiallySignedOutput,
    PSBT
)


class EPartiallySignedInput(PartiallySignedInput):
    """
    An object for a PSET input map.
    """

    TX_CLS = CETransaction
    TXIN_WITNESS_CLS = CETxInWitness
    TXOUT_CLS = CETxOut

    def __init__(self, version: int) -> None:
        if version != 2:
            raise PSBTSerializationError("Unsupported PSET version")

        super().__init__(version)


class EPartiallySignedOutput(PartiallySignedOutput):
    """
    An object for a PSET output map.
    """

    TXOUT_CLS = CETxOut

    def __init__(self, version: int) -> None:
        if version != 2:
            raise PSBTSerializationError("Unsupported PSET version")

        super().__init__(version)

    def _validate_deserialized(self) -> None:
        if self.amount is None:
            raise PSBTSerializationError("PSBT_OUTPUT_AMOUNT is required in PSBTv2")
        # We do not validate PSBT_OUTPUT_SCRIPT here because in fee output it is
        # normally empty.


class PSET(PSBT):
    """
    A class representing a PSET
    """

    MAGIC = b"pset\xff"

    # Classes for internal structures
    PSBTIN_CLS = EPartiallySignedInput
    PSBTOUT_CLS = EPartiallySignedOutput
    TX_CLS = CETransaction
    TXIN_CLS = CETxIn
    TXOUT_CLS = CETxOut

    def __init__(self, tx: Optional[CTransaction] = None) -> None:
        """
        :param tx: A Bitcoin transaction that specifies the inputs and outputs to use
        """
        super().__init__(tx)

        # Assume version 2 PSBT
        self.version = 2

    def deserialize(self, psbt: str) -> None:
        """
        Deserialize a base 64 encoded PSBT.

        :param psbt: A base 64 PSBT.
        """

        super().deserialize(psbt)

        # Only v2 is supported for PSET
        if self.version != 2:
            raise PSBTSerializationError("Unsupported PSET version")

    def _validate_deserialized(self, input_count: int, output_count: int) -> None:
        super()._validate_deserialized(input_count, output_count)

        # Check if PSBT_OUTPUT_SCRIPT is present in all outputs except for the last one (fee).
        if output_count < 2:
            raise PSBTSerializationError("Number of outputs in PSET must be at least 2")
        for i in range(output_count - 1):
            if not self.outputs[i].script:
                raise PSBTSerializationError("PSBT_OUTPUT_SCRIPT is required in PSET")
        fee_idx = output_count - 1
        if self.outputs[fee_idx].script is None or len(self.outputs[fee_idx].script) != 0:
            raise PSBTSerializationError("Empty PSBT_OUTPUT_SCRIPT is required in fee output of PSET")

    def convert_to_v0(self) -> None:
        """
        Sets this PSBT to version 0
        """

        raise PSBTSerializationError("Unsupported PSET version")
