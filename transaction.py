from .utils import PublicKey, Signature, TxID
from typing import Optional
from hashlib import sha256


class Transaction:
    """Represents a transaction that moves a single coin
    A transaction with no source creates money. It will only be created by the miner of a block."""

    def __init__(self, output: PublicKey, tx_input: Optional[TxID], signature: Signature) -> None:
        # DO NOT change these field names.
        self.output: PublicKey = output
        # DO NOT change these field names.
        self.input: Optional[TxID] = tx_input
        # DO NOT change these field names.
        self.signature: Signature = signature

    @staticmethod
    def get_message(input: Optional[TxID], output: PublicKey):
        """
        Defines the message that signs and verifies a transaction by concatenating hash of input tx
        and output public address. In case the transaction is a bank created transaction the message will be just
        the output public address.
        """
        return input + output if input else output

    def get_txid(self) -> TxID:
        """
        Returns the identifier of this transaction. This is the sha256 of the transaction contents.
        This function is used by the tests to compute the tx hash. Make sure to compute this every time 
        directly from the data in the transaction object, and not cache the result
        """
        hash_sha256 = sha256()
        hash_sha256.update(self.output)
        hash_sha256.update(self.signature)
        if self.input is not None:
            hash_sha256.update(self.input)
        return TxID(hash_sha256.digest())


"""
Importing this file should NOT execute code. It should only create definitions for the objects above.
Write any tests you have in a different file.
You may add additional methods, classes and files but be sure no to change the signatures of methods
included in this template.
"""
