from .utils import BlockHash, TxID
from .transaction import Transaction
from typing import List
from hashlib import sha256


class Block:
    """This class represents a block."""

    # implement __init__ as you see fit.
    def __init__(self, prev_block_hash: BlockHash, txs: List[Transaction]):
        self._txs: List[Transaction] = txs
        self._prev_block_hash: BlockHash = prev_block_hash

    @staticmethod
    def calculate_merkle_root(txs: List[TxID]):
        """
        This function takes a list of transaction IDs as input,
        hashes each ID using SHA-256 (which is a collision resistant hash function),
        and builds up the Merkle tree by combining adjacent hashes and hashing the result.
        The final hash at the top of the tree is returned as the Merkle root.
        """
        if len(txs) == 0:
            return b''
        # In case the number of items is odd, duplicate the last item
        if len(txs) % 2 == 1:
            txs.append(b'')
        while len(txs) > 1:
            level_hashes = []
            for i in range(0, len(txs), 2):
                h = sha256()
                h.update(txs[i] + txs[i + 1])
                level_hashes.append(BlockHash(h.digest()))
            txs = level_hashes
        return txs[0]

    def get_block_hash(self) -> BlockHash:
        """Gets the hash of this block. 
        This function is used by the tests. Make sure to compute the result from the data in the block every time 
        and not to cache the result"""
        hash_block = sha256()
        # concatenate merkle root with previous block hash
        hash_block.update(self._prev_block_hash)
        hash_block.update(Block.calculate_merkle_root(list(map(lambda tx: tx.get_txid(), self._txs))))
        # sha256 application
        return BlockHash(hash_block.digest())

    def get_transactions(self) -> List[Transaction]:
        """
        returns the list of transactions in this block.
        """
        return self._txs

    def get_prev_block_hash(self) -> BlockHash:
        """Gets the hash of the previous block"""
        return self._prev_block_hash
