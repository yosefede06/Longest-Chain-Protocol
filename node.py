from .utils import *
from .block import Block
from .transaction import Transaction
from secrets import token_bytes
from typing import Set, Optional, List, Dict
ERROR_MSG_SAME_NODE_CONNECTION = "Trying to establish connection with itself."
LENGTH_RANDOM_SIGNATURE = 64


class Node:
    def __init__(self) -> None:
        """Creates a new node with an empty mempool and no connections to others.
        Blocks mined by this node will reward the miner with a single new coin,
        created out of thin air and associated with the mining reward address"""
        self._private_key, self._public_key = gen_keys()
        self._mempool: List[Transaction] = []
        self._blockchain: List[Block] = []
        self._utxo: List[Transaction] = []
        self._last_seen_block_hash: BlockHash = GENESIS_BLOCK_PREV
        self._connected_nodes: Set[Node] = set()
        self._txs_map: Dict[TxID, Transaction] = dict()

    def connect(self, other: 'Node') -> None:
        """connects this node to another node for block and transaction updates.
        Connections are bi-directional, so the other node is connected to this one as well.
        Raises an exception if asked to connect to itself.
        The connection itself does not trigger updates about the mempool,
        but nodes instantly notify of their latest block to each other (see notify_of_block)"""
        if self is other:
            raise Exception(ERROR_MSG_SAME_NODE_CONNECTION)

        self._connected_nodes.add(other)
        other.get_connections().add(self)
        self.notify_of_block(other.get_latest_hash(), other)
        other.notify_of_block(self.get_latest_hash(), self)

    def disconnect_from(self, other: 'Node') -> None:
        """Disconnects this node from the other node. If the two were not connected, then nothing happens"""
        if other in self._connected_nodes:
            self._connected_nodes.remove(other)
        if self in other._connected_nodes:
            other._connected_nodes.remove(self)

    def get_connections(self) -> Set['Node']:
        """Returns a set containing the connections of this node."""
        return self._connected_nodes

    def add_transaction_to_mempool(self, transaction: Transaction) -> bool:
        """
        This function inserts the given transaction to the mempool.
        It will return False iff any of the following conditions hold:
        (i) the transaction is invalid (the signature fails)
        (ii) the source doesn't have the coin that it tries to spend
        (iii) there is contradicting tx in the mempool.

        If the transaction is added successfully, then it is also sent to neighboring nodes.
        Transactions that create money (with no inputs) are not placed in the mempool, and not propagated. 
        """

        utxo_ids = list(map(lambda tx: tx.get_txid(), self._utxo))
        mempool_input_ids = list(map(lambda tx: tx.input, self._mempool))
        # (iv) there is no input (i.e., this is an attempt to create money from nothing)
        if not transaction.input:
            return False
        # (ii) the source doesn't have the coin that he tries to spend
        if transaction.input not in utxo_ids:
            return False
        # (iii) there is contradicting tx in the mempool.
        if transaction.input in mempool_input_ids:
            return False
        # (i) the transaction is invalid (the signature fails)
        src_transaction = self._get_tx_with_id_from_utxo(transaction.input, self._utxo)
        message = Transaction.get_message(input=transaction.input, output=transaction.output)
        if not verify(message=message, sig=transaction.signature, pub_key=src_transaction.output):
            return False
        # Adds new transaction to the mempool
        self._mempool.append(transaction)
        for connected_node in self.get_connections():
            connected_node.add_transaction_to_mempool(transaction)
        return True

    def notify_of_block(self, block_hash: BlockHash, sender: 'Node') -> None:
        """This method is used by a node's connection to inform it that it has learned of a
        new block (or created a new block). If the block is unknown to the current Node, The block is requested.
        We assume the sender of the message is specified, so that the node can choose to request this block if
        it wishes to do so.
        (if it is part of a longer unknown chain, these blocks are requested as well, until reaching a known block).
        Upon receiving new blocks, they are processed and checked for validity (check all signatures, hashes,
        block size , etc).
        If the block is on the longest chain, the mempool and utxo change accordingly (ties, i.e., chains of similar length to that of this node are not adopted).
        If the block is indeed the tip of the longest chain,
        a notification of this block is sent to the neighboring nodes of this node.
        (no need to notify of previous blocks -- the nodes will fetch them if needed)

        A reorg may be triggered by this block's introduction. In this case the utxo is rolled back to the split point,
        and then rolled forward along the new branch. Be careful -- the new branch may contain invalid blocks.
        These and blocks that point to them should not be accepted to the blockchain (but earlier valid blocks may still form a longer chain)
        the mempool is similarly emptied of transactions that cannot be executed now.
        transactions that were rolled back and can still be executed are re-introduced into the mempool if they do
        not conflict.
        """

        if block_hash != GENESIS_BLOCK_PREV and not self._is_known_block(block_hash):
            curr_hash = block_hash
            copy_utxo = self._utxo.copy()
            old_branch: List[Block] = list()
            new_branch: List[Block] = list()
            # verifies block request hash corresponds to hashBlock provided by sender
            if sender.get_block(block_hash).get_block_hash() != block_hash:
                # get_block function is override by another node
                return None
            while not self._is_known_block(curr_hash) and curr_hash != GENESIS_BLOCK_PREV:
                try:
                    curr_block = sender.get_block(curr_hash)
                except ValueError:
                    return None
                new_branch.append(curr_block)
                curr_hash = curr_block.get_prev_block_hash()

            # check if sender node has a longer chain
            temp_hash = self.get_latest_hash()

            while temp_hash != curr_hash:
                curr_block = self.get_block(temp_hash)
                temp_hash = curr_block.get_prev_block_hash()
                old_branch.append(curr_block)

            if len(new_branch) > len(old_branch):
                # sender node has a longer chain
                self._update_utxo_to_branch(copy_utxo, old_branch)
                valid_blocks = self._check_new_branch_validity(copy_utxo, new_branch)
                if valid_blocks == 0 or valid_blocks <= len(old_branch):
                    return None
                # update blockchain branch:
                del self._blockchain[len(self._blockchain) - len(old_branch): len(self._blockchain)]
                new_branch = new_branch[::-1]
                new_branch = new_branch[:valid_blocks]
                self._blockchain.extend(new_branch)
                # updates utxo and mempool
                self._utxo = copy_utxo
                old_mempool = self._mempool.copy()
                self._mempool = list()
                for tx in old_mempool:
                    self.add_transaction_to_mempool(tx)
                # a notification of this block is sent to the neighboring nodes of this node.
                for neighboring_nodes in self.get_connections():
                    self.notify_of_block(block_hash, self)

    def get_blockchain(self):
        return self._blockchain

    def mine_block(self) -> BlockHash:
        """"
        This function allows the node to create a single block.
        The block should contain BLOCK_SIZE transactions (unless there aren't enough in the mempool). Of these,
        BLOCK_SIZE-1 transactions come from the mempool and one addtional transaction will be included that creates
        money and adds it to the address of this miner.
        Money creation transactions have None as their input, and instead of a signature, contain 48 random bytes.
        If a new block is created, all connections of this node are notified by calling their notify_of_block() method.
        The method returns the new block hash.
        """
        self._create_money(self._public_key)
        limit_mempool_transactions = self._mempool[:BLOCK_SIZE]
        self._mempool = self._mempool[BLOCK_SIZE:]
        block = Block(self.get_latest_hash(), limit_mempool_transactions)
        block_hash = block.get_block_hash()
        self._blockchain.append(block)
        for transaction in limit_mempool_transactions:
            self._update_utxo(transaction, self._utxo)
        for connected_node in self._connected_nodes:
            connected_node.notify_of_block(block_hash, self)
        return block_hash

    def get_block(self, block_hash: BlockHash) -> Block:
        """
        This function returns a block object given its hash.
        If the block doesnt exist, a ValueError is raised.
        """
        try:
            return self._blockchain[list(map(lambda block: block.get_block_hash(), self._blockchain)).index(block_hash)]

        except ValueError:

            raise ValueError("There is no block with the provided hash")

    def get_latest_hash(self) -> BlockHash:
        """
        This function returns the last block hash known to this node (the tip of its current chain).
        """
        return self._blockchain[-1].get_block_hash() if len(self._blockchain) > 0 else GENESIS_BLOCK_PREV

    def get_mempool(self) -> List[Transaction]:
        """
        This function returns the list of transactions that didn't enter any block yet.
        """
        return self._mempool

    def get_utxo(self) -> List[Transaction]:
        """
        This function returns the list of unspent transactions.
        """
        return self._utxo

    # ------------ Formerly wallet methods: -----------------------

    def create_transaction(self, target: PublicKey) -> Optional[Transaction]:
        """
        This function returns a signed transaction that moves an unspent coin to the target.
        It chooses the coin based on the unspent coins that this node has.
        If the node already tried to spend a specific coin, and such a transaction exists in its mempool,
        but it did not yet get into the blockchain then it should'nt try to spend it again (until clear_mempool() is
        called -- which will wipe the mempool and thus allow to attempt these re-spends).
        The method returns None if there are no outputs that have not been spent already.

        The transaction is added to the mempool (and as a result is also published to neighboring nodes)
        """
        unfreeze_txs = self._get_txs_ids_not_in_mempool()
        if not unfreeze_txs:
            return None
        txid = unfreeze_txs[0]
        message = Transaction.get_message(input=txid, output=target)
        tx = Transaction(target, txid, sign(message, self._private_key))
        self.add_transaction_to_mempool(tx)

        return tx

    def clear_mempool(self) -> None:
        """
        Clears the mempool of this node. All transactions waiting to be entered into the next block are gone.
        """
        self._mempool = []

    def get_balance(self) -> int:
        """
        This function returns the number of coins that this node owns according to its view of the blockchain.
        Coins that the node owned and sent away will still be considered as part of the balance until the spending
        transaction is in the blockchain.
        """
        return len(self._get_unspent_coins())

    def get_address(self) -> PublicKey:
        """
        This function returns the public address of this node (its public key).
        """
        return self._public_key

    # ------------ Private methods: -----------------------

    def _check_receive_tx(self, tx):
        return tx.output == self._public_key

    def _check_spend_tx(self, tx, balance):
        return tx.input is not None and balance.count(tx.input) > 0

    def _get_unspent_coins(self):
        balance = list()
        temp_hash = self.get_latest_hash()
        while GENESIS_BLOCK_PREV != temp_hash:
            temp_block = self.get_block(temp_hash)

            block_txs = temp_block.get_transactions()
            in_transactions = list(filter(self._check_receive_tx, block_txs))
            balance.extend(list(map(lambda tx: tx.get_txid(), in_transactions)))
            out_transactions = list(filter(lambda tx: self._check_spend_tx(tx, balance), block_txs))
            for tx in out_transactions:
                balance.remove(tx.input)
            temp_hash = temp_block.get_prev_block_hash()
        return balance

    def _get_txs_ids_not_in_mempool(self):
        mempool_input_ids = list(map(lambda tx: tx.input, self._mempool))
        return list(filter(lambda tx_id: tx_id not in mempool_input_ids, self._get_unspent_coins()))

    def _create_money(self, target: PublicKey) -> None:
        """
        This function inserts a transaction into the mempool that creates a single coin out of thin air.
        Instead of a signature, this transaction includes a random string of 64 bytes (so that every two
        creation transactions are different).
        """
        self._mempool.append(Transaction(output=target,
                                         tx_input=None,
                                         signature=Signature(token_bytes(LENGTH_RANDOM_SIGNATURE))))

    # Checks known block starting from the tip of the blockchain since splits are more probable to appear at the end.
    def _is_known_block(self, block_hash: BlockHash):
        return block_hash in list(map(lambda b: b.get_block_hash(), self._blockchain[::-1]))

    def _verify_block(self, block: Block, utxo: List[Transaction]):
        txs_already_seen = list()
        for transaction in block.get_transactions():
            if transaction.input not in txs_already_seen:
                txs_already_seen.append(transaction.input)
            else:
                return False
            if utxo is None:
                utxo = self._utxo
            # Transaction from money created with no input
            if transaction.input is None:
                continue
            # The transaction is invalid (the signature fails)
            src_transaction = self._get_tx_with_id_from_utxo(transaction.input, utxo)
            message = Transaction.get_message(input=transaction.input, output=transaction.output)
            if not verify(message=message, sig=transaction.signature, pub_key=src_transaction.output):
                return False
        return True

    def _get_tx_with_id_from_utxo(self, txId: TxID, utxo: List[Transaction]):
        utxo_ids = list(map(lambda tx: tx.get_txid(), utxo))
        return utxo[utxo_ids.index(txId)]

    def _check_new_branch_validity(self, copy_utxo, new_branch) -> int:
        valid_blocks = 0
        for block in reversed(new_branch):
            if not self._verify_block(block, copy_utxo):
                return valid_blocks
            for tx in block.get_transactions():
                self._update_utxo(tx, copy_utxo)
            valid_blocks += 1
        return valid_blocks

    def _update_utxo_to_branch(self, copy_utxo, old_branch):
        for block in reversed(old_branch):
            for tx in block.get_transactions():
                replace_tx = self._txs_map[tx.get_txid()]
                if replace_tx.input is not None:
                    copy_utxo.append(self._txs_map[replace_tx.input])
                copy_utxo.remove(replace_tx)

    def _update_utxo(self, transaction,  utxo):
        if transaction.input is not None:
            src_transaction = self._get_tx_with_id_from_utxo(transaction.input, utxo)
            # Removes previous transaction
            utxo.remove(src_transaction)
        utxo.append(transaction)
        self._txs_map[transaction.get_txid()] = transaction



"""
Importing this file should NOT execute code. It should only create definitions for the objects above.
Write any tests you have in a different file.
You may add additional methods, classes and files but be sure no to change the signatures of methods
included in this template.
"""
