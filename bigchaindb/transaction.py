from enum import Enum
from uuid import uuid4

from cryptoconditions import (
    ThresholdSha256Fulfillment,
    Ed25519Fulfillment,
)

from bigchaindb.util import (
    timestamp,
    get_hash_data,
)


class TransactionType(Enum):
    create = 'CREATE'
    transfer = 'TRANSFER'


class Fulfillment(object):

    def __init__(self, fid=None, owners_before=[], tx_input=None):
        """Create a new fulfillment

        Args:
            # TODO: Write a description here
            owners_before (Optional(list)): base58 encoded public key of the owners of the asset before this
            transaction.

        """
        self.fid = fid
        self.owners_before = owners_before
        self.tx_input = tx_input

    def to_dict(self):
        # `operation`: TRANSFER
        if self.tx_input and self.fid:
            return {
                'owners_before': self.owners_before,
                'input': self.tx_input,
                'fulfillment': None,
                'fid': self.fid
            }
        # `operation`: CREATE
        else:
            return {
                'owners_before': self.owners_before,
                'input': None,
                'fulfillment': None,
                'fid': 0
            }


class Condition(object):

    def __init__(self, fid, owners_after=[]):
        """Create a new condition for a fulfillment

        Args
            # TODO: Add more description
            owners_after (Optional(list)): base58 encoded public key of the owner of the digital asset after
            this transaction.

        """
        self.fid = fid
        self.owners_after = owners_after

    def __gen_condition(self):
        # NOTE: I have no clue why we're instantiating `Fulfillments` here but then
        # it's a condition in the end
        owners_after_count= len(self.owners_after)

        # threshold condition
        if owners_after_count > 1:
            fulfillment = ThresholdSha256Fulfillment(threshold=owners_after_count)
            for owner_after in self.owners_after:
                fulfillment.add_subfulfillment(Ed25519Fulfillment(public_key=owner_after))

        # simple signature condition
        elif owners_after_count == 1:
            fulfillment = Ed25519Fulfillment(public_key=self.owners_after[0])

        # TODO: Add hashlock condition
        else:
            fulfillment = None
        return fulfillment

    def to_dict(self):
        condition = self.__gen_condition()

        if condition:
            return {
                'owners_after': self.owners_after,
                'condition': {
                    'details': condition.to_dict(),
                    'uri': condition.condition_uri
                },
                'cid': self.fid
            }


class Transaction(object):
    VERSION = 1

    def __init__(self, fulfillments, conditions, payload=None):
        """Create a new transaction in memory

        A transaction in BigchainDB is a transfer of a digital asset between two entities represented
        by public keys.

        Currently BigchainDB supports two types of operations:

            `CREATE` - Only federation nodes are allowed to use this operation. In a create operation
            a federation node creates a digital asset in BigchainDB and assigns that asset to a public
            key. The owner of the private key can then decided to transfer this digital asset by using the
            `transaction id` of the transaction as an input in a `TRANSFER` transaction.

            `TRANSFER` - A transfer operation allows for a transfer of the digital assets between entities.

        If a transaction is initialized with the inputs being `None` a `operation` `CREATE` is
        chosen. Otherwise the transaction is of `operation` `TRANSFER`.

        Args:
            # TODO: Write a description here
            fulfillments
            conditions
            payload (Optional[dict]): dictionary with information about asset.

        Raises:
            TypeError: if the optional ``payload`` argument is not a ``dict``.


        """
        self.fulfillments = fulfillments
        self.conditions = conditions
        # Check if payload is either None or a dict. Otherwise throw
        if payload is not None and not isinstance(payload, dict):
            raise TypeError('`payload` must be an dict instance or None')
        else:
            self.payload = payload

        self.operation = TransactionType.transfer if self.inputs else TransactionType.create

    def to_dict(self):
        transaction = {
            'fulfillments': self.fulfillments.to_dict(),
            'conditions': self.conditions.to_dict(),
            # TODO: `operation` needs to be serialized correctly with an EnumSerializer
            'operation': self.operation,
            'timestamp': timestamp(),
            'data': {
                'uuid': str(uuid4()),
                'payload': self.payload,
            }
        }
        return {
            'id': get_hash_data(transaction),
            'version': self.VERSION,
            'transaction': transaction,
        }
