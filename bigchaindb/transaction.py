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
    CREATE = 0
    TRANSFER = 1

    # TODO: Is this the correct way of serializing an Enum?
    def __str__(self):
        return str(self.name)

    def __repr__(self):
        return str(self.name)


class Fulfillment(object):

    def __init__(self, owners_before=[], fid=0, tx_input=None):
        """Create a new fulfillment

        Args:
            # TODO: Write a description here
            owners_before (Optional(list)): base58 encoded public key of the owners of the asset before this
            transaction.

        """
        self.fid = fid
        self.tx_input = tx_input
        if not isinstance(owners_before, list):
            raise TypeError('`owners_before` must be an instance of list')
        else:
            self.owners_before = owners_before

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
                'fid': self.fid
            }


class Condition(object):

    def __init__(self, owners_after=[], cid=0):
        """Create a new condition for a fulfillment

        Args
            # TODO: Add more description
            owners_after (Optional(list)): base58 encoded public key of the owner of the digital asset after
            this transaction.

        """
        self.cid = cid
        if not isinstance(owners_after, list):
            raise TypeError('`owners_after` must be an instance of list')
        else:
            self.owners_after = owners_after

    def _gen_condition(self):
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
        condition = self._gen_condition()

        if condition:
            return {
                'owners_after': self.owners_after,
                'condition': {
                    'details': condition.to_dict(),
                    'uri': condition.condition_uri
                },
                'cid': self.cid
            }


class Transaction(object):
    VERSION = 1

    def __init__(self, fulfillments, conditions, operation, payload=None):
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
            operation
            payload (Optional[dict]): dictionary with information about asset.

        Raises:
            TypeError: if the optional ``payload`` argument is not a ``dict``.


        """
        self.operation = operation

        if not isinstance(fulfillments, list):
            raise TypeError('`fulfillments` must be an instance of list')
        else:
            self.fulfillments = fulfillments
        if not isinstance(conditions, list):
            raise TypeError('`conditions` must be an instance of list')
        else:
            self.conditions = conditions

        # Check if payload is either None or a dict. Otherwise throw
        if payload is not None and not isinstance(payload, dict):
            raise TypeError('`payload` must be an dict instance or None')
        else:
            self.payload = payload

    def sign(self):
        pass

    def to_dict(self):
        transaction = {
            'fulfillments': [fulfillment.to_dict() for fulfillment in self.fulfillments],
            'conditions': [condition.to_dict() for condition in self.conditions],
            # TODO: `operation` needs to be serialized correctly with an EnumSerializer
            'operation': str(self.operation),
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
