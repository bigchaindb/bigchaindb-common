from enum import Enum
from uuid import uuid4
from copy import deepcopy

from cryptoconditions import (
    Fulfillment as CCFulfillment,
    ThresholdSha256Fulfillment,
    Ed25519Fulfillment,
)

from bigchaindb.crypto import SigningKey
from bigchaindb.exceptions import (
    KeypairMismatchException
)
from bigchaindb.util import (
    get_hash_data,
    serialize,
    timestamp,
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
    def __init__(self, fulfillment, owners_before=None, fid=0, tx_input=None):
        """Create a new fulfillment

        Args:
            # TODO: Write a description here
            owners_before (Optional(list)): base58 encoded public key of the owners of the asset before this
            transaction.

        """
        self.fid = fid
        self.fulfillment = fulfillment
        self.tx_input = tx_input

        if owners_before is None:
            self.owners_before = []
        if not isinstance(owners_before, list):
            self.owners_before = [owners_before]

    def to_dict(self):
        return {
            'owners_before': self.owners_before,
            'input': self.tx_input,
            'fulfillment': self.fulfillment.serialize_uri(),
            'fid': self.fid,
        }


class Condition(object):
    def __init__(self, condition, owners_after=None, cid=0):
        """Create a new condition for a fulfillment

        Args
            # TODO: Add more description
            owners_after (Optional(list)): base58 encoded public key of the owner of the digital asset after
            this transaction.

        """
        self.cid = cid
        self.condition = condition

        if owners_after is None:
            self.owners_after = []
        if not isinstance(owners_after, list):
            self.owners_after = [owners_after]

    def to_dict(self):
        return {
            'owners_after': self.owners_after,
            'condition': {
                'details': self.condition.to_dict(),
                'uri': self.condition.condition_uri
            },
            'cid': self.cid
        }


class Transaction(object):
    VERSION = 1

    def __init__(self, conditions, operation, tx_input=None, fulfillments=None, payload=None):
        # TODO: Update this comment
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
        self.tx_input = tx_input

        if fulfillments is None:
            self.fulfillments = []
        if not isinstance(fulfillments, list):
            self.fulfillments = [fulfillments]

        if conditions is None:
            self.conditions = []
        if not isinstance(conditions, list):
            self.conditions = [conditions]

        # Check if payload is either None or a dict. Otherwise throw
        if payload is not None and not isinstance(payload, dict):
            raise TypeError('`payload` must be an dict instance or None')
        else:
            self.payload = payload

    def fulfill_conditions(self, private_keys):
        if private_keys is None:
            # TODO: Figure out the correct Python error
            raise Exception('`private_keys` cannot be None')
        if not isinstance(private_keys, list):
            private_keys = [private_keys]

        # Generate public keys from private keys and match them in a dictionary:
        #   key:     public_key
        #   value:   private_key
        gen_public_key = lambda private_key: private_key.get_verifying_key().to_ascii().decode()
        key_pairs = {gen_public_key(SigningKey(private_key)): SigningKey(private_key) for private_key in private_keys}

        for cid in enumerate(self.conditions):
            # NOTE: This is kinda ugly, but the CC-API doesn't leave us with no other choice at this point
            # NOTE: We could cast condition `to_dict`, but this saves us a serialization step
            # TODO: Figure out which fulfillments and conditions need to be present for `to_dict`
            tx_dict = self._to_dict()
            condition_dict = tx_dict['transaction']['conditions'][cid]
            fulfillment = CCFulfillment.from_dict(condition_dict['condition']['details'])

            self._add_fulfillment(self._fulfill_condition(condition_dict, fulfillment, serialize(tx_dict), key_pairs))

    def _fulfill_condition(self, condition, fulfillment, tx_serialized, key_pairs):
        owners_before = condition['owners_after']

        if isinstance(fulfillment, Ed25519Fulfillment):
            fulfillment = self._fulfill_simple_signature_condition(owners_before[0], fulfillment, tx_serialized,
                                                                   key_pairs)
        elif isinstance(fulfillment, ThresholdSha256Fulfillment):
            fulfillment = self._fulfill_threshold_signature_condition(owners_before, fulfillment, tx_serialized,
                                                                      key_pairs)
        return Fulfillment(fulfillment, owners_before, condition['cid'], self.tx_input)

    def _fulfill_simple_signature_condition(self, owner_before, fulfillment, tx_serialized, key_pairs):
        # TODO: Update comment
        """Fulfill a cryptoconditions.Ed25519Fulfillment

            Args:
                fulfillment (dict): BigchainDB fulfillment to fulfill.
                parsed_fulfillment (cryptoconditions.Ed25519Fulfillment): cryptoconditions.Ed25519Fulfillment instance.
                fulfillment_message (dict): message to sign.
                key_pairs (dict): dictionary of (public_key, private_key) pairs.

            Returns:
                object: fulfilled cryptoconditions.Ed25519Fulfillment

        """
        try:
            fulfillment.sign(tx_serialized, key_pairs[owner_before])
        except KeyError:
            raise KeypairMismatchException('Public key {} is not a pair to any of the private keys'
                                           .format(owner_before))
        return fulfillment

    def _fulfill_threshold_signature_fulfillment(self, owners_before, fulfillment, tx_serialized, key_pairs):
        # TODO: Update comment
        """Fulfill a cryptoconditions.ThresholdSha256Fulfillment

            Args:
                fulfillment (dict): BigchainDB fulfillment to fulfill.
                parsed_fulfillment (ThresholdSha256Fulfillment): ThresholdSha256Fulfillment instance.
                fulfillment_message (dict): message to sign.
                key_pairs (dict): dictionary of (public_key, private_key) pairs.

            Returns:
                object: fulfilled cryptoconditions.ThresholdSha256Fulfillment

            """
        fulfillment_copy = deepcopy(fulfillment)
        fulfillment.subconditions = []

        for owner_before in owners_before:
            try:
                subfulfillment = fulfillment_copy.get_subcondition_from_vk(owner_before)[0]
            except IndexError:
                raise KeypairMismatchException('Public key {} cannot be found in the fulfillment'
                                               .format(owner_before))
            try:
                private_key = key_pairs[owner_before]
            except KeyError:
                raise KeypairMismatchException('Public key {} is not a pair to any of the private keys'
                                               .format(owner_before))

            subfulfillment.sign(tx_serialized, private_key)
            fulfillment.add_subfulfillment(subfulfillment)

        return fulfillment

    def _add_fulfillment(self, fulfillment):
        self.fulfillments.append(fulfillment)

    def to_dict(self):
        return self._to_dict(self.fulfillments, self.conditions)

    def _to_dict(self, fulfillments=[], conditions=[]):
        transaction = {
            'fulfillments': [fulfillment.to_dict() for fulfillment in self.fulfillments],
            'conditions': [condition.to_dict() for condition in self.conditions],
            'operation': str(self.operation),
            'timestamp': timestamp(),
            'data': {
                'uuid': str(uuid4()),
                'payload': self.payload,
            }
        }
        return {
            # TODO: Figure out if fulfillment signature is hashed here sometimes. This would be bad.
            'id': get_hash_data(transaction),
            'version': self.VERSION,
            'transaction': transaction,
        }
