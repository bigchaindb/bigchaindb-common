from uuid import uuid4
from copy import deepcopy

from cryptoconditions import (
    Fulfillment as CCFulfillment,
    Condition as CCCondition,
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


class Fulfillment(object):
    def __init__(self, fulfillment_uri, owners_before=None, fid=0, tx_input=None):
        """Create a new fulfillment

        Args:
            # TODO: Write a description here
            owners_before (Optional(list)): base58 encoded public key of the owners of the asset before this
            transaction.

        """
        self.fid = fid
        # TODO: should we be able to pass fulfillments objects?
        self.fulfillment = CCFulfillment.from_uri(fulfillment_uri)
        self.tx_input = tx_input

        if not isinstance(owners_before, list):
            raise TypeError('`owners_before` must be a list instance')
        else:
            self.owners_before = owners_before

    def to_dict(self):
        return {
            'owners_before': self.owners_before,
            'input': self.tx_input,
            'fulfillment': self.fulfillment.serialize_uri(),
            'fid': self.fid,
        }

    @classmethod
    def from_dict(cls, ffill):
        """ Serializes a BigchainDB 'jsonized' fulfillment back to a BigchainDB Fulfillment class.
        """
        return cls(ffill['fulfillment'], ffill['owners_before'], ffill['fid'], ffill['input'])


class Condition(object):
    def __init__(self, condition_uri, owners_after=None, cid=0):
        """Create a new condition for a fulfillment

        Args
            # TODO: Add more description
            owners_after (Optional(list)): base58 encoded public key of the owner of the digital asset after
            this transaction.

        """
        self.cid = cid
        # TODO: should we be able to pass condition objects?
        self.condition = CCCondition.from_uri(condition_uri)

        if not isinstance(owners_after, list):
            raise TypeError('`owners_after` must be a list instance')
        else:
            self.owners_after = owners_after

    def to_dict(self):
        return {
            'owners_after': self.owners_after,
            'condition': {
                'details': self.condition.to_dict(),
                'uri': self.condition.serialize_uri()
            },
            'cid': self.cid
        }

    @classmethod
    def gen_default_condition(cls, owner_after):
        """Creates a default condition for a transaction of type `CREATE`.
        """
        return cls(Ed25519Fulfillment(public_key=owner_after).condition_uri, [owner_after], 0)

    @classmethod
    def from_dict(cls, cond):
        """ Serializes a BigchainDB 'jsonized' condition back to a BigchainDB Condition class.
        """
        return cls(cond['condition']['uri'], cond['owners_after'], cond['cid'], )


class Transaction(object):
    CREATE = 'CREATE'
    TRANSFER = 'TRANSFER'
    VERSION = 1

    def __init__(self, owners_after, inputs=None, payload=None):
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

        # TODO: Incorporate this text somewhere better in the docs of this class
        Some use cases for this class:

            1. Create a new `CREATE` transaction:
                - This means `inputs` is empty

            2. Create a new `TRANSFER` transaction:
                - This means `inputs` is a filled list (one to multiple transactions)

            3. Written transactions must be managed somehow in the user's program: use `from_dict`


        """
        self.fulfillments = []
        self.conditions = []
        if not isinstance(owners_after, list):
            raise TypeError('`owners_after` must be a list instance')
        else:
            self.owners_after = owners_after

        if inputs is not None and not isinstance(inputs, list):
            raise TypeError('`inputs` must be a list instance or None')
        elif inputs is None:
            # If `inputs` is None, this tells us that the user of this class wants to create a
            # transaction of type `CREATE`
            self.operation = Transaction.CREATE
            self._gen_default_condition()
        else:
            self.operation = Transaction.TRANSFER
            self.inputs = inputs

        # Check if payload is either None or a dict. Otherwise throw
        if payload is not None and not isinstance(payload, dict):
            raise TypeError('`payload` must be an dict instance or None')
        else:
            self.payload = payload

    def sign(self, private_keys):
        """ Signs a transaction by fulfilling the conditions given in the previous transactions.
            Acts as a proxy for `_fulfill_conditions`, for exposing a nicer API to the outside.
        """
        self._fulfill_conditions(private_keys)

    def _fulfill_conditions(self, private_keys):
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

    def _add_condition(self, condition):
        self.conditions.append(condition)

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

    @classmethod
    def from_dict(cls, tx):
        pass
