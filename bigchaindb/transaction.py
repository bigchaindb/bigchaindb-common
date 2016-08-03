from uuid import uuid4
from copy import deepcopy

from cryptoconditions import (
    Fulfillment as CCFulfillment,
    ThresholdSha256Fulfillment,
    Ed25519Fulfillment,
)

from bigchaindb.crypto import (
    SigningKey,
    hash_data,
)
from bigchaindb.exceptions import (
    KeypairMismatchException,
)
from bigchaindb.util import (
    serialize,
    # TODO: Rename function in util to `gen_timestamp` or `create_timestamp`
    timestamp as gen_timestamp,
)


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

        if not isinstance(owners_before, list):
            raise TypeError('`owners_before` must be a list instance')
        else:
            self.owners_before = owners_before

    def to_dict(self):
        try:
            # When we have signed the fulfillment, this will work
            fulfillment = self.fulfillment.serialize_uri()
        except TypeError:
            fulfillment = None

        return {
            'owners_before': self.owners_before,
            # TODO: Rename to `inputs` and `tx_inputs` and also make it an array
            'input': self.tx_input,
            'fulfillment': fulfillment,
            'details': self.fulfillment.to_dict(),
            'fid': self.fid,
        }

    @classmethod
    def gen_default(cls, owner_after):
        """Creates a default fulfillment for a transaction of type `CREATE`.
        """
        return cls(Ed25519Fulfillment(public_key=owner_after), [owner_after], 0)

    def gen_condition(self):
        return Condition(self.fulfillment.condition_uri, self.owners_before, self.fid)

    @classmethod
    def from_dict(cls, ffill):
        """ Serializes a BigchainDB 'jsonized' fulfillment back to a BigchainDB Fulfillment class.
        """
        try:
            fulfillment = CCFulfillment.from_uri(ffill['fulfillment'])
        except TypeError:
            fulfillment = CCFulfillment.from_dict(ffill['details'])
        return cls(fulfillment, ffill['owners_before'], ffill['fid'], ffill['input'])


class Condition(object):
    def __init__(self, condition_uri, owners_after=None, cid=0):
        # TODO: Add more description
        """Create a new condition for a fulfillment

        Args
            owners_after (Optional(list)): base58 encoded public key of the owner of the digital asset after
            this transaction.

        """
        self.cid = cid
        self.condition_uri = condition_uri

        if not isinstance(owners_after, list):
            raise TypeError('`owners_after` must be a list instance')
        else:
            self.owners_after = owners_after

    def to_dict(self):
        return {
            'owners_after': self.owners_after,
            'condition': self.condition_uri,
            'cid': self.cid
        }

    @classmethod
    def from_dict(cls, cond):
        """ Serializes a BigchainDB 'jsonized' condition back to a BigchainDB Condition class.
        """
        # NOTE: Here we're actually passing a fulfillment, why?
        return cls(cond['condition'], cond['owners_after'], cond['cid'])


class Data(object):

    def __init__(self, payload=None, payload_id=None):
        self.payload_id = payload_id if payload_id is not None else self.to_hash()
        if payload is not None and not isinstance(payload, dict):
            raise TypeError('`payload` must be a dict instance or None')
        else:
            self.payload = payload

    @classmethod
    def from_dict(cls, payload):
        try:
            return cls(payload['payload'], payload['hash'])
        except TypeError:
            return cls()

    def to_dict(self):
        if self.payload is None:
            return None
        else:
            return {
                'payload': self.payload,
                'hash': str(self.payload_id),
            }

    def to_hash(self):
        return uuid4()


class Transaction(object):
    CREATE = 'CREATE'
    TRANSFER = 'TRANSFER'
    VERSION = 1

    def __init__(self, operation, fulfillments=None, conditions=None, data=None, timestamp=None, version=None):
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
           data (Optional[dict]): dictionary with information about asset.

        Raises:
            TypeError: if the optional ``data`` argument is not a ``dict``.

        # TODO: Incorporate this text somewhere better in the docs of this class
        Some use cases for this class:

            1. Create a new `CREATE` transaction:
                - This means `inputs` is empty

            2. Create a new `TRANSFER` transaction:
                - This means `inputs` is a filled list (one to multiple transactions)

            3. Written transactions must be managed somehow in the user's program: use `from_dict`


        """
        self.operation = operation
        self.timestamp = timestamp if timestamp is not None else gen_timestamp()
        self.version = version if version is not None else Transaction.VERSION

        if conditions is not None and not isinstance(conditions, list):
            raise TypeError('`conditions` must be a list instance or None')
        elif conditions is None:
            self.conditions = []
        else:
            self.conditions = conditions

        if fulfillments is not None and not isinstance(fulfillments, list):
            raise TypeError('`fulfillments` must be a list instance or None')
        elif fulfillments is None:
            self.fulfillments = []
        else:
            self.fulfillments = fulfillments

        # TODO: rename this to data
        if data is not None and not isinstance(data, Data):
            raise TypeError('`data` must be a Data instance or None')
        else:
            self.data = data

    def sign(self, private_keys):
        """ Signs a transaction
            Acts as a proxy for `_sign_fulfillments`, for exposing a nicer API to the outside.
        """
        self._sign_fulfillments(private_keys)
        return self

    def _sign_fulfillments(self, private_keys):
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

        for fulfillment, condition in zip(self.fulfillments, self.conditions):
            # NOTE: We clone the current transaction but only add the condition and fulfillment we're currently
            # working on.
            tx_partial = Transaction(self.operation, [fulfillment], [condition], self.data, self.timestamp,
                                     self.version)
            self._sign_fulfillment(fulfillment, str(tx_partial), key_pairs)

    def _sign_fulfillment(self, fulfillment, tx_serialized, key_pairs):
        if isinstance(fulfillment.fulfillment, Ed25519Fulfillment):
            self._fulfill_simple_signature_fulfillment(fulfillment, tx_serialized, key_pairs)
        elif isinstance(fulfillment.fulfillment, ThresholdSha256Fulfillment):
            # TODO: get owners_before from fulfillment
            # TODO: Not sure if we need to update it to a new fulfillment
            fulfillment = self._fulfill_threshold_signature_fulfillment(fulfillment, tx_serialized, key_pairs)

    def _fulfill_simple_signature_fulfillment(self, fulfillment, tx_serialized, key_pairs):
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
        owner_before = fulfillment.owners_before[0]
        try:
            # NOTE: By signing the CC fulfillment here directly, we're changing the transactions's fulfillment by
            # reference, and that's good :)
            fulfillment.fulfillment.sign(tx_serialized, key_pairs[owner_before])
        except KeyError:
            raise KeypairMismatchException('Public key {} is not a pair to any of the private keys'
                                           .format(owner_before))

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

    def to_dict(self):
        try:
            data = self.data.to_dict()
        except AttributeError:
            # NOTE: data can be None and that's OK
            data = None

        tx_body = {
            'fulfillments': [fulfillment.to_dict() for fulfillment in self.fulfillments],
            'conditions': [condition.to_dict() for condition in self.conditions],
            'operation': str(self.operation),
            'timestamp': self.timestamp,
            'data': data,
        }
        tx = {
            'version': self.version,
            'transaction': tx_body,
        }

        tx_id = Transaction._to_hash(Transaction._to_str(Transaction._remove_signatures(tx)))
        tx['id'] = tx_id

        return tx

    @staticmethod
    def _remove_signatures(tx_dict):
        # NOTE: Remove reference since we need `tx_dict` only for the transaction's hash
        tx_dict = deepcopy(tx_dict)
        for fulfillment in tx_dict['transaction']['fulfillments']:
            fulfillment['details']['signature'] = None
            fulfillment['fulfillment'] = None
        return tx_dict

    @staticmethod
    def _to_hash(value):
        return hash_data(value)

    def to_hash(self):
        return self.to_dict()['id']

    @staticmethod
    def _to_str(value):
        return serialize(value)

    def __str__(self):
        return Transaction._to_str(self.to_dict())

    @classmethod
    def from_dict(cls, tx_body):
        tx = tx_body['transaction']
        return cls(tx['operation'], [Fulfillment.from_dict(fulfillment) for fulfillment in tx['fulfillments']],
                   [Condition.from_dict(condition) for condition in tx['conditions']], Data.from_dict(tx['data']),
                   tx['timestamp'], tx_body['version'])
