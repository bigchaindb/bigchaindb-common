from copy import deepcopy
from functools import reduce
from operator import and_
from uuid import uuid4

from cryptoconditions import (
    Fulfillment as CCFulfillment,
    ThresholdSha256Fulfillment,
    Ed25519Fulfillment,
)
from cryptoconditions.exceptions import ParsingError

from bigchaindb_common.crypto import (
    SigningKey,
    hash_data,
)
from bigchaindb_common.exceptions import (
    KeypairMismatchException,
    InvalidHash,
)
from bigchaindb_common.util import (
    serialize,
    gen_timestamp,
)


class Fulfillment(object):
    def __init__(self, fulfillment, owners_before, tx_input=None):
        self.fulfillment = fulfillment

        if tx_input is not None and not isinstance(tx_input, TransactionLink):
            raise TypeError('`tx_input` must be a TransactionLink instance')
        else:
            self.tx_input = tx_input

        if not isinstance(owners_before, list):
            raise TypeError('`owners_after` must be a list instance')
        else:
            self.owners_before = owners_before

    def __eq__(self, other):
        return self.to_dict() == other.to_dict()

    def to_dict(self, fid=None):
        try:
            fulfillment = self.fulfillment.serialize_uri()
        except (TypeError, AttributeError):
            fulfillment = None

        try:
            # NOTE: `self.tx_input` can be `None` and that's fine
            tx_input = self.tx_input.to_dict()
        except AttributeError:
            tx_input = None

        ffill = {
            'owners_before': self.owners_before,
            'input': tx_input,
            'fulfillment': fulfillment,
        }
        if fid is not None:
            ffill['fid'] = fid
        return ffill

    @classmethod
    def from_dict(cls, ffill):
        """ Serializes a BigchainDB 'jsonized' fulfillment back to a BigchainDB Fulfillment class.
        """
        try:
            fulfillment = CCFulfillment.from_uri(ffill['fulfillment'])
        except TypeError:
            fulfillment = None
        return cls(fulfillment, ffill['owners_before'], TransactionLink.from_dict(ffill['input']))


class TransactionLink(object):
    # NOTE: In an IPLD implementation, this class is not necessary anymore, as an IPLD link can simply point to an
    #       object, as well as an objects properties. So instead of having a (de)serializable class, we can have a
    #       simple IPLD link of the form: `/<tx_id>/transaction/conditions/<cid>/`
    def __init__(self, txid=None, cid=None):
        self.txid = txid
        self.cid = cid

    def __bool__(self):
        return not (self.txid is None and self.cid is None)

    def __eq__(self, other):
        return self.to_dict() == self.to_dict()

    @classmethod
    def from_dict(cls, link):
        try:
            return cls(link['txid'], link['cid'])
        except TypeError:
            return cls()

    def to_dict(self):
        if self.txid is None and self.cid is None:
            return None
        else:
            return {
                'txid': self.txid,
                'cid': self.cid,
            }


class Condition(object):
    def __init__(self, fulfillment, owners_after=None):
        # TODO: Add more description
        """Create a new condition for a fulfillment

        Args
            owners_after (Optional(list)): base58 encoded public key of the owner of the digital asset after
            this transaction.

        """
        self.fulfillment = fulfillment

        if not isinstance(owners_after, list):
            raise TypeError('`owners_after` must be a list instance')
        else:
            self.owners_after = owners_after

    def __eq__(self, other):
        return self.to_dict() == other.to_dict()

    def to_dict(self, cid=None):
        cond = {
            'owners_after': self.owners_after,
            'condition': {
                'details': self.fulfillment.to_dict(),
                'uri': self.fulfillment.condition_uri,
            }
        }
        if cid is not None:
            cond['cid'] = cid
        return cond

    @classmethod
    def from_dict(cls, cond):
        fulfillment = CCFulfillment.from_dict(cond['condition']['details'])
        return cls(fulfillment, cond['owners_after'])


class Data(object):
    def __init__(self, payload=None, payload_id=None):
        self.payload_id = payload_id if payload_id is not None else self.to_hash()
        if payload is not None and not isinstance(payload, dict):
            raise TypeError('`payload` must be a dict instance or None')
        else:
            self.payload = payload

    def __eq__(self, other):
        return self.to_dict() == other.to_dict()

    @classmethod
    def from_dict(cls, payload):
        try:
            return cls(payload['payload'], payload['uuid'])
        except TypeError:
            return cls()

    def to_dict(self):
        if self.payload is None:
            return None
        else:
            return {
                'payload': self.payload,
                'uuid': self.payload_id,
            }

    def to_hash(self):
        return str(uuid4())


class Transaction(object):
    CREATE = 'CREATE'
    TRANSFER = 'TRANSFER'
    GENESIS = 'GENESIS'
    ALLOWED_OPERATIONS = (CREATE, TRANSFER, GENESIS)
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
        self.timestamp = timestamp if timestamp is not None else gen_timestamp()
        self.version = version if version is not None else Transaction.VERSION

        if operation not in Transaction.ALLOWED_OPERATIONS:
            raise TypeError('`operation` must be either CREATE or TRANSFER')
        else:
            self.operation = operation

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

        if data is not None and not isinstance(data, Data):
            raise TypeError('`data` must be a Data instance or None')
        else:
            self.data = data

    def __eq__(self, other):
        return self.to_dict() == other.to_dict()

    def add_fulfillment(self, fulfillment):
        if fulfillment is not None and not isinstance(fulfillment, Fulfillment):
            raise TypeError('`fulfillment` must be a Fulfillment instance or None')
        else:
            self.fulfillments.append(fulfillment)

    def add_condition(self, condition):
        if condition is not None and not isinstance(condition, Condition):
            raise TypeError('`condition` must be a Condition instance or None')
        else:
            self.conditions.append(condition)

    def sign(self, private_keys):
        """ Signs a transaction
            Acts as a proxy for `_sign_fulfillments`, for exposing a nicer API to the outside.
        """
        self._sign_fulfillments(private_keys)
        return self

    def _sign_fulfillments(self, private_keys):
        if private_keys is None or not isinstance(private_keys, list):
            raise TypeError('`private_keys` must be a list instance')

        # Generate public keys from private keys and match them in a dictionary:
        #   key:     public_key
        #   value:   private_key
        def gen_public_key(private_key):
            # TODO FOR CC: Adjust interface so that this function becomes unnecessary
            return private_key.get_verifying_key().to_ascii().decode()
        key_pairs = {gen_public_key(SigningKey(private_key)): SigningKey(private_key) for private_key in private_keys}

        # TODO: The condition for a transfer-tx will come from an input
        for index, (fulfillment, condition) in enumerate(zip(self.fulfillments, self.conditions)):
            # NOTE: We clone the current transaction but only add the condition and fulfillment we're currently
            # working on plus all previously signed ones.
            tx_partial = Transaction(self.operation, [fulfillment], [condition], self.data, self.timestamp,
                                     self.version)
            tx_serialized = Transaction._to_str(Transaction._remove_signatures(tx_partial.to_dict()))
            self._sign_fulfillment(fulfillment, index, tx_serialized, key_pairs)

    def _sign_fulfillment(self, fulfillment, index, tx_serialized, key_pairs):
        if isinstance(fulfillment.fulfillment, Ed25519Fulfillment):
            self._sign_simple_signature_fulfillment(fulfillment, index, tx_serialized, key_pairs)
        elif isinstance(fulfillment.fulfillment, ThresholdSha256Fulfillment):
            self._sign_threshold_signature_fulfillment(fulfillment, index, tx_serialized, key_pairs)

    def _sign_simple_signature_fulfillment(self, fulfillment, index, tx_serialized, key_pairs):
        # NOTE: To eliminate the dangers of accidentially signing a condition by reference,
        #       we remove the reference of fulfillment here intentionally.
        #       If the user of this class knows how to use it, this should never happen,
        #       but then again, never say never.
        fulfillment = deepcopy(fulfillment)
        owner_before = fulfillment.owners_before[0]
        try:
            fulfillment.fulfillment.sign(tx_serialized, key_pairs[owner_before])
        except KeyError:
            raise KeypairMismatchException('Public key {} is not a pair to any of the private keys'
                                           .format(owner_before))
        self.fulfillments[index] = fulfillment

    def _sign_threshold_signature_fulfillment(self, fulfillment, index, tx_serialized, key_pairs):
        fulfillment = deepcopy(fulfillment)
        for owner_before in fulfillment.owners_before:
            try:
                # TODO: CC should throw a KeypairMismatchException, instead of our manual mapping here
                # TODO FOR CC: Naming wise this is not so smart, `get_subcondition` in fact doesn't return a condition
                #              but a fulfillment:(
                # TODO FOR CC: `get_subcondition` is singular. One would not expect to get a list back.
                subfulfillment = fulfillment.fulfillment.get_subcondition_from_vk(owner_before)[0]
            except IndexError:
                raise KeypairMismatchException('Public key {} cannot be found in the fulfillment'
                                               .format(owner_before))
            try:
                private_key = key_pairs[owner_before]
            except KeyError:
                raise KeypairMismatchException('Public key {} is not a pair to any of the private keys'
                                               .format(owner_before))

            subfulfillment.sign(tx_serialized, private_key)
        self.fulfillments[index] = fulfillment

    def fulfillments_valid(self, input_conditions=None):
        if self.operation in (Transaction.CREATE, Transaction.GENESIS):
            return self._fulfillments_valid([cond.fulfillment.condition_uri
                                             for cond in self.conditions])
        elif self.operation == Transaction.TRANSFER:
            return self._fulfillments_valid([cond.fulfillment.condition_uri
                                             for cond in input_conditions])
        else:
            raise TypeError('`operation` must be either `TRANSFER`, `CREATE` or `GENESIS`')

    def _fulfillments_valid(self, input_condition_uris):
        input_condition_uris_count = len(input_condition_uris)
        fulfillments_count = len(self.fulfillments)
        conditions_count = len(self.conditions)

        def gen_tx(fulfillment, condition, input_condition_uri=None):
            tx = Transaction(self.operation, [fulfillment], [condition],
                             self.data, self.timestamp, self.version)
            tx_serialized = Transaction._to_str(Transaction._remove_signatures(tx.to_dict()))
            return Transaction._fulfillment_valid(fulfillment, tx_serialized,
                                                  input_condition_uri)

        if not fulfillments_count == conditions_count == input_condition_uris_count:
            raise ValueError('Fulfillments, conditions and input_condition_uris must have the same count')
        else:
            return reduce(and_, map(gen_tx, self.fulfillments, self.conditions, input_condition_uris))

    @staticmethod
    def _fulfillment_valid(fulfillment, tx_serialized, input_condition_uri=None):
        try:
            parsed_fulfillment = CCFulfillment.from_uri(fulfillment.fulfillment.serialize_uri())
        except (TypeError, ValueError, ParsingError):
            return False
        input_condition_valid = input_condition_uri == fulfillment.fulfillment.condition_uri

        # NOTE: We pass a timestamp to `.validate`, as in case of a timeout condition we'll have to validate against
        #       it.
        return parsed_fulfillment.validate(message=tx_serialized, now=gen_timestamp()) and input_condition_valid

    def to_dict(self):
        try:
            data = self.data.to_dict()
        except AttributeError:
            # NOTE: data can be None and that's OK
            data = None

        tx_body = {
            'fulfillments': [fulfillment.to_dict(fid) for fid, fulfillment
                             in enumerate(self.fulfillments)],
            'conditions': [condition.to_dict(cid) for cid, condition
                           in enumerate(self.conditions)],
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
        # NOTE: We remove the reference since we need `tx_dict` only for the transaction's hash
        tx_dict = deepcopy(tx_dict)
        for fulfillment in tx_dict['transaction']['fulfillments']:
            # NOTE: Not all Cryptoconditions return a `signature` key (e.g. ThresholdSha256Fulfillment), so setting it
            #       to `None` in any case could yield incorrect signatures. This is why we only set it to `None` if
            #       it's set in the dict.
            fulfillment['fulfillment'] = None
        return tx_dict

    @staticmethod
    def _to_hash(value):
        return hash_data(value)

    @property
    def id(self):
        return self.to_hash()

    def to_hash(self):
        return self.to_dict()['id']

    @staticmethod
    def _to_str(value):
        return serialize(value)

    def __str__(self):
        return Transaction._to_str(self.to_dict())

    @classmethod
    # TODO: Make this method more pretty
    def from_dict(cls, tx_body):
        # NOTE: Remove reference to avoid side effects
        tx_body = deepcopy(tx_body)
        try:
            proposed_tx_id = tx_body.pop('id')
        except KeyError:
            raise InvalidHash()
        valid_tx_id = Transaction._to_hash(Transaction._to_str(Transaction._remove_signatures(tx_body)))
        if proposed_tx_id != valid_tx_id:
            raise InvalidHash()
        else:
            tx = tx_body['transaction']
            fulfillments = [Fulfillment.from_dict(fulfillment) for fulfillment
                            in tx['fulfillments']]
            conditions = [Condition.from_dict(condition) for condition
                          in tx['conditions']]
            data = Data.from_dict(tx['data'])
            return cls(tx['operation'], fulfillments, conditions, data,
                       tx['timestamp'], tx_body['version'])
