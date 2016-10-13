from pytest import raises

# TODO: Test asset amount


def test_asset_default_values():
    from bigchaindb_common.transaction import Asset

    asset = Asset()
    assert asset.data is None
    assert asset.data_id
    assert asset.divisible is False
    assert asset.updatable is False
    assert asset.refillable is False


def test_asset_creation_with_data(data):
    from bigchaindb_common.transaction import Asset
    
    asset = Asset(data)
    assert asset.data == data


def test_asset_invalid_asset_initialization():
    from bigchaindb_common.transaction import Asset

    with raises(TypeError):
        Asset(data='some wrong type')


def test_invalid_asset_comparison(data, data_id):
    from bigchaindb_common.transaction import Asset

    assert Asset(data, data_id) != 'invalid comparison'


def test_asset_serialization(data, data_id):
    from bigchaindb_common.transaction import Asset

    expected = {
        'id': data_id,
        'divisible': False,
        'updatable': False,
        'refillable': False,
        'data': data,
    }
    asset = Asset(data, data_id)
    assert asset.to_dict() == expected


def test_asset_deserialization(data, data_id):
    from bigchaindb_common.transaction import Asset

    asset_dict = {
        'id': data_id,
        'divisible': False,
        'updatable': False,
        'refillable': False,
        'data': data,
    }
    asset = Asset.from_dict(asset_dict)
    expected = Asset(data, data_id)
    assert asset == expected


"""
@pytest.mark.usefixtures('inputs')
def test_asset_transfer(b, user_vk, user_sk):
    tx_input = b.get_owned_ids(user_vk).pop()
    tx_create = b.get_transaction(tx_input['txid'])
    tx_transfer = b.create_transaction(user_vk, user_vk, tx_input, 'TRANSFER')
    tx_transfer_signed = b.sign_transaction(tx_transfer, user_sk)

    assert b.validate_transaction(tx_transfer_signed) == tx_transfer_signed
    assert tx_transfer_signed['transaction']['asset']['id'] == tx_create['transaction']['asset']['id']
"""

"""
def test_validate_bad_asset_creation(b, user_vk):
    from bigchaindb.util import get_hash_data
    from bigchaindb_common.exceptions import AmountError

    tx = b.create_transaction(b.me, user_vk, None, 'CREATE')
    tx['transaction']['asset'].update({'divisible': 1})
    tx['id'] = get_hash_data(tx['transaction'])
    tx_signed = b.sign_transaction(tx, b.me_private)
    with pytest.raises(TypeError):
        b.validate_transaction(tx_signed)

    tx = b.create_transaction(b.me, user_vk, None, 'CREATE')
    tx['transaction']['asset'].update({'refillable': 1})
    tx['id'] = get_hash_data(tx['transaction'])
    tx_signed = b.sign_transaction(tx, b.me_private)
    with pytest.raises(TypeError):
        b.validate_transaction(tx_signed)

    tx = b.create_transaction(b.me, user_vk, None, 'CREATE')
    tx['transaction']['asset'].update({'updatable': 1})
    tx['id'] = get_hash_data(tx['transaction'])
    tx_signed = b.sign_transaction(tx, b.me_private)
    with pytest.raises(TypeError):
        b.validate_transaction(tx_signed)

    tx = b.create_transaction(b.me, user_vk, None, 'CREATE')
    tx['transaction']['asset'].update({'data': 'a'})
    tx['id'] = get_hash_data(tx['transaction'])
    tx_signed = b.sign_transaction(tx, b.me_private)
    with pytest.raises(TypeError):
        b.validate_transaction(tx_signed)

    tx = b.create_transaction(b.me, user_vk, None, 'CREATE')
    tx['transaction']['conditions'][0]['amount'] = 'a'
    tx['id'] = get_hash_data(tx['transaction'])
    tx_signed = b.sign_transaction(tx, b.me_private)
    with pytest.raises(TypeError):
        b.validate_transaction(tx_signed)

    tx = b.create_transaction(b.me, user_vk, None, 'CREATE')
    tx['transaction']['conditions'][0]['amount'] = 2
    tx['transaction']['asset'].update({'divisible': False})
    tx['id'] = get_hash_data(tx['transaction'])
    tx_signed = b.sign_transaction(tx, b.me_private)
    with pytest.raises(AmountError):
        b.validate_transaction(tx_signed)

    tx = b.create_transaction(b.me, user_vk, None, 'CREATE')
    tx['transaction']['conditions'][0]['amount'] = 0
    tx['id'] = get_hash_data(tx['transaction'])
    tx_signed = b.sign_transaction(tx, b.me_private)
    with pytest.raises(AmountError):
        b.validate_transaction(tx_signed)
"""

"""
@pytest.mark.usefixtures('inputs')
def test_validate_transfer_asset_id_mismatch(b, user_vk, user_sk):
    from bigchaindb.util import get_hash_data
    from bigchaindb_common.exceptions import AssetIdMismatch

    tx_input = b.get_owned_ids(user_vk).pop()
    tx = b.create_transaction(user_vk, user_vk, tx_input, 'TRANFER')
    tx['transaction']['asset']['id'] = 'aaa'
    tx['id'] = get_hash_data(tx['transaction'])
    tx_signed = b.sign_transaction(tx, user_sk)
    with pytest.raises(AssetIdMismatch):
        b.validate_transaction(tx_signed)
"""

def test_validate_asset():
    from bigchaindb_common.transaction import Asset

    with raises(TypeError):
        Asset(divisible=1)
    with raises(TypeError):
        Asset(refillable=1)
    with raises(TypeError):
        Asset(updatable=1)
    with raises(TypeError):
        Asset(data='we need more lemon pledge')

    # TODO: Handle this
    # with pytest.raises(TypeError):
    #     b.create_transaction(b.me, b.me, None, 'CREATE', amount='a')
    # with pytest.raises(AmountError):
    #     b.create_transaction(b.me, b.me, None, 'CREATE', divisible=False, amount=2)
    # with pytest.raises(AmountError):
    #     b.create_transaction(b.me, b.me, None, 'CREATE', amount=0)


"""
@pytest.mark.usefixtures('inputs')
def test_get_asset_id_create_transaction(b, user_vk):
    from bigchaindb.assets import get_asset_id

    tx_input = b.get_owned_ids(user_vk).pop()
    tx_create = b.get_transaction(tx_input['txid'])
    asset_id = get_asset_id(tx_create)

    assert asset_id == tx_create['transaction']['asset']['id']
"""

"""
@pytest.mark.usefixtures('inputs')
def test_get_asset_id_transfer_transaction(b, user_vk, user_sk):
    from bigchaindb.assets import get_asset_id

    tx_input = b.get_owned_ids(user_vk).pop()
    # create a transfer transaction
    tx_transfer = b.create_transaction(user_vk, user_vk, tx_input, 'TRANSFER')
    tx_transfer_signed = b.sign_transaction(tx_transfer, user_sk)
    # create a block
    block = b.create_block([tx_transfer_signed])
    b.write_block(block, durability='hard')
    # vote the block valid
    vote = b.vote(block['id'], b.get_last_voted_block()['id'], True)
    b.write_vote(vote)
    asset_id = get_asset_id(tx_transfer)

    assert asset_id == tx_transfer['transaction']['asset']['id']
"""

"""
@pytest.mark.usefixtures('inputs')
def test_asset_id_mismatch(b, user_vk):
    from bigchaindb.assets import get_asset_id
    from bigchaindb_common.exceptions import AssetIdMismatch

    tx_input1, tx_input2 = b.get_owned_ids(user_vk)[:2]
    tx1 = b.get_transaction(tx_input1['txid'])
    tx2 = b.get_transaction(tx_input2['txid'])

    with pytest.raises(AssetIdMismatch):
        get_asset_id([tx1, tx2])
"""

"""
def test_get_asset_id_transaction_does_not_exist(b, user_vk):
    from bigchaindb_common.exceptions import TransactionDoesNotExist

    with pytest.raises(TransactionDoesNotExist):
        b.create_transaction(user_vk, user_vk, {'txid': 'bored', 'cid': '0'}, 'TRANSFER')
"""

"""
@pytest.mark.usefixtures('inputs')
def test_get_txs_by_asset_id(b, user_vk, user_sk):
    tx_input = b.get_owned_ids(user_vk).pop()
    tx = b.get_transaction(tx_input['txid'])
    asset_id = tx['transaction']['asset']['id']
    txs = b.get_txs_by_asset_id(asset_id)

    assert len(txs) == 1
    assert txs[0]['id'] == tx['id']
    assert txs[0]['transaction']['asset']['id'] == asset_id

    # create a transfer transaction
    tx_transfer = b.create_transaction(user_vk, user_vk, tx_input, 'TRANSFER')
    tx_transfer_signed = b.sign_transaction(tx_transfer, user_sk)
    # create the block
    block = b.create_block([tx_transfer_signed])
    b.write_block(block, durability='hard')
    # vote the block valid
    vote = b.vote(block['id'], b.get_last_voted_block()['id'], True)
    b.write_vote(vote)

    txs = b.get_txs_by_asset_id(asset_id)

    assert len(txs) == 2
    assert tx['id'] in [t['id'] for t in txs]
    assert tx_transfer['id'] in [t['id'] for t in txs]
    assert asset_id == txs[0]['transaction']['asset']['id']
    assert asset_id == txs[1]['transaction']['asset']['id']
"""
