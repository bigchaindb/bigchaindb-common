"""
Fixtures and setup / teardown functions

Tasks:
1. setup test database before starting the tests
2. delete test database after running the tests
"""

import os
import copy

import pytest


DB_NAME = 'bigchain_test_{}'.format(os.getpid())

CONFIG = {
    'database': {
        'name': DB_NAME
    },
    'keypair': {
        'private': '31Lb1ZGKTyHnmVK3LUMrAUrPNfd4sE2YyBt3UA4A25aA',
        'public': '4XYfCbabAWVUCbjTmRTFEu2sc3dFEdkse4r6X498B1s8'
    }
}

# Test user. inputs will be created for this user. Cryptography Keys
USER_SIGNING_KEY = '8eJ8q9ZQpReWyQT5aFCiwtZ5wDZC4eDnCen88p3tQ6ie'
USER_VERIFYING_KEY = 'JEAkEJqLbbgDRAtMm8YAjGp759Aq2qTn9eaEHUj2XePE'


# We need this function to avoid loading an existing
# conf file located in the home of the user running
# the tests. If it's too aggressive we can change it
# later.
@pytest.fixture(scope='function', autouse=True)
def ignore_local_config_file(monkeypatch):
    def mock_file_config(filename=None):
        raise FileNotFoundError()

    monkeypatch.setattr('bigchaindb.config_utils.file_config', mock_file_config)


@pytest.fixture
def restore_config(request, node_config):
    from bigchaindb import config_utils
    config_utils.dict_config(node_config)


@pytest.fixture(scope='module')
def node_config():
    return copy.deepcopy(CONFIG)


@pytest.fixture
def user_sk():
    return USER_SIGNING_KEY


@pytest.fixture
def user_vk():
    return USER_VERIFYING_KEY


@pytest.fixture
def b(request, node_config):
    restore_config(request, node_config)
    from bigchaindb import Bigchain
    return Bigchain()

