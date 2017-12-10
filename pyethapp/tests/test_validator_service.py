from itertools import count
import os
import pytest
import rlp
import shutil
import tempfile
from devp2p.service import BaseService
from ethereum.config import default_config
from pyethapp.config import update_config_with_defaults, get_default_config
from ethereum.hybrid_casper import casper_utils
from ethereum.pow.ethpow import mine
from ethereum.slogging import get_logger, configure_logging
from ethereum.tools import tester
from ethereum.utils import encode_hex, decode_int
from pyethapp.app import EthApp
from pyethapp.db_service import DBService
from pyethapp.eth_service import ChainService
from pyethapp.validator_service import ValidatorService
from pyethapp.pow_service import PoWService

log = get_logger('tests.validator_service')
configure_logging('tests.validator_service:debug,validator:debug,eth.chainservice:debug')

class MockAddress(object):
    def __init__(self):
        self.address = tester.accounts[0]
        self.privkey = tester.keys[0]
    def sign_tx(self, tx):
        return tx.sign(self.privkey)
mock_address = MockAddress()

class AccountsServiceMock(BaseService):
    name = 'accounts'

    def __init__(self, app):
        super(AccountsServiceMock, self).__init__(app)
        self.coinbase = mock_address

    def find(self, address):
        assert address == encode_hex(tester.accounts[0])
        return mock_address

class PeerManagerMock(BaseService):
    name = 'peermanager'

    def broadcast(*args, **kwargs):
        pass

@pytest.fixture()
def test_app(request, tmpdir):
    class TestApp(EthApp):
        def mine_blocks(self, n):
            for i in range(0, n):
                self.mine_one_block()

        def mine_to_next_epoch(self, number_of_epochs=1):
            epoch_length = self.config['eth']['block']['EPOCH_LENGTH']
            distance_to_next_epoch = (epoch_length - self.services.chain.chain.state.block_number) % epoch_length
            number_of_blocks = distance_to_next_epoch + epoch_length*(number_of_epochs-1) + 2
            return self.mine_blocks(number_of_blocks)

        def mine_one_block(self):
            """Mine until a valid nonce is found.
            :returns: the new head
            """
            log.debug('mining next block')
            block = self.services.chain.head_candidate
            chain = self.services.chain.chain
            head_number = chain.head.number
            delta_nonce = 10**6
            for start_nonce in count(0, delta_nonce):
                bin_nonce, mixhash = mine(block.number, block.difficulty, block.mining_hash,
                                            start_nonce=start_nonce, rounds=delta_nonce)
                if bin_nonce:
                    break
            self.services.chain.add_mined_block(block)
            self.services.pow.recv_found_nonce(bin_nonce, mixhash, block.mining_hash)
            if len(chain.time_queue) > 0:
                # If we mine two blocks within one second, pyethereum will
                # force the new block's timestamp to be in the future (see
                # ethereum1_setup_block()), and when we try to add that block
                # to the chain (via Chain.add_block()), it will be put in a
                # queue for later processing. Since we need to ensure the
                # block has been added before we continue the test, we
                # have to manually process the time queue.
                log.debug('block mined too fast, processing time queue')
                chain.process_time_queue(new_time=block.timestamp)
            log.debug('block mined')
            assert chain.head.difficulty == 1
            assert chain.head.number == head_number + 1
            return chain.head

    config = {
        'db': {'implementation': 'EphemDB'},
        'eth': {
            'block': {  # reduced difficulty, increased gas limit, allocations to test accounts
                'GENESIS_DIFFICULTY': 1,
                'BLOCK_DIFF_FACTOR': 2,  # greater than difficulty, thus difficulty is constant
                'GENESIS_GAS_LIMIT': 3141592,
                'GENESIS_INITIAL_ALLOC': {
                    encode_hex(tester.accounts[0]): {'balance': 10**24},
                },
                # Casper FFG stuff
                'EPOCH_LENGTH': 10,
                'WITHDRAWAL_DELAY': 100,
                'BASE_INTEREST_FACTOR': 0.02,
                'BASE_PENALTY_FACTOR': 0.002,
            }
        },
        'validate': [encode_hex(tester.accounts[0])],
    }

    services = [
        AccountsServiceMock,
        DBService,
        ChainService,
        PoWService,
        PeerManagerMock,
        ValidatorService,
        ]
    update_config_with_defaults(config, get_default_config([TestApp] + services))
    update_config_with_defaults(config, {'eth': {'block': default_config}})
    app = TestApp(config)

    for service in services:
        service.register_with_app(app)

    return app

def test_login_sequence(test_app):
    v = test_app.services.validator

    assert v.valcode_tx is None
    assert v.deposit_tx is None

    t = tester.State(v.chain.state.ephemeral_clone())
    c = tester.ABIContract(t, casper_utils.casper_abi, v.chain.casper_address)
    assert c.get_current_epoch() == 0

    # Mining these first three blocks does the following:
    # 1. validator sends the valcode tx
    test_app.mine_blocks(1)
    assert v.valcode_tx is not None
    assert v.valcode_addr is not None
    assert v.deposit_tx is None
    assert not v.chain.state.get_code(v.valcode_addr)

    # 2. validator sends the deposit tx
    test_app.mine_blocks(1)
    assert v.valcode_tx is not None
    assert v.deposit_tx is not None
    assert v.chain.state.get_code(v.valcode_addr)

    # This should still fail
    validator_index = v.get_validator_index(v.chain.state)
    assert validator_index is None

    # 3. validator becomes active
    test_app.mine_blocks(3)

    # Check validator index
    validator_index = v.get_validator_index(v.chain.state)
    assert validator_index == 1

    # Go from epoch 0 -> epoch 1
    test_app.mine_to_next_epoch()
    # Check that epoch 0 was finalized (no validators logged in)
    t = tester.State(v.chain.state.ephemeral_clone())
    c = tester.ABIContract(t, casper_utils.casper_abi, v.chain.casper_address)
    assert c.get_current_epoch() == 1
    assert c.get_votes__is_finalized(0)

    # Go from epoch 1 -> epoch 2
    test_app.mine_to_next_epoch()
    # Check that epoch 1 was finalized (no validators logged in)
    t = tester.State(v.chain.state.ephemeral_clone())
    c = tester.ABIContract(t, casper_utils.casper_abi, v.chain.casper_address)
    assert c.get_current_epoch() == 2
    assert c.get_votes__is_finalized(1)

    # Make sure we're not logged in yet
    target_epoch = v.chain.state.block_number // v.epoch_length
    t = tester.State(v.chain.state.ephemeral_clone())
    c = tester.ABIContract(t, casper_utils.casper_abi, v.chain.casper_address)
    assert not v.is_logged_in(c, target_epoch, validator_index)

    # Mine one more epoch and we should be logged in
    test_app.mine_to_next_epoch()
    t = tester.State(v.chain.state.ephemeral_clone())
    c = tester.ABIContract(t, casper_utils.casper_abi, v.chain.casper_address)
    assert c.get_current_epoch() == 3
    target_epoch = v.chain.state.block_number // v.epoch_length
    source_epoch = c.get_recommended_source_epoch()
    assert v.is_logged_in(c, target_epoch, validator_index)

    # Make sure the vote transaction was generated
    vote = v.votes[target_epoch]
    assert vote is not None
    vote_decoded = rlp.decode(vote)
    # validator index
    assert decode_int(vote_decoded[0]) == validator_index
    # target
    assert decode_int(vote_decoded[2]) == target_epoch
    # source
    assert decode_int(vote_decoded[3]) == source_epoch

    # Check deposit level
    # TODO: do not hardcode; pass into validator service on create
    assert c.get_total_curdyn_deposits() == 5000 * 10**18

    # This should still fail
    with pytest.raises(tester.TransactionFailed):
        c.get_main_hash_voted_frac()

    # One more epoch and the vote_frac has a value (since it requires there
    # to be at least one vote for both the current and the prev epoch)
    test_app.mine_to_next_epoch()
    t = tester.State(v.chain.state.ephemeral_clone())
    c = tester.ABIContract(t, casper_utils.casper_abi, v.chain.casper_address)
    assert c.get_current_epoch() == 4

    # One more block to mine the vote
    test_app.mine_blocks(1)

    # Check deposit level (gone up) and vote_frac
    t = tester.State(v.chain.state.ephemeral_clone())
    c = tester.ABIContract(t, casper_utils.casper_abi, v.chain.casper_address)
    voted_frac = c.get_main_hash_voted_frac()
    assert c.get_total_curdyn_deposits() > 5000 * 10**18
    assert voted_frac > 0.99

def test_logout_and_withdraw(test_app):
    pass

def test_double_login(test_app):
    pass

def test_login_logout_login(test_app):
    pass

# Test slashing conditions--make sure that we don't violate them, and also
# make sure that we can catch slashable behavior on the part of another validator.

def test_prevent_double_vote(test_app):
    pass

def test_no_surround(test_app):
    pass

def test_catch_violation(test_app):
    pass