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

class MockAccount(object):
    def __init__(self, account):
        for i in range(0, len(tester.accounts)):
            if encode_hex(tester.accounts[i]) == account:
                self.address = tester.accounts[i]
                self.privkey = tester.keys[i]
                return
        raise Exception("Bad account")

    def sign_tx(self, tx):
        return tx.sign(self.privkey)

class AccountsServiceMock(BaseService):
    name = 'accounts'

    def __init__(self, app):
        super(AccountsServiceMock, self).__init__(app)
        self.coinbase = None

    def find(self, account):
        self.coinbase = MockAccount(account)
        return self.coinbase

class PeerManagerMock(BaseService):
    name = 'peermanager'

    def broadcast(*args, **kwargs):
        pass

def _test_app(account):
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

        @property
        def casper(self):
            v = self.services.validator
            t = tester.State(v.chain.state.ephemeral_clone())
            return tester.ABIContract(t, casper_utils.casper_abi, v.chain.casper_address)

    config = {
        'db': {'implementation': 'EphemDB'},
        'eth': {
            'block': {  # reduced difficulty, increased gas limit, allocations to test accounts
                'GENESIS_DIFFICULTY': 1,
                'BLOCK_DIFF_FACTOR': 2,  # greater than difficulty, thus difficulty is constant
                'GENESIS_GAS_LIMIT': 3141592,
                'GENESIS_INITIAL_ALLOC': {
                    encode_hex(tester.accounts[0]): {'balance': 10**24},
                    encode_hex(tester.accounts[1]): {'balance': 10**24},
                },
                # Casper FFG stuff: set these arbitrarily short to facilitate testing
                'EPOCH_LENGTH': 10,
                'WITHDRAWAL_DELAY': 5,
                'BASE_INTEREST_FACTOR': 0.02,
                'BASE_PENALTY_FACTOR': 0.002,
                'DEPOSIT_SIZE': 5000 * 10**18,
            }
        },
        'validate': [encode_hex(account)],
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

@pytest.fixture()
def test_app():
    return _test_app(tester.accounts[0])

@pytest.fixture()
def test_app2():
    return _test_app(tester.accounts[1])

def test_login_logout_withdraw(test_app):
    """
    Basic full-circle test of normal validator behavior in normal circumstances
    (i.e., no slashing). Login, wait to vote, begin voting, logout, wait to withdraw
    deposit, then withdraw.
    """
    v = test_app.services.validator
    epoch_length = test_app.config['eth']['block']['EPOCH_LENGTH']
    withdrawal_delay = test_app.config['eth']['block']['WITHDRAWAL_DELAY']
    base_interest_factor = test_app.config['eth']['block']['BASE_INTEREST_FACTOR']
    base_penalty_factor = test_app.config['eth']['block']['BASE_PENALTY_FACTOR']
    deposit_size = test_app.config['eth']['block']['DEPOSIT_SIZE']
    initial_balance = test_app.config['eth']['block']['GENESIS_INITIAL_ALLOC'][encode_hex(v.coinbase.address)]['balance']

    assert not v.did_broadcast_valcode
    assert not v.did_broadcast_deposit
    assert v.chain.state.get_balance(v.coinbase.address) == initial_balance

    # We get opcode errors if this isn't true
    assert v.chain.state.is_METROPOLIS()

    assert test_app.casper.get_current_epoch() == 0

    # Mining these first three blocks does the following:
    # 1. validator sends the valcode tx
    test_app.mine_blocks(1)
    assert v.did_broadcast_valcode
    assert not v.did_broadcast_deposit
    assert v.valcode_addr is not None
    assert not v.chain.state.get_code(v.valcode_addr)

    # 2. validator sends the deposit tx
    test_app.mine_blocks(1)
    assert v.did_broadcast_valcode
    assert v.did_broadcast_deposit
    assert v.chain.state.get_code(v.valcode_addr)

    # This should still fail
    validator_index = v.get_validator_index(v.chain.state)
    assert validator_index is None

    # 3. validator becomes active
    test_app.mine_blocks(3)

    # Make sure the deposit moved
    assert v.chain.state.get_balance(v.coinbase.address) == initial_balance - deposit_size

    # Check validator index
    validator_index = v.get_validator_index(v.chain.state)
    assert validator_index == 1

    # Go from epoch 0 -> epoch 1
    test_app.mine_to_next_epoch()
    # Check that epoch 0 was finalized (no validators logged in)
    assert test_app.casper.get_current_epoch() == 1
    assert test_app.casper.get_votes__is_finalized(0)

    # Go from epoch 1 -> epoch 2
    test_app.mine_to_next_epoch()
    # Check that epoch 1 was finalized (no validators logged in)
    assert test_app.casper.get_current_epoch() == 2
    assert test_app.casper.get_votes__is_finalized(1)

    # Make sure we're not logged in yet
    target_epoch = v.chain.state.block_number // epoch_length
    assert not v.is_logged_in(test_app.casper, target_epoch, validator_index)

    # Mine one more epoch and we should be logged in
    test_app.mine_to_next_epoch()
    assert test_app.casper.get_current_epoch() == 3
    target_epoch = v.chain.state.block_number // epoch_length
    source_epoch = test_app.casper.get_recommended_source_epoch()
    assert v.is_logged_in(test_app.casper, target_epoch, validator_index)

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
    assert test_app.casper.get_total_curdyn_deposits() == deposit_size

    # This should still fail
    with pytest.raises(tester.TransactionFailed):
        test_app.casper.get_main_hash_voted_frac()

    # One more epoch and the vote_frac has a value (since it requires there
    # to be at least one vote for both the current and the prev epoch)
    test_app.mine_to_next_epoch()
    assert test_app.casper.get_current_epoch() == 4

    # One more block to mine the vote
    test_app.mine_blocks(1)

    # Check deposit level (gone up) and vote_frac
    voted_frac = test_app.casper.get_main_hash_voted_frac()
    assert test_app.casper.get_total_curdyn_deposits() > deposit_size
    assert voted_frac > 0.99

    # Finally, test logout and withdraw
    # Send logout
    v.broadcast_logout()
    test_app.mine_blocks(1)

    # Make sure we can't withdraw yet
    with pytest.raises(tester.TransactionFailed):
        v.broadcast_withdraw()

    # Make sure we are still logged in, can still vote, etc.
    test_app.mine_to_next_epoch()

    # One more block to mine the vote
    test_app.mine_blocks(1)
    assert test_app.casper.get_current_epoch() == 5
    voted_frac = test_app.casper.get_main_hash_voted_frac()
    assert test_app.casper.get_total_curdyn_deposits() > deposit_size
    assert voted_frac > 0.99
    target_epoch = v.chain.state.block_number // epoch_length
    assert v.is_logged_in(test_app.casper, target_epoch, validator_index)
    assert v.votes[target_epoch]

    # Mine two epochs
    test_app.mine_to_next_epoch()
    test_app.mine_to_next_epoch()

    # Make sure we don't vote, are not logged in
    assert test_app.casper.get_current_epoch() == 7

    # This fails because of division by zero
    with pytest.raises(tester.TransactionFailed):
        test_app.casper.get_main_hash_voted_frac()
    assert test_app.casper.get_total_curdyn_deposits() == 0
    target_epoch = v.chain.state.block_number // epoch_length
    assert not v.is_logged_in(test_app.casper, target_epoch, validator_index)
    with pytest.raises(KeyError):
        v.votes[target_epoch]

    # Mine until the epoch before we can withdraw
    test_app.mine_to_next_epoch(withdrawal_delay)
    assert test_app.casper.get_current_epoch() == 12

    # Make sure we cannot withdraw yet
    with pytest.raises(tester.TransactionFailed):
        v.broadcast_withdraw()

    # Make sure we can withdraw exactly at this epoch, not before
    test_app.mine_to_next_epoch()
    assert test_app.casper.get_current_epoch() == 13
    v.broadcast_withdraw()
    test_app.mine_blocks(1)

    # Make sure deposit was refunded (along with interest)
    assert v.chain.state.get_balance(v.coinbase.address) > initial_balance

    # Make sure finalization is still happening with no validators
    assert test_app.casper.get_votes__is_finalized(12)

def test_double_deposit(test_app):
    """
    Make sure we cannot login a second time if already logged in. Make sure
    second deposit tx fails.
    """
    v = test_app.services.validator
    initial_balance = test_app.config['eth']['block']['GENESIS_INITIAL_ALLOC'][encode_hex(v.coinbase.address)]['balance']
    epoch_length = test_app.config['eth']['block']['EPOCH_LENGTH']
    withdrawal_delay = test_app.config['eth']['block']['WITHDRAWAL_DELAY']
    assert test_app.casper.get_current_epoch() == 0

    # Broadcast valcode and deposits, log in, begin voting
    test_app.mine_to_next_epoch(3)

    # Try to login again, it should fail
    # To test this, we have break abstraction somewhat and simulate it here.
    deposit_tx = v.mk_deposit_tx(v.deposit_size, v.valcode_addr)
    with pytest.raises(tester.TransactionFailed):
        v.broadcast_tx(deposit_tx)

def test_login_logout_login(test_app):
    """
    Make sure we can login, logout, withdraw funds, then subsequently login
    and deposit again.
    """
    v = test_app.services.validator
    initial_balance = test_app.config['eth']['block']['GENESIS_INITIAL_ALLOC'][encode_hex(v.coinbase.address)]['balance']
    epoch_length = test_app.config['eth']['block']['EPOCH_LENGTH']
    withdrawal_delay = test_app.config['eth']['block']['WITHDRAWAL_DELAY']
    assert test_app.casper.get_current_epoch() == 0

    # Broadcast valcode and deposits, log in, begin voting
    test_app.mine_to_next_epoch(3)
    target_epoch = v.chain.state.block_number // epoch_length
    source_epoch = test_app.casper.get_recommended_source_epoch()
    assert v.is_logged_in(test_app.casper, target_epoch, validator_index)
    assert v.votes[target_epoch]

    # Broadcast logout
    v.broadcast_logout()
    test_app.mine_to_next_epoch(3+withdrawal_delay)

    # Redeem deposit
    v.broadcast_withdraw()
    test_app.mine_blocks(1)
    balance1 = v.chain.state.get_balance(v.coinbase.address)
    assert balance1 > initial_balance

    # Reset the validator state
    test_app.deregister_service(v)
    ValidatorService.register_with_app(test_app)
    v = test_app.services.validator

    # Log in again, begin voting
    test_app.mine_to_next_epoch(3)
    target_epoch = v.chain.state.block_number // epoch_length
    source_epoch = test_app.casper.get_recommended_source_epoch()
    assert v.is_logged_in(test_app.casper, target_epoch, validator_index)
    assert v.votes[target_epoch]

    # Broadcast logout again
    v.broadcast_logout()
    test_app.mine_to_next_epoch(3+withdrawal_delay)

    # Redeem deposit again
    v.broadcast_withdraw()
    test_app.mine_blocks(1)
    assert v.chain.state.get_balance(v.coinbase.address) > balance_1

def test_multiple_validators(test_app, test_app2):
    """
    Test how multiple validators behave in each others' presence. Make sure
    they both deposit and vote.
    """
    deposit_size = test_app.config['eth']['block']['DEPOSIT_SIZE']

    # Link the two validators
    v1 = test_app.services.validator
    v2 = test_app2.services.validator
    test_app2.services.chain = test_app.services.chain
    v2.chainservice = test_app.services.chain
    v2.chain = test_app.services.chain.chain
    test_app.services.chain.on_new_head_cbs.append(test_app2.services.validator.on_new_head)

    # Make sure the valcode txs worked
    test_app.mine_blocks(2)
    assert v1.chain.state.get_code(v1.valcode_addr)
    assert v2.chain.state.get_code(v2.valcode_addr)

    # Vote a bunch until vote frac is calculable
    test_app.mine_to_next_epoch(6)
    # One more block to mine the vote
    test_app.mine_blocks(1)
    voted_frac = test_app.casper.get_main_hash_voted_frac()
    assert test_app.casper.get_total_curdyn_deposits() > deposit_size * 2
    assert voted_frac > 0.99

# Test slashing conditions--make sure that we don't violate them, and also
# make sure that we can catch slashable behavior on the part of another validator.

def test_prevent_double_vote(test_app):
    """
    Make sure the validator service never votes for the same target epoch twice.
    """
    pass

def test_no_surround(test_app):
    """
    Make sure the validator service never casts a vote surrounding another.
    """
    pass

def test_catch_violation(test_app):
    """
    Make sure the validator service recognizes and reports slashable behavior
    on the part of another validator.
    """
    pass