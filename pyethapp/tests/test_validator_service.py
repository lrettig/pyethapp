from itertools import count
import pytest
import shutil
import tempfile
from devp2p.service import BaseService
from ethereum.config import default_config
from pyethapp.config import update_config_with_defaults, get_default_config
from ethereum.pow.ethpow import mine
from ethereum.slogging import get_logger, configure_logging
from ethereum.tools import tester
from ethereum.utils import encode_hex
from pyethapp.app import EthApp
from pyethapp.db_service import DBService
from pyethapp.eth_service import ChainService
from pyethapp.accounts import Account, AccountsService
from pyethapp.validator_service import ValidatorService
from pyethapp.pow_service import PoWService

log = get_logger('tests.validator_service')
# configure_logging('tests.validator_service:debug,validator:debug,eth.chainservice:debug,eth.pb.tx:debug')
configure_logging('tests.validator_service:debug,validator:debug,eth.chainservice:debug')

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

        def mine_epoch(self):
            epoch_length = self.config['eth']['block']['EPOCH_LENGTH']
            return self.mine_blocks(epoch_length)

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
        'data_dir': str(tmpdir),
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
        DBService,
        ChainService,
        PoWService,
        PeerManagerMock,
        ValidatorService,
        ]
    update_config_with_defaults(config, get_default_config([TestApp] + services))
    update_config_with_defaults(config, {'eth': {'block': default_config}})
    app = TestApp(config)

    # Add AccountsService first and initialize with coinbase account
    AccountsService.register_with_app(app)
    app.services.accounts.add_account(Account.new('', tester.keys[0]), store=False)

    for service in services:
        service.register_with_app(app)

    return app

def test_generate_valcode(test_app):
    v = test_app.services.validator
    epoch_length = test_app.config['eth']['block']['EPOCH_LENGTH']

    assert v.valcode_tx is None
    assert v.deposit_tx is None

    # Mining these first three blocks does the following:
    # 1. validator sends the valcode tx
    test_app.mine_blocks(1)
    assert v.valcode_tx is not None
    assert v.deposit_tx is None
    assert not v.chain.state.get_code(self.valcode_addr)

    # 2. validator sends the deposit tx
    test_app.mine_blocks(1)
    assert v.valcode_tx is not None
    assert v.deposit_tx is not None
    assert v.chain.state.get_code(self.valcode_addr)

    # 3. validator becomes active
    test_app.mine_blocks(3)

    # Two more epochs and the validator should begin voting
    test_app.mine_epoch()
    test_app.mine_epoch()

    # Two more epochs and the vote_frac has a value (since it requires there
    # to be at least one vote for both the current and the prev epoch)
    test_app.mine_epoch()
    test_app.mine_epoch()

    assert True
