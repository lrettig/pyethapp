from __future__ import print_function
from devp2p.service import BaseService
from ethereum.slogging import get_logger
from ethereum.messages import apply_transaction
from ethereum.tools import tester
from ethereum import transactions
from ethereum import abi, utils
from ethereum.hybrid_casper import casper_utils

log = get_logger('validator')

class ValidatorService(BaseService):

    name = 'validator'
    default_config = dict(validator=dict(
        validating=False,
        privkey='',
        deposit_size=0
    ))

    def __init__(self, app):
        super(ValidatorService, self).__init__(app)

        self.config = app.config

        self.chainservice = app.services.chain
        self.chain = self.chainservice.chain
        self.deposit_size = self.config['eth']['block']['DEPOSIT_SIZE']
        self.valcode_addr = None
        self.did_broadcast_valcode = False
        self.did_broadcast_deposit = False
        self.votes = dict()
        self.latest_target_epoch = -1
        self.latest_source_epoch = -1
        self.epoch_length = self.chain.env.config['EPOCH_LENGTH']

        if app.config['validate']:
            self.coinbase = app.services.accounts.find(app.config['validate'][0])
            self.validating = True
        else:
            self.validating = False

        self.chainservice.on_new_head_cbs.append(self.on_new_head)

    def on_new_head(self, block):
        if not self.validating:
            log.info('[hybrid_casper] not validating, not updating')
            return
        if self.chainservice.is_syncing:
            log.info('[hybrid_casper] chain syncing, not updating')
            return
        self.update()

    def broadcast_tx(self, tx):
        """
        Make sure that a transaction succeeds, and "broadcast" it to the chain service.
        """
        temp_state = self.chain.state.ephemeral_clone()
        success, output = apply_transaction(temp_state, tx)
        if not success:
            raise tester.TransactionFailed('Transaction failed, not broadcasting: {}'.format(str(tx)))
        log.info('[hybrid_casper] Broadcasting successful tx: {}'.format(str(tx)))
        self.chainservice.add_transaction(tx)

    def broadcast_logout(self):
        epoch = self.chain.state.block_number // self.epoch_length
        # Generage the message
        logout_msg = casper_utils.mk_logout(self.get_validator_index(self.chain.state),
                                            epoch, self.coinbase.privkey)
        # Generate transactions
        logout_tx = self.mk_logout_tx(logout_msg)
        self.broadcast_tx(logout_tx)

    def broadcast_withdraw(self):
        casper = tester.ABIContract(tester.State(self.chain.state.ephemeral_clone()), casper_utils.casper_abi,
                                    self.chain.casper_address)
        validator_index = self.get_validator_index(self.chain.state)
        withdrawal_delay = casper.get_withdrawal_delay()
        end_dynasty = casper.get_validators__end_dynasty(validator_index)
        end_epoch = casper.get_dynasty_start_epoch(end_dynasty + 1)
        current_dynasty = casper.get_dynasty()
        current_epoch = casper.get_current_epoch()
        log.info(('[hybrid_casper] Attempting withdraw at dynasty {} - end dynasty {} - ' +
            'current_epoch {} - end_epoch {} - withdrawal_delay {} - validator idx {}').format(
                current_dynasty, end_dynasty, current_epoch, end_epoch, withdrawal_delay, validator_index))

        withdraw_tx = self.mk_withdraw_tx(validator_index)
        self.broadcast_tx(withdraw_tx)

    def update(self):
        log.info('[hybrid_casper] validator {} updating'.format(self))
        # Make sure we have enough ETH to deposit
        if self.chain.state.get_balance(self.coinbase.address) < self.deposit_size:
            log.info('[hybrid_casper] Cannot login as validator: insufficient balance')
            return

        # Note about valcode and deposit transactions: these need to be broadcast in
        # a particular order, valcode first. In order to ensure this, we check that
        # the valcode tx exists before we attempt to broadcast the deposit tx.

        # Generate valcode and deposit transactions
        elif not self.did_broadcast_valcode:
            valcode_tx = self.mk_validation_code_tx()
            nonce = self.chain.state.get_nonce(self.coinbase.address)
            self.valcode_addr = utils.mk_contract_address(self.coinbase.address, nonce)
            log.info('[hybrid_casper] Broadcasting valcode tx: {}'.format(str(valcode_tx)))
            self.broadcast_tx(valcode_tx)
            self.did_broadcast_valcode = True

            # Wait for it to be mined
            return

        # No point in going beyond this point until the valcode tx is mined
        elif not self.chain.state.get_code(self.valcode_addr):
            log.info('[hybrid_casper] Waiting for valcode tx to be mined')
            return

        # Now we can broadcast the deposit
        elif not self.did_broadcast_deposit:
            deposit_tx = self.mk_deposit_tx(self.deposit_size, self.valcode_addr)
            log.info('[hybrid_casper] Broadcasting deposit tx: {}'.format(str(deposit_tx)))
            self.broadcast_tx(deposit_tx)
            self.did_broadcast_deposit = True

            # Wait for it to be mined
            return

        # We are clear to vote!
        casper = tester.ABIContract(tester.State(self.chain.state.ephemeral_clone()), casper_utils.casper_abi,
                                    self.chain.casper_address)
        validator_index = self.get_validator_index(self.chain.state)
        log.info('[hybrid_casper] Active validator index: {}'.format(validator_index))

        # This fails if there are zero deposits (div. by zero), e.g. if we are the first
        # validator to deposit
        try:
            voted_frac = casper.get_main_hash_voted_frac()
        except tester.TransactionFailed:
            voted_frac = "NaN"

        try:
            log.info('[hybrid_casper] Vote percent: {:.4%} - Deposits: {} - Recommended Source: {}'.format(
                float(voted_frac),
                casper.get_total_curdyn_deposits(),
                casper.get_recommended_source_epoch(),
            ))
            log.info('[hybrid_casper] Current epoch: {} - Current dynasty: {} - Start dynasty: {} - End dynasty: {}'.format(
                casper.get_current_epoch(),
                casper.get_dynasty(),
                casper.get_validators__start_dynasty(validator_index),
                casper.get_validators__end_dynasty(validator_index),
            ))
            is_justified = casper.get_votes__is_justified(casper.get_current_epoch())
            is_finalized = casper.get_votes__is_finalized(casper.get_current_epoch()-1)
            if is_justified:
                log.info('[hybrid_casper] Justified epoch: {}'.format(casper.get_current_epoch()))
            if is_finalized:
                log.info('[hybrid_casper] Finalized epoch: {}'.format(casper.get_current_epoch()-1))
        except tester.TransactionFailed as e:
            log.info('[hybrid_casper] Casper contract call failed: {}'.format(e))

        # Generate vote messages and broadcast if possible
        vote_msg = self.generate_vote_message()
        if vote_msg:
            vote_tx = self.mk_vote_tx(vote_msg)
            log.info('[hybrid_casper] Broadcasting vote: {}'.format(str(vote_tx)))
            self.chainservice.add_transaction(vote_tx)
        else:
            log.info('[hybrid_casper] Not voting this round')

    def is_logged_in(self, casper, target_epoch, validator_index):
        start_dynasty = casper.get_validators__start_dynasty(validator_index)
        end_dynasty = casper.get_validators__end_dynasty(validator_index)
        current_dynasty = casper.get_dynasty_in_epoch(target_epoch)
        past_dynasty = current_dynasty - 1
        in_current_dynasty = ((start_dynasty <= current_dynasty) and (current_dynasty < end_dynasty))
        in_prev_dynasty = ((start_dynasty <= past_dynasty) and (past_dynasty < end_dynasty))
        return (in_current_dynasty or in_prev_dynasty)

    def generate_vote_message(self):
        state = self.chain.state.ephemeral_clone()
        target_epoch = state.block_number // self.epoch_length
        # Wait until a specific blockheight before submitting vote
        wait_blocks = self.epoch_length // 4
        epoch_block_number = state.block_number % self.epoch_length
        if epoch_block_number < wait_blocks:
            log.info('[hybrid_casper] Waiting for epoch block {} to submit vote, now block {}'.format(wait_blocks, epoch_block_number))
            return None
        # NO_DBL_VOTE: Don't vote if we have already
        if target_epoch in self.votes:
            log.info('[hybrid_casper] Already voted for this epoch as target ({}), not voting again'.format(target_epoch))
            return None
        # Create a Casper contract which we can use to get related values
        casper = tester.ABIContract(tester.State(state), casper_utils.casper_abi, self.chain.casper_address)
        # Get the ancestry hash and source ancestry hash
        validator_index = self.get_validator_index(state)
        target_hash, target_epoch, source_epoch = self.get_recommended_casper_msg_contents(casper, validator_index)
        if target_hash is None:
            log.info('[hybrid_casper] Failed to get target hash, not voting')
            return None
        # Prevent NO_SURROUND slash. Note that this is a little over-conservative and thus suboptimal.
        # It strictly only allows votes for later sources and targets than we've already voted for.
        # It avoids voting in (rare) cases where it would be safe to do so, e.g., with an earlier
        # source _and_ an earlier target.
        if target_epoch < self.latest_target_epoch or source_epoch < self.latest_source_epoch:
            log.info('[hybrid_casper] Not voting to avoid NO_SURROUND slash')
            return None
        # Assert that we are logged in
        if not self.is_logged_in(casper, target_epoch, validator_index):
            log.info('[hybrid_casper] Validator not logged in, not voting')
            return None
        vote_msg = casper_utils.mk_vote(validator_index, target_hash, target_epoch, source_epoch, self.coinbase.privkey)
        # Save the vote message we generated
        self.votes[target_epoch] = vote_msg
        self.latest_target_epoch = target_epoch
        self.latest_source_epoch = source_epoch
        log.info('[hybrid_casper] Generated vote: validator %d - epoch %d - source_epoch %d - hash %s' %
                 (self.get_validator_index(state), target_epoch, source_epoch, utils.encode_hex(target_hash)))
        return vote_msg

    def get_recommended_casper_msg_contents(self, casper, validator_index):
        current_epoch = casper.get_current_epoch()
        if current_epoch == 0:
            return None, None, None
        # NOTE: Using `epoch_blockhash` because currently calls to `blockhash` within contracts
        # in the ephemeral state are off by one, so we can't use `get_recommended_target_hash()` :(
        target_hash = self.epoch_blockhash(current_epoch)
        source_epoch = casper.get_recommended_source_epoch()
        return target_hash, current_epoch, source_epoch

    def epoch_blockhash(self, epoch):
        if epoch == 0:
            return b'\x00' * 32
        return self.chain.get_block_by_number(epoch*self.epoch_length-1).hash

    def get_validator_index(self, state):
        t = tester.State(state.ephemeral_clone())
        casper = tester.ABIContract(t, casper_utils.casper_abi, self.chain.casper_address)
        if self.valcode_addr is None:
            raise Exception('Valcode address not set')
        try:
            vidx = casper.get_validator_indexes(self.coinbase.address)
        except tester.TransactionFailed:
            return None

        # Zero represents failure
        return None if vidx == 0 else vidx

    def mk_transaction(self, to=b'\x00' * 20, value=0, data=b'',
                       gasprice=tester.GASPRICE, startgas=tester.STARTGAS):
        nonce = self.chain.state.get_nonce(self.coinbase.address)
        tx = transactions.Transaction(nonce, gasprice, startgas, to, value, data)
        self.coinbase.sign_tx(tx)
        return tx

    def mk_validation_code_tx(self):
        return self.mk_transaction('', 0, casper_utils.mk_validation_code(self.coinbase.address))

    def mk_deposit_tx(self, value, valcode_addr):
        casper_ct = abi.ContractTranslator(casper_utils.casper_abi)
        deposit_func = casper_ct.encode('deposit', [valcode_addr, self.coinbase.address])
        return self.mk_transaction(self.chain.casper_address, value, deposit_func)

    def mk_withdraw_tx(self, validator_idx):
        casper_ct = abi.ContractTranslator(casper_utils.casper_abi)
        withdraw_func = casper_ct.encode('withdraw', [validator_idx])
        return self.mk_transaction(self.chain.casper_address, data=withdraw_func)

    def mk_logout_tx(self, login_logout_msg):
        casper_ct = abi.ContractTranslator(casper_utils.casper_abi)
        logout_func = casper_ct.encode('logout', [login_logout_msg])
        return self.mk_transaction(self.chain.casper_address, data=logout_func)

    def mk_vote_tx(self, vote_msg):
        casper_ct = abi.ContractTranslator(casper_utils.casper_abi)
        vote_func = casper_ct.encode('vote', [vote_msg])
        return self.mk_transaction(to=self.chain.casper_address, value=0, startgas=1000000, data=vote_func)
