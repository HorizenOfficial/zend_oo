#!/usr/bin/env python2
# Copyright (c) 2014 The Bitcoin Core developers
# Copyright (c) 2018 The Zencash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
from test_framework.test_framework import BitcoinTestFramework
from test_framework.authproxy import JSONRPCException
from test_framework.util import assert_equal, initialize_chain_clean, \
    start_nodes, sync_blocks, sync_mempools, connect_nodes_bi, mark_logs,\
    get_epoch_data, disconnect_nodes,\
    assert_false, assert_true
from test_framework.mc_test.mc_test import *
import os
import pprint
from decimal import Decimal
import time

DEBUG_MODE = 1
NUMB_OF_NODES = 3
EPOCH_LENGTH = 20
CERT_FEE = Decimal('0.00015')
HIGH_CERT_FEE = Decimal('0.00020')
LOW_CERT_FEE = Decimal('0.00005')

class quality_nodes(BitcoinTestFramework):

    alert_filename = None

    def setup_chain(self, split=False):
        print("Initializing test directory " + self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, NUMB_OF_NODES)
        self.alert_filename = os.path.join(self.options.tmpdir, "alert.txt")
        with open(self.alert_filename, 'w'):
            pass  # Just open then close to create zero-length file

    def setup_network(self, split=False):
        self.nodes = []

        self.nodes = start_nodes(NUMB_OF_NODES, self.options.tmpdir, extra_args=
            [['-debug=py', '-debug=sc', '-debug=mempool', '-debug=net', '-debug=cert', '-debug=zendoo_mc_cryptolib', '-logtimemicros=1']] * NUMB_OF_NODES)

        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 1, 2)
        sync_blocks(self.nodes[1:NUMB_OF_NODES])
        sync_mempools(self.nodes[1:NUMB_OF_NODES])
        self.is_network_split = split
        self.sync_all()

    def split_network(self):
        # Split the network of three nodes into nodes 0-1 and 2.
        assert not self.is_network_split
        disconnect_nodes(self.nodes[0], 1)
        disconnect_nodes(self.nodes[1], 0)
        self.is_network_split = True

    def join_network(self):
        # Join the (previously split) network pieces together: 0-1-2
        assert self.is_network_split
        connect_nodes_bi(self.nodes, 0, 1)
        #connect_nodes_bi(self.nodes, 1, 0)
        time.sleep(2)
        self.is_network_split = False

    def run_test(self):

        '''
        The test creates a sc, send funds to it and then sends a certificate to it,
        verifying also that specifying various combination of bad parameters causes a certificate
        to be refused. This test also checks that the receiver of cert backward transfer can spend it
        only when they become mature.
        '''

        # forward transfer amounts
        creation_amount = Decimal("0.5")
        fwt_amount = Decimal("200")
        bwt_amount_bad = Decimal("250.0")
        bwt_amount = Decimal("20")
        bwt_amount_2 = Decimal("30")

        self.nodes[0].getblockhash(0)

        # node 1 earns some coins, they would be available after 100 blocks
        mark_logs("Node 1 generates 1 block", self.nodes, DEBUG_MODE)
        self.nodes[1].generate(1)
        self.sync_all()
        self.nodes[2].generate(1)
        self.sync_all()

        mark_logs("Node 0 generates 220 block", self.nodes, DEBUG_MODE)
        self.nodes[0].generate(220)
        self.sync_all()

        # SC creation
        bal_before_sc_creation = self.nodes[1].getbalance("", 0)
        mark_logs("Node1 balance before SC creation: {}".format(bal_before_sc_creation), self.nodes, DEBUG_MODE)

        #generate wCertVk and constant
        mcTest = MCTestUtils(self.options.tmpdir, self.options.srcdir)
        vk_1 = mcTest.generate_params("sc1")
        constant = generate_random_field_element_hex()

        ret = self.nodes[1].sc_create(EPOCH_LENGTH, "dada", creation_amount, vk_1, "", constant)
        creating_tx = ret['txid']
        scid = ret['scid']
        mark_logs("Node 1 created the SC spending {} coins via tx {}.".format(creation_amount, creating_tx), self.nodes, DEBUG_MODE)
        self.sync_all()

        decoded_tx = self.nodes[1].getrawtransaction(creating_tx, 1)
        assert_equal(scid, decoded_tx['vsc_ccout'][0]['scid'])
        mark_logs("created SC id: {}".format(scid), self.nodes, DEBUG_MODE)

        mark_logs("Node0 confirms Sc creation generating 1 block", self.nodes, DEBUG_MODE)
        self.nodes[0].generate(1)
        sc_creating_height = self.nodes[0].getblockcount()
        self.sync_all()

        # Check node 1 balance following sc creation
        fee_sc_creation = self.nodes[1].gettransaction(creating_tx)['fee']
        mark_logs("Fee paid for SC creation: {}".format(fee_sc_creation), self.nodes, DEBUG_MODE)
        bal_after_sc_creation = self.nodes[1].getbalance("", 0)
        mark_logs("Node1 balance after SC creation: {}".format(bal_after_sc_creation), self.nodes, DEBUG_MODE)
        #assert_equal(bal_before_sc_creation, bal_after_sc_creation + creation_amount + creation_amount - fee_sc_creation - fee_sc_creation)

        assert_equal(self.nodes[0].getscinfo(scid)['items'][0]['balance'], Decimal(0))
        assert_equal(self.nodes[0].getscinfo(scid)['items'][0]['immature amounts'][0]['amount'], creation_amount)

        # Fwd Transfer to SC 1
        bal_before_fwd_tx = self.nodes[0].getbalance("", 0)
        mark_logs("Node0 balance before fwd tx: {}".format(bal_before_fwd_tx), self.nodes, DEBUG_MODE)
        fwd_tx = self.nodes[0].sc_send("abcd", fwt_amount, scid)
        mark_logs("Node0 transfers {} coins to SC 1 with tx {}...".format(fwt_amount, fwd_tx), self.nodes, DEBUG_MODE)
        self.sync_all()

        mark_logs("Node0 confirms fwd transfer generating 1 block", self.nodes, DEBUG_MODE)
        self.nodes[0].generate(1)
        self.sync_all()

        # Check node 0 balance following fwd tx
        fee_fwt = self.nodes[0].gettransaction(fwd_tx)['fee']
        mark_logs("Fee paid for fwd tx: {}".format(fee_fwt), self.nodes, DEBUG_MODE)
        bal_after_fwd_tx = self.nodes[0].getbalance("", 0)
        mark_logs("Node0 balance after fwd: {}".format(bal_after_fwd_tx), self.nodes, DEBUG_MODE)
        assert_equal(bal_before_fwd_tx, bal_after_fwd_tx + fwt_amount - fee_fwt - Decimal(8.75)) # 8.75 is matured coinbase

        assert_equal(self.nodes[0].getscinfo(scid)['items'][0]['balance'], Decimal(0))
        assert_equal(self.nodes[0].getscinfo(scid)['items'][0]['immature amounts'][0]['amount'], creation_amount)
        assert_equal(self.nodes[0].getscinfo(scid)['items'][0]['immature amounts'][1]['amount'], fwt_amount)


        bal_after_fwd_tx = self.nodes[0].getbalance("", 0)
        mark_logs("Node0 balance after fwd: {}".format(bal_after_fwd_tx), self.nodes, DEBUG_MODE)

        mark_logs("Node0 generating more blocks to achieve end of withdrawal epoch", self.nodes, DEBUG_MODE)
        self.nodes[0].generate(EPOCH_LENGTH - 2)
        self.sync_all()
        assert_equal(self.nodes[0].getscinfo(scid)['items'][0]['balance'], creation_amount + fwt_amount) # Sc balance has matured
        assert_equal(len(self.nodes[0].getscinfo(scid)['items'][0]['immature amounts']), 0)

        epoch_block_hash, epoch_number = get_epoch_data(scid, self.nodes[0], EPOCH_LENGTH)
        mark_logs("epoch_number = {}, epoch_block_hash = {}".format(epoch_number, epoch_block_hash), self.nodes, DEBUG_MODE)

        prev_epoch_block_hash = self.nodes[0].getblockhash(sc_creating_height - 1 + ((epoch_number) * EPOCH_LENGTH))

        pkh_node0 = self.nodes[0].getnewaddress("", True)
        self.sync_all()

        #Create proof for WCert
        quality = 0
        proof = mcTest.create_test_proof(
            "sc1", epoch_number, epoch_block_hash, prev_epoch_block_hash,
            quality, constant, [pkh_node0], [bwt_amount])

        mark_logs("Node 0 tries to perform a bwd transfer with insufficient Sc balance...", self.nodes, DEBUG_MODE)
        amounts = [{"pubkeyhash": pkh_node0, "amount": bwt_amount_bad}]

        try:
            self.nodes[0].send_certificate(scid, epoch_number, quality, epoch_block_hash, proof, amounts, CERT_FEE)
            assert(False)
        except JSONRPCException, e:
            errorString = e.error['message']
            mark_logs(errorString, self.nodes, DEBUG_MODE)

        #assert_equal("sidechain has insufficient funds" in errorString, True)
        assert_equal(self.nodes[0].getscinfo(scid)['items'][0]['balance'], creation_amount + fwt_amount)
        assert_equal(len(self.nodes[0].getscinfo(scid)['items'][0]['immature amounts']), 0)

        mark_logs("Node 0 tries to perform a bwd transfer with an invalid epoch number ...", self.nodes, DEBUG_MODE)
        amount_cert_1 = [{"pubkeyhash": pkh_node0, "amount": bwt_amount}]

        try:
            self.nodes[0].send_certificate(scid, epoch_number + 1, quality, epoch_block_hash, proof, amount_cert_1, CERT_FEE)
            assert(False)
        except JSONRPCException, e:
            errorString = e.error['message']
            mark_logs(errorString, self.nodes, DEBUG_MODE)

        assert_equal("invalid epoch data" in errorString, True)
        assert_equal(self.nodes[0].getscinfo(scid)['items'][0]['balance'], creation_amount + fwt_amount) # Sc has not been affected by faulty certificate
        assert_equal(len(self.nodes[0].getscinfo(scid)['items'][0]['immature amounts']), 0)

        mark_logs("Node 0 tries to perform a bwd transfer with an invalid quality ...", self.nodes, DEBUG_MODE)

        try:
            self.nodes[0].send_certificate(scid, epoch_number, quality - 1, epoch_block_hash, proof, amount_cert_1, CERT_FEE)
            assert(False)
        except JSONRPCException, e:
            errorString = e.error['message']
            mark_logs(errorString, self.nodes, DEBUG_MODE)

        #assert_equal("Invalid quality parameter" in errorString, True)
        assert_equal(self.nodes[0].getscinfo(scid)['items'][0]['balance'], creation_amount + fwt_amount) # Sc has not been affected by faulty certificate
        assert_equal(len(self.nodes[0].getscinfo(scid)['items'][0]['immature amounts']), 0)

        #--------------------------------------------------------------------------------------
        mark_logs("Node 0 tries to perform a bwd transfer using a wrong vk for the scProof...", self.nodes, DEBUG_MODE)

        # let's generate new params and create a correct proof with them
        mcTest.generate_params("sc_temp")

        quality = 100

        wrong_proof = mcTest.create_test_proof(
            "sc_temp", epoch_number, epoch_block_hash, prev_epoch_block_hash,
            quality, constant, [pkh_node0], [bwt_amount])

        try:
            self.nodes[0].send_certificate(scid, epoch_number, quality, epoch_block_hash, wrong_proof, amount_cert_1, CERT_FEE)
            assert(False)
        except JSONRPCException, e:
            errorString = e.error['message']
            mark_logs(errorString, self.nodes, DEBUG_MODE)

        assert_equal("bad-sc-cert-not-applicable" in errorString, True)
        assert_equal(self.nodes[0].getscinfo(scid)['items'][0]['balance'], creation_amount + fwt_amount) # Sc has not been affected by faulty certificate
        assert_equal(len(self.nodes[0].getscinfo(scid)['items'][0]['immature amounts']), 0)

        #---------------------end scProof tests-------------------------
        amount_cert_0 = [{"pubkeyhash": pkh_node0, "amount": bwt_amount}]

        self.split_network()

        # Create Cert1 with quality 100 and place it in node0
        mark_logs("Height: {}. cration height {}".format(self.nodes[0].getblockcount(), sc_creating_height), self.nodes, DEBUG_MODE)
        mark_logs("Height: {}. Epoch {}".format(self.nodes[0].getblockcount(), epoch_number), self.nodes, DEBUG_MODE)
        mark_logs("Create Cert1 with quality 100 and place it in node0", self.nodes, DEBUG_MODE)
        quality = 100
        proof = mcTest.create_test_proof(
            "sc1", epoch_number, epoch_block_hash, prev_epoch_block_hash,
            quality, constant, [pkh_node0], [bwt_amount])
        try:
            cert_1_epoch_0 = self.nodes[0].send_certificate(scid, epoch_number, quality, epoch_block_hash, proof, amount_cert_0, CERT_FEE)
            assert(len(cert_1_epoch_0) > 0)
            mark_logs("Certificate is {}".format(cert_1_epoch_0), self.nodes, DEBUG_MODE)
        except JSONRPCException, e:
            errorString = e.error['message']
            mark_logs("Send certificate failed with reason {}".format(errorString), self.nodes, DEBUG_MODE)
            assert(False)

        mark_logs("Check cert is in mempools", self.nodes, DEBUG_MODE)
        assert_equal(True, cert_1_epoch_0 in self.nodes[0].getrawmempool())
        cert1_mined = self.nodes[0].generate(2)[0]
        assert_true(cert_1_epoch_0 in self.nodes[0].getblock(cert1_mined, True)['cert'])

        # Create Cert2 with quality 100 and place it in node1
        mark_logs("Create Cert2 with quality 100 and place it in node1", self.nodes, DEBUG_MODE)
        pkh_node1 = self.nodes[1].getnewaddress("", True)
        amount_cert_1 = [{"pubkeyhash": pkh_node1, "amount": bwt_amount}]
        quality = 100
        proof = mcTest.create_test_proof(
            "sc1", epoch_number, epoch_block_hash, prev_epoch_block_hash,
            quality, constant, [pkh_node1], [bwt_amount])
        try:
            cert_2_epoch_0 = self.nodes[1].send_certificate(scid, epoch_number, quality, epoch_block_hash, proof, amount_cert_1, CERT_FEE)
            assert(len(cert_2_epoch_0) > 0)
            mark_logs("Certificate is {}".format(cert_2_epoch_0), self.nodes, DEBUG_MODE)
        except JSONRPCException, e:
            errorString = e.error['message']
            mark_logs("Send certificate failed with reason {}".format(errorString), self.nodes, DEBUG_MODE)
            assert(False)

        #Cert should be in mempool and could be placed in node_1 block
        mark_logs("Check cert is in mempools", self.nodes, DEBUG_MODE)
        assert_equal(True, cert_2_epoch_0 in self.nodes[1].getrawmempool())
        cert2_mined = self.nodes[1].generate(1)[0]
        assert_true(cert_2_epoch_0 in self.nodes[1].getblock(cert2_mined, True)['cert'])

        self.join_network()

        self.sync_all()
        assert_true(cert_1_epoch_0 in self.nodes[0].getblock(cert1_mined, True)['cert'])
        #assert_false(cert_2_epoch_0 in self.nodes[0].getblock(cert2_mined, True)['cert'])
        assert_false(cert_2_epoch_0 in self.nodes[0].getrawmempool())

        self.nodes[0].generate(EPOCH_LENGTH - 2)
        self.sync_all()

        self.split_network()

        # Create Cert3 with quality 100 and place it in node0
        prev_epoch_block_hash = epoch_block_hash
        epoch_block_hash, epoch_number = get_epoch_data(scid, self.nodes[0], EPOCH_LENGTH)
        mark_logs("Height: {}. creation height {}".format(self.nodes[0].getblockcount(), sc_creating_height), self.nodes, DEBUG_MODE)
        mark_logs("Height: {}. Epoch {}".format(self.nodes[0].getblockcount(), epoch_number), self.nodes, DEBUG_MODE)
        mark_logs("Create Cert1 with quality 100 and place it in node0", self.nodes, DEBUG_MODE)
        quality = 100
        amount_cert_0 = [{"pubkeyhash": pkh_node0, "amount": bwt_amount}]
        proof = mcTest.create_test_proof(
            "sc1", epoch_number, epoch_block_hash, prev_epoch_block_hash,
            quality, constant, [pkh_node0], [bwt_amount])
        try:
            cert_1_epoch_1 = self.nodes[0].send_certificate(scid, epoch_number, quality, epoch_block_hash, proof, amount_cert_0, CERT_FEE)
            assert(len(cert_1_epoch_1) > 0)
            mark_logs("Certificate is {}".format(cert_1_epoch_1), self.nodes, DEBUG_MODE)
        except JSONRPCException, e:
            errorString = e.error['message']
            mark_logs("Send certificate failed with reason {}".format(errorString), self.nodes, DEBUG_MODE)
            assert(False)

        mark_logs("Check cert is in mempools", self.nodes, DEBUG_MODE)
        assert_equal(True, cert_1_epoch_1 in self.nodes[0].getrawmempool())
        cert1_mined = self.nodes[0].generate(4)[0]
        assert_true(cert_1_epoch_1 in self.nodes[0].getblock(cert1_mined, True)['cert'])

        # Create Cert2 with quality 100 and place it in node1
        mark_logs("Create Cert2 with quality 100 and place it in node1", self.nodes, DEBUG_MODE)
        amount_cert_1 = [{"pubkeyhash": pkh_node1, "amount": bwt_amount}]
        quality = 110
        proof = mcTest.create_test_proof(
            "sc1", epoch_number, epoch_block_hash, prev_epoch_block_hash,
            quality, constant, [pkh_node1], [bwt_amount])
        try:
            cert_2_epoch_1 = self.nodes[1].send_certificate(scid, epoch_number, quality, epoch_block_hash, proof, amount_cert_1, CERT_FEE)
            assert(len(cert_2_epoch_1) > 0)
            mark_logs("Certificate is {}".format(cert_2_epoch_1), self.nodes, DEBUG_MODE)
        except JSONRPCException, e:
            errorString = e.error['message']
            mark_logs("Send certificate failed with reason {}".format(errorString), self.nodes, DEBUG_MODE)
            assert(False)

        mark_logs("Check cert is in mempools", self.nodes, DEBUG_MODE)
        assert_equal(True, cert_2_epoch_1 in self.nodes[1].getrawmempool())
        cert2_mined = self.nodes[1].generate(1)[0]
        assert_true(cert_2_epoch_1 in self.nodes[1].getblock(cert2_mined, True)['cert'])

        self.join_network()

        assert_true(cert_1_epoch_1 in self.nodes[0].getblock(cert1_mined, True)['cert'])
        #assert_false(cert_2_epoch_0 in self.nodes[0].getblock(cert2_mined, True)['cert'])
        assert_true(cert_2_epoch_1 in self.nodes[1].getrawmempool())

        self.nodes[0].generate(EPOCH_LENGTH - 2)

        time.sleep(5)


if __name__ == '__main__':
    quality_nodes().main()