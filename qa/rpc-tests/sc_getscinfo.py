#!/usr/bin/env python2
# Copyright (c) 2014 The Bitcoin Core developers
# Copyright (c) 2018 The Zencash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_framework import MINIMAL_SC_HEIGHT, MINER_REWARD_POST_H200
from test_framework.authproxy import JSONRPCException
from test_framework.util import assert_equal, initialize_chain_clean, \
    start_nodes, stop_nodes, get_epoch_data, \
    sync_blocks, sync_mempools, connect_nodes_bi, wait_bitcoinds, mark_logs, \
    assert_false, assert_true, swap_bytes
from test_framework.mc_test.mc_test import *
import os
import pprint
import time
from decimal import Decimal
from random import randrange
import math 

DEBUG_MODE = 1
NUMB_OF_NODES = 2


class sc_getscinfo(BitcoinTestFramework):

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
            [['-debug=py', '-debug=sc', '-debug=mempool', '-debug=net', '-debug=cert', '-scproofqueuesize=0', '-logtimemicros=1']] * NUMB_OF_NODES)

        for k in range(0, NUMB_OF_NODES-1):
            connect_nodes_bi(self.nodes, k, k+1)

        sync_blocks(self.nodes[1:NUMB_OF_NODES])
        sync_mempools(self.nodes[1:NUMB_OF_NODES])
        self.is_network_split = split
        self.sync_all()

    def run_test(self):

        ''' 
        (1) Create many SCs with increasing epoch length
        (2) Advance chain so to have a mix of ceased and alive sidechains
        (3) test getscinfo with filtering and pagination 
        '''

        creation_amount = Decimal("1.0")

        mark_logs("Node 0 generates {} block".format(MINIMAL_SC_HEIGHT/2), self.nodes, DEBUG_MODE)
        self.nodes[0].generate(MINIMAL_SC_HEIGHT/2)
        self.sync_all()
        mark_logs("Node 1 generates {} block".format(MINIMAL_SC_HEIGHT/2), self.nodes, DEBUG_MODE)
        self.nodes[1].generate(MINIMAL_SC_HEIGHT/2)
        self.sync_all()

        #generate wCertVk and constant
        mcTest = CertTestUtils(self.options.tmpdir, self.options.srcdir)
        constant = generate_random_field_element_hex()

        # number of sidechains to create
        NUM_OF_SIDECHAINS = 10 + randrange(10)

        # constant to obtain a number of alive sidechains for testing
        SUBSET_ALIVE = 3 + randrange(3)

        # base epoch length
        EPOCH_LENGTH = 5 + randrange(5)

        # number of blocks to generate for having a mixed set of ceased/alive sidechains
        NUM_GEN = EPOCH_LENGTH + NUM_OF_SIDECHAINS - SUBSET_ALIVE

        scids_all = []
        scids_alive = []

        # SCs creation
        mark_logs("Creating {} sidechains".format(NUM_OF_SIDECHAINS), self.nodes, DEBUG_MODE)
        for i in range(0, NUM_OF_SIDECHAINS):
            tag = "sc"+str(i+1)
            vk = mcTest.generate_params(tag)
            # use two nodes for creating sc
            idx = i%2
            ret = self.nodes[int(idx)].sc_create(EPOCH_LENGTH+i, "dada", creation_amount, vk, "abcdef", constant)
            creating_tx = ret['txid']
            scid = self.nodes[idx].getrawtransaction(creating_tx, 1)['vsc_ccout'][0]['scid']
            mark_logs("Node {} created SC {}".format(idx, scid), self.nodes, DEBUG_MODE)
            if i == NUM_OF_SIDECHAINS-SUBSET_ALIVE:
                scid_0 = scid
                tag_0 = tag

        self.sync_all()

        # add created scs to the mainchain
        cr_block_hash = self.nodes[0].generate(1)[-1]
        sc_creating_height = self.nodes[0].getblockcount()
        self.sync_all()
        

        mark_logs("Node0 generates {} more blocks to achieve end of some withdrawal epochs".format(NUM_GEN), self.nodes, DEBUG_MODE)
        self.nodes[0].generate(NUM_GEN)
        self.sync_all()

        #------------------------------------------------------------------------------------------
        mark_logs("Get all sidechains info in verbose mode", self.nodes, DEBUG_MODE)
        sc_info_all              = self.nodes[1].getscinfo("*")
        sc_info_all_default      = self.nodes[1].getscinfo("*", False, True, 0)
        sc_info_all_to_big       = self.nodes[1].getscinfo("*", False, True, 0, 1000)
        sc_info_all_to_unlimited = self.nodes[1].getscinfo("*", False, True, 0, -1)

        # check the syntaxes above yield the same result
        assert_equal(sc_info_all, sc_info_all_default)
        assert_equal(sc_info_all, sc_info_all_to_big)
        assert_equal(sc_info_all, sc_info_all_to_unlimited)

        assert_equal(sc_info_all['totalItems'], NUM_OF_SIDECHAINS)
        assert_equal(sc_info_all['from'], 0)
        assert_equal(sc_info_all['to'], NUM_OF_SIDECHAINS)

        # check all of them have right block creation hash which is part of verbose output
        # and fill the ordered scids lists
        for item in sc_info_all['items']:
            assert_equal(item['created at block height'], sc_creating_height)
            scids_all.append(item['scid'])
            if item['state'] == "ALIVE":
                scids_alive.append(item['scid'])

        NUM_ALIVE = len(scids_alive)

        a_ceased_scid = "*"
        # get a ceased scid
        for scid in scids_all:
            if scid not in scids_alive:
                a_ceased_scid = scid
                break

        #pprint.pprint(sc_info_all)

        #------------------------------------------------------------------------------------------
        mark_logs("Get only first two sidechains in non verbose mode", self.nodes, DEBUG_MODE)
        sc_info = self.nodes[1].getscinfo("*", False, False, 0, 2)
        assert_equal(sc_info['totalItems'], NUM_OF_SIDECHAINS)
        assert_equal(sc_info['from'], 0)
        assert_equal(sc_info['to'], 2)

        mark_logs("tot {}".format(sc_info['totalItems']), self.nodes, DEBUG_MODE)

        count = 0
        for item in sc_info['items']:
            try:
                assert_equal(item['created at block height'], sc_creating_height)
                assert_true(False)
            except Exception, e:
                # it is ok, we expected it
                pass

            assert_equal(scids_all[count], item['scid'])
            count += 1

        #------------------------------------------------------------------------------------------
        sz_subset = 3
        from_par = 5
        to_par = from_par + sz_subset
        mark_logs("Get only a subset of {} sidechains in verbose mode".format(sz_subset), self.nodes, DEBUG_MODE)
        sc_info = self.nodes[1].getscinfo("*", False, True, from_par, to_par)
        assert_equal(len(sc_info['items']), sz_subset)
        assert_equal(sc_info['totalItems'], NUM_OF_SIDECHAINS)
        assert_equal(sc_info['from'], from_par)
        assert_equal(sc_info['to'], to_par)

        count = from_par
        for item in sc_info['items']:
            assert_equal(item['created at block height'], sc_creating_height)
            assert_equal(scids_all[count], item['scid'])
            count += 1

        #pprint.pprint(sc_info)

        #------------------------------------------------------------------------------------------
        mark_logs("Get all alive sidechains with non-verbose output", self.nodes, DEBUG_MODE)
        sc_info_all_alive = self.nodes[1].getscinfo("*", True, False)
        assert_equal(sc_info_all_alive['totalItems'], NUM_ALIVE)
        count = 0
        for item in sc_info_all_alive['items']:
            assert_equal(item['state'], "ALIVE")
            assert_equal(scids_alive[count], item['scid'])
            count += 1

        #------------------------------------------------------------------------------------------
        mark_logs("Get last {} alive sidechains with verbose output".format(SUBSET_ALIVE), self.nodes, DEBUG_MODE)
        from_par = NUM_ALIVE - SUBSET_ALIVE
        sc_info_sub_alive = self.nodes[1].getscinfo("*", True, True, from_par, -1)
        assert_equal(sc_info_sub_alive['totalItems'], NUM_ALIVE)
        assert_equal(sc_info_sub_alive['from'], from_par)
        assert_equal(sc_info_sub_alive['to'], NUM_ALIVE)

        count = from_par
        for item in sc_info_sub_alive['items']:
            assert_equal(item['state'], "ALIVE")
            assert_equal(scids_alive[count], item['scid'])
            count += 1

        # negative tests
        mark_logs("Negative tests", self.nodes, DEBUG_MODE)
        #------------------------------------------------------------------------------------------
        try:
            self.nodes[1].getscinfo("*", False, True, -2, 5)
            assert_true(False)
        except JSONRPCException, e:
            print e.error['message']
            pass

        try:
            self.nodes[1].getscinfo("*", False, True, 5, 5)
            assert_true(False)
        except JSONRPCException, e:
            print e.error['message']
            pass

        try:
            self.nodes[1].getscinfo("*", True, True, 6, 5)
            assert_true(False)
        except JSONRPCException, e:
            print e.error['message']
            pass

        try:
            self.nodes[1].getscinfo("*", True, True, 1, -5)
            assert_true(False)
        except JSONRPCException, e:
            print e.error['message']
            pass

        try:
            self.nodes[1].getscinfo("*", False, True, NUM_OF_SIDECHAINS+2, -1)
            assert_true(False)
        except JSONRPCException, e:
            print e.error['message']
            pass

        try:
            # this is ok because the interval is legal
            self.nodes[1].getscinfo("*", False, True, NUM_ALIVE, 100)
        except JSONRPCException, e:
            print e.error['message']
            assert_true(False)

        # get a ceased sc info filtering on active state
        null_result = self.nodes[0].getscinfo(a_ceased_scid, True)
        pprint.pprint(null_result)
        assert_equal(null_result['totalItems'], 0)
        assert_equal(len(null_result['items']), int(0))

        FT_SC_FEE = Decimal('0')
        MBTR_SC_FEE = Decimal('0')
        CERT_FEE = Decimal('0.00015')
        bwt_amount = Decimal("0.20")

        item = self.nodes[0].getscinfo(scid_0)['items'][0]
        epoch_n = item['withdrawalEpochLength']
        epoch_number_1, epoch_cum_tree_hash_1 = get_epoch_data(scid_0, self.nodes[0], epoch_n)

        pkh_node1 = self.nodes[1].getnewaddress("", True)
        amount_cert = [{"pubkeyhash": pkh_node1, "amount": bwt_amount}]

        # Create Cert1 with quality 100 and place it in mempool
        mark_logs("Create Cert1 with quality 100 and place it in mempool", self.nodes, DEBUG_MODE)
        quality = 100
        scid0_swapped = str(swap_bytes(scid_0))

        proof = mcTest.create_test_proof(
            tag_0, scid0_swapped, epoch_number_1, quality, MBTR_SC_FEE, FT_SC_FEE, constant, epoch_cum_tree_hash_1, [pkh_node1], [bwt_amount])

        try:
            cert_1_epoch_0 = self.nodes[0].send_certificate(scid_0, epoch_number_1, quality,
                epoch_cum_tree_hash_1, proof, amount_cert, FT_SC_FEE, MBTR_SC_FEE, CERT_FEE)
            assert(len(cert_1_epoch_0) > 0)
            mark_logs("Certificate is {}".format(cert_1_epoch_0), self.nodes, DEBUG_MODE)
        except JSONRPCException, e:
            errorString = e.error['message']
            mark_logs("Send certificate failed with reason {}".format(errorString), self.nodes, DEBUG_MODE)
            assert(False)

        self.sync_all()

        result = self.nodes[0].getscinfo(scid_0)
        assert_equal(cert_1_epoch_0, result['items'][0]['unconf top quality certificate hash'])
        assert_equal(quality, result['items'][0]['unconf top quality certificate quality'])


if __name__ == '__main__':
    sc_getscinfo().main()
