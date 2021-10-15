#!/usr/bin/env python2
# Copyright (c) 2014 The Bitcoin Core developers
# Copyright (c) 2018 The Zencash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_framework import MINIMAL_SC_HEIGHT, MINER_REWARD_POST_H200
from test_framework.authproxy import JSONRPCException
from test_framework.util import assert_false, assert_true, assert_equal, initialize_chain_clean, \
    start_nodes, start_node, sync_blocks, sync_mempools, connect_nodes_bi, mark_logs, \
    get_epoch_data, swap_bytes, get_spendable 
from test_framework.mc_test.mc_test import *
import os
import pprint
from decimal import Decimal
from test_framework.mininode import COIN
import json
import time

NUMB_OF_NODES = 4
DEBUG_MODE = 1
EPOCH_LENGTH = 20
FT_SC_FEE = Decimal('0')
MBTR_SC_FEE = Decimal('0')
CERT_FEE = Decimal("0.00025")
CUSTOM_FEE_RATE_ZAT_PER_BYTE = Decimal('20.0')
CUSTOM_FEE_RATE_ZEN_PER_KBYTE = CUSTOM_FEE_RATE_ZAT_PER_BYTE/COIN*1000

class ScCertListsinceblock(BitcoinTestFramework):
    alert_filename = None

    def setup_chain(self, split=False):
        print("Initializing test directory " + self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, NUMB_OF_NODES)
        self.alert_filename = os.path.join(self.options.tmpdir, "alert.txt")
        with open(self.alert_filename, 'w'):
            pass  # Just open then close to create zero-length file

    def setup_network(self, split=False):

        self.nodes = start_nodes(NUMB_OF_NODES-1, self.options.tmpdir,
            extra_args=[
                ['-logtimemicros=1', '-debug=cert', '-debug=sc', '-debug=py', '-debug=mempool', '-allowdustoutput=0'],
                ['-logtimemicros=1', '-debug=cert', '-debug=sc', '-debug=py', '-debug=mempool', '-allowdustoutput=0'],
                ['-logtimemicros=1', '-debug=cert', '-debug=sc', '-debug=py', '-debug=mempool', '-allowdustoutput=0']
                ])

        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 1, 2)
        # do not connect node 3 at startup

        self.is_network_split = split
        self.sync_all()

    def run_test(self):
        '''
        '''

        mark_logs("Node 1 generates 2 block",self.nodes,DEBUG_MODE)
        self.nodes[1].generate(2)
        self.sync_all()

        mark_logs("Node 0 generates {} block".format(MINIMAL_SC_HEIGHT-2),self.nodes,DEBUG_MODE)
        self.nodes[0].generate(MINIMAL_SC_HEIGHT-2)
        self.sync_all()

        #generate wCertVk and constant
        mcTest = CertTestUtils(self.options.tmpdir, self.options.srcdir)
        vk = mcTest.generate_params('sc1')
        constant = generate_random_field_element_hex()

        # create SC
        #------------------------------------------------------------------------------------------------------------
        cmdInput = {
            'toaddress': "abcd", 'amount': 10.0, 'wCertVk': vk, 'withdrawalEpochLength': EPOCH_LENGTH,'constant': constant}

        mark_logs("\nNode 1 create SC", self.nodes, DEBUG_MODE)
        try:
            res = self.nodes[1].sc_create(cmdInput)
            tx =   res['txid']
            scid = res['scid']
            pprint.pprint(res)
            self.sync_all()
        except JSONRPCException, e:
            errorString = e.error['message']
            mark_logs(errorString,self.nodes,DEBUG_MODE)
            assert_true(False)

        blocks_d = {}
        mark_logs("\nNode 0 generates 1 block", self.nodes, DEBUG_MODE)
        bl = self.nodes[0].generate(1)[-1]
        self.sync_all()
        c = self.nodes[0].getblockcount()
        blocks_d[str(c)] = bl

        scid_swapped = str(swap_bytes(scid))
        addr_node2   = self.nodes[2].getnewaddress()

        q = 10

        for i in range(3):

            bwt_amount = Decimal(i+1)
            bwt_cert = [{"address": addr_node2, "amount": bwt_amount}]
            bwt_amount_array = [bwt_amount]
            addr_array = [addr_node2]

            mark_logs("\nAdvance epoch...", self.nodes, DEBUG_MODE)
            self.nodes[0].generate(EPOCH_LENGTH - 1)
            self.sync_all()
            epoch_number, epoch_cum_tree_hash = get_epoch_data(scid, self.nodes[0], EPOCH_LENGTH)
 
            mark_logs("Node 1 sends a cert with a bwd transfers of {} coins to Node2".format(bwt_amount), self.nodes, DEBUG_MODE)
            #==============================================================
            proof = mcTest.create_test_proof(
                "sc1", scid_swapped, epoch_number, q, MBTR_SC_FEE, FT_SC_FEE, epoch_cum_tree_hash,
                constant, addr_array, bwt_amount_array)
 
            try:
                cert = self.nodes[1].sc_send_certificate(scid, epoch_number, q,
                    epoch_cum_tree_hash, proof, bwt_cert, FT_SC_FEE, MBTR_SC_FEE)
            except JSONRPCException, e:
                errorString = e.error['message']
                print "Send certificate failed with reason {}".format(errorString)
                assert(False)

            self.sync_all()

            mark_logs("cert = {}".format(cert), self.nodes, DEBUG_MODE)
  
            mark_logs("\nNode 0 generates 1 block", self.nodes, DEBUG_MODE)
            bl = self.nodes[0].generate(1)[-1]
            self.sync_all()
            c = self.nodes[0].getblockcount()
            blocks_d[str(c)] = bl
 

        bal = self.nodes[2].getbalance()
        utx = self.nodes[2].listunspent()
        print "Node2 balance = {}".format(bal)
        #pprint.pprint(utx)

        for key, val in blocks_d.items():
            print(" height = {} ___________ block = {}_________________________________________".format(key, val))
            pprint.pprint(self.nodes[2].listsinceblock(val, 1, False, True))

######
# TODO check the case when change goes to the same node of the BWT


if __name__ == '__main__':
    ScCertListsinceblock().main()
