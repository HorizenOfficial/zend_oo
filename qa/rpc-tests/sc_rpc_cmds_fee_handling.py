#!/usr/bin/env python2
# Copyright (c) 2014 The Bitcoin Core developers
# Copyright (c) 2018 The Zencash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_framework import MINIMAL_SC_HEIGHT, MINER_REWARD_POST_H200
from test_framework.authproxy import JSONRPCException
from test_framework.util import assert_true, assert_equal, initialize_chain_clean, \
    start_nodes, sync_blocks, sync_mempools, connect_nodes_bi, mark_logs, \
    dump_sc_info, dump_sc_info_record
from test_framework.mc_test.mc_test import *
import os
import pprint
from decimal import Decimal
from test_framework.mininode import COIN
import json

NUMB_OF_NODES = 3
DEBUG_MODE = 1
SC_COINS_MAT = 2



class ScRpcCmdsFeeHandling(BitcoinTestFramework):
    alert_filename = None

    def setup_chain(self, split=False):
        print("Initializing test directory " + self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, NUMB_OF_NODES)
        self.alert_filename = os.path.join(self.options.tmpdir, "alert.txt")
        with open(self.alert_filename, 'w'):
            pass  # Just open then close to create zero-length file

    def setup_network(self, split=False):

        ed = "-exportdir=" + self.options.tmpdir
        self.nodes = start_nodes(NUMB_OF_NODES, self.options.tmpdir,
            extra_args=[
                ['-logtimemicros=1', '-debug=sc', '-debug=py', '-debug=mempool'],
                ['-logtimemicros=1', '-debug=sc', '-debug=py', '-debug=mempool',
                    '-paytxfee=0.00002'], # fee rate expressed in ZEN/Kb
                ['-logtimemicros=1', '-debug=sc', '-debug=py', '-debug=mempool']
                ])

        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 1, 2)
        self.is_network_split = split
        self.sync_all()

    def run_test(self):
        '''
        '''
        #{"withdrawalEpochLength", "fromaddress", "toaddress", "amount", "minconf", "fee", "customData"};

        # network topology: (0)--(1)--(3)
        def get_fee_rate(size, fee):
            return ((fee*COIN)/size)

        mark_logs("Node 1 generates 2 block",self.nodes,DEBUG_MODE)
        self.nodes[1].generate(2)
        self.sync_all()

        pprint.pprint(self.nodes[1].getinfo())

        mark_logs("Node 0 generates {} block".format(MINIMAL_SC_HEIGHT),self.nodes,DEBUG_MODE)
        self.nodes[0].generate(MINIMAL_SC_HEIGHT)
        self.sync_all()

        # send some very small amount to node 2, which will use them as input
        mark_logs("Node 0 send small coins to Node2", self.nodes, DEBUG_MODE)
        taddr2 = self.nodes[2].getnewaddress()
        amount = 0
        NUM_OF_TX = 100
        for i in range(NUM_OF_TX):
            amount = 0.000001 
            tx_for_input_2 = self.nodes[0].sendtoaddress(taddr2, Decimal(amount))
            self.sync_all()

        mark_logs("Node 0 generates 1 block",self.nodes,DEBUG_MODE)
        self.nodes[0].generate(1)
        self.sync_all()

        tx = []
        errorString = ""
        toaddress = "abcdef"

        #generate wCertVk and constant
        mcTest = CertTestUtils(self.options.tmpdir, self.options.srcdir)
        vk = mcTest.generate_params('sc1')
        constant = generate_random_field_element_hex()

        MIN_CONF = 1

        # create with a minconf value which is ok
        #--------------------------------------------------------------------------------------
        cmdInput = {'toaddress': toaddress, 'amount': 6.0, 'minconf': MIN_CONF, 'wCertVk': vk, 'constant': constant}

        mark_logs("\nNode 1 create SC with an minconf value in input which is OK, with scid auto generation and valid custom data", self.nodes, DEBUG_MODE)
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

        #txlist = self.nodes[1].listtransactions()
        tx_fee  = self.nodes[1].getrawmempool(True)[tx]['fee']
        tx_size = self.nodes[1].getrawmempool(True)[tx]['size']
        print "tx fee={}, sz={}, feeRate={}".format(tx_fee, tx_size, get_fee_rate(tx_size, tx_fee))

        mark_logs("\nNode 0 generates 1 block", self.nodes, DEBUG_MODE)
        self.nodes[0].generate(1)
        self.sync_all()

        # test sending funds
        #--------------------------------------------------------------------------------------
        # Having a lot of very small UTXOs makes fail the automatic algorithm for min fee computation:
        #  1. the tx is composed with some UTXO and 0 fee
        #  2. the minimum fee rate 1zat/Byte is used on tx size for computing the fee
        #  3. the tx is composed from scratch with some more UTXO (size increases) and the newly computed fee
        #  4. --> go to 2. ... and eat up all the UTXOs
        taddr = self.nodes[0].getnewaddress()
        mark_logs("\nNode2 sends funds to node0...expect to fail", self.nodes, DEBUG_MODE)
        try:
            tx = self.nodes[2].sendtoaddress(taddr, Decimal(0.000001))
            assert_true(False)
        except JSONRPCException, e:
            errorString = e.error['message']
            mark_logs(errorString,self.nodes,DEBUG_MODE)

        #decoded_tx = self.nodes[1].getrawtransaction(tx, 1)
        #if DEBUG_MODE:
        #    pprint.pprint(decoded_tx)

        mark_logs("\nNode 0 generates 1 block", self.nodes, DEBUG_MODE)
        self.nodes[0].generate(1)
        self.sync_all()
        '''
        '''

        mc_return_address = self.nodes[2].getnewaddress()
        outputs = [{'toaddress': toaddress, 'amount': Decimal(0.000001), "scid":scid, "mcReturnAddress": mc_return_address}]
        cmdParms = {}

        # A similar failure is expected also for SC related commands if the fee is not set by the user
        mark_logs("\nNode 2 sends funds to sc... expect to fail", self.nodes, DEBUG_MODE)
        try:
            tx = self.nodes[2].sc_send(outputs, cmdParms)
            assert_true(False)
        except JSONRPCException, e:
            errorString = e.error['message']
            mark_logs(errorString,self.nodes,DEBUG_MODE)

        # set the fee and resend
        cmdParms = {"fee":0.0}
        mark_logs("\nNode 2 sends funds to sc... expect to fail", self.nodes, DEBUG_MODE)
        try:
            tx = self.nodes[2].sc_send(outputs, cmdParms)
        self.sync_all()
        except JSONRPCException, e:
            errorString = e.error['message']
            mark_logs(errorString,self.nodes,DEBUG_MODE)
            assert_true(False)

        decoded_tx = self.nodes[1].getrawtransaction(tx, 1)
        if DEBUG_MODE:
            pprint.pprint(decoded_tx)

        tx_fee  = self.nodes[1].getrawmempool(True)[tx]['fee']
        tx_size = self.nodes[1].getrawmempool(True)[tx]['size']
        print "tx fee={}, sz={}, feeRate={}".format(tx_fee, tx_size, get_fee_rate(tx_size, tx_fee))

        mark_logs("\nNode 0 generates 2 block", self.nodes, DEBUG_MODE)
        self.nodes[0].generate(2)
        self.sync_all()



if __name__ == '__main__':
    ScRpcCmdsFeeHandling().main()
