#!/usr/bin/env python2
# Copyright (c) 2014 The Bitcoin Core developers
# Copyright (c) 2018 The Zencash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
from test_framework.test_framework import BitcoinTestFramework
from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import MINIMAL_SC_HEIGHT
from test_framework.util import assert_true, assert_equal, initialize_chain_clean, \
    start_nodes, stop_nodes, wait_bitcoinds, sync_blocks, sync_mempools, connect_nodes_bi, mark_logs, \
    dump_sc_info, dump_sc_info_record, get_epoch_data, get_spendable, swap_bytes, advance_epoch
from test_framework.mc_test.mc_test import *
import os
import pprint
from decimal import Decimal
import json
import time

NUMB_OF_NODES = 2
DEBUG_MODE = 1
EPOCH_LENGTH = 40
FT_SC_FEE = Decimal('0')
MBTR_SC_FEE = Decimal('0')
CERT_FEE = Decimal("0.03")

# 128 Mb
BIT_VECTOR_DATA_FILE = "../zen/test_data/bitVec_128M_gzip_hex_string.txt"
BIT_VECTOR_FE  = "3b37cb671d3fadf7280374e00bea3f5022542303c931e62b85a6db0dc66b4d07"
# deserialized:
# e07daf7690d0e09ed82fdb4f05b2c8f10505d332c3b88121ef7c76744f2ea52e
#---

NODE0_TEST_BLOCK_MAX_SIZE = 180000
NODE0_TEST_BLOCK_TX_PARTITION_MAX_SIZE = NODE0_TEST_BLOCK_MAX_SIZE

# this will not allow miner to chose tx/certificate basing on priority
NODE0_TEST_BLOCK_PRIORITY_SIZE = 0

# real max size
NODE1_TEST_BLOCK_MAX_SIZE = 4000000
NODE1_TEST_BLOCK_PRIORITY_SIZE = 2000000

# no txes here, just certs
NODE1_TEST_BLOCK_TX_PARTITION_MAX_SIZE = 0

class sc_big_certs(BitcoinTestFramework):
    alert_filename = None

    def setup_chain(self, split=False):
        print("Initializing test directory " + self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, NUMB_OF_NODES)
        self.alert_filename = os.path.join(self.options.tmpdir, "alert.txt")
        with open(self.alert_filename, 'w'):
            pass  # Just open then close to create zero-length file

    def setup_network(self, split=False):

        self.nodes = start_nodes(NUMB_OF_NODES, self.options.tmpdir,
                                 extra_args=[['-logtimemicros=1', '-debug=py', '-debug=sc', '-debug=mempool', '-debug=cert', '-debug=bench',
                                              '-blockmaxsize=%d'%NODE0_TEST_BLOCK_MAX_SIZE,
                                              '-blocktxpartitionmaxsize=%d'%NODE0_TEST_BLOCK_TX_PARTITION_MAX_SIZE,
                                              '-blockprioritysize=%d'%NODE0_TEST_BLOCK_PRIORITY_SIZE,
                                              '-scproofqueuesize=0'],
                                              ['-logtimemicros=1', '-debug=py', '-debug=sc', '-debug=mempool', '-debug=cert', '-debug=bench',
                                              '-blockmaxsize=%d'%NODE1_TEST_BLOCK_MAX_SIZE,
                                              '-blocktxpartitionmaxsize=%d'%NODE1_TEST_BLOCK_TX_PARTITION_MAX_SIZE,
                                              '-blockprioritysize=%d'%NODE1_TEST_BLOCK_PRIORITY_SIZE,
                                              '-scproofqueuesize=0'],
                                              ])

        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = split
        self.sync_all()

    def run_test(self):
        '''
        Create a SC and avance epoch, then create a set of large certificates for the SC, each of them having
        size near to the upper limit of 150K. Create also a large number of txes with fee rate greater than certs.
        Generate a block using a miner with reduced block size and with selection policy based on fee only (no priority).
        Verify that no certificates are included in the block.
        Generate a second block using a miner with maximum block size but tx partition size set to 0.
        Verify that the block is filled with low feerate certs only. 
        '''

        def create_sc(cmdInput, node):
            try:
                res = node.create_sidechain(cmdInput)
                tx =   res['txid']
                scid = res['scid']
            except JSONRPCException, e:
                errorString = e.error['message']
                mark_logs(errorString,self.nodes,DEBUG_MODE)
                assert_true(False);

            return tx, scid

        # network topology: (0)--(1)

        print "Miner 0 have max block sz = {}, max tx partition sz = {}, block prio sz = {}".format(NODE0_TEST_BLOCK_MAX_SIZE, NODE0_TEST_BLOCK_TX_PARTITION_MAX_SIZE, NODE0_TEST_BLOCK_PRIORITY_SIZE)
        print "Miner 1 have max block sz = {}, max tx partition sz = {}, block prio sz = {}".format(NODE1_TEST_BLOCK_MAX_SIZE, NODE1_TEST_BLOCK_TX_PARTITION_MAX_SIZE, NODE1_TEST_BLOCK_PRIORITY_SIZE)

        mark_logs("Node 1 generates {} block".format(200), self.nodes, DEBUG_MODE)
        self.nodes[1].generate(200)
        self.sync_all()

        mark_logs("Node 0 generates {} block".format(MINIMAL_SC_HEIGHT-200), self.nodes, DEBUG_MODE)
        self.nodes[0].generate(MINIMAL_SC_HEIGHT-200)
        self.sync_all()
        
        data = ""
        with open(BIT_VECTOR_DATA_FILE, 'r') as file:
            data = file.read()

        #generate Vks and constant
        certMcTest = CertTestUtils(self.options.tmpdir, self.options.srcdir)
        certVk = certMcTest.generate_params('scs')
        constant = generate_random_field_element_hex()

        cr_amount = 100.0

        #-------------------------------------------------------
        fee = 0.000025

        NUM_OF_CFE = 1
        feCfg = []
        cmtCfg = []
        nbit = 16
        for i in range(0, NUM_OF_CFE):
            feCfg.append(nbit)
            cmtCfg.append([254*512*8, 130096]) # 128 Mb

        cmdInput = {
            'withdrawalEpochLength': EPOCH_LENGTH, 'amount': cr_amount, 'fee': fee,
            'constant':constant , 'wCertVk': certVk, 'toaddress':"cdcd",
            'vFieldElementCertificateFieldConfig':feCfg, 'vBitVectorCertificateFieldConfig':cmtCfg
        }
      
        tx, scid = create_sc(cmdInput, self.nodes[0]);
        mark_logs("Created SC with scid={} via tx={}".format(scid, tx), self.nodes,DEBUG_MODE)
        self.sync_all()
        hexTx = self.nodes[0].getrawtransaction(tx)
        print "sz=", len(hexTx)//2

        # advance epoch
        self.nodes[0].generate(EPOCH_LENGTH)
        self.sync_all()
        epoch_number, epoch_cum_tree_hash = get_epoch_data(scid, self.nodes[0], EPOCH_LENGTH)

        NUM_OF_BWT = 572
        MAX_CERT_SIZE = 150000
        MIN_NUM_CERT_IN_FULL_BLOCK = NODE1_TEST_BLOCK_MAX_SIZE / MAX_CERT_SIZE 

        bwt_amount = Decimal('0.1')
        if (MIN_NUM_CERT_IN_FULL_BLOCK > 0):
            bwt_amount = (Decimal(cr_amount - 0.1)/NUM_OF_BWT)/MIN_NUM_CERT_IN_FULL_BLOCK

        pkh_node1 = self.nodes[1].getnewaddress("", True)

        mark_logs("Creating certs...", self.nodes, DEBUG_MODE)
        q = 10000
        tot_num_cert = 0
        tot_cert_sz = 0

        while True:
            bwt_cert = []
            pkh_array = []
            bwt_amount_array = []
            proof = None

            for i in range(0, NUM_OF_BWT):
 
                pkh_array.append(pkh_node1)
                bwt_amount_array.append(bwt_amount)
 
                entry = {"pubkeyhash": pkh_node1, "amount": bwt_amount}
                bwt_cert.append(entry)
 
            vCfe = []
            vCmt = []
            vSerFe = []
            for i in range(0, NUM_OF_CFE):
                vCfe.append("0100")
                vSerFe.append("000000000000000000000000000000000000000000000000000000000000" + "0100")
 
            for i in range(0, NUM_OF_CFE):
                vCmt.append(data)
                vSerFe.append(BIT_VECTOR_FE)
 
 
            t0 = time.time()
            proof = certMcTest.create_test_proof(
                "scs", epoch_number, (q+tot_num_cert), MBTR_SC_FEE, FT_SC_FEE, constant, epoch_cum_tree_hash, pkh_array, bwt_amount_array, vSerFe)
            assert_true(proof != None)
            t1 = time.time()
            print "...proof with sz={} generated: {} secs".format(len(proof)//2, t1-t0)
            
            try:
                cert = self.nodes[0].send_certificate(scid, epoch_number, (q+tot_num_cert),
                    epoch_cum_tree_hash, proof, bwt_cert, FT_SC_FEE, MBTR_SC_FEE, CERT_FEE, vCfe, vCmt)
            except JSONRPCException, e:
                errorString = e.error['message']
                print "Send certificate failed with reason {}".format(errorString)
                assert(False)

            self.sync_all()
            tot_num_cert += 1
  
            hexCert = self.nodes[0].getrawtransaction(cert)
            sz = len(hexCert)//2
            tot_cert_sz += sz

            print("cert={}, sz={}, zatPerK={}".format(cert, sz, round((CERT_FEE*COIN*1000))/sz))

            if tot_cert_sz > NODE1_TEST_BLOCK_MAX_SIZE:
                break

        print "tot cert   = {}, tot sz = {} ".format(tot_num_cert, tot_cert_sz)

        mark_logs("Creating txes...", self.nodes, DEBUG_MODE)
        tot_num_tx = 0
        tot_tx_sz = 0
        taddr_node0 = self.nodes[0].getnewaddress()
        taddr_node1 = self.nodes[1].getnewaddress()

        # this will lead to a fee rate higher than the one of certs, which are much bigger
        fee = CERT_FEE

        am = 0.1
        cd = "effe" * 512
        sc_ft = [ {"address":"abc", "amount":am, "scid":scid} ]
        sc_cr = []
        sc_cr.append({
            "epoch_length": 30,
            "amount": 0.00001,
            'wCertVk': certVk,
            "address": "abb",
            "constant": constant,
            "customData": cd
        })

        # there are a few coinbase utxo now matured
        listunspent = self.nodes[1].listunspent()

        while True:
            if len(listunspent) <= tot_num_tx:
                # all utxo have been spent
                self.sync_all()
                break

            utxo = listunspent[tot_num_tx]
            change = utxo['amount'] - Decimal(am) - Decimal(fee) 
            raw_inputs  = [ {'txid' : utxo['txid'], 'vout' : utxo['vout']}]
            raw_outs    = { taddr_node1: change }
            try:
                raw_tx = self.nodes[1].createrawtransaction(raw_inputs, raw_outs, [], sc_cr, sc_ft)
                signed_tx = self.nodes[1].signrawtransaction(raw_tx)
                tx = self.nodes[1].sendrawtransaction(signed_tx['hex'])
            except JSONRPCException, e:
                errorString = e.error['message']
                print "Send raw tx failed with reason {}".format(errorString)
                assert(False)

            tot_num_tx += 1
            hexTx = self.nodes[1].getrawtransaction(tx)
            sz = len(hexTx)//2
            tot_tx_sz += sz
            print("tx={}, sz={}, zatPerK={}".format(tx, sz, round((fee*COIN*1000))/sz))

            if tot_tx_sz > 2*NODE0_TEST_BLOCK_TX_PARTITION_MAX_SIZE:
                self.sync_all()
                break

        print "tot tx   = {}, tot sz = {} ".format(tot_num_tx, tot_tx_sz)

        mark_logs("Node0 generating 1 block, checking blocks partitions...", self.nodes, DEBUG_MODE)
        self.nodes[0].generate(1)
        self.sync_all()
        ret = self.nodes[0].getmininginfo()

        # no certs here, they are hi-prio but larger than max prio size in node 0
        assert_equal(ret['currentblockcert'], 0)
        # only txes here
        assert_true(ret['currentblocktx'] > 0)
        # but not all of them, since total size is larger that tx part
        mined_tx = ret['currentblocktx']
        assert_true(mined_tx < tot_num_tx)

        print "block num of cert = ", ret['currentblockcert']
        print "block size        = ", ret['currentblocksize']
        print "block num of tx   = ", ret['currentblocktx']
        print "tx partition used = ", ret['currenttxpartitionused']

        mark_logs("Node1 generating 1 block, checking blocks partitions...", self.nodes, DEBUG_MODE)
        self.nodes[1].generate(1)
        self.sync_all()
        ret = self.nodes[1].getmininginfo()

        # all certs but one are here
        mined_certs = ret['currentblockcert']
        assert_equal(mined_certs, tot_num_cert - 1)
        # no txes here because tx part size is null
        assert_true(ret['currentblocktx'] == 0)

        print "block num of cert = ", ret['currentblockcert']
        print "block size        = ", ret['currentblocksize']
        print "block num of tx   = ", ret['currentblocktx']
        print "tx partition used = ", ret['currenttxpartitionused']

        assert_true(len(self.nodes[0].getrawmempool()) == tot_num_cert - mined_certs + tot_num_tx - mined_tx)

        
        
if __name__ == '__main__':
    sc_big_certs().main()

