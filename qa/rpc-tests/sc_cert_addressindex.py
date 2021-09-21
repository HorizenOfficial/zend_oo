#!/usr/bin/env python2
# Copyright (c) 2014 The Bitcoin Core developers
# Copyright (c) 2018 The Zencash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import initialize_chain_clean, assert_equal, \
    start_nodes, get_epoch_data, \
    sync_blocks, sync_mempools, connect_nodes_bi, mark_logs, \
    swap_bytes, disconnect_nodes
from test_framework.test_framework import MINIMAL_SC_HEIGHT, MINER_REWARD_POST_H200
from test_framework.mc_test.mc_test import *
import os
from decimal import Decimal
import time

DEBUG_MODE = 1
NUMB_OF_NODES = 2
EPOCH_LENGTH = 100
CERT_FEE = Decimal("0.000123")
SC_FEE = Decimal("0.000345")
TX_FEE = Decimal("0.000567")
FT_SC_FEE = Decimal('0')
MBTR_SC_FEE = Decimal('0')
SC_COINS_MAT = 2
MINIMAL_SC_HEIGHT = 420

ORDINARY_OUTPUT = 0
TOP_QUALITY_CERT_BACKWARD_TRANSFER = 1
LOW_QUALITY_CERT_BACKWARD_TRANSFER = 2

class sc_cert_addressindex(BitcoinTestFramework):

    alert_filename = None

    def setup_chain(self, split=False):
        print("Initializing test directory "+self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, NUMB_OF_NODES)
        self.alert_filename = os.path.join(self.options.tmpdir, "alert.txt")
        with open(self.alert_filename, 'w'):
            pass  # Just open then close to create zero-length file

    def setup_network(self, split=False):
        self.nodes = start_nodes(NUMB_OF_NODES, self.options.tmpdir, extra_args= [['-blockprioritysize=0',
            '-debug=py', '-debug=sc', '-debug=mempool', '-debug=net', '-debug=cert', '-debug=zendoo_mc_cryptolib',
            '-scproofqueuesize=0', '-logtimemicros=1', '-addressindex', '-sccoinsmaturity=%d' % SC_COINS_MAT]] * NUMB_OF_NODES )

        for idx, _ in enumerate(self.nodes):
            if idx < (NUMB_OF_NODES-1):
                connect_nodes_bi(self.nodes, idx, idx+1)

        sync_blocks(self.nodes[1:NUMB_OF_NODES])
        sync_mempools(self.nodes[1:NUMB_OF_NODES])
        self.is_network_split = split
        self.sync_all()

    def split_network(self):
    # Split the network of three nodes into nodes 0 and 1.
        assert not self.is_network_split
        disconnect_nodes(self.nodes[0], 1)
        disconnect_nodes(self.nodes[1], 0)
        self.is_network_split = True

    def join_network(self):
        # Join the (previously split) network pieces together: 0-1
        assert self.is_network_split
        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 1, 0)
        # self.sync_all()
        time.sleep(2)
        self.is_network_split = False    

    def run_test(self):

        #amounts
        creation_amount = Decimal("50")
        bwt_amount = Decimal("5")
        tAddr1 = self.nodes[1].getnewaddress()
        pkh_node1 = self.nodes[1].validateaddress(tAddr1)['pubkeyhash']

        self.nodes[0].generate(MINIMAL_SC_HEIGHT)
        self.sync_all()    
        
        mark_logs("Node 0 generates {} block".format(MINIMAL_SC_HEIGHT), self.nodes, DEBUG_MODE)

        #generate wCertVk and constant
        mcTest = CertTestUtils(self.options.tmpdir, self.options.srcdir)
        vk = mcTest.generate_params("sc1")
        constant = generate_random_field_element_hex()

        ret = self.nodes[0].sc_create(EPOCH_LENGTH, "dada", creation_amount, vk, "", constant)
        creating_tx = ret['txid']
        scid = ret['scid']
        scid_swapped = str(swap_bytes(scid))
        mark_logs("Node 1 created the SC spending {} coins via tx {}.".format(creation_amount, creating_tx), self.nodes, DEBUG_MODE)
        self.sync_all()

        decoded_tx = self.nodes[0].getrawtransaction(creating_tx, 1)
        assert_equal(scid, decoded_tx['vsc_ccout'][0]['scid'])
        mark_logs("created SC id: {}".format(scid), self.nodes, DEBUG_MODE)

        mark_logs("Node0 confirms Sc creation generating 1 block", self.nodes, DEBUG_MODE)
        self.nodes[0].generate(1)
        self.sync_all()

        #Advance for 1 Epoch
        mark_logs("Advance for 1 Epoch", self.nodes, DEBUG_MODE)
        self.nodes[0].generate(EPOCH_LENGTH)
        self.sync_all()

        #Mine Certificate 1 with quality = 5
        epoch_number, epoch_cum_tree_hash = get_epoch_data(scid, self.nodes[0], EPOCH_LENGTH)
        quality = 5
        proof = mcTest.create_test_proof(
            "sc1", scid_swapped, epoch_number, quality, MBTR_SC_FEE, FT_SC_FEE, epoch_cum_tree_hash, constant, [pkh_node1], [bwt_amount])

        amount_cert_1 = [{"pubkeyhash": pkh_node1, "amount": bwt_amount}]

        mark_logs("Mine Certificate 1 with quality = {}...".format(quality), self.nodes, DEBUG_MODE)

        cert1 = self.nodes[0].send_certificate(scid, epoch_number, quality,
            epoch_cum_tree_hash, proof, amount_cert_1, FT_SC_FEE, MBTR_SC_FEE, CERT_FEE)
        self.sync_all()
        
        ####### Test getaddressmempool ########
        addressmempool = self.nodes[1].getaddressmempool({"addresses":[tAddr1]})
        assert_equal(len(addressmempool),1)
        assert_equal(addressmempool[0]['txid'], cert1)
        assert_equal(addressmempool[0]['satoshis'], float(bwt_amount) * 1e8)
        assert_equal(addressmempool[0]['address'], tAddr1)
        assert_equal(addressmempool[0]['outstatus'], TOP_QUALITY_CERT_BACKWARD_TRANSFER)

        self.nodes[0].generate(1)
        self.sync_all()

        ####### Test getaddressmempool ########
        addressmempool = self.nodes[1].getaddressmempool({"addresses":[tAddr1]})
        assert_equal(addressmempool, [])
        ####### Test getaddresstxids ########
        addresstxids = self.nodes[1].getaddresstxids({"addresses":[tAddr1]})
        #assert_equal(len(addresstxids),1)
        #assert_equal(addresstxids[0],cert1)
        ####### Test getaddressbalance ########
        addressbalance = self.nodes[1].getaddressbalance({"addresses":[tAddr1]})
        addressbalanceWithImmature = self.nodes[1].getaddressbalance({"addresses":[tAddr1]}, True)
        #TODO: Verify the difference between addressbalance and addressbalanceWithImmature
        ####### Test getaddressutxo ########
        addressutxo = self.nodes[1].getaddressutxos({"addresses":[tAddr1]})
        addressutxoWithImmature = self.nodes[1].getaddressutxos({"addresses":[tAddr1]}, True)
        #TODO: Verify the difference between addressutxo and addressutxoWithImmature

        #Add to mempool Certificate 2 with quality = 7
        epoch_number, epoch_cum_tree_hash = get_epoch_data(scid, self.nodes[0], EPOCH_LENGTH)
        quality = 7  
        bwt_amount2 = Decimal("7")      
        mark_logs("Add to mempool Certificate 2 with quality = {}...".format(quality), self.nodes, DEBUG_MODE)
        proof = mcTest.create_test_proof(
            "sc1", scid_swapped, epoch_number, quality, MBTR_SC_FEE, FT_SC_FEE, epoch_cum_tree_hash, constant, [pkh_node1], [bwt_amount2])

        amount_cert_2 = [{"pubkeyhash": pkh_node1, "amount": bwt_amount2}]

        cert2 = self.nodes[0].send_certificate(scid, epoch_number, quality,
            epoch_cum_tree_hash, proof, amount_cert_2, FT_SC_FEE, MBTR_SC_FEE, CERT_FEE)
        self.sync_all()

        ####### Test getaddressmempool ########
        addressmempool = self.nodes[1].getaddressmempool({"addresses":[tAddr1]})
        assert_equal(len(addressmempool), 1)
        assert_equal(addressmempool[0]['txid'], cert2)
        assert_equal(addressmempool[0]['satoshis'], float(bwt_amount2) * 1e8)
        assert_equal(addressmempool[0]['address'], tAddr1)
        assert_equal(addressmempool[0]['outstatus'], TOP_QUALITY_CERT_BACKWARD_TRANSFER)

        quality = 9
        bwt_amount3 = Decimal("9")
        mark_logs("Add to mempool Certificate 3 with quality = {}...".format(quality), self.nodes, DEBUG_MODE)
        proof = mcTest.create_test_proof(
            "sc1", scid_swapped, epoch_number, quality, MBTR_SC_FEE, FT_SC_FEE, epoch_cum_tree_hash, constant, [pkh_node1], [bwt_amount3])

        amount_cert_3 = [{"pubkeyhash": pkh_node1, "amount": bwt_amount3}]

        cert3 = self.nodes[0].send_certificate(scid, epoch_number, quality,
            epoch_cum_tree_hash, proof, amount_cert_3, FT_SC_FEE, MBTR_SC_FEE, CERT_FEE)
        self.sync_all()

        ####### Test getaddressmempool ########
        addressmempool = self.nodes[1].getaddressmempool({"addresses":[tAddr1]})
        assert_equal(len(addressmempool), 2)
        assert_equal(addressmempool[0]['txid'], cert2)
        assert_equal(addressmempool[0]['satoshis'], float(bwt_amount2) * 1e8)
        assert_equal(addressmempool[0]['address'], tAddr1)
        assert_equal(addressmempool[0]['outstatus'], LOW_QUALITY_CERT_BACKWARD_TRANSFER)

        assert_equal(addressmempool[1]['txid'], cert3)
        assert_equal(addressmempool[1]['satoshis'], float(bwt_amount3) * 1e8)
        assert_equal(addressmempool[1]['address'], tAddr1)
        assert_equal(addressmempool[1]['outstatus'], TOP_QUALITY_CERT_BACKWARD_TRANSFER)

        self.nodes[0].generate(1)
        self.sync_all()

        ####### Test getaddresstxids ########
        addresstxids = self.nodes[1].getaddresstxids({"addresses":[tAddr1]})
        #assert_equal(len(addresstxids),3)
        #TODO: Verify that Certificate1,2,3 are in the response     
        ####### Test getaddressmempool ########
        addressmempool = self.nodes[1].getaddressmempool({"addresses":[tAddr1]})
        assert_equal(len(addressmempool), 0)
        ####### Test getaddressbalance ########
        addressbalance = self.nodes[1].getaddressbalance({"addresses":[tAddr1]})
        addressbalanceWithImmature = self.nodes[1].getaddressbalance({"addresses":[tAddr1]}, True)  
        #TODO: Verify the difference between addressbalance and addressbalanceWithImmature
        addressutxo = self.nodes[1].getaddressutxos({"addresses":[tAddr1]})
        addressutxoWithImmature = self.nodes[1].getaddressutxos({"addresses":[tAddr1]}, True)
        #TODO: Verify the difference between addressutxo and addressutxoWithImmature    


        # Split the network: (0)--(1) / (2)
        mark_logs("\nSplit network", self.nodes, DEBUG_MODE)
        self.split_network()
        mark_logs("The network is split: 0-1 .. 2", self.nodes, DEBUG_MODE)


        #Mine a block with Certificate 4 with quality = 11 and Certificate 5 with quality = 13
        epoch_number, epoch_cum_tree_hash = get_epoch_data(scid, self.nodes[0], EPOCH_LENGTH)
        quality = 11
        bwt_amount4 = Decimal("11")
        mark_logs("Create a Certificate 4 with quality = {}...".format(quality), self.nodes, DEBUG_MODE)
        proof = mcTest.create_test_proof(
            "sc1", scid_swapped, epoch_number, quality, MBTR_SC_FEE, FT_SC_FEE, epoch_cum_tree_hash, constant, [pkh_node1], [bwt_amount4])

        amount_cert_4 = [{"pubkeyhash": pkh_node1, "amount": bwt_amount4}]

        self.nodes[0].send_certificate(scid, epoch_number, quality,
            epoch_cum_tree_hash, proof, amount_cert_4, FT_SC_FEE, MBTR_SC_FEE, CERT_FEE)

        quality = 13
        bwt_amount5 = Decimal("13")
        mark_logs("Create a Certificat 5 with quality = {}...".format(quality), self.nodes, DEBUG_MODE)
        proof = mcTest.create_test_proof(
            "sc1", scid_swapped, epoch_number, quality, MBTR_SC_FEE, FT_SC_FEE, epoch_cum_tree_hash, constant, [pkh_node1], [bwt_amount5])

        amount_cert_5 = [{"pubkeyhash": pkh_node1, "amount": bwt_amount5}]

        self.nodes[0].send_certificate(scid, epoch_number, quality,
            epoch_cum_tree_hash, proof, amount_cert_5, FT_SC_FEE, MBTR_SC_FEE, CERT_FEE)

        self.nodes[0].generate(1)

        # Checking the network chain tips
        mark_logs("\nChecking network chain tips...", self.nodes, DEBUG_MODE)
        print(self.nodes[0].getblockchaininfo()['blocks'])
        print(self.nodes[1].getblockchaininfo()['blocks'])

        assert_equal(self.nodes[0].getblockchaininfo()['blocks'], 524)
        assert_equal(self.nodes[1].getblockchaininfo()['blocks'], 523)

        mark_logs("\nJoining network", self.nodes, DEBUG_MODE)
        self.join_network()
        mark_logs("\nNetwork joined", self.nodes, DEBUG_MODE)

        ####### Test getaddresstxids ########
        addresstxids = self.nodes[1].getaddresstxids({"addresses":[tAddr1]})
        #assert_equal(len(addresstxids),5)
        #TODO: Verify that Certificate1,2,3,4,5 are in the response     
        ####### Test getaddressmempool ########
        addressmempool = self.nodes[1].getaddressmempool({"addresses":[tAddr1]})
        assert_equal(len(addressmempool), 0)
        ####### Test getaddressbalance ########
        addressbalance = self.nodes[1].getaddressbalance({"addresses":[tAddr1]})
        addressbalanceWithImmature = self.nodes[1].getaddressbalance({"addresses":[tAddr1]}, True)  
        #TODO: Verify the difference between addressbalance and addressbalanceWithImmature
        addressutxo = self.nodes[1].getaddressutxos({"addresses":[tAddr1]})
        addressutxoWithImmature = self.nodes[1].getaddressutxos({"addresses":[tAddr1]}, True)
        #TODO: Verify the difference between addressutxo and addressutxoWithImmature    

        # Checking the network chain tips
        mark_logs("\nChecking network chain tips...", self.nodes, DEBUG_MODE)
        for i in range(0, NUMB_OF_NODES):
            print(self.nodes[i].getblockchaininfo()['blocks'])
            assert_equal(self.nodes[i].getblockchaininfo()['blocks'],524)

if __name__ == '__main__':
    sc_cert_addressindex().main()
