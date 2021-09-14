#!/usr/bin/env python2
# Copyright (c) 2014 The Bitcoin Core developers
# Copyright (c) 2018 The Zencash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
from test_framework.test_framework import BitcoinTestFramework
from test_framework.authproxy import JSONRPCException
from test_framework.util import assert_equal, initialize_chain_clean, \
    start_nodes, sync_blocks, sync_mempools, connect_nodes_bi, mark_logs, \
    get_epoch_data, assert_false, assert_true, swap_bytes, advance_epoch
from test_framework.test_framework import MINIMAL_SC_HEIGHT, MINER_REWARD_POST_H200
from test_framework.mc_test.mc_test import *
import os
import pprint
from decimal import Decimal

DEBUG_MODE = 1
NUMB_OF_NODES = 2
EPOCH_LENGTH = 17
FT_SC_FEE = Decimal('0')
MBTR_SC_FEE = Decimal('0')
CERT_FEE = Decimal('0.00015')


class sc_big_certificate(BitcoinTestFramework):
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
        [['-debug=py', '-debug=sc', '-debug=mempool', '-debug=net', '-debug=cert', '-debug=zendoo_mc_cryptolib',
          '-scproofqueuesize=0', '-logtimemicros=1']] * NUMB_OF_NODES)

        connect_nodes_bi(self.nodes, 0, 1)
        sync_blocks(self.nodes[1:NUMB_OF_NODES])
        sync_mempools(self.nodes[1:NUMB_OF_NODES])
        self.is_network_split = split
        self.sync_all()

    def run_test(self):

        '''
        The test creates a sc, send funds to it and then sends a certificate to it,
        verifying also that large size causes a certificate to be refused.
        This test also checks that csw certificate also will be refused.
        '''

        # forward transfer amounts
        creation_amount = Decimal("1.0")

        self.nodes[0].getblockhash(0)

        # node 1 earns some coins, they would be available after 100 blocks
        mark_logs("Node 1 generates 1 block", self.nodes, DEBUG_MODE)
        self.nodes[1].generate(1)
        self.sync_all()

        mark_logs("Node 0 generates {} block".format(MINIMAL_SC_HEIGHT), self.nodes, DEBUG_MODE)
        self.nodes[0].generate(MINIMAL_SC_HEIGHT)
        self.sync_all()

        # Checking large certificate rejection
        mark_logs("Generation certificate of the lage size", self.nodes, DEBUG_MODE)
        LARGE_CERT_NUM_CONSTRAINTS = 1 << 14
        SEGMENT_SIZE = 1 << 11

        certMcTest = CertTestUtils(self.options.tmpdir, self.options.srcdir)

        vk_sc1 = certMcTest.generate_params("sc1", "cert", LARGE_CERT_NUM_CONSTRAINTS, SEGMENT_SIZE)
        constant = generate_random_field_element_hex()
        ret = self.nodes[1].sc_create(EPOCH_LENGTH, "ddda", creation_amount, vk_sc1, "", constant)
        scid1 = ret['scid']
        creating_tx = ret['txid']
        scid1_swapped = str(swap_bytes(scid1))
        mark_logs("Node 1 created the SC spending {} coins via tx {}.".format(creation_amount, creating_tx), self.nodes,
                  DEBUG_MODE)

        self.nodes[1].generate(1)
        self.nodes[1].generate(EPOCH_LENGTH)
        self.sync_all()
        quality = 10

        epoch_number, epoch_cum_tree_hash = get_epoch_data(scid1, self.nodes[0], EPOCH_LENGTH)
        proof = certMcTest.create_test_proof("sc1", scid1_swapped, epoch_number, quality, MBTR_SC_FEE, FT_SC_FEE,
                                          epoch_cum_tree_hash, constant, [], [], [], LARGE_CERT_NUM_CONSTRAINTS, SEGMENT_SIZE)

        mark_logs("Proof size bytes: {}".format(len(proof) / 2), self.nodes, DEBUG_MODE)
        try:
            self.nodes[0].send_certificate(scid1, epoch_number, quality,
                                           epoch_cum_tree_hash, proof, [], FT_SC_FEE, MBTR_SC_FEE, CERT_FEE)
            assert (False)
        except JSONRPCException, e:
            errorString = e.error['message']
            mark_logs(errorString, self.nodes, DEBUG_MODE)
            assert_equal("bad-sc-cert-not-applicable" in errorString, True)


        # Check large CSW certificate
        CERT_NUM_CONSTRAINTS = 1 << 13
        LARGE_CSW_NUM_CONSTRAINTS = 1 << 14

        cswMcTest = CSWTestUtils(self.options.tmpdir, self.options.srcdir)
        vk_sc2 = certMcTest.generate_params('sc2', 'cert', CERT_NUM_CONSTRAINTS, SEGMENT_SIZE)
        cswVk_sc2  = cswMcTest.generate_params('sc2', 'csw', LARGE_CSW_NUM_CONSTRAINTS, SEGMENT_SIZE)

        fe1 = "00000000000000000000000000000000000000000000000000000000" + "ab000100"
        fe2 = "8a7d5229f440d4700d8b0343de4e14400d1cb87428abf83bd67153bf58871721"
        vCmt = ["021f8b08000000000002ff017f0080ff44c7e21ba1c7c0a29de006cb8074e2ba39f15abfef2525a4cbb3f235734410bda21cdab6624de769ceec818ac6c2d3a01e382e357dce1f6e9a0ff281f0fedae0efe274351db37599af457984dcf8e3ae4479e0561341adfff4746fbe274d90f6f76b8a2552a6ebb98aee918c7ceac058f4c1ae0131249546ef5e22f4187a07da02ca5b7f000000"]
        proofCfeArray = [fe1, fe2]

        feCfg = []
        cmtCfg = []

        # one custom bv element with:
        # - as many bits in the uncompressed form (must be divisible by 254 and 8)
        # - up to 151 bytes in the compressed form
        cmtCfg.append([[254*4, 151]])
        # all certs must have custom FieldElements with exactly those values as size in bits
        feCfg.append([31])

        cmdInput = {
            'withdrawalEpochLength': EPOCH_LENGTH, 'amount': creation_amount, 'fee': CERT_FEE,
            'constant':constant , 'wCertVk': vk_sc2, 'wCeasedVk': cswVk_sc2, 'toaddress':"cdcd",
            'vFieldElementCertificateFieldConfig':feCfg[0], 'vBitVectorCertificateFieldConfig':cmtCfg[0]}

        ret = self.nodes[1].create_sidechain(cmdInput)
        scid2 = ret['scid']
        scid2_swapped = str(swap_bytes(scid2))
        self.nodes[1].generate(1)
        self.nodes[1].generate(EPOCH_LENGTH)
        self.sync_all()

        epoch_number, epoch_cum_tree_hash = get_epoch_data(scid2, self.nodes[1], EPOCH_LENGTH)
        proof = certMcTest.create_test_proof("sc2", scid2_swapped, epoch_number, quality, MBTR_SC_FEE, FT_SC_FEE,
                                          epoch_cum_tree_hash, constant, [], [], proofCfeArray, CERT_NUM_CONSTRAINTS, SEGMENT_SIZE)

        try:
            self.nodes[1].send_certificate(scid2, epoch_number, quality,
                                           epoch_cum_tree_hash, proof, [], FT_SC_FEE, MBTR_SC_FEE, CERT_FEE, ["ab000100"], vCmt)
        except JSONRPCException, e:
            errorString = e.error['message']
            mark_logs(errorString, self.nodes, DEBUG_MODE)
            assert (False)


        self.nodes[1].generate(EPOCH_LENGTH)

        epoch_number, epoch_cum_tree_hash = get_epoch_data(scid2, self.nodes[1], EPOCH_LENGTH)
        proof = certMcTest.create_test_proof("sc2", scid2_swapped, epoch_number, quality, MBTR_SC_FEE, FT_SC_FEE,
                                          epoch_cum_tree_hash, constant, [], [], proofCfeArray, CERT_NUM_CONSTRAINTS, SEGMENT_SIZE)

        try:
            self.nodes[1].send_certificate(scid2, epoch_number, quality,
                                           epoch_cum_tree_hash, proof, [], FT_SC_FEE, MBTR_SC_FEE, CERT_FEE, ["ab000100"], vCmt)
        except JSONRPCException, e:
            errorString = e.error['message']
            mark_logs(errorString, self.nodes, DEBUG_MODE)
            assert (False)

        self.nodes[1].generate(EPOCH_LENGTH)
        self.nodes[1].generate(5)
        self.sync_all()

        sc_csw_amount = Decimal("0.1")

        ret = self.nodes[0].getscinfo(scid2, False, False)['items'][0]
        mark_logs("sc2 state: {}".format(ret['state']), self.nodes, DEBUG_MODE)
        assert_equal(ret['state'], "CEASED")

        # CSW sender MC address, in taddress and pub key hash formats
        csw_mc_address = self.nodes[0].getnewaddress()
        pkh_mc_address = self.nodes[0].validateaddress(csw_mc_address)['pubkeyhash']
        actCertData = self.nodes[0].getactivecertdatahash(scid2)['certDataHash']
        ceasingCumScTxCommTree = self.nodes[0].getceasingcumsccommtreehash(scid2)['ceasingCumScTxCommTree']
        nullifier = generate_random_field_element_hex()

        csw_proof = cswMcTest.create_test_proof(
            "sc2", sc_csw_amount, str(scid2_swapped), nullifier, pkh_mc_address, ceasingCumScTxCommTree,
            actCertData, constant, LARGE_CERT_NUM_CONSTRAINTS, SEGMENT_SIZE)

        assert_true(csw_proof != None)
        mark_logs("CSW Proof size bytes: {}".format(len(csw_proof) / 2), self.nodes, DEBUG_MODE)

        sc_csws = [
            {
                "amount": sc_csw_amount,
                "senderAddress": csw_mc_address,
                "scId": scid2,
                "epoch": 0,
                "nullifier": nullifier,
                "activeCertData": None,
                "ceasingCumScTxCommTree": ceasingCumScTxCommTree,
                "scProof": csw_proof
            }]

        # recipient MC address
        taddr = self.nodes[1].getnewaddress()
        sc_csw_tx_outs = {taddr: (Decimal(sc_csw_amount) + Decimal("0.15"))}

        rawtx = self.nodes[0].createrawtransaction([], sc_csw_tx_outs, sc_csws)
        funded_tx = self.nodes[0].fundrawtransaction(rawtx)
        sigRawtx = self.nodes[0].signrawtransaction(funded_tx['hex'], None, None, "NONE")
        try:
            self.nodes[0].sendrawtransaction(sigRawtx['hex'])
            assert(False)
        except JSONRPCException, e:
            errorString = e.error['message']
            mark_logs(errorString, self.nodes, DEBUG_MODE)

        self.sync_all()


if __name__ == '__main__':
    sc_big_certificate().main()
