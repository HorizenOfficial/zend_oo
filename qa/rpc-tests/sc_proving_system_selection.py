#!/usr/bin/env python2
# Copyright (c) 2014 The Bitcoin Core developers
# Copyright (c) 2018 The Zencash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
from test_framework.test_framework import BitcoinTestFramework
from test_framework.authproxy import JSONRPCException
from test_framework.util import assert_equal, assert_true, assert_false, initialize_chain_clean, \
    stop_nodes, wait_bitcoinds, \
    start_nodes, sync_blocks, sync_mempools, connect_nodes_bi, disconnect_nodes, mark_logs, \
    dump_sc_info_record, get_epoch_data
from test_framework.mc_test.mc_test import *
import os
from decimal import Decimal
import pprint
import time

NUMB_OF_NODES = 1
DEBUG_MODE = 1
SC_COINS_MAT = 2
EPOCH_LENGTH = 10
MAX_MONEY = 21000000

class SCProvingSystemSelection(BitcoinTestFramework):
    alert_filename = None

    def setup_chain(self, split=False):
        print("Initializing test directory " + self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, NUMB_OF_NODES)
        self.alert_filename = os.path.join(self.options.tmpdir, "alert.txt")
        with open(self.alert_filename, 'w'):
            pass  # Just open then close to create zero-length file

    def setup_network(self, split=False):
        self.nodes = []

        self.nodes = start_nodes(NUMB_OF_NODES, self.options.tmpdir,
                                 extra_args=[["-sccoinsmaturity=%d" % SC_COINS_MAT, '-logtimemicros=1', '-debug=sc',
                                              '-debug=py', '-debug=mempool', '-debug=net',
                                              '-debug=bench']] * NUMB_OF_NODES)

        #connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = split
        self.sync_all()

    def run_test(self):

        '''
        When creating a new sidechain, the developer must provide the type of proving system to be used for verifying
        certificates proof (and, optionally, the one for Ceased Sidechain Withdrawals proof in case they are supported).
        This test checks that the proving system selection is handled correctly.
        '''

        # network topology: (0)

        mark_logs("Node 0 generates 220 blocks", self.nodes, DEBUG_MODE)
        blocks = self.nodes[0].generate(220)
        self.sync_all()

        # Sidechain parameters
        withdrawalEpochLength = EPOCH_LENGTH
        address = "dada"
        creation_amount = Decimal("50.0")
        custom_data = "bb" * 1024
        ftScFee = 10
        mbtrScFee = 20
        mbtrRequestDataLength = 1

        mcTest = MCTestUtils(self.options.tmpdir, self.options.srcdir)
        vk_tag = "sc1_cert"
        vk = mcTest.generate_params(vk_tag)
        constant = generate_random_field_element_hex()
        cswVk_tag = "sc1_csw"
        cswVk  = mcTest.generate_params(cswVk_tag)
        feCfg = []
        bvCfg = []


        # ---------------------------------------------------------------------------------------
        # Node 0 - Create a sidechain providing an undefined certificate proving system [sc_create()]
        mark_logs("\nNode 0 creates a sidechain with an undefined certificate proving system", self.nodes, DEBUG_MODE)

        proving_system = 0

        try:
            ret = self.nodes[0].sc_create(withdrawalEpochLength, address, creation_amount, proving_system, vk)
            assert_true(False)
        except JSONRPCException, e:
            errorString = e.error['message']
            mark_logs(errorString,self.nodes,DEBUG_MODE)

        assert_true("Invalid certProvingSystem" in errorString)


        # ---------------------------------------------------------------------------------------
        # Node 0 - Create a sidechain providing an invalid certificate proving system [sc_create()]
        mark_logs("\nNode 0 creates a sidechain with an invalid certificate proving system", self.nodes, DEBUG_MODE)

        proving_system = 3

        try:
            ret = self.nodes[0].sc_create(withdrawalEpochLength, address, creation_amount, proving_system, vk)
            assert_true(False)
        except JSONRPCException, e:
            errorString = e.error['message']
            mark_logs(errorString,self.nodes,DEBUG_MODE)

        assert_true("Invalid certProvingSystem" in errorString)


        # ---------------------------------------------------------------------------------------
        # Node 0 - Create a sidechain providing a CSW verification key and an undefined CSW proving system [sc_create()]
        mark_logs("\nNode 0 creates a sidechain with an undefined CSW proving system", self.nodes, DEBUG_MODE)

        cert_proving_system = 1
        csw_proving_system = 0

        try:
            ret = self.nodes[0].sc_create(withdrawalEpochLength, address, creation_amount, cert_proving_system, vk,
                                          custom_data, constant, csw_proving_system, cswVk)
            assert_true(False)
        except JSONRPCException, e:
            errorString = e.error['message']
            mark_logs(errorString,self.nodes,DEBUG_MODE)

        assert_true("Invalid cswProvingSystem" in errorString)


        # ---------------------------------------------------------------------------------------
        # Node 0 - Create a sidechain providing a CSW verification key and an invalid CSW proving system [sc_create()]
        mark_logs("\nNode 0 creates a sidechain with an invalid CSW proving system", self.nodes, DEBUG_MODE)

        cert_proving_system = 1
        csw_proving_system = 3

        try:
            ret = self.nodes[0].sc_create(withdrawalEpochLength, address, creation_amount, cert_proving_system, vk,
                                          custom_data, constant, csw_proving_system, cswVk)
            assert_true(False)
        except JSONRPCException, e:
            errorString = e.error['message']
            mark_logs(errorString,self.nodes,DEBUG_MODE)

        assert_true("Invalid cswProvingSystem" in errorString)


        # ---------------------------------------------------------------------------------------
        # Node 0 - Create a sidechain without providing a certificate proving system [create_sidechain()]
        mark_logs("\nNode 0 creates a new sidechain with create_sidechain() without providing the certificate proving system", self.nodes, DEBUG_MODE)

        cmdInput = { "toaddress": address, "amount": creation_amount, 'wCertVk': vk }
        
        try:
            creating_tx = self.nodes[0].create_sidechain(cmdInput)['txid']
            assert_true(False)
        except JSONRPCException, e:
            errorString = e.error['message']
            mark_logs(errorString,self.nodes,DEBUG_MODE)

        assert_true("Missing mandatory parameter in input: \"certProvingSystem\"" in errorString)


        # ---------------------------------------------------------------------------------------
        # Node 0 - Create a sidechain providing an undefined certificate proving system [create_sidechain()]
        mark_logs("\nNode 0 creates a new sidechain with create_sidechain() providing an undefined certificate proving system", self.nodes, DEBUG_MODE)

        proving_system = 0
        cmdInput = { "toaddress": address, "amount": creation_amount, 'wCertVk': vk, 'certProvingSystem': proving_system }
        
        try:
            creating_tx = self.nodes[0].create_sidechain(cmdInput)['txid']
            assert_true(False)
        except JSONRPCException, e:
            errorString = e.error['message']
            mark_logs(errorString,self.nodes,DEBUG_MODE)

        assert_true("Invalid certProvingSystem" in errorString)


        # ---------------------------------------------------------------------------------------
        # Node 0 - Create a sidechain providing an invalid certificate proving system [create_sidechain()]
        mark_logs("\nNode 0 creates a new sidechain with create_sidechain() providing an invalid certificate proving system", self.nodes, DEBUG_MODE)

        proving_system = 3
        cmdInput = { "toaddress": address, "amount": creation_amount, 'wCertVk': vk, 'certProvingSystem': proving_system }
        
        try:
            creating_tx = self.nodes[0].create_sidechain(cmdInput)['txid']
            assert_true(False)
        except JSONRPCException, e:
            errorString = e.error['message']
            mark_logs(errorString,self.nodes,DEBUG_MODE)

        assert_true("Invalid certProvingSystem" in errorString)


        # ---------------------------------------------------------------------------------------
        # Node 0 - Create a sidechain providing a CSW key and omitting the CSW proving system [create_sidechain()]
        mark_logs("\nNode 0 creates a new sidechain with create_sidechain() providing a CSW key and omitting the CSW proving system", self.nodes, DEBUG_MODE)

        proving_system = 1
        cmdInput = { "toaddress": address, "amount": creation_amount, 'wCertVk': vk, 'certProvingSystem': proving_system, 'wCeasedVk': cswVk }
        
        try:
            creating_tx = self.nodes[0].create_sidechain(cmdInput)['txid']
            assert_true(False)
        except JSONRPCException, e:
            errorString = e.error['message']
            mark_logs(errorString,self.nodes,DEBUG_MODE)

        assert_true("cswProvingSystem must be defined if a wCeasedVk is provided" in errorString)


        # ---------------------------------------------------------------------------------------
        # Node 0 - Create a sidechain providing a CSW key and an undefined CSW proving system [create_sidechain()]
        mark_logs("\nNode 0 creates a new sidechain with create_sidechain() providing a CSW key and an undefined CSW proving system", self.nodes, DEBUG_MODE)

        cert_proving_system = 1
        csw_proving_system = 0
        cmdInput = { "toaddress": address, "amount": creation_amount, 'wCertVk': vk, 'certProvingSystem': cert_proving_system,
                     'wCeasedVk': cswVk, 'cswProvingSystem': csw_proving_system }
        
        try:
            creating_tx = self.nodes[0].create_sidechain(cmdInput)['txid']
            assert_true(False)
        except JSONRPCException, e:
            errorString = e.error['message']
            mark_logs(errorString,self.nodes,DEBUG_MODE)

        assert_true("Invalid cswProvingSystem" in errorString)


        # ---------------------------------------------------------------------------------------
        # Node 0 - Create a sidechain providing a CSW key and an invalid CSW proving system [create_sidechain()]
        mark_logs("\nNode 0 creates a new sidechain with create_sidechain() providing a CSW key and an invalid CSW proving system", self.nodes, DEBUG_MODE)

        cert_proving_system = 1
        csw_proving_system = 3
        cmdInput = { "toaddress": address, "amount": creation_amount, 'wCertVk': vk, 'certProvingSystem': cert_proving_system,
                     'wCeasedVk': cswVk, 'cswProvingSystem': csw_proving_system }
        
        try:
            creating_tx = self.nodes[0].create_sidechain(cmdInput)['txid']
            assert_true(False)
        except JSONRPCException, e:
            errorString = e.error['message']
            mark_logs(errorString,self.nodes,DEBUG_MODE)

        assert_true("Invalid cswProvingSystem" in errorString)


        # ---------------------------------------------------------------------------------------
        # Node 0 - Create a sidechain without providing the certificate proving system [create_raw_transaction()]
        mark_logs("\nNode 0 creates a new sidechain with create_raw_transaction() without providing the certificate proving system", self.nodes, DEBUG_MODE)

        sc_cr = [{
            "epoch_length": withdrawalEpochLength, "amount": creation_amount, "address": address, "wCertVk": vk }]

        try:
            rawtx = self.nodes[0].createrawtransaction([],{},[],sc_cr)
            assert_true(False)
        except JSONRPCException, e:
            errorString = e.error['message']
            mark_logs(errorString,self.nodes,DEBUG_MODE)

        assert_true("Invalid parameter or missing certProvingSystem key" in errorString)


        # ---------------------------------------------------------------------------------------
        # Node 0 - Create a sidechain providing an undefined certificate proving system [create_raw_transaction()]
        mark_logs("\nNode 0 creates a new sidechain with create_raw_transaction() providing an undefined certificate proving system", self.nodes, DEBUG_MODE)

        proving_system = 0
        sc_cr = [{
            "epoch_length": withdrawalEpochLength, "amount": creation_amount, "address": address,
            "certProvingSystem": proving_system, "wCertVk": vk }]

        try:
            rawtx = self.nodes[0].createrawtransaction([],{},[],sc_cr)
            assert_true(False)
        except JSONRPCException, e:
            errorString = e.error['message']
            mark_logs(errorString,self.nodes,DEBUG_MODE)

        assert_true("Invalid parameter certProvingSystem" in errorString)


         # ---------------------------------------------------------------------------------------
        # Node 0 - Create a sidechain providing an invalid certificate proving system [create_raw_transaction()]
        mark_logs("\nNode 0 creates a new sidechain with create_raw_transaction() providing an invalid certificate proving system", self.nodes, DEBUG_MODE)

        proving_system = 3
        sc_cr = [{
            "epoch_length": withdrawalEpochLength, "amount": creation_amount, "address": address,
            "certProvingSystem": proving_system, "wCertVk": vk }]

        try:
            rawtx = self.nodes[0].createrawtransaction([],{},[],sc_cr)
            assert_true(False)
        except JSONRPCException, e:
            errorString = e.error['message']
            mark_logs(errorString,self.nodes,DEBUG_MODE)

        assert_true("Invalid parameter certProvingSystem" in errorString)


        # ---------------------------------------------------------------------------------------
        # Node 0 - Create a sidechain providing a CSW key and omitting the CSW proving system [create_raw_transaction()]
        mark_logs("\nNode 0 creates a new sidechain with create_raw_transaction() providing a CSW key and omitting the CSW proving system", self.nodes, DEBUG_MODE)

        proving_system = 1
        sc_cr = [{
            "epoch_length": withdrawalEpochLength, "amount": creation_amount, "address": address,
            "certProvingSystem": proving_system, "wCertVk": vk, "wCeasedVk": cswVk }]

        try:
            rawtx = self.nodes[0].createrawtransaction([],{},[],sc_cr)
            assert_true(False)
        except JSONRPCException, e:
            errorString = e.error['message']
            mark_logs(errorString,self.nodes,DEBUG_MODE)

        assert_true("cswProvingSystem must be defined if a wCeasedVk is provided" in errorString)


        # ---------------------------------------------------------------------------------------
        # Node 0 - Create a sidechain providing a CSW key and an undefined CSW proving system [create_raw_transaction()]
        mark_logs("\nNode 0 creates a new sidechain with create_raw_transaction() providing a CSW key and an undefined CSW proving system", self.nodes, DEBUG_MODE)

        cert_proving_system = 1
        csw_proving_system = 0
        sc_cr = [{
            "epoch_length": withdrawalEpochLength, "amount": creation_amount, "address": address,
            "certProvingSystem": proving_system, "wCertVk": vk, "cswProvingSystem": csw_proving_system, "wCeasedVk": cswVk }]
        
        try:
            rawtx = self.nodes[0].createrawtransaction([],{},[],sc_cr)
            assert_true(False)
        except JSONRPCException, e:
            errorString = e.error['message']
            mark_logs(errorString,self.nodes,DEBUG_MODE)

        assert_true("Invalid parameter cswProvingSystem" in errorString)


        # ---------------------------------------------------------------------------------------
        # Node 0 - Create a sidechain providing a CSW key and an invalid CSW proving system [create_raw_transaction()]
        mark_logs("\nNode 0 creates a new sidechain with create_raw_transaction() providing a CSW key and an invalid CSW proving system", self.nodes, DEBUG_MODE)

        cert_proving_system = 1
        csw_proving_system = 3
        sc_cr = [{
            "epoch_length": withdrawalEpochLength, "amount": creation_amount, "address": address,
            "certProvingSystem": proving_system, "wCertVk": vk, "cswProvingSystem": csw_proving_system, "wCeasedVk": cswVk }]
        
        try:
            rawtx = self.nodes[0].createrawtransaction([],{},[],sc_cr)
            assert_true(False)
        except JSONRPCException, e:
            errorString = e.error['message']
            mark_logs(errorString,self.nodes,DEBUG_MODE)

        assert_true("Invalid parameter cswProvingSystem" in errorString)


        # ---------------------------------------------------------------------------------------
        # Node 0 - Create a valid sidechain with sc_create()
        mark_logs("\nNode 0 creates a new sidechain [sc_create()]", self.nodes, DEBUG_MODE)

        cert_proving_system = 1
        csw_proving_system = 2

        try:
            ret = self.nodes[0].sc_create(withdrawalEpochLength, address, creation_amount, cert_proving_system, vk,
                                          custom_data, constant, csw_proving_system, cswVk)
        except JSONRPCException, e:
            errorString = e.error['message']
            mark_logs(errorString,self.nodes,DEBUG_MODE)
            assert_true(False)

        creating_tx = ret['txid']
        scid = ret['scid']
        self.sync_all()

        mark_logs("Verify that the proving systems have been set correctly on the transaction JSON object", self.nodes, DEBUG_MODE)
        decoded_tx = self.nodes[0].getrawtransaction(creating_tx, 1)
        assert_equal(cert_proving_system, decoded_tx['vsc_ccout'][0]['certProvingSystem'])
        assert_equal(csw_proving_system, decoded_tx['vsc_ccout'][0]['cswProvingSystem'])

        mark_logs("Verify that sidechain configuration is as expected [mempool]", self.nodes, DEBUG_MODE)
        scinfo0 = self.nodes[0].getscinfo(scid)['items'][0]
        assert_equal(scinfo0['certificateProvingSystem'], cert_proving_system)
        assert_equal(scinfo0['cswProvingSystem'], csw_proving_system)

        mark_logs("Node0 generating 1 block", self.nodes, DEBUG_MODE)
        prev_epoch_block_hash = self.nodes[0].getblockhash(self.nodes[0].getblockcount())
        blocks.extend(self.nodes[0].generate(1))
        self.sync_all()

        mark_logs("Verify that sidechain configuration is as expected after connecting the new block", self.nodes, DEBUG_MODE)
        scinfo0 = self.nodes[0].getscinfo(scid)['items'][0]
        assert_equal(scinfo0['certificateProvingSystem'], cert_proving_system)
        assert_equal(scinfo0['cswProvingSystem'], csw_proving_system)


        # ---------------------------------------------------------------------------------------
        # Node 0 - Create a valid sidechain with create_sidechain()
        mark_logs("\nNode 0 creates a new sidechain with create_sidechain()", self.nodes, DEBUG_MODE)

        cert_proving_system = 1
        csw_proving_system = 2
        cmdInput = { "toaddress": address, "amount": creation_amount, 'wCertVk': vk, 'certProvingSystem': cert_proving_system,
                     'wCeasedVk': cswVk, 'cswProvingSystem': csw_proving_system }
        
        try:
            creating_tx = self.nodes[0].create_sidechain(cmdInput)['txid']
        except JSONRPCException, e:
            errorString = e.error['message']
            mark_logs(errorString,self.nodes,DEBUG_MODE)
            assert_true(False)

        self.sync_all()

        mark_logs("Verify that the proving systems have been set correctly on the transaction JSON object", self.nodes, DEBUG_MODE)
        decoded_tx = self.nodes[0].getrawtransaction(creating_tx, 1)
        assert_equal(cert_proving_system, decoded_tx['vsc_ccout'][0]['certProvingSystem'])
        assert_equal(csw_proving_system, decoded_tx['vsc_ccout'][0]['cswProvingSystem'])

        mark_logs("Verify that sidechain configuration is as expected [mempool]", self.nodes, DEBUG_MODE)
        scinfo0 = self.nodes[0].getscinfo(scid)['items'][0]
        assert_equal(scinfo0['certificateProvingSystem'], cert_proving_system)
        assert_equal(scinfo0['cswProvingSystem'], csw_proving_system)

        mark_logs("Node0 generating 1 block", self.nodes, DEBUG_MODE)
        prev_epoch_block_hash = self.nodes[0].getblockhash(self.nodes[0].getblockcount())
        blocks.extend(self.nodes[0].generate(1))
        self.sync_all()

        mark_logs("Verify that sidechain configuration is as expected after connecting the new block", self.nodes, DEBUG_MODE)
        scinfo0 = self.nodes[0].getscinfo(scid)['items'][0]
        assert_equal(scinfo0['certificateProvingSystem'], cert_proving_system)
        assert_equal(scinfo0['cswProvingSystem'], csw_proving_system)


        # ---------------------------------------------------------------------------------------
        # Node 0 - Create a valid sidechain with createrawtransaction()
        mark_logs("\nNode 0 creates a new sidechain with createrawtransaction()", self.nodes, DEBUG_MODE)

        sc_cr = [{
            "epoch_length": withdrawalEpochLength, "amount": creation_amount, "address": address,
            "certProvingSystem": proving_system, "wCertVk": vk,
            "wCeasedVk": cswVk, "cswProvingSystem": csw_proving_system }]

        try:
            rawtx = self.nodes[0].createrawtransaction([],{},[],sc_cr)
            funded_tx = self.nodes[0].fundrawtransaction(rawtx)
            sigRawtx = self.nodes[0].signrawtransaction(funded_tx['hex'])
            creating_tx = self.nodes[0].sendrawtransaction(sigRawtx['hex'])
        except JSONRPCException, e:
            errorString = e.error['message']
            mark_logs(errorString,self.nodes,DEBUG_MODE)
            assert_true(False)

        self.sync_all()

        mark_logs("Verify that the proving systems have been set correctly on the transaction JSON object", self.nodes, DEBUG_MODE)
        decoded_tx = self.nodes[0].getrawtransaction(creating_tx, 1)
        assert_equal(cert_proving_system, decoded_tx['vsc_ccout'][0]['certProvingSystem'])
        assert_equal(csw_proving_system, decoded_tx['vsc_ccout'][0]['cswProvingSystem'])

        mark_logs("Verify that sidechain configuration is as expected [mempool]", self.nodes, DEBUG_MODE)
        scinfo0 = self.nodes[0].getscinfo(scid)['items'][0]
        assert_equal(scinfo0['certificateProvingSystem'], cert_proving_system)
        assert_equal(scinfo0['cswProvingSystem'], csw_proving_system)

        mark_logs("Node0 generating 1 block", self.nodes, DEBUG_MODE)
        prev_epoch_block_hash = self.nodes[0].getblockhash(self.nodes[0].getblockcount())
        blocks.extend(self.nodes[0].generate(1))
        self.sync_all()

        mark_logs("Verify that sidechain configuration is as expected after connecting the new block", self.nodes, DEBUG_MODE)
        scinfo0 = self.nodes[0].getscinfo(scid)['items'][0]
        assert_equal(scinfo0['certificateProvingSystem'], cert_proving_system)
        assert_equal(scinfo0['cswProvingSystem'], csw_proving_system)


if __name__ == '__main__':
    SCProvingSystemSelection().main()
