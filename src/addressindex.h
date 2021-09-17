// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ADDRESSINDEX_H
#define BITCOIN_ADDRESSINDEX_H

#include "uint256.h"
#include "amount.h"

struct CMempoolAddressDelta
{
    enum OutputStatus
    {
        // TODO maybe add a NOT_AN_OUTPUT for inputs
        NOT_A_CERT_BACKWARD_TRANSFER, 
        TOP_QUALITY_CERT_BACKWARD_TRANSFER,    /**< top quality certificate, it has a possibility to reach maturity one day*/
        LOW_QUALITY_CERT_BACKWARD_TRANSFER     /**< low quality compared to another cert for the same scid in the mempool */
    };

    int64_t time;
    CAmount amount;
    uint256 prevhash;
    unsigned int prevout;
    OutputStatus outStatus;

    CMempoolAddressDelta(int64_t t, CAmount a, uint256 hash, unsigned int out, OutputStatus status = NOT_A_CERT_BACKWARD_TRANSFER) {
        time = t;
        amount = a;
        prevhash = hash;
        prevout = out;
        outStatus = status;
    }

    CMempoolAddressDelta(int64_t t, CAmount a, OutputStatus status = NOT_A_CERT_BACKWARD_TRANSFER) {
        time = t;
        amount = a;
        prevhash.SetNull();
        prevout = 0;
        outStatus = status;
    }
};

struct CMempoolAddressDeltaKey
{
    int type;
    uint160 addressBytes;
    uint256 txhash;
    unsigned int index;
    int spending;

    CMempoolAddressDeltaKey(int addressType, uint160 addressHash, uint256 hash, unsigned int i, int s) {
        type = addressType;
        addressBytes = addressHash;
        txhash = hash;
        index = i;
        spending = s;
    }

    CMempoolAddressDeltaKey(int addressType, uint160 addressHash) {
        type = addressType;
        addressBytes = addressHash;
        txhash.SetNull();
        index = 0;
        spending = 0;
    }
};

struct CMempoolAddressDeltaKeyCompare
{
    bool operator()(const CMempoolAddressDeltaKey& a, const CMempoolAddressDeltaKey& b) const {
        if (a.type == b.type) {
            if (a.addressBytes == b.addressBytes) {
                if (a.txhash == b.txhash) {
                    if (a.index == b.index) {
                        return a.spending < b.spending;
                    } else {
                        return a.index < b.index;
                    }
                } else {
                    return a.txhash < b.txhash;
                }
            } else {
                return a.addressBytes < b.addressBytes;
            }
        } else {
            return a.type < b.type;
        }
    }
};

#endif // BITCOIN_ADDRESSINDEX_H
