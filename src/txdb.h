// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TXDB_H
#define BITCOIN_TXDB_H

#include "coins.h"
#include "leveldbwrapper.h"

#include <map>
#include <string>
#include <utility>
#include <vector>

class CBlockFileInfo;
class CBlockIndex;
struct CDiskTxPos;
class uint256;

//! -dbcache default (MiB)
static const int64_t nDefaultDbCache = 100;
//! max. -dbcache in (MiB)
static const int64_t nMaxDbCache = sizeof(void*) > 4 ? 16384 : 1024;
//! min. -dbcache in (MiB)
static const int64_t nMinDbCache = 4;

/** CCoinsView backed by the LevelDB coin database (chainstate/) */
class CCoinsViewDB : public CCoinsView
{
protected:
    CLevelDBWrapper db;
    CCoinsViewDB(std::string dbName, size_t nCacheSize, bool fMemory = false, bool fWipe = false);
public:
    CCoinsViewDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);

    bool GetAnchorAt(const uint256 &rt, ZCIncrementalMerkleTree &tree)   const override;
    bool GetNullifier(const uint256 &nf)                                 const override;
    bool GetCoins(const uint256 &txid, CCoins &coins)                    const override;
    bool HaveCoins(const uint256 &txid)                                  const override;
    bool GetSidechain(const uint256& scId, CSidechain& info)             const override;
    bool HaveSidechain(const uint256& scId)                              const override;
    bool HaveSidechainEvents(int height)                                 const override;
    bool GetSidechainEvents(int height, CSidechainEvents& ceasingScs)    const override;
    void GetScIds(std::set<uint256>& scIdsList)                          const override;
    uint256 GetBestBlock()                                               const override;
    uint256 GetBestAnchor()                                              const override;
    bool HaveCswNullifier(const uint256& scId,
                          const CFieldElement& nullifier)  const override;

    bool BatchWrite(CCoinsMap &mapCoins,
                    const uint256 &hashBlock,
                    const uint256 &hashAnchor,
                    CAnchorsMap &mapAnchors,
                    CNullifiersMap &mapNullifiers,
                    CSidechainsMap& mapSidechains,
                    CSidechainEventsMap& mapSidechainEvents,
                    CCswNullifiersMap& cswNullifies)                           override;
    bool GetStats(CCoinsStats &stats)                                    const override;
    void Dump_info() const;
};

/** Access to the block database (blocks/index/) */
class CBlockTreeDB : public CLevelDBWrapper
{
public:
    CBlockTreeDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);
private:
    CBlockTreeDB(const CBlockTreeDB&);
    void operator=(const CBlockTreeDB&);
public:
    bool WriteBatchSync(const std::vector<std::pair<int, const CBlockFileInfo*> >& fileInfo, int nLastFile, const std::vector<const CBlockIndex*>& blockinfo);
    bool ReadBlockFileInfo(int nFile, CBlockFileInfo &fileinfo);
    bool ReadLastBlockFile(int &nFile);
    bool WriteReindexing(bool fReindex);
    bool ReadReindexing(bool &fReindex);
    bool WriteFastReindexing(bool fReindexFast);
    bool ReadFastReindexing(bool &fReindexFast);
    bool ReadTxIndex(const uint256 &txid, CDiskTxPos &pos);
    bool WriteTxIndex(const std::vector<std::pair<uint256, CDiskTxPos> > &list);
    bool WriteFlag(const std::string &name, bool fValue);
    bool ReadFlag(const std::string &name, bool &fValue);
    bool LoadBlockIndexGuts();
};

#endif // BITCOIN_TXDB_H
