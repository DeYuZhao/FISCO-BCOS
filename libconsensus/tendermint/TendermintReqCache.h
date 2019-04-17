//
// Created by 赵德宇 on 2019-04-01.
//

#ifndef FISCO_BCOS_TENDERMINTREQCACHE_H
#define FISCO_BCOS_TENDERMINTREQCACHE_H

#endif //FISCO_BCOS_TENDERMINTREQCACHE_H
#pragma once
#include <json_spirit/JsonSpiritHeaders.h>
#include <libconsensus/tendermint/Common.h>
#include <libdevcore/CommonJS.h>
#include <libdevcore/easylog.h>
#include <libethcore/Protocol.h>
namespace dev
{
namespace consensus
{
class TendermintReqCache : public std::enable_shared_from_this<TendermintReqCache>
{
public:
    TendermintReqCache(dev::PROTOCOL_ID const& protocol) : m_protocolId(protocol)
    {
        m_groupId = dev::eth::getGroupAndProtocol(m_protocolId).first;
    }

    virtual ~TendermintReqCache() { m_futureProposeCache.clear(); }
    /// specified prepareRequest exists in raw-prepare-cache or not?
    /// @return true : the prepare request exists in the  raw-prepare-cache
    /// @return false : the prepare request doesn't exist in the  raw-prepare-cache
    inline bool isExistPrepare(ProposeReq const& req)
    {
        return m_rawProposeCache.block_hash == req.block_hash;
    }
    /// specified SignReq exists in the sign-cache or not?
    inline bool isExistSign(PreVoteReq const& req)
    {
        return cacheExists(m_preVoteCache, req.block_hash, req.sig.hex());
    }

    /// specified commitReq exists in the commit-cache or not?
    inline bool isExistCommit(PreCommitReq const& req)
    {
        return cacheExists(m_preCommitCache, req.block_hash, req.sig.hex());
    }

    /// specified viewchangeReq exists in the viewchang-cache or not?
//    inline bool isExistViewChange(ViewChangeReq const& req)
//    {
//        return cacheExists(m_recvViewChangeReq, req.view, req.idx);
//    }

    /// get the size of the cached sign requests according to given block hash
    inline size_t getSigCacheSize(h256 const& blockHash) const
    {
        return getSizeFromCache(blockHash, m_preVoteCache);
    }
    /// get the size of the cached commit requests according to given block hash
    inline size_t getCommitCacheSize(h256 const& blockHash) const
    {
        return getSizeFromCache(blockHash, m_preCommitCache);
    }
    /// get the size of cached viewchange requests according to given view
//    inline size_t getViewChangeSize(VIEWTYPE const& toView) const
//    {
//        return getSizeFromCache(toView, m_recvViewChangeReq);
//    }

    template <typename T, typename S>
    inline size_t getSizeFromCache(T const& key, S& cache) const
    {
        auto it = cache.find(key);
        if (it != cache.end())
        {
            return it->second.size();
        }
        return 0;
    }

    inline ProposeReq const& rawProposeCache() { return m_rawProposeCache; }
    inline ProposeReq const& proposeCache() { return m_proposeCache; }
    inline ProposeReq const& committedProposeCache() { return m_committedProposeCache; }
    ProposeReq* mutableCommittedProposeCache() { return &m_committedProposeCache; }
    /// get the future prepare according to specified block hash
    inline std::shared_ptr<ProposeReq> futureProposeCache(uint64_t const& blockNumber)
    {
        auto it = m_futureProposeCache.find(blockNumber);
        if (it != m_futureProposeCache.end())
        {
            return it->second;
        }
        return nullptr;
    }
    /// add specified raw-prepare-request into the raw-prepare-cache
    /// reset the prepare-cache
    inline void addRawPropose(ProposeReq const& req)
    {
        m_rawProposeCache = req;
        TENDERMINTReqCache_LOG(DEBUG) << LOG_DESC("addRawPropose") << LOG_KV("height", req.height)
                                << LOG_KV("reqIdx", req.idx)
                                << LOG_KV("hash", req.block_hash.abridged());
        m_proposeCache = ProposeReq();
    }

    /// add prepare request to prepare-cache
    /// remove cached request with the same block_hash but inconsistent view compaired with the
    /// specified prepare-request from the sign-cache and commit-cache
    inline void addProposeReq(ProposeReq const& req)
    {
        m_proposeCache = req;
        removeInvalidSignCache(req.block_hash, req.round);
        removeInvalidCommitCache(req.block_hash, req.round);
    }
    /// add specified signReq to the sign-cache
    inline void addVoteReq(PreVoteReq const& req)
    {
        m_preVoteCache[req.block_hash][req.sig.hex()] = req;
    }
    /// add specified commit cache to the commit-cache
    inline void addCommitReq(PreCommitReq const& req)
    {
        m_preCommitCache[req.block_hash][req.sig.hex()] = req;
    }
    /// add specified viewchange cache to the viewchange-cache
//    inline void addViewChangeReq(ViewChangeReq const& req)
//    {
//        auto it = m_recvViewChangeReq.find(req.view);
//        if (it != m_recvViewChangeReq.end())
//        {
//            auto itv = it->second.find(req.idx);
//            if (itv != it->second.end())
//            {
//                itv->second = req;
//            }
//            else
//            {
//                it->second.insert(std::make_pair(req.idx, req));
//            }
//        }
//        else
//        {
//            std::unordered_map<IDXTYPE, ViewChangeReq> viewMap;
//            viewMap.insert(std::make_pair(req.idx, req));
//
//            m_recvViewChangeReq.insert(std::make_pair(req.view, viewMap));
//        }
//
//        // m_recvViewChangeReq[req.view][req.idx] = req;
//    }

    template <typename T, typename S>
    inline void addReq(T const& req, S& cache)
    {
        cache[req.block_hash][req.sig.hex()] = req;
    }

    /// add future-prepare cache
    inline void addFutureProposeCache(ProposeReq const& req)
    {
        auto it = m_futureProposeCache.find(req.height);
        if (it == m_futureProposeCache.end())
        {
            TENDERMINTReqCache_LOG(INFO)
                    << LOG_DESC("addFuturePrepareCache") << LOG_KV("height", req.height)
                    << LOG_KV("reqIdx", req.idx) << LOG_KV("hash", req.block_hash.abridged());
            m_futureProposeCache[req.height] = std::make_shared<ProposeReq>(std::move(req));
        }
    }

    /// get the future prepare cache size
    inline size_t futureProposeCacheSize() { return m_futureProposeCache.size(); }

    /// update m_committedPrepareCache to m_rawPrepareCache before broadcast the commit-request
    inline void updateCommittedPropose() { m_committedProposeCache = m_rawProposeCache; }
    /// obtain the sig-list from m_commitCache, and append the sig-list to given block
    bool generateAndSetSigList(dev::eth::Block& block, const IDXTYPE& minSigSize);
    ///  determine can trigger viewchange or not
//    bool canTriggerViewChange(VIEWTYPE& minView, IDXTYPE const& minInvalidNodeNum,
//                              VIEWTYPE const& toView, dev::eth::BlockHeader const& highestBlock,
//                              int64_t const& consensusBlockNumber);

    /// trigger viewchange
//    inline void triggerViewChange(VIEWTYPE const& curView)
//    {
//        m_rawProposeCache.clear();
//        m_proposeCache.clear();
//        m_preVoteCache.clear();
//        m_preCommitCache.clear();
//        m_futureProposeCache.clear();
//        removeInvalidViewChange(curView);
//    }
    /// delete requests cached in m_signCache, m_commitCache and m_prepareCache according to hash
    /// update the sign cache and commit cache immediately
    /// in case of that the commit/sign requests with the same hash are solved in
    /// handleCommitMsg/handleSignMsg again
    void delCache(h256 const& hash);
    inline void collectGarbage(dev::eth::BlockHeader const& highestBlockHeader)
    {
        removeInvalidEntryFromCache(highestBlockHeader, m_preVoteCache);
        removeInvalidEntryFromCache(highestBlockHeader, m_preCommitCache);
    }
    /// remove invalid view-change requests according to view and the current block header
//    void removeInvalidViewChange(VIEWTYPE const& view, dev::eth::BlockHeader const& highestBlock);
//    inline void delInvalidViewChange(dev::eth::BlockHeader const& curHeader)
//    {
//        removeInvalidEntryFromCache(curHeader, m_recvViewChangeReq);
//    }
    inline void clearAllExceptCommitCache()
    {
        m_proposeCache.clear();
        m_preVoteCache.clear();
//        m_recvViewChangeReq.clear();
    }

    inline void clearAll()
    {
        m_rawProposeCache.clear();
        clearAllExceptCommitCache();
        m_preCommitCache.clear();
    }

    /// erase specified future request from the future prepare cache
    void eraseHandledFutureReq(uint64_t const& blockNumber)
    {
        if (m_futureProposeCache.find(blockNumber) != m_futureProposeCache.end())
        {
            m_futureProposeCache.erase(blockNumber);
        }
    }
    /// complemented functions for UTs
    std::unordered_map<h256, std::unordered_map<std::string, PreVoteReq>>& mutableVoteCache()
    {
        return m_preVoteCache;
    }
    std::unordered_map<h256, std::unordered_map<std::string, PreCommitReq>>& mutableCommitCache()
    {
        return m_preCommitCache;
    }
//    std::unordered_map<VIEWTYPE, std::unordered_map<IDXTYPE, ViewChangeReq>>&
//    mutableViewChangeCache()
//    {
//        return m_recvViewChangeReq;
//    }
    void getCacheConsensusStatus(json_spirit::Array& statusArray) const;

private:
    /// remove invalid requests cached in cache according to current block
    template <typename T, typename U, typename S>
    void inline removeInvalidEntryFromCache(dev::eth::BlockHeader const& highestBlockHeader,
                                            std::unordered_map<T, std::unordered_map<U, S>>& cache)
    {
        for (auto it = cache.begin(); it != cache.end();)
        {
            for (auto cache_entry = it->second.begin(); cache_entry != it->second.end();)
            {
                /// delete expired cache
                if (cache_entry->second.height < highestBlockHeader.number())
                    cache_entry = it->second.erase(cache_entry);
                    /// in case of faked block hash
                else if (cache_entry->second.height == highestBlockHeader.number() &&
                         cache_entry->second.block_hash != highestBlockHeader.hash())
                    cache_entry = it->second.erase(cache_entry);
                else
                    cache_entry++;
            }
            if (it->second.size() == 0)
                it = cache.erase(it);
            else
                it++;
        }
    }

//    inline void removeInvalidViewChange(VIEWTYPE const& curView)
//    {
//        for (auto it = m_recvViewChangeReq.begin(); it != m_recvViewChangeReq.end();)
//        {
//            if (it->first <= curView)
//                it = m_recvViewChangeReq.erase(it);
//            else
//                it++;
//        }
//    }
    /// remove sign cache according to block hash and view
    void removeInvalidSignCache(h256 const& blockHash, int64_t const& round);
    /// remove commit cache according to block hash and view
    void removeInvalidCommitCache(h256 const& blockHash, int64_t const& round);

    template <typename T, typename U, typename S>
    inline bool cacheExists(T const& cache, U const& mainKey, S const& key)
    {
        auto it = cache.find(mainKey);
        if (it == cache.end())
            return false;
        return (it->second.find(key)) != (it->second.end());
    }

    /// get the status of specified cache into the json object
    /// (maily for prepareCache, m_committedPrepareCache, m_futurePrepareCache and rawPrepareCache)
    template <typename T>
    void getCacheStatus(json_spirit::Array& jsonArray, std::string const& key, T const& cache) const
    {
        json_spirit::Object cacheStatus;
        cacheStatus.push_back(
                json_spirit::Pair(key + "_blockHash", "0x" + toHex(cache.block_hash)));
        cacheStatus.push_back(json_spirit::Pair(key + "_height", cache.height));
        cacheStatus.push_back(json_spirit::Pair(key + "_idx", toString(cache.idx)));
        cacheStatus.push_back(json_spirit::Pair(key + "_round", toString(cache.round)));
        jsonArray.push_back(cacheStatus);
    }

    template <typename T>
    void getCollectedCacheStatus(
            json_spirit::Array& cacheJsonArray, std::string const& key, T const& cache) const
    {
        json_spirit::Object tmp_obj;
        tmp_obj.push_back(json_spirit::Pair(key + "_cachedSize", toString(cache.size())));
        cacheJsonArray.push_back(tmp_obj);
        for (auto i : cache)
        {
            json_spirit::Object entry;
            entry.push_back(json_spirit::Pair(key + "_key", dev::toJS(i.first)));
            entry.push_back(
                    json_spirit::Pair(key + "_collectedSize", std::to_string(i.second.size())));
            cacheJsonArray.push_back(entry);
        }
    }

private:
    dev::PROTOCOL_ID m_protocolId;
    dev::GROUP_ID m_groupId;
    /// cache for prepare request
    ProposeReq m_proposeCache = ProposeReq();
    /// cache for raw prepare request
    ProposeReq m_rawProposeCache;
    /// cache for signReq(maps between hash and sign requests)
    std::unordered_map<h256, std::unordered_map<std::string, PreVoteReq>> m_preVoteCache;
    /// cache for received-viewChange requests(maps between view and view change requests)
//    std::unordered_map<VIEWTYPE, std::unordered_map<IDXTYPE, ViewChangeReq>> m_recvViewChangeReq;
    /// cache for commited requests(maps between hash and commited requests)
    std::unordered_map<h256, std::unordered_map<std::string, PreCommitReq>> m_preCommitCache;
    /// cache for prepare request need to be backup and saved
    ProposeReq m_committedProposeCache;
    /// cache for the future prepare cache
    /// key: block hash, value: the cached future prepeare
    std::unordered_map<uint64_t, std::shared_ptr<ProposeReq>> m_futureProposeCache;
};
}  // namespace consensus
}  // namespace dev