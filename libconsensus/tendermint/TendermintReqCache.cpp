//
// Created by 赵德宇 on 2019-04-01.
//
#include "TendermintReqCache.h"
using namespace dev::eth;
namespace dev
{
namespace consensus
{
/**
 * @brief: delete requests cached in m_preVoteCache, m_preCommitCache and m_proposeCache according to hash
 * @param hash
 */
void TendermintReqCache::delCache(h256 const& hash)
{
    TENDERMINTReqCache_LOG(DEBUG) << LOG_DESC("delCache") << LOG_KV("hash", hash.abridged());
    /// delete from sign cache
    auto psign = m_preVoteCache.find(hash);
    if (psign != m_preVoteCache.end())
        m_preVoteCache.erase(psign);
    /// delete from commit cache
    auto pcommit = m_preCommitCache.find(hash);
    if (pcommit != m_preCommitCache.end())
        m_preCommitCache.erase(pcommit);
    /// delete from prepare cache
    if (hash == m_proposeCache.block_hash)
    {
        m_proposeCache.clear();
    }
}

/**
 * @brief: obtain the sig-list from m_commitCache
 *         and append the sig-list to given block
 * @param block: block need to append sig-list
 * @param minSigSize: minimum size of the sig list
 */
bool TendermintReqCache::generateAndSetSigList(dev::eth::Block& block, IDXTYPE const& minSigSize)
{
    std::vector<std::pair<u256, Signature>> sig_list;
    if (m_preCommitCache.count(m_proposeCache.block_hash) > 0)
    {
        for (auto const& item : m_preCommitCache[m_proposeCache.block_hash])
        {
            sig_list.push_back(
                    std::make_pair(u256(item.second.idx), Signature(item.first.c_str())));
        }
        if (sig_list.size() < minSigSize)
        {
            return false;
        }
        /// set siglist for prepare cache
        block.setSigList(sig_list);
        return true;
    }
    return false;
}

/**
 * @brief: determine can trigger viewchange or not
 * @param minView: return value, the min view of the received-viewchange requests
 * @param minInvalidNodeNum: the min-valid num of received-viewchange-request required by trigger
 * viewchange
 * @param toView: next view, used to filter the received-viewchange-request
 * @param highestBlock: current block-header, used to filter the received-viewchange-request
 * @param consensusBlockNumber: number of the consensused block number
 * @return true: should trigger viewchange
 * @return false: can't trigger viewchange
 */
//bool TendermintReqCache::canTriggerViewChange(VIEWTYPE& minView, IDXTYPE const& maxInvalidNodeNum,
//                                        VIEWTYPE const& toView, dev::eth::BlockHeader const& highestBlock,
//                                        int64_t const& consensusBlockNumber)
//{
//    std::map<IDXTYPE, VIEWTYPE> idx_view_map;
//    minView = MAXVIEW;
//    int64_t min_height = INT64_MAX;
//    for (auto const& viewChangeItem : m_recvViewChangeReq)
//    {
//        if (viewChangeItem.first > toView)
//        {
//            for (auto const& viewChangeEntry : viewChangeItem.second)
//            {
//                auto it = idx_view_map.find(viewChangeEntry.first);
//                if ((it == idx_view_map.end() || viewChangeItem.first > it->second) &&
//                    viewChangeEntry.second.height >= highestBlock.number())
//                {
//                    /// update to lower view
//                    if (it != idx_view_map.end())
//                    {
//                        it->second = viewChangeItem.first;
//                    }
//                    else
//                    {
//                        idx_view_map.insert(
//                                std::make_pair(viewChangeEntry.first, viewChangeItem.first));
//                    }
//
//                    // idx_view_map[viewChangeEntry.first] = viewChangeItem.first;
//
//                    if (minView > viewChangeItem.first)
//                        minView = viewChangeItem.first;
//                    /// update to lower height
//                    if (min_height > viewChangeEntry.second.height)
//                        min_height = viewChangeEntry.second.height;
//                }
//            }
//        }
//    }
//    IDXTYPE count = idx_view_map.size();
//    bool flag =
//            (min_height == consensusBlockNumber) && (min_height == m_committedPrepareCache.height);
//    return (count > maxInvalidNodeNum) && !flag;
//}
/**
 * @brief: remove invalid view-change requests according to view and the current block header
 * @param view
 * @param highestBlock: the current block header
 */
//void TendermintReqCache::removeInvalidViewChange(
//        VIEWTYPE const& view, dev::eth::BlockHeader const& highestBlock)
//{
//    auto it = m_recvViewChangeReq.find(view);
//    if (it == m_recvViewChangeReq.end())
//    {
//        return;
//    }
//
//    for (auto pview = it->second.begin(); pview != it->second.end();)
//    {
//        /// remove old received view-change
//        if (pview->second.height < highestBlock.number())
//            pview = it->second.erase(pview);
//            /// remove invalid view-change request with invalid hash
//        else if (pview->second.height == highestBlock.number() &&
//                 pview->second.block_hash != highestBlock.hash())
//            pview = it->second.erase(pview);
//        else
//            pview++;
//    }
//}
/// remove sign cache according to block hash and round
void TendermintReqCache::removeInvalidSignCache(h256 const& blockHash, int64_t const& round)
{
    auto it = m_preVoteCache.find(blockHash);
    if (it == m_preVoteCache.end())
        return;
    for (auto pcache = it->second.begin(); pcache != it->second.end();)
    {
        /// erase invalid round
        if (pcache->second.round != round)
            pcache = it->second.erase(pcache);
        else
            pcache++;
    }
}
/// remove commit cache according to block hash and round
void TendermintReqCache::removeInvalidCommitCache(h256 const& blockHash, int64_t const& round)
{
    auto it = m_preCommitCache.find(blockHash);
    if (it == m_preCommitCache.end())
        return;
    for (auto pcache = it->second.begin(); pcache != it->second.end();)
    {
        if (pcache->second.round != round)
            pcache = it->second.erase(pcache);
        else
            pcache++;
    }
}

/// get the consensus status
void TendermintReqCache::getCacheConsensusStatus(json_spirit::Array& status_array) const
{
    /// prepare cache
    getCacheStatus(status_array, "proposeCache", m_proposeCache);
    /// raw prepare cache
    getCacheStatus(status_array, "rawProposeCache", m_rawProposeCache);
    /// commited prepare cache
    getCacheStatus(status_array, "committedProposeCache", m_committedProposeCache);
    /// future prepare cache
    /// signCache
    getCollectedCacheStatus(status_array, "preVoteCache", m_preVoteCache);
    getCollectedCacheStatus(status_array, "preCommitCache", m_preCommitCache);
//    getCollectedCacheStatus(status_array, "viewChangeCache", m_recvViewChangeReq);
}

}
}