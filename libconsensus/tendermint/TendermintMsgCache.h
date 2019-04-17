//
// Created by 赵德宇 on 2019-04-01.
//

#ifndef FISCO_BCOS_TENDERMINTMSGCACHE_H
#define FISCO_BCOS_TENDERMINTMSGCACHE_H

#endif //FISCO_BCOS_TENDERMINTMSGCACHE_H
#pragma once
#include <libconsensus/tendermint/Common.h>
#include <libdevcore/Common.h>
#include <libdevcore/FixedHash.h>
#include <libdevcore/Guards.h>
#include <libdevcore/easylog.h>
#include <unordered_map>
namespace dev
{
namespace consensus
{
/// cache object of given ndoe
struct TendermintMsgCache
{
public:
    /**
     * @brief: insert given key into the given-type-cache of the given node id
     *
     * @param type : packet type
     * @param key: mainly the signature of specified broadcast packet
     * @return true : insert succeed
     * @return false : insert failed
     */
    inline bool insertByPacketType(unsigned const& type, std::string const& key)
    {
        switch (type)
        {
            case ProposeReqPacket:
                insertMessage(x_knownPropose, m_knownPropose, c_knownPropose, key);
                return true;
            case PreVoteReqPacket:
                insertMessage(x_knownVote, m_knownVote, c_knownVote, key);
                return true;
            case PreCommitReqPacket:
                insertMessage(x_knownCommit, m_knownCommit, c_knownCommit, key);
                return true;
//            case ViewChangeReqPacket:
//                insertMessage(x_knownViewChange, m_knownViewChange, c_knownViewChange, key);
//                return true;
            default:
                LOG(DEBUG) << "Invalid packet type:" << type;
                return false;
        }
    }

    /**
     * @brief : given key exists in the given-type-cache of the given node id or not
     *
     * @param type: packet type
     * @param key: mainly the signature of specified broadcast packet
     * @return true: the given key exists
     * @return false: the given key doesn't exist
     */
    inline bool exists(unsigned const& type, std::string const& key)
    {
        switch (type)
        {
            case ProposeReqPacket:
                return exists(x_knownPropose, m_knownPropose, key);
            case PreVoteReqPacket:
                return exists(x_knownVote, m_knownVote, key);
            case PreCommitReqPacket:
                return exists(x_knownCommit, m_knownCommit, key);
//            case ViewChangeReqPacket:
//                return exists(x_knownViewChange, m_knownViewChange, key);
            default:
                LOG(DEBUG) << "Invalid packet type:" << type;
                return false;
        }
    }

    inline bool exists(Mutex& lock, QueueSet<std::string>& queue, std::string const& key)
    {
        /// lock succ
        DEV_GUARDED(lock)
            return queue.exist(key);
        /// lock failed
        return false;
    }

    inline void insertMessage(Mutex& lock, QueueSet<std::string>& queue, size_t const& maxCacheSize,
                              std::string const& key)
    {
        DEV_GUARDED(lock)
        {
            if (queue.size() > maxCacheSize)
                queue.pop();
            queue.push(key);
        }
    }
    /// clear all the cache
    inline void clearAll()
    {
        DEV_GUARDED(x_knownPropose)
            m_knownPropose.clear();
        DEV_GUARDED(x_knownVote)
            m_knownVote.clear();
        DEV_GUARDED(x_knownCommit)
            m_knownCommit.clear();
//        DEV_GUARDED(x_knownViewChange)
//            m_knownViewChange.clear();
    }

private:
    /// mutex for m_knownPropose
    Mutex x_knownPropose;
    /// cache for the propose packet
    QueueSet<std::string> m_knownPropose;
    /// mutex for m_knownVote
    Mutex x_knownVote;
    /// cache for the vote packet
    QueueSet<std::string> m_knownVote;
    /// mutex for m_knownCommit
    Mutex x_knownCommit;
    /// cache for the commit packet
    QueueSet<std::string> m_knownCommit;
    /// mutex for m_knownViewChange
//    Mutex x_knownViewChange;
    /// cache for the viewchange packet
//    QueueSet<std::string> m_knownViewChange;

    /// the limit size for propose packet cache
    static const unsigned c_knownPropose = 1024;
    /// the limit size for vote packet cache
    static const unsigned c_knownVote = 1024;
    /// the limit size for commit packet cache
    static const unsigned c_knownCommit = 1024;
    /// the limit size for viewchange packet cache
//    static const unsigned c_knownViewChange = 1024;
};

class TendermintBroadcastCache
{
public:
    /**
     * @brief : insert key into the queue according to node id and packet type
     *
     * @param nodeId : node id
     * @param type: packet type
     * @param key: key (mainly the signature of specified broadcast packet)
     * @return true: insert success
     * @return false: insert failed
     */
    inline bool insertKey(h512 const& nodeId, unsigned const& type, std::string const& key)
    {
        if (!m_broadCastKeyCache.count(nodeId))
            m_broadCastKeyCache[nodeId] = std::make_shared<TendermintMsgCache>();
        return m_broadCastKeyCache[nodeId]->insertByPacketType(type, key);
    }

    /**
     * @brief: determine whether the key of given packet type existed in the cache of given node id
     *
     * @param nodeId : node id
     * @param type: packet type
     * @param key: mainly the signature of specified broadcast packe
     * @return true : the key exists in the cache
     * @return false: the key doesn't exist in the cache
     */
    inline bool keyExists(h512 const& nodeId, unsigned const& type, std::string const& key)
    {
        if (!m_broadCastKeyCache.count(nodeId))
            return false;
        return m_broadCastKeyCache[nodeId]->exists(type, key);
    }

    /// clear all caches
    inline void clearAll()
    {
        for (auto& item : m_broadCastKeyCache)
            item.second->clearAll();
    }

private:
    /// maps between node id and its broadcast cache
    std::unordered_map<h512, std::shared_ptr<TendermintMsgCache>> m_broadCastKeyCache;
};
}  // namespace consensus
}  // namespace dev