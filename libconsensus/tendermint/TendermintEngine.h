//
// Created by 赵德宇 on 2019-04-01.
//

#ifndef FISCO_BCOS_TENDERMINTENGINE_H
#define FISCO_BCOS_TENDERMINTENGINE_H

#endif //FISCO_BCOS_TENDERMINTENGINE_H
#pragma once
#include "Common.h"
#include "TendermintMsgCache.h"
#include "TendermintReqCache.h"
#include "TimeManager.h"
#include <libconsensus/ConsensusEngineBase.h>
#include <libdevcore/FileSystem.h>
#include <libdevcore/LevelDB.h>
#include <libdevcore/concurrent_queue.h>
#include <libsync/SyncStatus.h>
#include <sstream>

#include <libp2p/P2PMessage.h>
#include <libp2p/P2PSession.h>
#include <libp2p/Service.h>

namespace dev
{
namespace consensus
{
enum CheckValid
{
    T_VALID = 0,
    T_INVALID = 1,
    T_FUTURE = 2
};
using TendermintMsgQueue = dev::concurrent_queue<TendermintMsgPacket>;

class TendermintEngine : public ConsensusEngineBase
{
public:
    virtual ~TendermintEngine(){
        stop();
    }
    TendermintEngine(std::shared_ptr<dev::p2p::P2PInterface> _service,
        std::shared_ptr<dev::txpool::TxPoolInterface> _txPool,
        std::shared_ptr<dev::blockchain::BlockChainInterface> _blockChain,
        std::shared_ptr<dev::sync::SyncInterface> _blockSync,
        std::shared_ptr<dev::blockverifier::BlockVerifierInterface> _blockVerifier,
        dev::PROTOCOL_ID const& _protocolId, std::string const& _baseDir, KeyPair const& _keyPair,
        h512s const& _sealerList = h512s())
    : ConsensusEngineBase(_service, _txPool, _blockChain, _blockSync, _blockVerifier, _protocolId,
            _keyPair, _sealerList),m_baseDir(_baseDir)
    {
        TENDERMINTENGINE_LOG(INFO) << LOG_DESC("Register handler for TENDERMINTEngine");
        m_service->registerHandlerByProtoclID(
            m_protocolId, boost::bind(&TendermintEngine::onRecvTendermintMessage, this, _1, _2, _3));
        m_broadCastCache = std::make_shared<TendermintBroadcastCache>();
        m_reqCache = std::make_shared<TendermintReqCache>(m_protocolId);

        /// register checkSealerList to blockSync for check SealerList
        m_blockSync->registerConsensusVerifyHandler(boost::bind(&TendermintEngine::checkBlock, this, _1));
    }

    void setBaseDir(std::string const& _path) { m_baseDir = _path; }

    std::string const& getBaseDir() { return m_baseDir; }

    inline void setIntervalBlockTime(unsigned const& _intervalBlockTime)
    {
        m_timeManager.m_intervalBlockTime = _intervalBlockTime;
    }

    inline unsigned const& getIntervalBlockTime() const
    {
        return m_timeManager.m_intervalBlockTime;
    }
    void start() override;

    virtual bool reachBlockIntervalTime()
    {
        if (false == getLeader().first)
        {
            return false;
        }
        /// the block is sealed by the next leader, and can execute after the last block has been
        /// consensused
        if (m_notifyNextLeaderSeal)
        {
            /// represent that the latest block has not been consensused
            if (getNextLeader() == nodeIdx())
            {
                return false;
            }
            return true;
        }
        /// the block is sealed by the current leader
        return (utcTime() - m_timeManager.m_lastConsensusTime) >= m_timeManager.m_intervalBlockTime;
    }
    /// in case of the next leader packeted the number of maxTransNum transactions before the last
    /// block is consensused
    /// when sealing for the next leader,  return true only if the last block has been consensused
    /// even if the maxTransNum condition has been meeted
    bool canHandleBlockForNextLeader()
    {
        /// get leader failed
        if (false == getLeader().first)
        {
            return false;
        }
        /// the case that only a node is both the leader and the next leader
        if (getLeader().second == nodeIdx())
        {
            return true;
        }
        if (m_notifyNextLeaderSeal && getNextLeader() == nodeIdx())
        {
            return false;
        }
        return true;
    }
    void rehandleCommitedProposeCache(ProposeReq const& req);
    bool shouldSeal();
    /// broadcast propose message
    bool generatePropose(dev::eth::Block const& block);
    /// update the context of Tendermint after commit a block into the block-chain
    void reportBlock(dev::eth::Block const& block) override;
//    void onViewChange(std::function<void()> const& _f)
//    {
//        m_onViewChange = _f;
//        m_notifyNextLeaderSeal = false;
//    }
    void onNotifyNextLeaderReset(std::function<void(dev::h256Hash const& filter)> const& _f)
    {
        m_onNotifyNextLeaderReset = _f;
    }

    bool inline shouldReset(dev::eth::Block const& block)
    {
        return block.getTransactionSize() == 0 && m_omitEmptyBlock;
    }
    void setStorage(dev::storage::Storage::Ptr storage) { m_storage = storage; }
    const std::string consensusStatus() override;
    void setOmitEmptyBlock(bool setter) { m_omitEmptyBlock = setter; }

    void setMaxTTL(uint8_t const& ttl) { maxTTL = ttl; }

    inline IDXTYPE getNextLeader() const { return (m_highestBlock.number() + 1) % m_nodeNum; }

    inline std::pair<bool, IDXTYPE> getLeader() const
    {
        if (m_cfgErr || m_leaderFailed || m_highestBlock.sealer() == Invalid256)
        {
            return std::make_pair(false, MAXIDX);
        }
        return std::make_pair(true, (m_round + m_highestBlock.number()) % m_nodeNum);
    }

protected:
    void reportBlockWithoutLock(dev::eth::Block const& block);
    void workLoop() override;
    void handleFutureBlock();
    void collectGarbage();
    void checkTimeout();
    bool getNodeIDByIndex(dev::network::NodeID& nodeId, const IDXTYPE& idx) const;
    inline void checkBlockValid(dev::eth::Block const& block) override
    {
        ConsensusEngineBase::checkBlockValid(block);
        checkSealerList(block);
    }
//    bool needOmit(Sealing const& sealing);

    void getAllNodesViewStatus(json_spirit::Array& status);

    /// broadcast specified message to all-peers with cache-filter and specified filter
    bool broadcastMsg(unsigned const& packetType, std::string const& key, bytesConstRef data,
                      std::unordered_set<dev::network::NodeID> const& filter =
                      std::unordered_set<dev::network::NodeID>(),
                      unsigned const& ttl = 0);

//    void sendViewChangeMsg(dev::network::NodeID const& nodeId);
//    bool sendMsg(dev::network::NodeID const& nodeId, unsigned const& packetType,
//                 std::string const& key, bytesConstRef data, unsigned const& ttl = 1);
    /// 1. generate and broadcast signReq according to given prepareReq
    /// 2. add the generated signReq into the cache
    bool broadcastVoteReq(ProposeReq const& req);

    /// broadcast commit message
    bool broadcastCommitReq(ProposeReq const& req);
    /// broadcast view change message
//    bool shouldBroadcastViewChange();
//    bool broadcastViewChangeReq();
    /// handler called when receiving data from the network
    void onRecvTendermintMessage(dev::p2p::NetworkException exception,
                           std::shared_ptr<dev::p2p::P2PSession> session, dev::p2p::P2PMessage::Ptr message);
    bool handleProposeMsg(ProposeReq const& propose_req, std::string const& endpoint = "self");
    /// handler prepare messages
    bool handleProposeMsg(ProposeReq& proposeReq, TendermintMsgPacket const& tendermintMsg);
    /// 1. decode the network-received PBFTMsgPacket to signReq
    /// 2. check the validation of the signReq
    /// add the signReq to the cache and
    /// heck the size of the collected signReq is over 2/3 or not
    bool handleVoteMsg(PreVoteReq& signReq, TendermintMsgPacket const& tendermintMsg);
    bool handleCommitMsg(PreCommitReq& commitReq, TendermintMsgPacket const& tendermintMsg);
//    bool handleViewChangeMsg(ViewChangeReq& viewChangeReq, PBFTMsgPacket const& pbftMsg);
    void handleMsg(TendermintMsgPacket const& tendermintMsg);
//    void catchupView(ViewChangeReq const& req, std::ostringstream& oss);
    void checkAndCommit();

    /// if collect >= 2/3 SignReq and CommitReq, then callback this function to commit block
    void checkAndSave();
//    void checkAndChangeView();

protected:
    void initTendermintEnv();
    /// recalculate m_nodeNum && m_f && m_cfgErr(must called after setSigList)
    void resetConfig() override;
    virtual void initBackupDB();
    void reloadMsg(std::string const& _key, TendermintMsg* _msg);
    void backupMsg(std::string const& _key, TendermintMsg const& _msg);
    inline std::string getBackupMsgPath() { return m_baseDir + "/" + c_backupMsgDirName; }

    bool checkSign(TendermintMsg const& req) const;
    inline bool broadcastFilter(
            dev::network::NodeID const& nodeId, unsigned const& packetType, std::string const& key)
    {
        return m_broadCastCache->keyExists(nodeId, packetType, key);
    }

    /**
     * @brief: insert specified key into the cache of broadcast
     *         used to filter the broadcasted message(in case of too-many repeated broadcast
     * messages)
     * @param nodeId: the node id of the message broadcasted to
     * @param packetType: the packet type of the broadcast-message
     * @param key: the key of the broadcast-message, is the signature of the broadcast-message in
     * common
     */
    inline void broadcastMark(
            dev::network::NodeID const& nodeId, unsigned const& packetType, std::string const& key)
    {
        /// in case of useless insert
        if (m_broadCastCache->keyExists(nodeId, packetType, key))
            return;
        m_broadCastCache->insertKey(nodeId, packetType, key);
    }
    inline void clearMask() { m_broadCastCache->clearAll(); }
    /// get the index of specified sealer according to its node id
    /// @param nodeId: the node id of the sealer
    /// @return : 1. >0: the index of the sealer
    ///           2. equal to -1: the node is not a sealer(not exists in sealer list)
    inline ssize_t getIndexBySealer(dev::network::NodeID const& nodeId)
    {
        ReadGuard l(m_sealerListMutex);
        ssize_t index = -1;
        for (size_t i = 0; i < m_sealerList.size(); ++i)
        {
            if (m_sealerList[i] == nodeId)
            {
                index = i;
                break;
            }
        }
        return index;
    }
    /// get the node id of specified sealer according to its index
    /// @param index: the index of the node
    /// @return h512(): the node is not in the sealer list
    /// @return node id: the node id of the node
    inline dev::network::NodeID getSealerByIndex(size_t const& index) const
    {
        ReadGuard l(m_sealerListMutex);
        if (index < m_sealerList.size())
            return m_sealerList[index];
        return dev::network::NodeID();
    }

    /// trans data into message
    inline dev::p2p::P2PMessage::Ptr transDataToMessage(bytesConstRef data,
                                                        PACKET_TYPE const& packetType, PROTOCOL_ID const& protocolId, unsigned const& ttl)
    {
        dev::p2p::P2PMessage::Ptr message = std::make_shared<dev::p2p::P2PMessage>();
        // std::shared_ptr<dev::bytes> p_data = std::make_shared<dev::bytes>();
        bytes ret_data;
        TendermintMsgPacket packet;
        packet.data = data.toBytes();
        packet.packet_id = packetType;
        if (ttl == 0)
            packet.ttl = maxTTL;
        else
            packet.ttl = ttl;
        packet.encode(ret_data);
        std::shared_ptr<dev::bytes> p_data = std::make_shared<dev::bytes>(std::move(ret_data));
        message->setBuffer(p_data);
        message->setProtocolID(protocolId);
        return message;
    }

    inline dev::p2p::P2PMessage::Ptr transDataToMessage(
            bytesConstRef data, PACKET_TYPE const& packetType, unsigned const& ttl)
    {
        return transDataToMessage(data, packetType, m_protocolId, ttl);
    }

    /**
     * @brief : the message received from the network is valid or not?
     *      invalid cases: 1. received data is empty
     *                     2. the message is not sended by sealers
     *                     3. the message is not receivied by sealers
     *                     4. the message is sended by the node-self
     * @param message : message constructed from data received from the network
     * @param session : the session related to the network data(can get informations about the
     * sender)
     * @return true : the network-received message is valid
     * @return false: the network-received message is invalid
     */
    bool isValidReq(dev::p2p::P2PMessage::Ptr message,
                    std::shared_ptr<dev::p2p::P2PSession> session, ssize_t& peerIndex) override
    {
        /// check message size
        if (message->buffer()->size() <= 0)
            return false;
        /// check whether in the sealer list
        peerIndex = getIndexBySealer(session->nodeID());
        if (peerIndex < 0)
        {
            TENDERMINTENGINE_LOG(TRACE) << LOG_DESC(
                    "isValidReq: Recv PBFT msg from unkown peer:" + session->nodeID().abridged());
            return false;
        }
        /// check whether this node is in the sealer list
        dev::network::NodeID node_id;
        bool is_sealer = getNodeIDByIndex(node_id, nodeIdx());
        if (!is_sealer || session->nodeID() == node_id)
            return false;
        return true;
    }

    /// check the specified prepareReq is valid or not
    CheckValid isValidPropose(ProposeReq const& req, std::ostringstream& oss) const;

    /**
     * @brief: common check process when handle SignReq and CommitReq
     *         1. the request should be existed in prepare cache,
     *            if the request is the future request, should add it to the propose cache
     *         2. the sealer of the request shouldn't be the node-self
     *         3. the round of the request must be equal to the view of the propose cache
     *         4. the signature of the request must be valid
     * @tparam T: the type of the request
     * @param req: the request should be checked
     * @param oss: information to debug
     * @return CheckResult:
     *  1. CheckResult::FUTURE: the request is the future req;
     *  2. CheckResult::INVALID: the request is invalid
     *  3. CheckResult::VALID: the request is valid
     */
    template <class T>
    inline CheckValid checkReq(T const& req, std::ostringstream& oss) const
    {
        if (m_reqCache->proposeCache().block_hash != req.block_hash)
        {
            TENDERMINTENGINE_LOG(TRACE) << LOG_DESC("checkReq: sign or commit Not exist in prepare cache")
                                  << LOG_KV("prepHash",
                                            m_reqCache->proposeCache().block_hash.abridged())
                                  << LOG_KV("hash", req.block_hash.abridged())
                                  << LOG_KV("INFO", oss.str());
            /// is future ?
            bool is_future = isFutureBlock(req);
            if (is_future && checkSign(req))
            {
                TENDERMINTENGINE_LOG(INFO)
                        << LOG_DESC("checkReq: Recv future request")
                        << LOG_KV("prepHash", m_reqCache->proposeCache().block_hash.abridged())
                        << LOG_KV("INFO", oss.str());
                return CheckValid::T_FUTURE;
            }
            return CheckValid::T_INVALID;
        }
        /// check the sealer of this request
        if (req.idx == nodeIdx())
        {
            TENDERMINTENGINE_LOG(TRACE) << LOG_DESC("checkReq: Recv own req")
                                  << LOG_KV("INFO", oss.str());
            return CheckValid::T_INVALID;
        }
        /// check view
//        if (m_reqCache->proposeCache().view != req.view)
//        {
//            TENDERMINTENGINE_LOG(TRACE) << LOG_DESC("checkReq: Recv req with unconsistent view")
//                                  << LOG_KV("prepView", m_reqCache->proposeCache().view)
//                                  << LOG_KV("view", req.view) << LOG_KV("INFO", oss.str());
//            return CheckResult::INVALID;
//        }
        /// check round
        if (m_reqCache->proposeCache().round != req.round)
        {
            TENDERMINTENGINE_LOG(TRACE) << LOG_DESC("checkReq: Recv req with unconsistent round")
                                        << LOG_KV("prepRound", m_reqCache->proposeCache().round)
                                        << LOG_KV("round", req.round) << LOG_KV("INFO", oss.str());
            return CheckValid::T_INVALID;
        }
        if (!checkSign(req))
        {
            TENDERMINTENGINE_LOG(TRACE) << LOG_DESC("checkReq:  invalid sign")
                                  << LOG_KV("INFO", oss.str());
            return CheckValid::T_INVALID;
        }
        return CheckValid::T_VALID;
    }

    CheckValid isValidVoteReq(PreVoteReq const& req, std::ostringstream& oss) const;
    CheckValid isValidCommitReq(PreCommitReq const& req, std::ostringstream& oss) const;
//    bool isValidViewChangeReq(
//            ViewChangeReq const& req, IDXTYPE const& source, std::ostringstream& oss);

    template <class T>
    inline bool hasConsensused(T const& req) const
    {
        if (req.height < m_consensusBlockNumber ||
            (req.height == m_consensusBlockNumber && req.round < m_round))
        {
            return true;
        }
        return false;
    }

    /**
     * @brief : decide the sign or commit request is the future request or not
     *          1. the block number is no smalller than the current consensused block number
     *          2. or the view is no smaller than the current consensused block number
     */
    template <typename T>
    inline bool isFutureBlock(T const& req) const
    {
        if (req.height >= m_consensusBlockNumber || req.round > m_round)
        {
            return true;
        }
        return false;
    }

    template <typename T>
    inline bool isFuturePropose(T const& req) const
    {
        if (req.height > m_consensusBlockNumber ||
            (req.height == m_consensusBlockNumber && req.round > m_round))
        {
            return true;
        }
        return false;
    }

    inline bool isHashSavedAfterCommit(ProposeReq const& req) const
    {
        if (req.height == m_reqCache->committedProposeCache().height &&
            req.block_hash != m_reqCache->committedProposeCache().block_hash)
        {
            /// TODO: remove these logs in the atomic functions
            TENDERMINTENGINE_LOG(DEBUG)
                    << LOG_DESC("isHashSavedAfterCommit: hasn't been cached after commit")
                    << LOG_KV("height", req.height)
                    << LOG_KV("cacheHeight", m_reqCache->committedProposeCache().height)
                    << LOG_KV("hash", req.block_hash.abridged())
                    << LOG_KV("cacheHash", m_reqCache->committedProposeCache().block_hash.abridged());
            return false;
        }
        return true;
    }

    inline bool isValidLeader(ProposeReq const& req) const
    {
        auto leader = getLeader();
        /// get leader failed or this prepareReq is not broadcasted from leader
        if (!leader.first || req.idx != leader.second)
        {
            return false;
        }

        return true;
    }

    void checkSealerList(dev::eth::Block const& block);
    /// check block
    bool checkBlock(dev::eth::Block const& block);
    void execBlock(Sealing& sealing, ProposeReq const& req, std::ostringstream& oss);
//    void changeViewForEmptyBlock()
//    {
//        m_timeManager.changeView();
//        m_timeManager.m_changeCycle = 0;
//        m_fastViewChange = true;
//        m_signalled.notify_all();
//    }

    void changeRoundForEmptyBlock()
    {
        m_timeManager.changeRound();
        m_timeManager.m_changeCycle = 0;
        m_fastViewChange = true;
        m_signalled.notify_all();
    }

    void notifySealing(dev::eth::Block const& block);
    virtual bool isDiskSpaceEnough(std::string const& path)
    {
        return boost::filesystem::space(path).available > 1024;
    }

//    void updateViewMap(IDXTYPE const& idx, VIEWTYPE const& view)
//    {
//        WriteGuard l(x_viewMap);
//        m_viewMap[idx] = view;
//    }

    void updateRoundMap(IDXTYPE const& idx, int64_t const& round)
    {
        WriteGuard l(x_roundMap);
        m_roundMap[idx] = round;
    }

protected:
//    VIEWTYPE m_view = 0;
//    VIEWTYPE m_toView = 0;
    int64_t m_round = 0;
    std::string m_baseDir;
    bool m_leaderFailed = false;
    bool m_notifyNextLeaderSeal = false;

    dev::storage::Storage::Ptr m_storage;

    // backup msg
    std::shared_ptr<dev::db::LevelDB> m_backupDB = nullptr;

    /// static vars
    static const std::string c_backupKeyCommitted;
    static const std::string c_backupMsgDirName;
    static const unsigned c_PopWaitSeconds = 5;

    std::shared_ptr<TendermintBroadcastCache> m_broadCastCache;
    std::shared_ptr<TendermintReqCache> m_reqCache;
    TimeManage m_timeManager;
    TendermintMsgQueue m_msgQueue;
    mutable Mutex m_mutex;

    std::condition_variable m_signalled;
    Mutex x_signalled;

//    std::function<void()> m_onViewChange;
    std::function<void(dev::h256Hash const& filter)> m_onNotifyNextLeaderReset;

    /// for output time-out caused viewchange
    /// m_fastViewChange is false: output viewchangeWarning to indicate PBFT consensus timeout
    bool m_fastViewChange = false;

    uint8_t maxTTL = MAXTTL;

    /// map between nodeIdx to view
//    mutable SharedMutex x_viewMap;
//    std::map<IDXTYPE, VIEWTYPE> m_viewMap;

    /// map between nodeIdx to round
    mutable SharedMutex x_roundMap;
    std::map<IDXTYPE, VIEWTYPE> m_roundMap;

    /// Locked Block
    bool m_lockedBlock = false;

    mutable SharedMutex x_roundNodeNum;
    IDXTYPE m_roundNodeNum = 0;
};
}
}