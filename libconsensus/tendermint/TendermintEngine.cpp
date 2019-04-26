//
// Created by 赵德宇 on 2019-04-03.
//
#include "TendermintEngine.h"
#include <libconsensus/Sealer.h>
#include <json_spirit/JsonSpiritHeaders.h>
#include <libconfig/GlobalConfigure.h>
#include <libdevcore/CommonJS.h>
#include <libdevcore/Worker.h>
#include <libethcore/CommonJS.h>
#include <libsecurity/EncryptedLevelDB.h>
#include <libstorage/Storage.h>
#include <libtxpool/TxPool.h>
using namespace dev::eth;
using namespace dev::db;
using namespace dev::blockverifier;
using namespace dev::blockchain;
using namespace dev::p2p;
using namespace dev::storage;
namespace dev
{
namespace consensus
{
    const std::string TendermintEngine::c_backupKeyCommitted = "committed";
    const std::string TendermintEngine::c_backupMsgDirName = "tendermintMsgBackup";

    void TendermintEngine::start()
    {
        initPBFTEnv(3 * getIntervalBlockTime());
        ConsensusEngineBase::start();
        TENDERMINTENGINE_LOG(INFO) << "[#Start TendermintEngine...]";
    }

    void TendermintEngine::initPBFTEnv(unsigned view_timeout)
    {
        Guard l(m_mutex);
        resetConfig();
        m_consensusBlockNumber = 0;
        m_view = m_toView = 0;
        m_leaderFailed = false;
        initBackupDB();
        m_timeManager.initTimerManager(view_timeout);
        m_connectedNode = m_nodeNum;
        TENDERMINTENGINE_LOG(INFO) << "[#Tendermint init env successfully]";
    }

    bool TendermintEngine::shouldSeal()
    {
        if (m_cfgErr || m_accountType != NodeAccountType::SealerAccount)
        {
            return false;
        }
        /// check leader
        std::pair<bool, IDXTYPE> ret = getLeader();
        if (!ret.first)
        {
            return false;
        }
        if (ret.second != nodeIdx())
        {
            /// if current node is the next leader
            /// and it has been notified to seal new block, return true
            if (m_notifyNextLeaderSeal && getNextLeader() == nodeIdx())
            {
                return true;
            }
            return false;
        }
        if (m_reqCache->committedPrepareCache().height == m_consensusBlockNumber)
        {
            if (m_reqCache->rawPrepareCache().height != m_consensusBlockNumber)
            {
                rehandleCommitedPrepareCache(m_reqCache->committedPrepareCache());
            }
            return false;
        }
        return true;
    }

/**
 * @brief: rehandle the unsubmitted committedPrepare
 * @param req: the unsubmitted committed prepareReq
 */
    void TendermintEngine::rehandleCommitedPrepareCache(ProposeReq const& req)
    {
        Guard l(m_mutex);
        TENDERMINTENGINE_LOG(INFO) << LOG_DESC("rehandleCommittedPrepare") << LOG_KV("nodeIdx", nodeIdx())
                             << LOG_KV("nodeId", m_keyPair.pub().abridged())
                             << LOG_KV("hash", req.block_hash.abridged()) << LOG_KV("H", req.height);
        m_broadCastCache->clearAll();
        ProposeReq prepare_req(req, m_keyPair, m_view, nodeIdx());
        bytes prepare_data;
        prepare_req.encode(prepare_data);
        /// broadcast prepare message
        broadcastMsg(ProposeReqPacket, prepare_req.uniqueKey(), ref(prepare_data));
        handlePrepareMsg(prepare_req);
        /// note blockSync to the latest number, in case of the block number of other nodes is larger
        /// than this node
        m_blockSync->noteSealingBlockNumber(m_blockChain->number());
    }

/// recalculate m_nodeNum && m_f && m_cfgErr(must called after setSigList)
    void TendermintEngine::resetConfig()
    {
        updateMaxBlockTransactions();
        auto node_idx = MAXIDX;
        updateConsensusNodeList();
        {
            ReadGuard l(m_sealerListMutex);
            for (size_t i = 0; i < m_sealerList.size(); i++)
            {
                if (m_sealerList[i] == m_keyPair.pub())
                {
                    m_accountType = NodeAccountType::SealerAccount;
                    node_idx = i;
                    break;
                }
            }
            m_nodeNum = m_sealerList.size();
        }
        m_f = (m_nodeNum - 1) / 3;
        m_cfgErr = (node_idx == MAXIDX);
        {
            WriteGuard l(m_idxMutex);
            m_idx = node_idx;
        }
    }

/// init pbftMsgBackup
    void TendermintEngine::initBackupDB()
    {
        /// try-catch has already been considered by libdevcore/LevelDB.*
        std::string path = getBackupMsgPath();
        boost::filesystem::path path_handler = boost::filesystem::path(path);
        if (!boost::filesystem::exists(path_handler))
        {
            boost::filesystem::create_directories(path_handler);
        }

        db::BasicLevelDB* basicDB = NULL;
        leveldb::Status status;

        if (g_BCOSConfig.diskEncryption.enable)
            status = EncryptedLevelDB::Open(LevelDB::defaultDBOptions(), path_handler.string(),
                                            &basicDB, g_BCOSConfig.diskEncryption.cipherDataKey);
        else
            status = BasicLevelDB::Open(LevelDB::defaultDBOptions(), path_handler.string(), &basicDB);

        LevelDB::checkStatus(status, path_handler);

        m_backupDB = std::make_shared<LevelDB>(basicDB);

        if (!isDiskSpaceEnough(path))
        {
            TENDERMINTENGINE_LOG(ERROR) << LOG_DESC(
                    "initBackupDB: Disk space is insufficient. Release disk space and try again");
            BOOST_THROW_EXCEPTION(NotEnoughAvailableSpace());
        }
        // reload msg from db to commited-prepare-cache
        reloadMsg(c_backupKeyCommitted, m_reqCache->mutableCommittedPrepareCache());
    }

/**
 * @brief: reload PBFTMsg from DB to msg according to specified key
 * @param key: key used to index the PBFTMsg
 * @param msg: save the PBFTMsg readed from the DB
 */
    void TendermintEngine::reloadMsg(std::string const& key, TendermintMsg* msg)
    {
        if (!m_backupDB || !msg)
        {
            return;
        }
        try
        {
            bytes data = fromHex(m_backupDB->lookup(key));
            if (data.empty())
            {
                TENDERMINTENGINE_LOG(DEBUG) << LOG_DESC("reloadMsg: Empty message stored")
                                      << LOG_KV("nodeIdx", nodeIdx())
                                      << LOG_KV("nodeId", m_keyPair.pub().abridged());
                return;
            }
            msg->decode(ref(data), 0);
            TENDERMINTENGINE_LOG(DEBUG) << LOG_DESC("reloadMsg") << LOG_KV("fromIdx", msg->idx)
                                  << LOG_KV("nodeId", m_keyPair.pub().abridged())
                                  << LOG_KV("H", msg->height)
                                  << LOG_KV("hash", msg->block_hash.abridged())
                                  << LOG_KV("nodeIdx", nodeIdx())
                                  << LOG_KV("myNode", m_keyPair.pub().abridged());
        }
        catch (std::exception& e)
        {
            TENDERMINTENGINE_LOG(WARNING) << LOG_DESC("reloadMsg from db failed")
                                    << LOG_KV("EINFO", boost::diagnostic_information(e));
            return;
        }
    }

/**
 * @brief: backup specified PBFTMsg with specified key into the DB
 * @param _key: key of the PBFTMsg
 * @param _msg : data to backup in the DB
 */
    void TendermintEngine::backupMsg(std::string const& _key, TendermintMsg const& _msg)
    {
        if (!m_backupDB)
        {
            return;
        }
        bytes message_data;
        _msg.encode(message_data);
        try
        {
            m_backupDB->insert(_key, toHex(message_data));
        }
        catch (std::exception& e)
        {
            TENDERMINTENGINE_LOG(WARNING) << LOG_DESC("backupMsg failed")
                                    << LOG_KV("EINFO", boost::diagnostic_information(e));
        }
    }

/// sealing the generated block into prepareReq and push its to msgQueue
    bool TendermintEngine::generatePrepare(Block const& block)
    {
        TENDERMINTENGINE_LOG(DEBUG) << LOG_DESC("Funcation: generatePrepare");
        Guard l(m_mutex);
        m_notifyNextLeaderSeal = false;
        ProposeReq prepare_req(block, m_keyPair, m_view, nodeIdx());
        bytes prepare_data;
        prepare_req.encode(prepare_data);

        /// broadcast the generated preparePacket
        bool succ = broadcastMsg(ProposeReqPacket, prepare_req.uniqueKey(), ref(prepare_data));
        if (succ)
        {
            if (prepare_req.pBlock->getTransactionSize() == 0 && m_omitEmptyBlock)
            {
                m_leaderFailed = true;
                changeViewForEmptyBlock();
                return true;
            }
            handlePrepareMsg(prepare_req);
        }
        /// reset the block according to broadcast result
        TENDERMINTENGINE_LOG(DEBUG) << LOG_DESC("generateLocalPrepare")
                              << LOG_KV("hash", prepare_req.block_hash.abridged())
                              << LOG_KV("H", prepare_req.height) << LOG_KV("nodeIdx", nodeIdx())
                              << LOG_KV("myNode", m_keyPair.pub().abridged());
        m_signalled.notify_all();
        return succ;
    }

/**
 * @brief : 1. generate and broadcast signReq according to given prepareReq,
 *          2. add the generated signReq into the cache
 * @param req: specified PrepareReq used to generate signReq
 */
    bool TendermintEngine::broadcastSignReq(ProposeReq const& req)
    {
        PreVoteReq sign_req(req, m_keyPair, nodeIdx());
        bytes sign_req_data;
        sign_req.encode(sign_req_data);
        bool succ = broadcastMsg(PreVoteReqPacket, sign_req.uniqueKey(), ref(sign_req_data));
        m_reqCache->addSignReq(sign_req);
        return succ;
    }

    bool TendermintEngine::getNodeIDByIndex(h512& nodeID, const IDXTYPE& idx) const
    {
        nodeID = getSealerByIndex(idx);
        if (nodeID == h512())
        {
            TENDERMINTENGINE_LOG(ERROR) << LOG_DESC("getNodeIDByIndex: not sealer") << LOG_KV("Idx", idx)
                                  << LOG_KV("myNode", m_keyPair.pub().abridged());
            return false;
        }
        return true;
    }

    bool TendermintEngine::checkSign(TendermintMsg const& req) const
    {
        h512 node_id;
        if (getNodeIDByIndex(node_id, req.idx))
        {
            Public pub_id = jsToPublic(toJS(node_id.hex()));
            return dev::verify(pub_id, req.sig, req.block_hash) &&
                   dev::verify(pub_id, req.sig2, req.fieldsWithoutBlock());
        }
        return false;
    }

/**
 * @brief: 1. generate commitReq according to prepare req
 *         2. broadcast the commitReq
 * @param req: the prepareReq that used to generate commitReq
 */
    bool TendermintEngine::broadcastCommitReq(ProposeReq const& req)
    {
        PreCommitReq commit_req(req, m_keyPair, nodeIdx());
        bytes commit_req_data;
        commit_req.encode(commit_req_data);
        bool succ = broadcastMsg(PreCommitReqPacket, commit_req.uniqueKey(), ref(commit_req_data));
        if (succ)
            m_reqCache->addCommitReq(commit_req);
        return succ;
    }


/// send view change message to the given node
    void TendermintEngine::sendViewChangeMsg(dev::network::NodeID const& nodeId)
    {
        RoundChangeReq req(
                m_keyPair, m_highestBlock.number(), m_toView, nodeIdx(), m_highestBlock.hash());
        TENDERMINTENGINE_LOG(DEBUG) << LOG_DESC("sendViewChangeMsg: send viewchange to started node")
                              << LOG_KV("v", m_view) << LOG_KV("toV", m_toView)
                              << LOG_KV("highNum", m_highestBlock.number())
                              << LOG_KV("peerNode", nodeId.abridged())
                              << LOG_KV("hash", req.block_hash.abridged())
                              << LOG_KV("nodeIdx", nodeIdx())
                              << LOG_KV("myNode", m_keyPair.pub().abridged());

        bytes view_change_data;
        req.encode(view_change_data);
        sendMsg(nodeId, RoundChangeReqPacket, req.uniqueKey(), ref(view_change_data));
    }

    bool TendermintEngine::broadcastViewChangeReq()
    {
        RoundChangeReq req(
                m_keyPair, m_highestBlock.number(), m_toView, nodeIdx(), m_highestBlock.hash());
        TENDERMINTENGINE_LOG(DEBUG) << LOG_DESC("broadcastViewChangeReq ") << LOG_KV("v", m_view)
                              << LOG_KV("toV", m_toView) << LOG_KV("highNum", m_highestBlock.number())
                              << LOG_KV("hash", req.block_hash.abridged())
                              << LOG_KV("nodeIdx", nodeIdx())
                              << LOG_KV("myNode", m_keyPair.pub().abridged());
        /// view change not caused by fast view change
        if (!m_fastViewChange)
        {
            TENDERMINTENGINE_LOG(WARNING) << LOG_DESC("ViewChangeWarning: not caused by omit empty block ")
                                    << LOG_KV("v", m_view) << LOG_KV("toV", m_toView)
                                    << LOG_KV("highNum", m_highestBlock.number())
                                    << LOG_KV("hash", req.block_hash.abridged())
                                    << LOG_KV("nodeIdx", nodeIdx())
                                    << LOG_KV("myNode", m_keyPair.pub().abridged());
        }

        bytes view_change_data;
        req.encode(view_change_data);
        return broadcastMsg(RoundChangeReqPacket, req.uniqueKey(), ref(view_change_data));
    }

/// set default ttl to 1 to in case of forward-broadcast
    bool TendermintEngine::sendMsg(dev::network::NodeID const& nodeId, unsigned const& packetType,
                             std::string const& key, bytesConstRef data, unsigned const& ttl)
    {
        /// is sealer?
        if (getIndexBySealer(nodeId) < 0)
        {
            return true;
        }
        /// packet has been broadcasted?
        if (broadcastFilter(nodeId, packetType, key))
        {
            return true;
        }
        auto sessions = m_service->sessionInfosByProtocolID(m_protocolId);
        if (sessions.size() == 0)
        {
            return false;
        }
        for (auto session : sessions)
        {
            if (session.nodeID == nodeId)
            {
                m_service->asyncSendMessageByNodeID(
                        session.nodeID, transDataToMessage(data, packetType, ttl), nullptr);
                TENDERMINTENGINE_LOG(DEBUG) << LOG_DESC("sendMsg") << LOG_KV("packetType", packetType)
                                      << LOG_KV("dstNodeId", nodeId.abridged())
                                      << LOG_KV("remote_endpoint", session.nodeIPEndpoint.name())
                                      << LOG_KV("nodeIdx", nodeIdx())
                                      << LOG_KV("myNode", m_keyPair.pub().abridged());
                broadcastMark(session.nodeID, packetType, key);
                return true;
            }
        }
        return false;
    }

/**
 * @brief: broadcast specified message to all-peers with cache-filter and specified filter
 *         broadcast solutions:
 *         1. peer is not the sealer: stop broadcasting
 *         2. peer is in the filter list: mark the message as broadcasted, and stop broadcasting
 *         3. the packet has been broadcasted: stop broadcast
 * @param packetType: the packet type of the broadcast-message
 * @param key: the key of the broadcast-message(is the signature of the message in common)
 * @param data: the encoded data of to be broadcasted(RLP encoder now)
 * @param filter: the list that shouldn't be broadcasted to
 */
    bool TendermintEngine::broadcastMsg(unsigned const& packetType, std::string const& key,
                                  bytesConstRef data, std::unordered_set<h512> const& filter, unsigned const& ttl)
    {
        TENDERMINTENGINE_LOG(INFO) << LOG_DESC("Function:  broadcastMsg")
                                   << LOG_KV("packetType", packetType);
        auto sessions = m_service->sessionInfosByProtocolID(m_protocolId);
        m_connectedNode = sessions.size();
        for (auto session : sessions)
        {
            /// get node index of the sealer from m_sealerList failed ?
            if (getIndexBySealer(session.nodeID) < 0)
                continue;
            /// peer is in the _filter list ?
            if (filter.count(session.nodeID))
            {
                broadcastMark(session.nodeID, packetType, key);
                continue;
            }
            /// packet has been broadcasted?
            if (broadcastFilter(session.nodeID, packetType, key))
                continue;
            TENDERMINTENGINE_LOG(TRACE) << LOG_DESC("broadcastMsg") << LOG_KV("packetType", packetType)
                                  << LOG_KV("dstNodeId", session.nodeID.abridged())
                                  << LOG_KV("dstIp", session.nodeIPEndpoint.name())
                                  << LOG_KV("ttl", (ttl == 0 ? maxTTL : ttl))
                                  << LOG_KV("nodeIdx", nodeIdx())
                                  << LOG_KV("myNode", session.nodeID.abridged());
            /// send messages
            m_service->asyncSendMessageByNodeID(
                    session.nodeID, transDataToMessage(data, packetType, ttl), nullptr);
            broadcastMark(session.nodeID, packetType, key);
        }
        return true;
    }

/**
 * @brief: check the specified prepareReq is valid or not
 *       1. should not be existed in the prepareCache
 *       2. if allowSelf is false, shouldn't be generated from the node-self
 *       3. hash of committed prepare should be equal to the block hash of prepareReq if their
 * height is equal
 *       4. sign of PrepareReq should be valid(public key to verify sign is obtained according to
 * req.idx)
 * @param req: the prepareReq need to be checked
 * @param allowSelf: whether can solve prepareReq generated by self-node
 * @param oss
 * @return true: the specified prepareReq is valid
 * @return false: the specified prepareReq is invalid
 */
    CheckValid TendermintEngine::isValidPrepare(ProposeReq const& req, std::ostringstream& oss) const
    {
        if (m_reqCache->isExistPrepare(req))
        {
            TENDERMINTENGINE_LOG(TRACE) << LOG_DESC("InvalidPrepare: Duplicated Prep")
                                  << LOG_KV("EINFO", oss.str());
            return CheckValid ::T_INVALID;
        }
        if (hasConsensused(req))
        {
            TENDERMINTENGINE_LOG(TRACE) << LOG_DESC("InvalidPrepare: Consensused Prep")
                                  << LOG_KV("EINFO", oss.str());
            return CheckValid ::T_INVALID;
        }

        if (isFuturePrepare(req))
        {
            TENDERMINTENGINE_LOG(INFO) << LOG_DESC("FutureBlock") << LOG_KV("EINFO", oss.str());
            m_reqCache->addFuturePrepareCache(req);
            return CheckValid ::T_FUTURE;
        }
        if (!isValidLeader(req))
        {
            return CheckValid ::T_INVALID;
        }
        if (!isHashSavedAfterCommit(req))
        {
            TENDERMINTENGINE_LOG(TRACE) << LOG_DESC("InvalidPrepare: not saved after commit")
                                  << LOG_KV("EINFO", oss.str());
            return CheckValid ::T_INVALID;
        }
        if (!checkSign(req))
        {
            TENDERMINTENGINE_LOG(TRACE) << LOG_DESC("InvalidPrepare: invalid signature")
                                  << LOG_KV("EINFO", oss.str());
            return CheckValid ::T_INVALID;
        }
        return CheckValid ::T_VALID;
    }

/// check sealer list
    void TendermintEngine::checkSealerList(Block const& block)
    {
        ReadGuard l(m_sealerListMutex);
        if (m_sealerList != block.blockHeader().sealerList())
        {
            TENDERMINTENGINE_LOG(ERROR) << LOG_DESC("checkSealerList: wrong sealers")
                                  << LOG_KV("Nsealer", m_sealerList.size())
                                  << LOG_KV("NBlockSealer", block.blockHeader().sealerList().size())
                                  << LOG_KV("hash", block.blockHeader().hash().abridged())
                                  << LOG_KV("nodeIdx", nodeIdx())
                                  << LOG_KV("myNode", m_keyPair.pub().abridged());
            BOOST_THROW_EXCEPTION(
                    BlockSealerListWrong() << errinfo_comment("Wrong Sealer List of Block"));
        }
    }

/// check Block sign
    bool TendermintEngine::checkBlock(Block const& block)
    {
        /// ignore the genesis block
        if (block.blockHeader().number() == 0)
        {
            return true;
        }
        {
            /// check sealer list(node list)
            ReadGuard l(m_sealerListMutex);
            if (m_sealerList != block.blockHeader().sealerList())
            {
                TENDERMINTENGINE_LOG(ERROR) << LOG_DESC("checkBlock: wrong sealers")
                                      << LOG_KV("Nsealer", m_sealerList.size())
                                      << LOG_KV("NBlockSealer", block.blockHeader().sealerList().size())
                                      << LOG_KV("hash", block.blockHeader().hash().abridged())
                                      << LOG_KV("nodeIdx", nodeIdx())
                                      << LOG_KV("myNode", m_keyPair.pub().abridged());
                return false;
            }
        }

        /// check sealer(sealer must be a sealer)
        if (getSealerByIndex(block.blockHeader().sealer().convert_to<size_t>()) == NodeID())
        {
            TENDERMINTENGINE_LOG(ERROR) << LOG_DESC("checkBlock: invalid sealer ")
                                  << LOG_KV("sealer", block.blockHeader().sealer());
            return false;
        }
        /// check sign num
        auto sig_list = block.sigList();
        if (sig_list.size() < minValidNodes())
        {
            TENDERMINTENGINE_LOG(ERROR) << LOG_DESC("checkBlock: insufficient signatures")
                                  << LOG_KV("signNum", sig_list.size())
                                  << LOG_KV("minValidSign", minValidNodes());
            return false;
        }
        /// check sign
        for (auto sign : sig_list)
        {
            if (sign.first >= m_sealerList.size())
            {
                TENDERMINTENGINE_LOG(ERROR) << LOG_DESC("checkBlock: overflowed signer")
                                      << LOG_KV("signer", sign.first)
                                      << LOG_KV("Nsealer", m_sealerList.size());
                return false;
            }
            if (!dev::verify(m_sealerList[sign.first.convert_to<size_t>()], sign.second,
                             block.blockHeader().hash()))
            {
                TENDERMINTENGINE_LOG(ERROR) << LOG_DESC("checkBlock: invalid sign")
                                      << LOG_KV("signer", sign.first)
                                      << LOG_KV("pub",
                                                m_sealerList[sign.first.convert_to<size_t>()].abridged())
                                      << LOG_KV("hash", block.blockHeader().hash().abridged());
                return false;
            }
        }  /// end of check sign

        /// Check whether the number of transactions in block exceeds the limit
        if (block.transactions().size() > maxBlockTransactions())
        {
            return false;
        }
        return true;
    }

/**
 * @brief: notify the seal module to seal block if the current node is the next leader
 * @param block: block obtained from the prepare packet, used to filter transactions
 */
    void TendermintEngine::notifySealing(dev::eth::Block const& block)
    {
        TENDERMINTENGINE_LOG(INFO) << LOG_DESC("Function:  notifySealing");
        if (!m_onNotifyNextLeaderReset)
        {
            return;
        }
        /// only if the current node is the next leader and not the current leader
        /// notify the seal module to seal new block
        if (getLeader().first == true && getLeader().second != nodeIdx() &&
            nodeIdx() == getNextLeader())
        {
            /// obtain transaction filters
            h256Hash filter;
            for (auto& trans : block.transactions())
            {
                filter.insert(trans.sha3());
            }
            TENDERMINTENGINE_LOG(DEBUG) << "I am the next leader = " << getNextLeader()
                                  << ", filter trans size = " << filter.size()
                                  << ", total trans = " << m_txPool->status().current;
            m_notifyNextLeaderSeal = true;
            /// function registered in PBFTSealer to reset the block for the next leader by
            /// resetting the block number to current block number + 2
            m_onNotifyNextLeaderReset(filter);
        }
    }

    void TendermintEngine::execBlock(Sealing& sealing, ProposeReq const& req, std::ostringstream&)
    {
        /// no need to decode the local generated prepare packet
        if (req.pBlock)
        {
            sealing.block = *req.pBlock;
        }
            /// decode the network received prepare packet
        else
        {
            sealing.block.decode(ref(req.block), CheckTransaction::None);
        }
        /// return directly if it's an empty block
        if (sealing.block.getTransactionSize() == 0 && m_omitEmptyBlock)
        {
            sealing.p_execContext = nullptr;
            return;
        }

        checkBlockValid(sealing.block);

        /// notify the next leader seal a new block
        /// this if condition to in case of dead-lock when generate local prepare and notifySealing
        if (req.idx != nodeIdx())
        {
            notifySealing(sealing.block);
        }

        m_blockSync->noteSealingBlockNumber(sealing.block.header().number());

        /// ignore the signature verification of the transactions have already been verified in
        /// transation pool
        /// the transactions that has not been verified by the txpool should be verified
        m_txPool->verifyAndSetSenderForBlock(sealing.block);

        auto start_exec_time = utcTime();
        sealing.p_execContext = executeBlock(sealing.block);
        auto time_cost = utcTime() - start_exec_time;
        TENDERMINTENGINE_LOG(DEBUG) << LOG_DESC("execBlock")
                              << LOG_KV("blkNum", sealing.block.header().number())
                              << LOG_KV("reqIdx", req.idx)
                              << LOG_KV("hash", sealing.block.header().hash().abridged())
                              << LOG_KV("nodeIdx", nodeIdx())
                              << LOG_KV("myNode", m_keyPair.pub().abridged())
                              << LOG_KV("timecost", time_cost)
                              << LOG_KV("execPerTx",
                                        (float)time_cost / (float)sealing.block.getTransactionSize());
    }

/// check whether the block is empty
    bool TendermintEngine::needOmit(Sealing const& sealing)
    {
        TENDERMINTENGINE_LOG(INFO) << LOG_DESC("Function:  needOmit");
        if (sealing.block.getTransactionSize() == 0 && m_omitEmptyBlock)
        {
            TENDERMINTENGINE_LOG(TRACE) << LOG_DESC("needOmit")
                                  << LOG_KV("blkNum", sealing.block.blockHeader().number())
                                  << LOG_KV("hash", sealing.block.blockHeader().hash().abridged())
                                  << LOG_KV("nodeIdx", nodeIdx())
                                  << LOG_KV("myNode", m_keyPair.pub().abridged());
            return true;
        }
        return false;
    }

/**
 * @brief: this function is called when receive-given-protocol related message from the network
 *        1. check the validation of the network-received data(include the account type of the
 * sender and receiver)
 *        2. decode the data into PBFTMsgPacket
 *        3. push the message into message queue to handler later by workLoop
 * @param exception: exceptions related to the received-message
 * @param session: the session related to the network data(can get informations about the sender)
 * @param message: message constructed from data received from the network
 */
    void TendermintEngine::onRecvPBFTMessage(
            NetworkException, std::shared_ptr<P2PSession> session, P2PMessage::Ptr message)
    {
        TENDERMINTENGINE_LOG(INFO) << LOG_DESC("Function:  onRecvPBFTMessage");
        if (nodeIdx() == MAXIDX)
        {
            TENDERMINTENGINE_LOG(TRACE) << LOG_DESC(
                    "onRecvPBFTMessage: I'm an observer, drop the PBFT message packets directly");
            return;
        }
        TendermintMsgPacket tendermint_msg;
        bool valid = decodeToRequests(tendermint_msg, message, session);
        if (!valid)
        {
            return;
        }
        if (tendermint_msg.packet_id <= RoundChangeReqPacket)
        {
            m_msgQueue.push(tendermint_msg);
            /// notify to handleMsg after push new PBFTMsgPacket into m_msgQueue
            m_signalled.notify_all();
        }
        else
        {
            TENDERMINTENGINE_LOG(DEBUG) << LOG_DESC("onRecvPBFTMessage: illegal msg ")
                                  << LOG_KV("fromId", tendermint_msg.packet_id)
                                  << LOG_KV("fromIp", tendermint_msg.endpoint) << LOG_KV("nodeIdx", nodeIdx())
                                  << LOG_KV("myNode", m_keyPair.pub().abridged());
        }
    }

    bool TendermintEngine::handlePrepareMsg(ProposeReq& prepare_req, TendermintMsgPacket const& tendermintMsg)
    {
        bool valid = decodeToRequests(prepare_req, ref(tendermintMsg.data));
        if (!valid)
        {
            return false;
        }
        return handlePrepareMsg(prepare_req, tendermintMsg.endpoint);
    }

/**
 * @brief: handle the prepare request:
 *       1. check whether the prepareReq is valid or not
 *       2. if the prepareReq is valid:
 *       (1) add the prepareReq to raw-prepare-cache
 *       (2) execute the block
 *       (3) sign the prepareReq and broadcast the signed prepareReq
 *       (4) callback checkAndCommit function to determin can submit the block or not
 * @param prepare_req: the prepare request need to be handled
 * @param self: if generated-prepare-request need to handled, then set self to be true;
 *              else this function will filter the self-generated prepareReq
 */
    bool TendermintEngine::handlePrepareMsg(ProposeReq const& prepareReq, std::string const& endpoint)
    {
        Timer t;
        std::ostringstream oss;
        oss << LOG_DESC("handlePrepareMsg") << LOG_KV("reqIdx", prepareReq.idx)
            << LOG_KV("view", prepareReq.view) << LOG_KV("number", prepareReq.height)
            << LOG_KV("highNum", m_highestBlock.number()) << LOG_KV("consNum", m_consensusBlockNumber)
            << LOG_KV("fromIp", endpoint) << LOG_KV("hash", prepareReq.block_hash.abridged())
            << LOG_KV("nodeIdx", nodeIdx()) << LOG_KV("myNode", m_keyPair.pub().abridged());
        /// check the prepare request is valid or not
        auto valid_ret = isValidPrepare(prepareReq, oss);
        if (valid_ret == CheckValid ::T_INVALID)
        {
            return false;
        }
        /// update the view for given idx
        updateViewMap(prepareReq.idx, prepareReq.view);

        if (valid_ret == CheckValid ::T_FUTURE)
        {
            return true;
        }
        /// add raw prepare request
        m_reqCache->addRawPrepare(prepareReq);

        Sealing workingSealing;
        try
        {
            execBlock(workingSealing, prepareReq, oss);
        }
        catch (std::exception& e)
        {
            TENDERMINTENGINE_LOG(WARNING) << LOG_DESC("Block execute failed") << LOG_KV("INFO", oss.str())
                                    << LOG_KV("EINFO", boost::diagnostic_information(e));
            return true;
        }
        /// whether to omit empty block
        if (needOmit(workingSealing))
        {
            changeViewForEmptyBlock();
            return true;
        }

        /// generate prepare request with signature of this node to broadcast
        /// (can't change prepareReq since it may be broadcasted-forwarded to other nodes)
        ProposeReq sign_prepare(prepareReq, workingSealing, m_keyPair);
        m_reqCache->addPrepareReq(sign_prepare);
        TENDERMINTENGINE_LOG(DEBUG) << LOG_DESC("handlePrepareMsg: add prepare cache and broadcastSignReq")
                              << LOG_KV("blkNum", sign_prepare.height)
                              << LOG_KV("hash", sign_prepare.block_hash.abridged())
                              << LOG_KV("nodeIdx", nodeIdx())
                              << LOG_KV("myNode", m_keyPair.pub().abridged());

        /// broadcast the re-generated signReq(add the signReq to cache)
        if (!broadcastSignReq(sign_prepare))
        {
            TENDERMINTENGINE_LOG(WARNING) << LOG_DESC("broadcastSignReq failed") << LOG_KV("INFO", oss.str());
        }
        checkAndCommit();
        TENDERMINTENGINE_LOG(DEBUG) << LOG_DESC("handlePrepareMsg Succ")
                              << LOG_KV("Timecost", 1000 * t.elapsed()) << LOG_KV("INFO", oss.str());
        return true;
    }


    void TendermintEngine::checkAndCommit()
    {
        size_t sign_size = m_reqCache->getSigCacheSize(m_reqCache->prepareCache().block_hash);
        /// must be equal to minValidNodes:in case of callback checkAndCommit repeatly in a round of
        /// PBFT consensus
        if (sign_size == minValidNodes())
        {
            TENDERMINTENGINE_LOG(DEBUG) << LOG_DESC("checkAndCommit, SignReq enough")
                                  << LOG_KV("number", m_reqCache->prepareCache().height)
                                  << LOG_KV("sigSize", sign_size)
                                  << LOG_KV("hash", m_reqCache->prepareCache().block_hash.abridged())
                                  << LOG_KV("nodeIdx", nodeIdx())
                                  << LOG_KV("myNode", m_keyPair.pub().abridged());
            if (m_reqCache->prepareCache().view != m_view)
            {
                TENDERMINTENGINE_LOG(DEBUG) << LOG_DESC("checkAndCommit: InvalidView")
                                      << LOG_KV("prepView", m_reqCache->prepareCache().view)
                                      << LOG_KV("view", m_view)
                                      << LOG_KV(
                                              "hash", m_reqCache->prepareCache().block_hash.abridged())
                                      << LOG_KV("prepH", m_reqCache->prepareCache().height);
                return;
            }
            m_reqCache->updateCommittedPrepare();
            /// update and backup the commit cache
            TENDERMINTENGINE_LOG(DEBUG) << LOG_DESC("checkAndCommit: backup/updateCommittedPrepare")
                                  << LOG_KV("blkNum", m_reqCache->committedPrepareCache().height)
                                  << LOG_KV("hash",
                                            m_reqCache->committedPrepareCache().block_hash.abridged())
                                  << LOG_KV("nodeIdx", nodeIdx())
                                  << LOG_KV("myNode", m_keyPair.pub().abridged());
            backupMsg(c_backupKeyCommitted, m_reqCache->committedPrepareCache());
            TENDERMINTENGINE_LOG(DEBUG) << LOG_DESC("checkAndCommit: broadcastCommitReq")
                                  << LOG_KV("blkNum", m_reqCache->prepareCache().height)
                                  << LOG_KV("hash", m_reqCache->prepareCache().block_hash.abridged())
                                  << LOG_KV("nodeIdx", nodeIdx())
                                  << LOG_KV("myNode", m_keyPair.pub().abridged());
            if (!broadcastCommitReq(m_reqCache->prepareCache()))
            {
                TENDERMINTENGINE_LOG(WARNING) << LOG_DESC("checkAndCommit: broadcastCommitReq failed");
            }
            m_timeManager.m_lastSignTime = utcTime();
            checkAndSave();
        }
    }

/// if collect >= 2/3 SignReq and CommitReq, then callback this function to commit block
/// check whether view and height is valid, if valid, then commit the block and clear the context
    void TendermintEngine::checkAndSave()
    {
        size_t sign_size = m_reqCache->getSigCacheSize(m_reqCache->prepareCache().block_hash);
        size_t commit_size = m_reqCache->getCommitCacheSize(m_reqCache->prepareCache().block_hash);
        if (sign_size >= minValidNodes() && commit_size >= minValidNodes())
        {
            TENDERMINTENGINE_LOG(DEBUG) << LOG_DESC("checkAndSave: CommitReq enough")
                                  << LOG_KV("blkNum", m_reqCache->prepareCache().height)
                                  << LOG_KV("commitSize", commit_size)
                                  << LOG_KV("hash", m_reqCache->prepareCache().block_hash.abridged())
                                  << LOG_KV("nodeIdx", nodeIdx())
                                  << LOG_KV("myNode", m_keyPair.pub().abridged());
            if (m_reqCache->prepareCache().view != m_view)
            {
                TENDERMINTENGINE_LOG(DEBUG) << LOG_DESC("checkAndSave: InvalidView")
                                      << LOG_KV("prepView", m_reqCache->prepareCache().view)
                                      << LOG_KV("view", m_view)
                                      << LOG_KV("prepHeight", m_reqCache->prepareCache().height)
                                      << LOG_KV(
                                              "hash", m_reqCache->prepareCache().block_hash.abridged())
                                      << LOG_KV("nodeIdx", nodeIdx())
                                      << LOG_KV("myNode", m_keyPair.pub().abridged());
                return;
            }
            /// add sign-list into the block header
            if (m_reqCache->prepareCache().height > m_highestBlock.number())
            {
                /// Block block(m_reqCache->prepareCache().block);
                std::shared_ptr<dev::eth::Block> p_block = m_reqCache->prepareCache().pBlock;
                m_reqCache->generateAndSetSigList(*p_block, minValidNodes());
                auto start_commit_time = utcTime();
                /// callback block chain to commit block
                CommitResult ret = m_blockChain->commitBlock((*p_block),
                                                             std::shared_ptr<ExecutiveContext>(m_reqCache->prepareCache().p_execContext));
                /// drop handled transactions
                if (ret == CommitResult::OK)
                {
                    dropHandledTransactions(*p_block);
                    m_blockSync->noteSealingBlockNumber(m_reqCache->prepareCache().height);
                    TENDERMINTENGINE_LOG(DEBUG)
                            << LOG_DESC("CommitBlock Succ")
                            << LOG_KV("blkNum", m_reqCache->prepareCache().height)
                            << LOG_KV("reqIdx", m_reqCache->prepareCache().idx)
                            << LOG_KV("hash", m_reqCache->prepareCache().block_hash.abridged())
                            << LOG_KV("nodeIdx", nodeIdx()) << LOG_KV("myNode", m_keyPair.pub().abridged())
                            << LOG_KV("time_cost", utcTime() - start_commit_time);
                    m_reqCache->delCache(m_reqCache->prepareCache().block_hash);
                }
                else
                {
                    TENDERMINTENGINE_LOG(WARNING)
                            << LOG_DESC("CommitBlock Failed")
                            << LOG_KV("blkNum", p_block->blockHeader().number())
                            << LOG_KV("highNum", m_highestBlock.number())
                            << LOG_KV("reqIdx", m_reqCache->prepareCache().idx)
                            << LOG_KV("hash", p_block->blockHeader().hash().abridged())
                            << LOG_KV("nodeIdx", nodeIdx()) << LOG_KV("myNode", m_keyPair.pub().abridged());
                    /// note blocksync to sync
                    m_blockSync->noteSealingBlockNumber(m_blockChain->number());
                    m_txPool->handleBadBlock(*p_block);
                }
            }
            else
            {
                TENDERMINTENGINE_LOG(WARNING)
                        << LOG_DESC("checkAndSave: Consensus Failed, Block already exists")
                        << LOG_KV("blkNum", m_reqCache->prepareCache().height)
                        << LOG_KV("highNum", m_highestBlock.number())
                        << LOG_KV("blkHash", m_reqCache->prepareCache().block_hash.abridged())
                        << LOG_KV("highHash", m_highestBlock.hash().abridged())
                        << LOG_KV("nodeIdx", nodeIdx()) << LOG_KV("myNode", m_keyPair.pub().abridged());
            }
        }
    }

    void TendermintEngine::reportBlock(Block const& block)
    {
        Guard l(m_mutex);
        reportBlockWithoutLock(block);
    }
/// update the context of PBFT after commit a block into the block-chain
/// 1. update the highest to new-committed blockHeader
/// 2. update m_view/m_toView/m_leaderFailed/m_lastConsensusTime/m_consensusBlockNumber
/// 3. delete invalid view-change requests according to new highestBlock
/// 4. recalculate the m_nodeNum/m_f according to newer SealerList
/// 5. clear all caches related to prepareReq and signReq
    void TendermintEngine::reportBlockWithoutLock(Block const& block)
    {
        TENDERMINTENGINE_LOG(INFO) << LOG_DESC("Function:  reportBlockWithoutLock");
        if (m_blockChain->number() == 0 || m_highestBlock.number() < block.blockHeader().number())
        {
            /// update the highest block
            m_highestBlock = block.blockHeader();
            if (m_highestBlock.number() >= m_consensusBlockNumber)
            {
                m_view = m_toView = 0;
                m_leaderFailed = false;
                m_timeManager.m_lastConsensusTime = utcTime();
                m_timeManager.m_changeCycle = 0;
                m_consensusBlockNumber = m_highestBlock.number() + 1;
                /// delete invalid view change requests from the cache
                m_reqCache->delInvalidViewChange(m_highestBlock);
            }
            resetConfig();
            m_reqCache->delCache(m_highestBlock.hash());
            TENDERMINTENGINE_LOG(INFO) << LOG_DESC("^^^^^^^^Report") << LOG_KV("num", m_highestBlock.number())
                                 << LOG_KV("sealerIdx", m_highestBlock.sealer())
                                 << LOG_KV("hash", m_highestBlock.hash().abridged())
                                 << LOG_KV("next", m_consensusBlockNumber)
                                 << LOG_KV("tx", block.getTransactionSize())
                                 << LOG_KV("nodeIdx", nodeIdx());
        }
    }

/**
 * @brief: 1. decode the network-received PBFTMsgPacket to signReq
 *         2. check the validation of the signReq
 *         3. submit the block into blockchain if the size of collected signReq and
 *            commitReq is over 2/3
 * @param sign_req: return value, the decoded signReq
 * @param pbftMsg: the network-received PBFTMsgPacket
 */
    bool TendermintEngine::handleSignMsg(PreVoteReq& sign_req, TendermintMsgPacket const& tendermintMsg)
    {
        Timer t;
        bool valid = decodeToRequests(sign_req, ref(tendermintMsg.data));
        if (!valid)
        {
            return false;
        }
        std::ostringstream oss;
        oss << LOG_DESC("handleSignMsg") << LOG_KV("num", sign_req.height)
            << LOG_KV("highNum", m_highestBlock.number()) << LOG_KV("GenIdx", sign_req.idx)
            << LOG_KV("Sview", sign_req.view) << LOG_KV("view", m_view)
            << LOG_KV("fromIdx", tendermintMsg.node_idx) << LOG_KV("fromNode", tendermintMsg.node_id.abridged())
            << LOG_KV("fromIp", tendermintMsg.endpoint) << LOG_KV("hash", sign_req.block_hash.abridged())
            << LOG_KV("nodeIdx", nodeIdx()) << LOG_KV("myNode", m_keyPair.pub().abridged());
        auto check_ret = isValidSignReq(sign_req, oss);
        if (check_ret == CheckValid ::T_INVALID)
        {
            return false;
        }
        updateViewMap(sign_req.idx, sign_req.view);

        if (check_ret == CheckValid ::T_FUTURE)
        {
            return true;
        }
        m_reqCache->addSignReq(sign_req);

        checkAndCommit();
        TENDERMINTENGINE_LOG(DEBUG) << LOG_DESC("handleSignMsg Succ")
                              << LOG_KV("Timecost", 1000 * t.elapsed()) << LOG_KV("INFO", oss.str());
        return true;
    }

/**
 * @brief: check the given signReq is valid or not
 *         1. the signReq shouldn't be existed in the cache
 *         2. callback checkReq to check the validation of given request
 * @param req: the given request to be checked
 * @param oss: log to debug
 * @return true: check succeed
 * @return false: check failed
 */
    CheckValid TendermintEngine::isValidSignReq(PreVoteReq const& req, std::ostringstream& oss) const
    {
        if (m_reqCache->isExistSign(req))
        {
            TENDERMINTENGINE_LOG(TRACE) << LOG_DESC("InValidSignReq: Duplicated sign")
                                  << LOG_KV("INFO", oss.str());
            return CheckValid ::T_INVALID;
        }
        if (hasConsensused(req))
        {
            TENDERMINTENGINE_LOG(TRACE) << LOG_DESC("Sign requests have been consensused")
                                  << LOG_KV("INFO", oss.str());
            return CheckValid ::T_INVALID;
        }
        CheckValid result = checkReq(req, oss);
        /// to ensure that the collected signature size is equal to minValidNodes
        /// so that checkAndCommit can be called, and the committed request backup can be stored
        if ((result == CheckValid ::T_FUTURE) &&
            m_reqCache->getSigCacheSize(req.block_hash) < (size_t)(minValidNodes() - 1))
        {
            m_reqCache->addSignReq(req);
            TENDERMINTENGINE_LOG(INFO) << LOG_DESC("FutureBlock") << LOG_KV("INFO", oss.str());
        }
        return result;
    }

/**
 * @brief : 1. decode the network-received message into commitReq
 *          2. check the validation of the commitReq
 *          3. add the valid commitReq into the cache
 *          4. submit to blockchain if the size of collected commitReq is over 2/3
 * @param commit_req: return value, the decoded commitReq
 * @param pbftMsg: the network-received PBFTMsgPacket
 */
    bool TendermintEngine::handleCommitMsg(PreCommitReq& commit_req, TendermintMsgPacket const& tendermintMsg)
    {
        Timer t;
        bool valid = decodeToRequests(commit_req, ref(tendermintMsg.data));
        if (!valid)
        {
            return false;
        }
        std::ostringstream oss;
        oss << LOG_DESC("handleCommitMsg") << LOG_KV("blkNum", commit_req.height)
            << LOG_KV("highNum", m_highestBlock.number()) << LOG_KV("GenIdx", commit_req.idx)
            << LOG_KV("Cview", commit_req.view) << LOG_KV("view", m_view)
            << LOG_KV("fromIdx", tendermintMsg.node_idx) << LOG_KV("fromNode", tendermintMsg.node_id.abridged())
            << LOG_KV("fromIp", tendermintMsg.endpoint) << LOG_KV("hash", commit_req.block_hash.abridged())
            << LOG_KV("nodeIdx", nodeIdx()) << LOG_KV("myNode", m_keyPair.pub().abridged());
        auto valid_ret = isValidCommitReq(commit_req, oss);
        if (valid_ret == CheckValid ::T_INVALID)
        {
            return false;
        }
        /// update the view for given idx
        updateViewMap(commit_req.idx, commit_req.view);

        if (valid_ret == CheckValid ::T_FUTURE)
        {
            return true;
        }
        m_reqCache->addCommitReq(commit_req);
        checkAndSave();
        TENDERMINTENGINE_LOG(DEBUG) << LOG_DESC("handleCommitMsg Succ") << LOG_KV("INFO", oss.str())
                              << LOG_KV("Timecost", 1000 * t.elapsed());
        return true;
    }

/**
 * @brief: check the given commitReq is valid or not
 * @param req: the given commitReq need to be checked
 * @param oss: info to debug
 * @return true: the given commitReq is valid
 * @return false: the given commitReq is invalid
 */
    CheckValid TendermintEngine::isValidCommitReq(PreCommitReq const& req, std::ostringstream& oss) const
    {
        if (m_reqCache->isExistCommit(req))
        {
            TENDERMINTENGINE_LOG(TRACE) << LOG_DESC("InvalidCommitReq: Duplicated")
                                  << LOG_KV("INFO", oss.str());
            return CheckValid ::T_INVALID;
        }
        if (hasConsensused(req))
        {
            TENDERMINTENGINE_LOG(TRACE) << LOG_DESC("InvalidCommitReq: has consensued")
                                  << LOG_KV("INFO", oss.str());
            return CheckValid ::T_INVALID;
        }
        CheckValid result = checkReq(req, oss);
        if (result == CheckValid ::T_FUTURE)
        {
            m_reqCache->addCommitReq(req);
        }
        return result;
    }

    bool TendermintEngine::handleViewChangeMsg(RoundChangeReq& viewChange_req, TendermintMsgPacket const& tendermintMsg)
    {
        bool valid = decodeToRequests(viewChange_req, ref(tendermintMsg.data));
        if (!valid)
        {
            return false;
        }
        std::ostringstream oss;
        oss << LOG_KV("blkNum", viewChange_req.height) << LOG_KV("highNum", m_highestBlock.number())
            << LOG_KV("GenIdx", viewChange_req.idx) << LOG_KV("Cview", viewChange_req.view)
            << LOG_KV("view", m_view) << LOG_KV("fromIdx", tendermintMsg.node_idx)
            << LOG_KV("fromNode", tendermintMsg.node_id.abridged()) << LOG_KV("fromIp", tendermintMsg.endpoint)
            << LOG_KV("hash", viewChange_req.block_hash.abridged()) << LOG_KV("nodeIdx", nodeIdx())
            << LOG_KV("myNode", m_keyPair.pub().abridged());
        valid = isValidViewChangeReq(viewChange_req, tendermintMsg.node_idx, oss);
        if (!valid)
        {
            return false;
        }

        m_reqCache->addViewChangeReq(viewChange_req);
        if (viewChange_req.view == m_toView)
        {
            checkAndChangeView();
        }
        else
        {
            VIEWTYPE min_view = 0;
            bool should_trigger = m_reqCache->canTriggerViewChange(
                    min_view, m_f, m_toView, m_highestBlock, m_consensusBlockNumber);
            if (should_trigger)
            {
                m_timeManager.changeView();
                m_toView = min_view - 1;
                m_fastViewChange = true;
                TENDERMINTENGINE_LOG(INFO) << LOG_DESC("Trigger fast-viewchange") << LOG_KV("view", m_view)
                                     << LOG_KV("toView", m_toView) << LOG_KV("minView", min_view)
                                     << LOG_KV("INFO", oss.str());
                m_signalled.notify_all();
            }
        }
        TENDERMINTENGINE_LOG(DEBUG) << LOG_DESC("handleViewChangeMsg Succ ") << oss.str();
        return true;
    }

    bool TendermintEngine::isValidViewChangeReq(
            RoundChangeReq const& req, IDXTYPE const& source, std::ostringstream& oss)
    {
        if (m_reqCache->isExistViewChange(req))
        {
            TENDERMINTENGINE_LOG(TRACE) << LOG_DESC("InvalidViewChangeReq: Duplicated")
                                  << LOG_KV("INFO", oss.str());
            return false;
        }
        if (req.idx == nodeIdx())
        {
            TENDERMINTENGINE_LOG(TRACE) << LOG_DESC("InvalidViewChangeReq: own req")
                                  << LOG_KV("INFO", oss.str());
            return false;
        }
        if (req.view + 1 < m_toView && req.idx == source)
        {
            catchupView(req, oss);
        }
        /// check view and block height
        if (req.height < m_highestBlock.number() || req.view <= m_view)
        {
            TENDERMINTENGINE_LOG(TRACE) << LOG_DESC("InvalidViewChangeReq: invalid view or height")
                                  << LOG_KV("INFO", oss.str());
            return false;
        }
        /// check block hash
        if ((req.height == m_highestBlock.number() && req.block_hash != m_highestBlock.hash()) ||
            (m_blockChain->getBlockByHash(req.block_hash) == nullptr))
        {
            TENDERMINTENGINE_LOG(TRACE) << LOG_DESC("InvalidViewChangeReq, invalid hash")
                                  << LOG_KV("highHash", m_highestBlock.hash().abridged())
                                  << LOG_KV("INFO", oss.str());
            return false;
        }
        if (!checkSign(req))
        {
            TENDERMINTENGINE_LOG(TRACE) << LOG_DESC("InvalidViewChangeReq: invalid sign")
                                  << LOG_KV("INFO", oss.str());
            return false;
        }
        return true;
    }

    void TendermintEngine::catchupView(RoundChangeReq const& req, std::ostringstream& oss)
    {
        TENDERMINTENGINE_LOG(INFO) << LOG_DESC("Function:  catchupView");
        if (req.view + 1 < m_toView)
        {
            TENDERMINTENGINE_LOG(DEBUG) << LOG_DESC("catchupView") << LOG_KV("toView", m_toView)
                                  << LOG_KV("INFO", oss.str());
            dev::network::NodeID nodeId;
            bool succ = getNodeIDByIndex(nodeId, req.idx);
            if (succ)
            {
                sendViewChangeMsg(nodeId);
            }
        }
    }

    void TendermintEngine::checkAndChangeView()
    {
//        Sealing sealing;
//        sealing.block.header().populateFromParent(m_blockChain->getBlockByNumber(m_blockChain->number())->header());
//        uint64_t parentTime = m_blockChain->getBlockByNumber(m_blockChain->number())->header().timestamp();
//        sealing.block.header().setTimestamp(std::max(parentTime + 1, utcTime()));
//        std::shared_ptr<dev::consensus::ConsensusInterface> m_consensusEngine;
//
//        BlockHeader& header = sealing.block.header();
//        header.setSealerList(m_sealerList);
//        header.setSealer(nodeIdx());
//        header.setLogBloom(LogBloom());
//        header.setGasUsed(u256(0));
//        std::vector<bytes> extra_data;
//        header.setExtraData(extra_data);
//        sealing.block.calTransactionRoot();
//        generatePrepare(sealing.block);
        IDXTYPE count = m_reqCache->getViewChangeSize(m_toView);
        if (count >= minValidNodes() - 1)
        {
            TENDERMINTENGINE_LOG(INFO) << LOG_DESC("checkAndChangeView: Reach consensus")
                                 << LOG_KV("to_view", m_toView);
            /// reach to consensue dure to fast view change
            if (m_timeManager.m_lastSignTime == 0)
            {
                m_fastViewChange = false;
            }
            m_leaderFailed = false;
            m_timeManager.m_lastConsensusTime = utcTime();
            m_view = m_toView;
            m_notifyNextLeaderSeal = false;
            m_reqCache->triggerViewChange(m_view);
            m_blockSync->noteSealingBlockNumber(m_blockChain->number());
        }
    }

/// collect all caches
    void TendermintEngine::collectGarbage()
    {
        TENDERMINTENGINE_LOG(INFO) << LOG_DESC("Function:  collectGarbage");
        Guard l(m_mutex);
        if (!m_highestBlock)
        {
            return;
        }
        Timer t;
        std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
        if (now - m_timeManager.m_lastGarbageCollection >
            std::chrono::seconds(m_timeManager.CollectInterval))
        {
            m_reqCache->collectGarbage(m_highestBlock);
            m_timeManager.m_lastGarbageCollection = now;
            TENDERMINTENGINE_LOG(DEBUG) << LOG_DESC("collectGarbage")
                                  << LOG_KV("Timecost", 1000 * t.elapsed());
        }
    }

    void TendermintEngine::checkTimeout()
    {
        TENDERMINTENGINE_LOG(INFO) << LOG_DESC("Function:  checkTimeout");
        bool flag = false;
        {
            Guard l(m_mutex);
            if (m_timeManager.isTimeout())
            {
                /// timeout not triggered by fast view change
                if (m_timeManager.m_lastConsensusTime != 0)
                {
                    m_fastViewChange = false;
                }
                Timer t;
                m_toView += 1;
                m_leaderFailed = true;
                m_timeManager.updateChangeCycle();
                m_blockSync->noteSealingBlockNumber(m_blockChain->number());
                m_timeManager.m_lastConsensusTime = utcTime();
                flag = true;
                m_reqCache->removeInvalidViewChange(m_toView, m_highestBlock);
                if (!broadcastViewChangeReq())
                {
                    return;
                }
                checkAndChangeView();
                TENDERMINTENGINE_LOG(DEBUG) << LOG_DESC("checkTimeout Succ") << LOG_KV("view", m_view)
                                      << LOG_KV("toView", m_toView) << LOG_KV("nodeIdx", nodeIdx())
                                      << LOG_KV("myNode", m_keyPair.pub().abridged())
                                      << LOG_KV("timecost", t.elapsed() * 1000);
            }
        }
        if (flag && m_onViewChange)
            m_onViewChange();
    }

    void TendermintEngine::handleMsg(TendermintMsgPacket const& tendermintMsg)
    {
        Guard l(m_mutex);
        TendermintMsg tendermint_msg;
        std::string key;
        bool succ = false;
        switch (tendermintMsg.packet_id)
        {
            case ProposeReqPacket:
            {
                ProposeReq prepare_req;
                succ = handlePrepareMsg(prepare_req, tendermintMsg);
                key = prepare_req.uniqueKey();
                tendermint_msg = prepare_req;
                break;
            }
            case PreVoteReqPacket:
            {
                PreVoteReq req;
                succ = handleSignMsg(req, tendermintMsg);
                key = req.uniqueKey();
                tendermint_msg = req;
                break;
            }
            case PreCommitReqPacket:
            {
                PreCommitReq req;
                succ = handleCommitMsg(req, tendermintMsg);
                key = req.uniqueKey();
                tendermint_msg = req;
                break;
            }
            case RoundChangeReqPacket:
            {
                RoundChangeReq req;
                succ = handleViewChangeMsg(req, tendermintMsg);
                key = req.uniqueKey();
                tendermint_msg = req;
                break;
            }
            default:
            {
                TENDERMINTENGINE_LOG(DEBUG) << LOG_DESC("handleMsg:  Err pbft message")
                                      << LOG_KV("from", tendermintMsg.node_idx) << LOG_KV("nodeIdx", nodeIdx())
                                      << LOG_KV("myNode", m_keyPair.pub().abridged());
                return;
            }
        }

        if (tendermintMsg.ttl == 1)
        {
            return;
        }
        bool height_flag = (tendermint_msg.height > m_highestBlock.number()) ||
                           (m_highestBlock.number() - tendermint_msg.height < 10);
        if (succ && key.size() > 0 && height_flag)
        {
            std::unordered_set<h512> filter;
            filter.insert(tendermintMsg.node_id);
            /// get the origin gen node id of the request
            h512 gen_node_id = getSealerByIndex(tendermint_msg.idx);
            if (gen_node_id != h512())
            {
                filter.insert(gen_node_id);
            }
            unsigned current_ttl = tendermintMsg.ttl - 1;
            broadcastMsg(tendermintMsg.packet_id, key, ref(tendermintMsg.data), filter, current_ttl);
        }
    }

/// start a new thread to handle the network-receivied message
    void TendermintEngine::workLoop()
    {
        while (isWorking())
        {
            try
            {
                std::pair<bool, TendermintMsgPacket> ret = m_msgQueue.tryPop(c_PopWaitSeconds);
                if (ret.first)
                {
                    TENDERMINTENGINE_LOG(INFO)
                            << LOG_DESC("workLoop: handleMsg")
                            << LOG_KV("type", std::to_string(ret.second.packet_id))
                            << LOG_KV("fromIdx", ret.second.node_idx) << LOG_KV("nodeIdx", nodeIdx())
                            << LOG_KV("myNode", m_keyPair.pub().abridged());
                    handleMsg(ret.second);
                }
                else if (m_reqCache->futurePrepareCacheSize() == 0)
                {
                    std::unique_lock<std::mutex> l(x_signalled);
                    m_signalled.wait_for(l, std::chrono::milliseconds(5));
                }
//                checkTimeout();
//                handleFutureBlock();
                collectGarbage();
            }
            catch (std::exception& _e)
            {
                LOG(ERROR) << _e.what();
            }
        }
    }


/// handle the prepareReq cached in the futurePrepareCache
    void TendermintEngine::handleFutureBlock()
    {
        Guard l(m_mutex);
        std::shared_ptr<ProposeReq> p_future_prepare =
                m_reqCache->futurePrepareCache(m_consensusBlockNumber);
        if (p_future_prepare && p_future_prepare->view == m_view)
        {
            TENDERMINTENGINE_LOG(INFO) << LOG_DESC("handleFutureBlock")
                                 << LOG_KV("blkNum", p_future_prepare->height)
                                 << LOG_KV("highNum", m_highestBlock.number()) << LOG_KV("view", m_view)
                                 << LOG_KV("conNum", m_consensusBlockNumber)
                                 << LOG_KV("hash", p_future_prepare->block_hash.abridged())
                                 << LOG_KV("nodeIdx", nodeIdx())
                                 << LOG_KV("myNode", m_keyPair.pub().abridged());
            handlePrepareMsg(*p_future_prepare);
            m_reqCache->eraseHandledFutureReq(p_future_prepare->height);
        }
    }

/// get the status of PBFT consensus
    const std::string TendermintEngine::consensusStatus()
    {
        TENDERMINTENGINE_LOG(INFO) << LOG_DESC("Function:  consensusStatus");
        json_spirit::Array status;
        json_spirit::Object statusObj;
        getBasicConsensusStatus(statusObj);
        /// get other informations related to PBFT
        statusObj.push_back(json_spirit::Pair("connectedNodes", m_connectedNode));
        /// get the current view
        statusObj.push_back(json_spirit::Pair("currentView", m_view));
        /// get toView
        statusObj.push_back(json_spirit::Pair("toView", m_toView));
        /// get leader failed or not
        statusObj.push_back(json_spirit::Pair("leaderFailed", m_leaderFailed));
        status.push_back(statusObj);

        /// get view of node id
        getAllNodesViewStatus(status);

        /// get cache-related informations
        m_reqCache->getCacheConsensusStatus(status);
        json_spirit::Value value(status);
        std::string status_str = json_spirit::write_string(value, true);
        return status_str;
    }

    void TendermintEngine::getAllNodesViewStatus(json_spirit::Array& status)
    {
        updateViewMap(nodeIdx(), m_view);
        json_spirit::Array view_array;
        ReadGuard l(x_viewMap);
        for (auto it : m_viewMap)
        {
            json_spirit::Object view_obj;
            dev::network::NodeID node_id = getSealerByIndex(it.first);
            if (node_id != dev::network::NodeID())
            {
                view_obj.push_back(json_spirit::Pair("nodeId", dev::toHex(node_id)));
                view_obj.push_back(json_spirit::Pair("view", it.second));
                view_array.push_back(view_obj);
            }
        }
        status.push_back(view_array);
    }

}// namespace consensus
}// namespace dev
