//
// Created by 赵德宇 on 2019-04-01.
//

#ifndef FISCO_BCOS_TENDERMINTSEALER_H
#define FISCO_BCOS_TENDERMINTSEALER_H

#endif //FISCO_BCOS_TENDERMINTSEALER_H
#pragma once
#include "TendermintEngine.h"
#include <libconsensus/Sealer.h>
#include <sstream>
namespace dev
{
namespace consensus
{
class TendermintSealer : public Sealer
{
public:
    TendermintSealer(std::shared_ptr<dev::p2p::P2PInterface> _service,
            std::shared_ptr<dev::txpool::TxPoolInterface> _txPool,
            std::shared_ptr<dev::blockchain::BlockChainInterface> _blockChain,
            std::shared_ptr<dev::sync::SyncInterface> _blockSync,
            std::shared_ptr<dev::blockverifier::BlockVerifierInterface> _blockVerifier,
            int16_t const& _protocolId, std::string const& _baseDir, KeyPair const& _key_pair,
            h512s const& _sealerList = h512s())
    : Sealer(_txPool, _blockChain, _blockSync)
    {
        m_consensusEngine = std::make_shared<TendermintEngine>(_service, _txPool, _blockChain, _blockSync,
                _blockVerifier, _protocolId, _baseDir, _key_pair, _sealerList);
        m_tendermintEngine = std::dynamic_pointer_cast<TendermintEngine>(m_consensusEngine);
        /// called by viewchange procedure to reset block when timeout
//        m_tendermintEngine->onViewChange(boost::bind(&TendermintSealer::resetBlockForViewChange, this));
        /// called by the next leader to reset block when it receives the prepare block
        m_tendermintEngine->onNotifyNextLeaderReset(
                boost::bind(&TendermintSealer::resetBlockForNextLeader, this, _1));
    }

    void start() override;
    void stop() override;
    /// can reset the sealing block or not?
    bool shouldResetSealing() override
    {
        /// only the leader need reset sealing in PBFT
        return Sealer::shouldResetSealing() &&
               (m_tendermintEngine->getLeader().second == m_tendermintEngine->nodeIdx());
    }

protected:
    void handleBlock() override;
    bool shouldSeal() override;
    // only the leader can generate the latest block
    bool shouldHandleBlock() override
    {
        return m_sealing.block.blockHeader().number() == (m_blockChain->number() + 1) &&
               (m_tendermintEngine->getLeader().first &&
               m_tendermintEngine->getLeader().second == m_tendermintEngine->nodeIdx());
    }

    bool reachBlockIntervalTime() override
    {
        return m_tendermintEngine->reachBlockIntervalTime() || m_sealing.block.getTransactionSize() > 0;
    }
    /// in case of the next leader packeted the number of maxTransNum transactions before the last
    /// block is consensused
    bool canHandleBlockForNextLeader() override
    {
        return m_tendermintEngine->canHandleBlockForNextLeader();
    }

private:
    /// reset block when view changes
    void resetBlockForViewChange()
    {
        {
            DEV_WRITE_GUARDED(x_sealing)
                resetSealingBlock();
        }
        m_signalled.notify_all();
        m_blockSignalled.notify_all();
    }

    /// reset block for the next leader
    void resetBlockForNextLeader(dev::h256Hash const& filter)
    {
        {
            DEV_WRITE_GUARDED(x_sealing)
                resetSealingBlock(filter, true);
        }
        m_signalled.notify_all();
        m_blockSignalled.notify_all();
    }

    void setBlock();

protected:
    std::shared_ptr<TendermintEngine> m_tendermintEngine;
};

}
}