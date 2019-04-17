//
// Created by 赵德宇 on 2019-04-01.
//

#ifndef FISCO_BCOS_TIMEMANAGER_H
#define FISCO_BCOS_TIMEMANAGER_H

#endif //FISCO_BCOS_TIMEMANAGER_H
#pragma once
#include <libdevcore/Common.h>
namespace dev
{
namespace consensus
{
struct TimeManager
{
    /// last execution finish time, only one will be used at last
    /// the finish time of executing tx by leader
    unsigned m_viewTimeout;
    unsigned m_changeCycle = 0;
    uint64_t m_lastSignTime = 0;
    uint64_t m_lastConsensusTime;
    unsigned m_intervalBlockTime = 1000;
    /// time point of last signature collection
    std::chrono::system_clock::time_point m_lastGarbageCollection;
    const unsigned kMaxChangeCycle = 20;
    const unsigned CollectInterval = 60;

    inline void initTimerManager(unsigned view_timeout)
    {
        m_lastConsensusTime = utcTime();
        m_lastSignTime = 0;
        m_viewTimeout = view_timeout;
        m_changeCycle = 0;
        m_lastGarbageCollection = std::chrono::system_clock::now();
    }

    inline void changeView()
    {
        m_lastConsensusTime = 0;
        m_lastSignTime = 0;
        /// m_changeCycle = 0;
    }

    inline void changeRound()
    {
        m_lastConsensusTime = 0;
        m_lastSignTime = 0;
    }


    inline void updateChangeCycle()
    {
        m_changeCycle = std::min(m_changeCycle + 1, (unsigned)kMaxChangeCycle);
    }

    inline bool isTimeout()
    {
        auto now = utcTime();
        auto last = std::max(m_lastConsensusTime, m_lastSignTime);
        auto interval = (uint64_t)(m_viewTimeout * std::pow(1.5, m_changeCycle));
        return (now - last >= interval);
    }
};
}  // namespace consensus
}  // namespace dev