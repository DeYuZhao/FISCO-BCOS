//
// Created by 赵德宇 on 2019-04-01.
//

#ifndef FISCO_BCOS_COMMON_H
#define FISCO_BCOS_COMMON_H

#endif //FISCO_BCOS_COMMON_H
#pragma once
#include <libconsensus/Common.h>
#include <libdevcore/RLP.h>
#include <libdevcrypto/Common.h>
#include <libdevcrypto/Hash.h>
#include <libethcore/Block.h>
#include <libethcore/Exceptions.h>
#define TENDERMINTENGINE_LOG(LEVEL)                                                                  \
    LOG(LEVEL) << "[g:" << std::to_string(m_groupId) << "][p:" << std::to_string(m_protocolId) \
               << "][CONSENSUS][Tendermint]"

#define TENDERMINTSEALER_LOG(LEVEL)                                      \
    LOG(LEVEL) << "[g:" << std::to_string(m_tendermintEngine->groupId()) \
               << "][p:" << std::to_string(m_tendermintEngine->protocolId()) << "][CONSENSUS][SEALER]"

#define TENDERMINTReqCache_LOG(LEVEL)                                                                 \
    LOG(LEVEL) << "[g:" << std::to_string(m_groupId) << "] [p:" << std::to_string(m_protocolId) \
               << "][CONSENSUS]"
namespace dev
{
namespace consensus
{
enum TendermintPacketType
{
    ProposeReqPacket = 0x00,
    PreVoteReqPacket = 0x01,
    PreCommitReqPacket = 0x02,
    TendermintPacketCount
};

/// Tendermint message
struct TendermintMsgPacket
{
    /// the index of the node that sends this tendermint message
    IDXTYPE node_idx;
    /// the node id of the node that sends this pbft message
    h512 node_id;
    /// type of the packet(maybe propose, prevote or precommit)
    /// (receive from the network or send to the network)
    byte packet_id;
    /// ttl
    uint8_t ttl;
    /// the data of concrete request(receive from or send to the network)
    bytes data;
    /// timestamp of receive this tendermint message
    u256 timestamp;
    /// endpoint
    std::string endpoint;
    /// default constructor
    TendermintMsgPacket()
            : node_idx(0), node_id(h512(0)), packet_id(0), ttl(MAXTTL), timestamp(u256(utcTime()))
    {}
    virtual ~TendermintMsgPacket() = default;
    bool operator==(TendermintMsgPacket const& msg)
    {
        return node_idx == msg.node_idx && node_id == msg.node_id && packet_id == msg.packet_id &&
               data == msg.data;
    }
    bool operator!=(TendermintMsgPacket const& msg) { return !operator==(msg); }
    /**
     * @brief : encode network-send part of TendermintMsgPacket into bytes (RLP encoder)
     * @param encodedBytes: encoded bytes of the network-send part of TendermintMsgPacket
     */
    virtual void encode(bytes& encodedBytes) const
    {
        RLPStream tmp;
        streamRLPFields(tmp);
        RLPStream list_rlp;
        list_rlp.appendList(1).append(tmp.out());
        list_rlp.swapOut(encodedBytes);
    }
    /**
     * @brief : decode the network-receive part of TendermintMsgPacket into TendermintMsgPacket object
     * @param data: network-receive part of TendermintMsgPacket
     * @ Exception Case: if decode failed, we throw exceptions
     */
    virtual void decode(bytesConstRef _data)
    {
        RLP rlp(_data);
        populate(rlp[0]);
    }

    /// RLP decode: serialize network-received packet-data from bytes to RLP
    void streamRLPFields(RLPStream& s) const { s << packet_id << ttl << data; }

    /**
     * @brief: set non-network-receive-or-send part of TendermintMsgPacket
     * @param idx: the index of the node that send the TendermintMsgPacket
     * @param nodeId : the id of the node that send the TendermintMsgPacket
     */
    void setOtherField(IDXTYPE const& idx, h512 const& nodeId, std::string const& _endpoint)
    {
        node_idx = idx;
        node_id = nodeId;
        endpoint = _endpoint;
        timestamp = u256(utcTime());
    }
    /// populate TendermintMsgPacket from RLP object
    void populate(RLP const& rlp)
    {
        try
        {
            int field = 0;
            packet_id = rlp[field = 0].toInt<uint8_t>();
            ttl = rlp[field = 1].toInt<uint8_t>();
            data = rlp[field = 2].toBytes();
        }
        catch (Exception const& e)
        {
            e << dev::eth::errinfo_name("invalid msg format");
            throw;
        }
    }
};

/// the base class of Tendermint message
struct TendermintMsg
{
    /// the number of the block that is handling
    int64_t height = -1;
    /// round when construct this TendermintMsg
    int64_t round = -1;
    /// view when construct this TendermintMsg
//    VIEWTYPE view = MAXVIEW;
    /// index of the node generate the TendermintMsg
    IDXTYPE idx = MAXIDX;
    /// timestamp when generate the TendermintMsg
    u256 timestamp = Invalid256;
    /// block-header hash of the block handling
    h256 block_hash = h256();
    /// signature to the block_hash
    Signature sig = Signature();
    /// signature to the hash of other fields except block_hash, sig and sig2
    Signature sig2 = Signature();
    TendermintMsg() = default;
    TendermintMsg(KeyPair const& _keyPair, int64_t const& _height, int64_t const& _round,
            IDXTYPE const& _idx, h256 const _blockHash)
    {
        height = _height;
        round = _round;
//        view = _view;
        idx = _idx;
        timestamp = u256(utcTime());
        block_hash = _blockHash;
        sig = signHash(block_hash, _keyPair);
        sig2 = signHash(fieldsWithoutBlock(), _keyPair);
    }
    virtual ~TendermintMsg() = default;

    bool operator==(TendermintMsg const& req) const
    {
        return height == req.height && round == req.round && block_hash == req.block_hash &&
               sig == req.sig && sig2 == req.sig2;
    }

    bool operator!=(TendermintMsg const& req) const { return !operator==(req); }
    /**
     * @brief: encode the TendermintMsg into bytes
     * @param encodedBytes: the encoded bytes of specified TendermintMsg
     */
    virtual void encode(bytes& encodedBytes) const
    {
        RLPStream tmp;
        streamRLPFields(tmp);
        RLPStream list_rlp;
        list_rlp.appendList(1).append(tmp.out());
        list_rlp.swapOut(encodedBytes);
    }

    /**
     * @brief : decode the bytes received from network into TendermintMsg object
     * @param data : network-received data to be decoded
     * @param index: the index of RLP data need to be populated
     * @Exception Case: if decode failed, throw exception directly
     */
    virtual void decode(bytesConstRef data, size_t const& index = 0)
    {
        RLP rlp(data);
        populate(rlp[index]);
    }

    /// trans PBFTMsg into RLPStream for encoding
    virtual void streamRLPFields(RLPStream& _s) const
    {
        _s << height << round << idx << timestamp << block_hash << sig.asBytes() << sig2.asBytes();
    }

    /// populate specified rlp into TendermintMsg object
    virtual void populate(RLP const& rlp)
    {
        int field = 0;
        try
        {
            height = rlp[field = 0].toInt<int64_t>();
            round = rlp[field = 1].toInt<int64_t >();
//            view = rlp[field = 2].toInt<VIEWTYPE>();
            idx = rlp[field = 2].toInt<IDXTYPE>();
            timestamp = rlp[field = 3].toInt<u256>();
            block_hash = rlp[field = 4].toHash<h256>(RLP::VeryStrict);
            sig = dev::Signature(rlp[field = 5].toBytesConstRef());
            sig2 = dev::Signature(rlp[field = 6].toBytesConstRef());
        }
        catch (Exception const& _e)
        {
            _e << dev::eth::errinfo_name("invalid msg format")
               << dev::eth::BadFieldError(field, toHex(rlp[field].data().toBytes()));
            throw;
        }
    }

    /// clear the TendermintMsg
    void clear()
    {
        height = -1;
        round = -1;
//        view = MAXVIEW;
        idx = MAXIDX;
        timestamp = Invalid256;
        block_hash = h256();
        sig = Signature();
        sig2 = Signature();
    }

    /// get the hash of the fields without block_hash, sig and sig2
    h256 fieldsWithoutBlock() const
    {
        RLPStream ts;
        ts << height << round << idx << timestamp;
        return dev::sha3(ts.out());
    }

    /**
     * @brief : sign for specified hash using given keyPair
     * @param hash: hash data need to be signed
     * @param keyPair: keypair used to sign for the specified hash
     * @return Signature: signature result
     */
    Signature signHash(h256 const& hash, KeyPair const& keyPair) const
    {
        return dev::sign(keyPair.secret(), hash);
    }

    std::string uniqueKey() const { return sig.hex() + sig2.hex(); }
};

/// definition of the propose requests
struct ProposeReq : public TendermintMsg
{
    /// block data
    bytes block;
    std::shared_ptr<dev::eth::Block> pBlock = nullptr;
    /// execution result of block(save the execution result temporarily)
    /// no need to send or receive accross the network
    dev::blockverifier::ExecutiveContext::Ptr p_execContext = nullptr;
    /// default constructor
    ProposeReq() = default;
    ProposeReq(KeyPair const& _keyPair, int64_t const& _height, int64_t const& _round,
               IDXTYPE const& _idx, h256 const _blockHash)
            : TendermintMsg(_keyPair, _height, _round, _idx, _blockHash), p_execContext(nullptr)
    {}

    /**
     * @brief: populate the propose request from specified propose request,
     *         given view and node index
     *
     * @param req: given propose request to populate the ProposeReq object
     * @param keyPair: keypair used to sign for the ProposeReq
     * @param _view: current view
     * @param _idx: index of the node that generates this ProposeReq
     */
    ProposeReq(ProposeReq const& req, KeyPair const& keyPair, int64_t const& _round, IDXTYPE const& _idx)
    {
        height = req.height;
        round = _round;
//        view = _view;
        idx = _idx;
        timestamp = u256(utcTime());
        block_hash = req.block_hash;
        sig = signHash(block_hash, keyPair);
        sig2 = signHash(fieldsWithoutBlock(), keyPair);
        block = req.block;
        pBlock = req.pBlock;
        p_execContext = nullptr;
    }

    /**
     * @brief: construct ProposeReq from given block, view and node idx
     * @param blockStruct : the given block used to populate the ProposeReq
     * @param keyPair : keypair used to sign for the ProposeReq
     * @param _view : current view
     * @param _idx : index of the node that generates this ProposeReq
     */
    ProposeReq(dev::eth::Block const& blockStruct, KeyPair const& keyPair, int64_t const& _round, IDXTYPE const& _idx)
    {
        height = blockStruct.blockHeader().number();
        round = _round;
//        view = _view;
        idx = _idx;
        timestamp = u256(utcTime());
        block_hash = blockStruct.blockHeader().hash();
        sig = signHash(block_hash, keyPair);
        sig2 = signHash(fieldsWithoutBlock(), keyPair);
        blockStruct.encode(block);
        pBlock = std::make_shared<dev::eth::Block>(std::move(blockStruct));
        p_execContext = nullptr;
    }

    /**
     * @brief : update the ProposeReq with specified block and block-execution-result
     *
     * @param sealing : object contains both block and block-execution-result
     * @param keyPair : keypair used to sign for the ProposeReq
     */
    ProposeReq(ProposeReq const& req, Sealing const& sealing, KeyPair const& keyPair)
    {
        height = req.height;
        round = req.round;
//        view = req.view;
        idx = req.idx;
        p_execContext = sealing.p_execContext;
        /// sealing.block.encode(block);
        timestamp = u256(utcTime());
        block_hash = sealing.block.blockHeader().hash();
        sig = signHash(block_hash, keyPair);
        sig2 = signHash(fieldsWithoutBlock(), keyPair);
        pBlock = std::make_shared<dev::eth::Block>(std::move(sealing.block));
        LOG(DEBUG) << "Re-generate prepare_requests since block has been executed, time = "
                   << timestamp << " , block_hash: " << block_hash.abridged();
    }

    bool operator==(ProposeReq const& req) const
    {
        return TendermintMsg::operator==(req) && req.block == block;
    }
    bool operator!=(ProposeReq const& req) const { return !(operator==(req)); }

    /// trans ProposeReq from object to RLPStream
    virtual void streamRLPFields(RLPStream& _s) const
    {
        TendermintMsg::streamRLPFields(_s);
        _s << block;
    }

    /// populate ProposeReq from given RLP object
    virtual void populate(RLP const& _rlp)
    {
        TendermintMsg::populate(_rlp);
        int field = 0;
        try
        {
            block = _rlp[field = 7].toBytes();
        }
        catch (Exception const& _e)
        {
            _e << dev::eth::errinfo_name("invalid msg format")
               << dev::eth::BadFieldError(field, toHex(_rlp[field].data().toBytes()));
            throw;
        }
    }
};

/// prevote request
struct PreVoteReq : public TendermintMsg
{
    PreVoteReq() = default;

    /**
     * @brief: populate the PreVoteReq from given ProposeReq and node index
     *
     * @param req: ProposeReq used to populate the PreVoteReq
     * @param keyPair: keypair used to sign for the PreVoteReq
     * @param _idx: index of the node that generates this PreVoteReq
     */
    PreVoteReq(ProposeReq const& req, KeyPair const& keyPair, IDXTYPE const& _idx)
    {
        height = req.height;
        round = req.round;
//        view = req.view;
        idx = _idx;
        timestamp = u256(utcTime());
        block_hash = req.block_hash;
        sig = signHash(block_hash, keyPair);
        sig2 = signHash(fieldsWithoutBlock(), keyPair);
    }
};

/// precommit request
struct PreCommitReq : public TendermintMsg
{
    PreCommitReq() = default;
    /**
     * @brief: populate the CommitReq from given PrepareReq and node index
     *
     * @param req: PrepareReq used to populate the CommitReq
     * @param keyPair: keypair used to sign for the CommitReq
     * @param _idx: index of the node that generates this CommitReq
     */
    PreCommitReq(ProposeReq const& req, KeyPair const& keyPair, IDXTYPE const& _idx)
    {
        height = req.height;
        round = req.round;
//        view = req.view;
        idx = _idx;
        timestamp = u256(utcTime());
        block_hash = req.block_hash;
        sig = signHash(block_hash, keyPair);
        sig2 = signHash(fieldsWithoutBlock(), keyPair);
    }
};


}
}