pragma solidity ^0.6.10;


import "./ControllerChange.sol";


contract MaskIdData is ControllerChange{
    
    bytes32 constant private MASKID_KEY_CREATED = "created";
    bytes32 constant private MASKID_KEY_AUTHENTICATION = "/maskId/auth";
    
    uint firstBlockNum;
    uint lastBlockNum;
    uint maskIdCount = 0;

    //identity => block.number
    mapping(address => uint) changed;

    //block.number => block.number
    mapping(uint => uint) blockAfterLink;

    event MaskIdAttributeChanged(
        address indexed identity,
        bytes32 key,
        bytes value,
        uint previousBlock,
        int updated
    );
    
    event MaskIdHistory(
        address indexed identity,
        uint previousBlock,
        int created
    );

    //构造函数
    constructor() 
        public
    {
        firstBlockNum = block.number;
        lastBlockNum = firstBlockNum;
    }

    //创建MaskId
    function creatMaskId(
        address identity,
        bytes memory auth,
        bytes memory created,
        int updated
    )
        external
        onlyController()
    {
        emit MaskIdAttributeChanged(identity, MASKID_KEY_CREATED, created, changed[identity], updated);
        emit MaskIdAttributeChanged(identity, MASKID_KEY_AUTHENTICATION, auth, changed[identity], updated);
        changed[identity] = block.number;
        if (block.number > lastBlockNum) {
            blockAfterLink[lastBlockNum] = block.number;
            lastBlockNum = block.number;
        }
        emit MaskIdHistory(identity, lastBlockNum, updated);
        maskIdCount++;
    }


    //设置属性
    function setAttribute(
        address identity,
        bytes32 key,
        bytes memory value,
        int updated
    )
        external
        onlyController()
    {
        emit MaskIdAttributeChanged(identity, key, value, changed[identity], updated);
        changed[identity] = block.number;
    }


    //判断身份是否存在
    function isIdentityExist(
        address identity
    ) 
        public
        view
        returns (bool)
    {
        if (address(0x0) != identity && 0 != changed[identity]) {
            return true;
        }
            return false;
    }
    
    //获取最近相关区块
    function getLatestRelatedBlock(
        address identity
    )
        public
        view
        returns (uint)
    {
        return changed[identity];
    }

    //获取第一个区块
    function getFirstBlockNum()
        public
        view
        returns (uint)
    {
        return firstBlockNum;
    }

    //获取最后一个区块
    function getLastBlockNum()
        public
        view
        returns (uint)
    {
        return lastBlockNum;
    }

    //获取下一个区块
    function getNextBlockNumByBlockNum(
        uint currentBlockNum
    ) 
        public 
        view 
        returns (uint) 
    {
        return blockAfterLink[currentBlockNum];
    }

    //获取maskid数目
    function getMaskIdCount() 
        public 
        view 
        returns (uint) 
    {
        return maskIdCount;
    }
    
}