pragma solidity ^0.6.10;


import "./Access.sol";
import "./Permission.sol";
import "./MaskIdData.sol";


contract MaskIdController is Access{
    
    
    Permission private permission;
    MaskIdData private maskIdData;
    

    //构造函数
    constructor(
        address permissionAddress,
        address maskIdDataAddress
    )
        public
    {
        permission = Permission(permissionAddress);
        maskIdData = MaskIdData(maskIdDataAddress);
    }

    //创建MaskId
    function creatMaskId(
        address identity,
        bytes memory auth,
        bytes memory created,
        int updated
    )
        public
        onlyOwner()
    {
        maskIdData.creatMaskId(identity, auth, created, updated);
    }

    //代理创建MaskId
    function delegateCreateMaskId(
        address identity,
        bytes memory auth,
        bytes memory created,
        int updated
    )
        public
        returns (uint)
    {
        if (permission.checkPermission(msg.sender, permission.MODIFY_ISSUER())) {
            maskIdData.creatMaskId(identity, auth, created, updated);
            return permission.RETURN_CODE_SUCCEED();
        }
        return permission.RETURN_CODE_FAILURE_NO_PERMISSION();
    }

    //设置属性
    function setAttribute(
        address identity,
        bytes32 key,
        bytes memory value,
        int updated
    )
        public
        onlyOwner()
    {
        maskIdData.setAttribute(identity, key, value, updated);
    }

    //代理创建属性  
    function delegateSetAttribute(
        address identity,
        bytes32 key,
        bytes memory value,
        int updated
    )
        public
        returns (uint)
    {
        if (permission.checkPermission(msg.sender, permission.MODIFY_ISSUER())) {
            maskIdData.setAttribute(identity, key, value, updated);
            return permission.RETURN_CODE_SUCCEED();
        } 
        return permission.RETURN_CODE_FAILURE_NO_PERMISSION();
    }

    //判断身份是否存在
    function isIdentityExist(
        address identity
    ) 
        public
        view
        returns (bool)
    {
        return maskIdData.isIdentityExist(identity);
    }
    
    //获取最近相关区块
    function getLatestRelatedBlock(
        address identity
    )
        public
        view
        returns (uint)
    {
        return maskIdData.getLatestRelatedBlock(identity);
    }

    //获取第一个区块
    function getFirstBlockNum()
        public
        view
        returns (uint)
    {
        return maskIdData.getFirstBlockNum();
    }

    //获取最后一个区块
    function getLastBlockNum()
        public
        view
        returns (uint)
    {
        return maskIdData.getLastBlockNum();
    }

    //获取下一个区块
    function getNextBlockNumByBlockNum(
        uint currentBlockNum
    ) 
        public 
        view 
        returns (uint) 
    {
        return maskIdData.getNextBlockNumByBlockNum(currentBlockNum);
    }

    //获取maskid数目
    function getMaskIdCount() 
        public 
        view 
        returns (uint) 
    {
        return maskIdData.getMaskIdCount();
    }
    
}