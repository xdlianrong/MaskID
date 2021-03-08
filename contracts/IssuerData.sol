pragma solidity ^0.6.10;


import "./ControllerChange.sol";
import "./Permission.sol";


contract IssuerData is ControllerChange{
    
    //结构体
    struct Issuer {
        // [0]name, [1]desc
        bytes32[16] attribBytes32;//授权机构名称	机构名称必须小于32个字节，非空，且仅包含ASCII码可打印字符（ASCII值位于32~126）
        // [0]create date, [1]update date, [15]flag for recognition
        int[16] attribInt;//创建日期	注册时不需要传入，SDK内置默认为当前时间
        bytes accValue; //授权方累积判定值
    }

    Permission private permission;

    //error codes
    uint constant private RETURN_CODE_SUCCESS = 0;
    uint constant private RETURN_CODE_FAILURE_ALREADY_EXISTS = 500201;
    uint constant private RETURN_CODE_FAILURE_NOT_EXIST = 500202;
    uint constant private RETURN_CODE_NAME_ALREADY_EXISTS = 500203;
    uint constant private RETUEN_CODE_UNRECOGNIZED = 500204;

    //address => issuerStruct
    mapping (address => Issuer) private issuerMap;

    //issuerName => address
    mapping (bytes32 => address) private uniqueNameMap;
    
    //issuer数组
    address[] private issuerArray;
    
    constructor(
        address permissionAddress
    ) 
        public
    {
        permission = Permission(permissionAddress);
    }
    

    //添加issuer
    function addIssuerFromAddress (
        address addr,
        bytes32[16]  memory attribBytes32,
        int[16]  memory attribInt,
        bytes  memory accValue
    )
        external
        onlyController()
        returns (uint)
    {
        if (issuerMap[addr].attribBytes32[0] != bytes32(0)) {
            return RETURN_CODE_FAILURE_ALREADY_EXISTS;
        }
        if (isNameDuplicate(attribBytes32[0])) {
            return RETURN_CODE_NAME_ALREADY_EXISTS;
        }
        Issuer memory issuer = Issuer(attribBytes32, attribInt, accValue);
        issuerMap[addr] = issuer;
        issuerArray.push(addr);
        uniqueNameMap[attribBytes32[0]] = addr;
        return RETURN_CODE_SUCCESS;
    }

    //认证issuer
    function recognizeIssuer
    (
        address addr
    ) 
        external
        onlyController()
        returns (uint)
    {
        if (issuerMap[addr].attribBytes32[0] == bytes32(0)) {
            return RETURN_CODE_FAILURE_NOT_EXIST;
        }
        permission.addRole(addr, permission.ROLE_ISSUER());
        issuerMap[addr].attribInt[15] = int(1);
        return RETURN_CODE_SUCCESS;
    }

    //取消认证issuer
    function deRecognizeIssuer
    (
        address addr
    ) 
        external
        onlyController()
        returns (uint)
    {
        permission.removeRole(addr, permission.ROLE_ISSUER());
        issuerMap[addr].attribInt[15] = int(0);
        return RETURN_CODE_SUCCESS;
    }

    //删除issuer
    function deleteIssuerFromAddress(
        address addr
    ) 
        external 
        onlyController()
        returns (uint)
    {
        if (issuerMap[addr].attribBytes32[0] == bytes32(0)) {
            return RETURN_CODE_FAILURE_NOT_EXIST;
        }
        permission.removeRole(addr, permission.ROLE_ISSUER());
        uniqueNameMap[issuerMap[addr].attribBytes32[0]] = address(0x0);
        delete issuerMap[addr];
        uint datasetLength = issuerArray.length;
        uint index;
        for (index = 0; index < datasetLength; index++) {
            if (issuerArray[index] == addr) { 
                break;
            }
        } 
        if (index != datasetLength-1) {
            issuerArray[index] = issuerArray[datasetLength-1];
        }
        delete issuerArray[datasetLength-1];
        //issuerArray.length--;
        return RETURN_CODE_SUCCESS;
        
    }

    //判断是否为issuer
    function isIssuer(
        address addr
    )
        public
        view
        returns (bool)
    {

        if (issuerMap[addr].attribBytes32[0] == bytes32(0)){
            return false;
        }
        return true;
    }

    function getDatasetLength()
        public
        view
        returns (uint)
    {
        return issuerArray.length;

    }
    
    function getIssuerFromIndex(
        uint index
    ) 
        public 
        view 
        returns (address) 
    {
        return issuerArray[index];
    }
    
    function getIssuerInfoNonAccValue(
        address addr
    )
        public
        view
        returns (bytes32[16] memory, int[16] memory)
    {
        bytes32[16] memory allBytes32;
        int[16] memory allInt;
        for (uint index = 0; index < 16; index++) {
            allBytes32[index] = issuerMap[addr].attribBytes32[index];
            allInt[index] = issuerMap[addr].attribInt[index];
        }
        return (allBytes32, allInt);
    }

    function getIssuerInfoAccValue(
        address addr
    )
        public
        view
        returns (bytes memory)
    {
        return issuerMap[addr].accValue;
    }

    function isNameDuplicate(
        bytes32 name
    )
        public
        view
        returns (bool)
    {
        if (uniqueNameMap[name] == address(0x0)) {
            return false;
        }
        return true;
    }

    function getAddressFromName(
        bytes32 name
    )
        public
        view
        returns (address)
    {
        return uniqueNameMap[name];
    }

}