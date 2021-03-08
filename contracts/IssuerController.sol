pragma solidity ^0.6.10;


import "./Permission.sol";
import "./IssuerData.sol";


contract IssuerController {

    // Event structure to store tx records
    uint constant private OPERATION_ADD = 0;
    uint constant private OPERATION_REMOVE = 1;
    uint constant private EMPTY_ARRAY_SIZE = 1;

    IssuerData private issuerData;
    Permission private permission;

    event IssuerRetLog(uint operation, uint retCode, address addr);

    constructor (
        address issuerDataAddress,
        address permissionAddress
    )
        public
    {
        issuerData = IssuerData(issuerDataAddress);
        permission = Permission(permissionAddress);
    }

    //addIssuer
    function addIssuerFromAddress (
        address addr,
        bytes32[16]  memory attribBytes32,
        int[16]  memory attribInt,
        bytes  memory accValue
    )
        public
        returns (uint)
    {
        if (!permission.checkPermission(tx.origin, permission.MODIFY_ISSUER())) {
            return permission.RETURN_CODE_FAILURE_NO_PERMISSION();
        }
        uint result = issuerData.addIssuerFromAddress(addr, attribBytes32, attribInt, accValue);
        emit IssuerRetLog(OPERATION_ADD, result, addr);
        return result;
    }

    //recognizeIssuer
    function recognizeIssuer
    (
        address addr
    ) 
        public 
        returns (uint)
    {
        if (!permission.checkPermission(tx.origin, permission.MODIFY_ISSUER())) {
            return permission.RETURN_CODE_FAILURE_NO_PERMISSION();
        }
        uint result = issuerData.recognizeIssuer(addr);
        emit IssuerRetLog(OPERATION_ADD, result, addr);
        return result;
    }

    //deRecognizeIssuer
    function deRecognizeIssuer
    (
        address addr
    ) 
        public
        returns (uint)
    {
        if (!permission.checkPermission(tx.origin, permission.MODIFY_ISSUER())) {
            return permission.RETURN_CODE_FAILURE_NO_PERMISSION();
        }
        uint result = issuerData.deRecognizeIssuer(addr);
        emit IssuerRetLog(OPERATION_REMOVE, result, addr);
        return result;
    }

    //removeIssuer
    function removeIssuer (
        address addr
    ) 
        public
        returns (uint)
    {
        if (!permission.checkPermission(tx.origin, permission.MODIFY_ISSUER())) {
            return permission.RETURN_CODE_FAILURE_NO_PERMISSION();
        }
        uint result = issuerData.deleteIssuerFromAddress(addr);
        emit IssuerRetLog(OPERATION_REMOVE, result, addr);
        return result;
    }

    //isIssuer
    function isIssuer(
        address addr
    ) 
        public 
        view 
        returns (bool) 
    {
        if (!permission.checkPermission(addr, permission.ROLE_ISSUER())) {
            return false;
        }
        return issuerData.isIssuer(addr);
    }

    //getIssuerAddressList
    function getIssuerAddressList (
        uint startPos,
        uint num
    )
        public
        view
        returns(address[] memory)
    {
        uint totalLength = issuerData.getDatasetLength();
        uint dataLength;

        if (totalLength < startPos) {
            return new address[](EMPTY_ARRAY_SIZE);
        } else if (totalLength <= startPos + num) {
            dataLength = totalLength - startPos;
        } else {
            dataLength = num;
        }

        address[] memory issuerArray = new address[](dataLength);
        for (uint index = 0; index < dataLength; index++) {
            issuerArray[index] = issuerData.getIssuerFromIndex(startPos + index);
        }
        return issuerArray;

    }

    //getIssuerInfoNonAccValue
    function getIssuerInfoNonAccValue(
        address addr
    )
        public 
        view
        returns (bytes32[] memory, int[] memory)
    {
        bytes32[16] memory allBytes32;
        int[16] memory allInt;
        (allBytes32, allInt) = issuerData.getIssuerInfoNonAccValue(addr);
        bytes32[] memory finalBytes32 = new bytes32[](16);
        int[] memory finalInt = new int[](16);
        for (uint index = 0; index < 16; index++) {
            finalBytes32[index] = allBytes32[index];
            finalInt[index] = allInt[index];
        }
        return (finalBytes32, finalInt);
    }

    //getAddressFromName
    function getAddressFromName(
        bytes32 name
    )
        public
        view
        returns (address)
    {
        return issuerData.getAddressFromName(name);
    }
    
}