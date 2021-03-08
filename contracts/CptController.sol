pragma solidity ^0.6.10;


import "./Permission.sol";
import "./MaskIdController.sol";
import "./CptData.sol";


contract CptController {

    // Error codes
    uint constant private CPT_NOT_EXIST = 500301;
    uint constant private ISSUER_CPT_ID_EXCEED_MAX = 500302;
    uint constant private CPT_PUBLISHER_NOT_EXIST = 500303;
    uint constant private CPT_ALREADY_EXIST = 500304;
    uint constant private NO_PERMISSION = 500305;

    // Default CPT version
    int constant private CPT_DEFAULT_VERSION = 1;

    MaskIdController private maskIdController;
    Permission private permission;
    CptData private cptData;

    event RegisterCptRetLog(
        uint retCode, 
        uint cptId, 
        int cptVersion
    );

    event UpdateCptRetLog(
        uint retCode, 
        uint cptId, 
        int cptVersion
    );

    constructor(
        address cptDataAddress,
        address maskIdControllerAddress,
        address permissionAddress
    )
        public
    {
        maskIdController = MaskIdController(maskIdControllerAddress);
        permission = Permission(permissionAddress);
        cptData = CptData(cptDataAddress);
    }

    //注册cptinner
    function registerCptInner(
        address publisher, 
        int[8] memory intArray, 
        bytes32[8] memory bytes32Array,
        bytes32[128] memory jsonSchemaArray, 
        uint8 v, 
        bytes32 r, 
        bytes32 s
    ) 
        private 
        returns (bool) 
    {
        if (!maskIdController.isIdentityExist(publisher)) {
            emit RegisterCptRetLog(CPT_PUBLISHER_NOT_EXIST, 0, 0);
            return false;
        }
        uint cptId = cptData.getCptId(publisher); 
        if (cptId == 0) {
            emit RegisterCptRetLog(ISSUER_CPT_ID_EXCEED_MAX, 0, 0);
            return false;
        }
        int cptVersion = CPT_DEFAULT_VERSION;
        intArray[0] = cptVersion;
        cptData.putCpt(cptId, publisher, intArray, bytes32Array, jsonSchemaArray, v, r, s);

        RegisterCptRetLog(0, cptId, cptVersion);
        return true;
    }

    //注册cpt
    function registerCpt(
        address publisher, 
        int[8] memory intArray, 
        bytes32[8] memory bytes32Array,
        bytes32[128] memory jsonSchemaArray, 
        uint8 v, 
        bytes32 r, 
        bytes32 s
    ) 
        public 
        returns (bool) 
    {
        return registerCptInner(publisher, intArray, bytes32Array, jsonSchemaArray, v, r, s);
    }

    //更新cptinner
    function updateCptInner(
        uint cptId, 
        address publisher, 
        int[8] memory intArray, 
        bytes32[8] memory bytes32Array,
        bytes32[128] memory jsonSchemaArray, 
        uint8 v, 
        bytes32 r, 
        bytes32 s
    ) 
        private 
        returns (bool) 
    {
        if (!maskIdController.isIdentityExist(publisher)) {
            emit UpdateCptRetLog(CPT_PUBLISHER_NOT_EXIST, 0, 0);
            return false;
        }
        if (!permission.checkPermission(tx.origin, permission.MODIFY_ISSUER())
            && publisher != cptData.getCptPublisher(cptId)) {
            emit UpdateCptRetLog(NO_PERMISSION, 0, 0);
            return false;
        }
        if (cptData.isCptExist(cptId)) {
            int[8] memory cptIntArray = cptData.getCptIntArray(cptId);
            int cptVersion = cptIntArray[0] + 1;
            intArray[0] = cptVersion;
            int created = cptIntArray[1];
            intArray[1] = created;
            cptData.putCpt(cptId, publisher, intArray, bytes32Array, jsonSchemaArray, v, r, s);
            emit UpdateCptRetLog(0, cptId, cptVersion);
            return true;
        } else {
            emit UpdateCptRetLog(CPT_NOT_EXIST, 0, 0);
            return false;
        }
    }

    //更新cpt
    function updateCpt(
        uint cptId, 
        address publisher, 
        int[8] memory intArray, 
        bytes32[8] memory bytes32Array,
        bytes32[128] memory jsonSchemaArray, 
        uint8 v, 
        bytes32 r, 
        bytes32 s
    )
        public
        returns (bool)
    {
        return updateCptInner(cptId, publisher, intArray, bytes32Array, jsonSchemaArray, v, r, s);
    }

    //查询cptinner
    function queryCptInner(
        uint cptId
    ) 
        private 
        view 
        returns (
        address publisher, 
        int[] memory intArray, 
        bytes32[] memory bytes32Array,
        bytes32[] memory jsonSchemaArray, 
        uint8 v, 
        bytes32 r, 
        bytes32 s)
    {
        publisher = cptData.getCptPublisher(cptId);
        intArray = getCptDynamicIntArray(cptId);
        bytes32Array = getCptDynamicBytes32Array(cptId);
        jsonSchemaArray = getCptDynamicJsonSchemaArray(cptId);
        (v, r, s) = cptData.getCptSignature(cptId);
    }

    //查询cpt
    function queryCpt(
        uint cptId
    ) 
        public 
        view 
        returns 
    (
        address publisher, 
        int[] memory intArray, 
        bytes32[] memory bytes32Array,
        bytes32[] memory jsonSchemaArray, 
        uint8 v, 
        bytes32 r, 
        bytes32 s)
    {
        return queryCptInner(cptId);
    }

    function getCptDynamicIntArray(
        uint cptId
    ) 
        public
        view 
        returns (int[] memory)
    {
        int[8] memory staticIntArray = cptData.getCptIntArray(cptId);
        int[] memory dynamicIntArray = new int[](8);
        for (uint i = 0; i < 8; i++) {
            dynamicIntArray[i] = staticIntArray[i];
        }
        return dynamicIntArray;
    }

    function getCptDynamicBytes32Array(
        uint cptId
    ) 
        public 
        view 
        returns (bytes32[] memory )
    {
        bytes32[8] memory staticBytes32Array = cptData.getCptBytes32Array(cptId);
        bytes32[] memory dynamicBytes32Array = new bytes32[](8);
        for (uint i = 0; i < 8; i++) {
            dynamicBytes32Array[i] = staticBytes32Array[i];
        }
        return dynamicBytes32Array;
    }

    function getCptDynamicJsonSchemaArray(
        uint cptId
    ) 
        public 
        view 
        returns (bytes32[] memory) 
    {
        bytes32[128] memory staticBytes32Array = cptData.getCptJsonSchemaArray(cptId);
        bytes32[] memory dynamicBytes32Array = new bytes32[](128);
        for (uint i = 0; i < 128; i++) {
            dynamicBytes32Array[i] = staticBytes32Array[i];
        }
        return dynamicBytes32Array;
    }

    function getCptIdList(uint startPos, uint num)
        public
        view
        returns (uint[] memory)
    {
        uint totalLength = cptData.getDatasetLength();
        uint dataLength;
        if (totalLength < startPos) {
            return new uint[](1);
        } else if (totalLength <= startPos + num) {
            dataLength = totalLength - startPos;
        } else {
            dataLength = num;
        }
        uint[] memory result = new uint[](dataLength);
        for (uint i = 0; i < dataLength; i++) {
            result[i] = cptData.getCptIdFromIndex(i);
        }
        return result;
    }

    function getTotalCptId() 
        public 
        view 
        returns (uint) 
    {
        return cptData.getDatasetLength();
    }

    // --------------------------------------------------------
    // Credential Template storage related funcs
    // store the cptId and blocknumber
    mapping (uint => uint) credentialTemplateStored;
    event CredentialTemplate(
        uint cptId,
        bytes credentialPublicKey,
        bytes credentialProof
    );

    function putCredentialTemplate(
        uint cptId,
        bytes memory credentialPublicKey,
        bytes memory credentialProof
    )
        public
    {
        emit CredentialTemplate(cptId, credentialPublicKey, credentialProof);
        credentialTemplateStored[cptId] = block.number;
    }

    function getCredentialTemplateBlock(
        uint cptId
    )
        public
        view
        returns(uint)
    {
        return credentialTemplateStored[cptId];
    }

}