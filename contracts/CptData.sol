pragma solidity ^0.6.10;


import "./ControllerChange.sol";
import "./IssuerData.sol";


contract CptData is ControllerChange{

    struct Cpt {
        //store the did address of cpt publisher
        address publisher;
        // [0]: cpt version, [1]: created, [2]: updated, [3]: the CPT ID
        int[8] intArray;
        // [0]: desc
        bytes32[8] bytes32Array;
        //store json schema
        bytes32[128] jsonSchemaArray;
        //store signature
        Signature signature;
    }

    struct Signature {
        uint8 v; 
        bytes32 r; 
        bytes32 s;
    }

    // CPT ID has been categorized into 3 zones: 0 - 999 are reserved for system CPTs,
    //  1000-2000000 for Authority Issuer's CPTs, and the rest for common WeIdentiy DIDs.
    uint constant public ISSUER_START_ID = 1000;
    uint constant public NONE_ISSUER_START_ID = 2000000;
    uint private issuer_current_id = 1000;
    uint private none_issuer_current_id = 2000000;

    IssuerData private issuerData;

    mapping (uint => Cpt) private cptMap;
    uint[] private cptIdList;
    address owner;

    constructor (
        address issuerDataAddress
    )
        public
    {
        issuerData = IssuerData(issuerDataAddress);
        owner = msg.sender;
    }
    
    //发布cpt
    function putCpt(
        uint cptId, 
        address cptPublisher, 
        int[8] memory cptIntArray, 
        bytes32[8] memory cptBytes32Array,
        bytes32[128] memory cptJsonSchemaArray, 
        uint8 cptV, 
        bytes32 cptR, 
        bytes32 cptS
    ) 
        external
        onlyController()
        returns (bool) 
    {
        Signature memory cptSignature = Signature({v: cptV, r: cptR, s: cptS});
        cptMap[cptId] = Cpt({publisher: cptPublisher, intArray: cptIntArray, bytes32Array: cptBytes32Array, jsonSchemaArray:cptJsonSchemaArray, signature: cptSignature});
        cptIdList.push(cptId);
        return true;
    }

    //获取cptid
    function getCptId(
        address publisher
    ) 
        external
        onlyController()
        returns 
        (uint cptId)
    {
        if (issuerData.isIssuer(publisher)) {
            while (isCptExist(issuer_current_id)) {
                issuer_current_id++;
            }
            cptId = issuer_current_id++;
            if (cptId >= NONE_ISSUER_START_ID) {
                cptId = 0;
            }
        } else {
            while (isCptExist(none_issuer_current_id)) {
                none_issuer_current_id++;
            }
            cptId = none_issuer_current_id++;
        }
    }

    //通过cptid获取cpt
    function getCpt(
        uint cptId
    ) 
        public 
        view
        returns (
        address publisher, 
        int[8] memory intArray, 
        bytes32[8] memory bytes32Array,
        bytes32[128] memory jsonSchemaArray, 
        uint8 v, 
        bytes32 r, 
        bytes32 s) 
    {
        Cpt memory cpt = cptMap[cptId];
        publisher = cpt.publisher;
        intArray = cpt.intArray;
        bytes32Array = cpt.bytes32Array;
        jsonSchemaArray = cpt.jsonSchemaArray;
        v = cpt.signature.v;
        r = cpt.signature.r;
        s = cpt.signature.s;
    } 

    //通过cptid查看cpt发布者地址
    function getCptPublisher(
        uint cptId
    ) 
        public 
        view
        returns (address publisher)
    {
        Cpt memory cpt = cptMap[cptId];
        publisher = cpt.publisher;
    }

    function isCptExist(
        uint cptId
    ) 
        public 
        view 
        returns (bool)
    {
        int[8] memory intArray = getCptIntArray(cptId);
        if (intArray[0] != 0) {
            return true;
        } else {
            return false;
        }
    }

    function getCptIntArray(
        uint cptId
    ) 
        public 
        view 
        returns (int[8] memory intArray)
    {
        Cpt memory cpt = cptMap[cptId];
        intArray = cpt.intArray;
    }

    function getCptJsonSchemaArray(
        uint cptId
    ) 
        public 
        view 
        returns (bytes32[128] memory jsonSchemaArray)
    {
        Cpt memory cpt = cptMap[cptId];
        jsonSchemaArray = cpt.jsonSchemaArray;
    }

    function getCptBytes32Array(
        uint cptId
    ) 
        public 
        view 
        returns (bytes32[8] memory bytes32Array)
    {
        Cpt memory cpt = cptMap[cptId];
        bytes32Array = cpt.bytes32Array;
    }

    function getCptSignature(
        uint cptId
    ) 
        public 
        view 
        returns (uint8 v, bytes32 r, bytes32 s) 
    {
        Cpt memory cpt = cptMap[cptId];
        v = cpt.signature.v;
        r = cpt.signature.r;
        s = cpt.signature.s;
    }

    function getDatasetLength() 
        public 
        view
        returns (uint) 
    {
        return cptIdList.length;
    }

    function getCptIdFromIndex(
        uint index
    )
        public 
        view
        returns (uint) 
    {
        return cptIdList[index];
    }
    
}