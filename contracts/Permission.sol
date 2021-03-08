pragma solidity ^0.6.10;


contract Permission {

    //error code.
    uint constant public RETURN_CODE_FAILURE_NO_PERMISSION = 500000;
    uint constant public RETURN_CODE_SUCCEED = 0;
    
    //role related constants.
    uint constant public ROLE_ISSUER = 100;
    uint constant public ROLE_ADMIN = 102;
    
    //operation related constants.
    uint constant public MODIFY_ISSUER = 200;
    uint constant public MODIFY_ADMIN = 202;
    uint constant public MODIFY_KEY_CPT = 203;

    //MAPPING.
    mapping (address => bool) public issuerRoleBearer;
    mapping (address => bool) public adminRoleBearer;

    //constructor.
    constructor() 
        public
    {
        issuerRoleBearer[msg.sender] = true;
        adminRoleBearer[msg.sender] = true;
    }

    //add role
    function addRole(
        address addr,
        uint role
    )
        public
        returns (uint)
    {
        if (role == ROLE_ISSUER) {
            if (checkPermission(tx.origin, MODIFY_ISSUER)){
                issuerRoleBearer[addr] = true;
                return RETURN_CODE_SUCCEED;
            }
            return RETURN_CODE_FAILURE_NO_PERMISSION;
            
        }
        if (role == ROLE_ADMIN) {
            if (checkPermission(tx.origin, MODIFY_ADMIN)){
                adminRoleBearer[addr] = true;
                return RETURN_CODE_SUCCEED;
            }
            return RETURN_CODE_FAILURE_NO_PERMISSION;
        }
    }

    //remove role
    function removeRole(
        address addr,
        uint role
    ) 
        public
        returns (uint)
    {
        if (role == ROLE_ISSUER) {
            if (checkPermission(tx.origin, MODIFY_ISSUER)){
                issuerRoleBearer[addr] = false;
                return RETURN_CODE_SUCCEED;
            }
            else{
                return RETURN_CODE_FAILURE_NO_PERMISSION;
            }
        }
        if (role == ROLE_ADMIN) {
            if (checkPermission(tx.origin, MODIFY_ADMIN)){
                adminRoleBearer[addr] = false;
                return RETURN_CODE_SUCCEED;
            }
            return RETURN_CODE_FAILURE_NO_PERMISSION;
        }
    }
    
    //check role
    function checkRole(
        address addr,
        uint role
    )
        public
        view
        returns (bool result)
    {
        if (role == ROLE_ISSUER) {
            result = issuerRoleBearer[addr];
            return result;
        }
        if (role == ROLE_ADMIN) {
            result = adminRoleBearer[addr];
            return result;
        }
    }

    //check permission
    function checkPermission(
        address addr,
        uint operation
    )
        public
        view
        returns (bool)
    {
        if (operation == MODIFY_ISSUER) {
            if (adminRoleBearer[addr]) {
                return true;
            }
        }
        if (operation == MODIFY_ADMIN) {
            if (adminRoleBearer[addr]) {
                return true;
            }
        }
        if (operation == MODIFY_KEY_CPT) {
            if (issuerRoleBearer[addr]) {
                return true;
            }
        }
        return false;
    }
    
}