pragma solidity ^0.6.10;


import "./Access.sol";


contract PermissionChange is Access { 
    
    address internal _permissionAddress;

    function permissionChange(address permissionAddress) external onlyOwner() {
        _permissionAddress = permissionAddress;
    }

}