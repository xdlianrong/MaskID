pragma solidity ^0.6.10;


import "./Access.sol";


contract ControllerChange is Access { 

    function setController(address controller) external onlyOwner() {
        _controller = controller;
    }

}