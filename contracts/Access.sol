pragma solidity ^0.6.10;


contract Access { 

    address internal _owner;
    address internal _controller;

    constructor()
        public
    {
        _owner = msg.sender;
    }

    modifier onlyOwner() {
        require (_owner == msg.sender,"Only owner can call this function!");
        _;
    }
    
    modifier onlyController() {
        require(_controller == msg.sender,"Only controller contract can call this function!");
        _;
    }

}