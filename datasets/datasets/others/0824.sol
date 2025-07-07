// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;


contract Counter {
    uint public count;
    address public owner;


    constructor() {
        owner = msg.sender;
    }


    function increment() public {
        require(msg.sender == owner, "Only owner can increment");
        count += 1;
    }


    function decrement() public {
        require(msg.sender == owner, "Only owner can decrement");
        require(count > 0, "Count is already zero");
        count -= 1;
    }
}


