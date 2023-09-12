//Code for the multi-signature smart contract wallet
//This 'Wallet' contract is generic + will only be deployed
//If an upgrade is required, we deploy a new wallet and user upgrade their
//proxy to point to the new wallet

//SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {BaseAccount} from "account-abstraction/core/BaseAccount.sol"; //extend Wallet.sol to inherit from BaseAccount.sol (basic account implementation provided by the account-abstraction SDL)
import {UserOperation} from "account-abstraction/interfaces/UserOperation.sol"; //Struct for representing a UserOperation
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol"; //This is used to validate signatures through the ECDSA library
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {TokenCallbackHandler} from "account-abstraction/samples/callback/TokenCallbackHandler.sol";

contract Wallet is 
    BaseAccount,
    Initializable,
    UUPSUpgradeable,
    TokenCallbackHandler
{
    using ECDSA for bytes32;

    address public immutable walletFactory;
    IEntryPoint private immutable _entryPoint;
    address[] public owners;

    //Emit event once wallet is initialized
    event WalletInitialized(IEntryPoint indexed entryPoint, address[] owner);

    modifier _requireFromEntryPointOrFactory() {
        require(
            msg.sender == address(_entryPoint) || msg.sender == walletFactory,
            "Only entry point or wallet factory can call."
        );
        _;
    }

    constructor(IEntryPoint anEntryPoint, address ourWalletFactory) {
        _entryPoint = anEntryPoint;
        walletFactory = ourWalletFactory;
    }

    //modifier 'initializer' ensure the initialize function can only be called once
    function initialize(address[] memory initialOwners) public initializer {
        _initialize(initialOwners);
    }


    //Runs only a single transaction
    function execute(
        address dest,
        uint256 value,
        bytes calldata func
    ) external _requireFromEntryPointOrFactory {
        _call(dest, value, func);
    }

   //Runs multiple transactions
    function executeBatch (
        address[] calldata dests,
        uint256[] calldata values,
        bytes[] calldata funcs
    ) external _requireFromEntryPointOrFactory {
        require(dests.length == funcs.length, "wrong dests length");
        require(values.length == funcs.length, "wrong values lengths");
        for (uint256 i = 0; i < dests.length; i++) {
            _call(dests[i], values[i], funcs[i]);
        }
    }

    function _validateSignature(
        UserOperation calldata userOp,  // UserOperation data structure passed as input
        bytes32 userOpHash  // Hash of the UserOperation without the signatures
    ) internal view override returns (uint256) {
        // Convert the userOpHash to an Ethereum Signed Message Hash
        bytes32 hash = userOpHash.toEthSignedMessageHash();

        //Decode the signatures from the userOp and store them in a bytes array in memory
        bytes[] memory signatures = abi.decode(userOp.signature, (bytes[]));

        //Loop through all the owners of the wallet
        for (uint256 i = 0; i < owners.length; i++) {
            //Recover the signer's address from each signature
            //If the recovered address doesn't match the owner's address, return SIG_VALIDATION_FAILED
            if(owners[i] != hash.recover(signatures[i])) {
                return SIG_VALIDATION_FAILED;
            }
        }
        // If all signatures are valid (i.e., they all belong to the owners), return 0
        return 0;
    }

    //Set owners and wmit WalletInitialized event
    function _initialize(address[] memory initialOwners) internal {
        require(initialOwners.length > 0, "No owners :o");
        owners = initialOwners;
        emit WalletInitialized(_entryPoint, initialOwners);
    }

    //Call the built in call function within the evm.
    //This function is called with the addess, ether amount, and data
    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly {
                //Assembly code here skips the first 32 bytes of result, which contains the data length.
                //It then loads the actual error message using mload and calls revert with this error message
                revert(add(result, 32), mload(result))
            }
        }
    }

    function encodeSignatures(
        bytes[] memory signatures
    ) public pure returns (bytes memory){
        return abi.encode(signatures);
    }

    //Returns the EntryPoint saved earlier
    function entryPoint() public view override returns (IEntryPoint) {
        return _entryPoint;
    }

    function getDeposit() public view returns (uint256) {
        return entryPoint().balanceOf(address(this));
    }

    function addDeposit() public payable {
        entryPoint().depositTo{value: msg.value}(address(this));
    }

    function _authorizeUpgrade(
        address
    ) internal view override _requireFromEntryPointOrFactory {

    }

    receive() external payable {}
}