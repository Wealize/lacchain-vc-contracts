// SPDX-License-Identifier:MIT
pragma solidity ^0.6.2;

/**
 * A base contract to be inherited by any contract that want to receive relayed transactions
 * A subclass must use "_msgSender()" instead of "msg.sender"
 */
abstract contract BaseRelayRecipient{

    /**
     * return the sender of this call.
     * if the call came through our Relay Hub, return the original sender.
     * should be used in the contract anywhere instead of msg.sender
     */
    function _msgSender() internal virtual returns (address sender) {
        bytes memory bytesRelayHub;
        (,bytesRelayHub) = getTrustedForwarder().call(abi.encodeWithSignature("getRelayHub()"));

        if (msg.sender == abi.decode(bytesRelayHub, (address))){ //sender is RelayHub then return origin sender
            bytes memory bytesSender;
            (,bytesSender) = getTrustedForwarder().call(abi.encodeWithSignature("getMsgSender()"));
        
            return abi.decode(bytesSender, (address));
        } else { //sender is not RelayHub, so it is another smart contract 
            return msg.sender;
        }
    }

    /*
     * Forwarder singleton we accept calls from
     */
    function getTrustedForwarder() public virtual returns (address);
}
