# Liquid application : Integration Guide

## Applications and Roles

This is a brief guidance on integration of the Liquid application running on a hardware wallet into signature workflow. In this document, we describe the application running on the **Ledger Nano S** platform of Ledger hardware wallets sharing the same development framework and built-in operating system, BOLOS (also including Nano S Plus and Nano X models).

We assume that normally the Liquid transactions are prepared and managed using a desktop or a mobile application offering rich user interface and in most cases network connection as well. Let's call it the **host app**, or simply **host**, considering its principal role. It could also be called the *companion app* in Ledger's terminology.

The hardware wallet application, called **HWW app** for brevity, is a small program loadable into a specialized digital signature device typically having the form-factor of a USB token with a tiny screen. Such a device provides an additional layer of security for the host app by offloading signature and private key management features to a separate small computer with strong memory protection capabilities (which the hardware wallet is). The wide range of loadable HWW apps allows support of different tokens and networks. In our case that is Liquid Network and the assets it supports.

## Interaction Protocol

The protocol used by the host app to communicate with HWW app is very similar to the widespread ISO/IEC 7816-4 protocol for smart cards. The communication protocol consists of a set of commands that can be used to control and manage HWW app and also the structure of the command/response payloads exchanged between the parties – the Application Protocol Data Unit (APDU).

APDUs are coming in two forms: command APDUs and response APDUs. Command APDUs are sent from a host app to a HWW app and contain the instruction code, parameters, and data. Response APDUs are sent back from a HWW app containing the response data and status code.

In addition, the Event / Commands / Status model is added to make communication process more interactive and allow HWW app having asynchronous responses as it processes lengthy transactions. This feature is implemented by the help of specialized status code `SW_INTERRUPTED_EXECUTION` (`0xE000`). It is returned by HWW app accompanied by appropriate command code and information to signal that it needs something from the host before processing continues. This could be some additional data that is not provided within initial command APDU. Or it could be a piece of HWW app's response if it's too large to fit within a single response block. The host app responses with special *CONTINUE* command `CLA = 0xF8` and `INS = 0x01`, containing the appropriate response.

So, the `SW_INTERRUPTED_EXECUTION` status code could be seen as a backward request from HWW app to the host app. APDU processing may result in many such status codes returned by HWW app before the final result is returned together with `SW_OK` (`0x9000`).

Please see [here](liquid.md) for a detailed specification on the APDU protocol of the HWW app.

## Typical Usage Scenarios

### Wallet creation

When a hardware wallet is used to store a master key, its assistance is typically needed for the host app to create and manage a new wallet on the user's behalf. The host app can use `GET_MASTER_FINGERPRINT` to get master key fingerprint and `GET_EXTENDED_PUBKEY` to derive the public keys associated with the wallet it creates.

For the wallets intended for confidential transactions, let's call them "blinded", the command `LIQUID_GET_MASTER_BLINDING_KEY` allows asking the HWW app to provide the master private blinding key. The HWW app derives it from the seed according to SLIP-0077. A blinding key for a specific scriptPubKey can be obtained using `LIQUID_GET_BLINDING_KEY`.

For the multisig wallets, the procedure of wallet creation is a bit more complicated because the HWW app expects such wallets to be registered before use with user approval. The HWW app supports `REGISTER_WALLET` command for this purpose. On multisig wallet registration, the host provides wallet descriptor and all public keys.

Once the user approves, the `REGISTER_WALLET` returns to the client a 32-byte HMAC-SHA256. This will be provided to any future command that makes use of the wallet policy. The HMAC should be permanently stored on the host during the whole lifecycle of the wallet. If HMAC is lost, the wallet registration must be repeated from scratch.

### Receiving crypto assets

### Sending crypto assets

### Signing an arbitrary message

## Wallet Descriptors

## PSET as a Merkle Tree

## Important PSET Fields

## Tests and Reference Implementation
