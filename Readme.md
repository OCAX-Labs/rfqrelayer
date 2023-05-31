# RFQ Relayer

## Overview

This is a proof-of-concept application for the Request For Quote relayer - a decentralized messaging/db system that coordinates all key activities in OCAX's RFQ marketplace. The primary objective of this POC application is to allow the testing and evaluation of alternative schemes that can be used for determining the best quotes submitted for an RFQ. Ultimately the key requirements of this system are as follows:

1. RFQs can be submitted by whitelisted market participants who have successfully passed the onboarding criteria for the marketplace - the RFQ will specify the details of the underlying token (contract address, decimals, symbol) as well as the volume that quotes are being requested on and the duration of the RFQ (length of time that bids will be accepted). The RFQ will not reveal the requestors' intentions with respect to either buying or selling.

2. The RFQ's identity will be represented by their OCAX wallet address used in the transaction - for the POC, we are assuming that the wallet address used for the transaction will be the requestors identifier - for our production application, we will be exploring various options to ensure some level of anonymity for the duration of an RFQ.

3. The Relayer will be responsible for validating the RFQ, including whether the underlying requestor has passed OCAX onboarding requirements to complete the transaction and whether the token details are correct (For the purpose of the POC only "mock" validation will be performed).

4. Once validated, the RFQ will be broadcast to OCAX whitelisted market makers by the relayer - and the relayer will be open to receive the best bid and ask for quotes for the RFQ for the specified RFQ duration. The broadcasted RFQ will include a required deadline for settlement should a quoter's bid be accepted. Under our current approach, where the requestor isn't revealing their intentions to buy or sell - the broadcasted quote will only be encrypted using TLS.

5. Each market maker, when ready to submit a bid under the POC - will have an endpoint on the relayer to get any necessary keys required for encrypting and signing submitted quotes - in production, OCAX will need to provide an SDK to facilitate the submission of bids - this POC is intended to allow the testing of a variety of encryption schemes for bid submission - our initial approach to be included in the POC is detailed below.

6. Received Quotes will be validated by the relayer using a similar approach to validation used for the "requestor." Quotes received after the designated rfq duration will be rejected by the relayer.

7. Upon the expiry of the RFQ auction period, the relayer will create a "snapshot" of the rfq - for each MPC node, which includes all the received encrypted quotes and the contract addresses for the settlement/escrow and matching smart contracts. Depending on the final MPC schemes chosen for evaluating the bids, the relayer will pre-process the snapshot to split the data into secret shares for ZK processing by the MPC nodes. The relayer will then post the snapshot to the MPC nodes for processing and trigger listeners on the smart contracts to listen for the finalized calculation of the best bid quote and the best ask quote submitted by the "quoters."

8. The relayer will then submit the best quotes to the Requestor, with a designated deadline for accepting either quote. If the requestor wishes to accept one of these quotes (bid or ask), they will either: 1) in the case of a bid quote, submit the underlying currency (USDC or other designated stablecoin tbd) to the settlement/escrow contract or 2) in the case of the best ask quote submit the tokens they wish to sell to the settlement/escrow contract. The relayer will listen for receipt of either of these tokens and then notify the winning bidder - that they must deliver the relevant tokens to settle the transaction.

9. In the case of the quoter defaulting on the delivery of tokens for settlement - the requestor's funds would be released back to the requestor along with a portion of the bonding penalty (TBD).

## Pre-Requisites
- Golang 1.20+

## Installation and Setup

## Usage

### API Endpoints

## Testing

## Notes On The Relayer POC

### Decentralized DB

- The POC has been initially developed using an Ethereum-like blockchain and cryptography for persisting the RFQ data - with data stored in pebbleDB a simple key-value store - while this may be adequate for the POC - more research needs to be completed on the optimal underlying store to be used as other distributed databases may offer better performance for the relayer.

### Encryption of Quotes

Initially for the encryption of quotes we will implement the following scheme (this may be adjusted depending on the the Secure MPC protocol utilized/recommended by our cryptogaphy specialists)

1. **Symmetric Key Generation**: Each bidder generates a unique symmetric key for each bid.

2. **Bid Encryption**: The bid data is encrypted with the symmetric key.

3. **Asymmetric Encryption**: The symmetric key is then encrypted with the public keys of each MPC node.

4. **Bid Submission**: The bidders submit the symmetrically-encrypted bid and the asymmetrically-encrypted symmetric key to the relayer.

5. **Secret Sharing**: The relayer uses a secret sharing scheme like Shamir's to split the encrypted bids (and the encrypted symmetric keys) into shares. Each bid is split into n shares, where n is the number of MPC nodes. 

6. **Distribution of Shares**: The relayer distributes the shares to the MPC nodes such that each node receives one share of each bid. No node should receive more than one share of the same bid, and no node should receive all the shares of any bid.

7. **Bid Evaluation**: Each MPC node uses its private key to decrypt the symmetric key, which is then used to decrypt the share of the bid data. The nodes collaboratively reconstruct the bids and determine the highest bid.

8. **Key Storage for Audit**: After the auction, the symmetric keys used to encrypt the bids are encrypted with the auditor's public key and stored by the relayer. This allows the auditor to decrypt and review the bid data for any auction, but does not allow anyone else to do so.


## Architecture





## Development Tasks TODO

- decentralized database with designated block/transaction validators (in progress)
- TCP transport to GET/POST Data (in progress)
- finalize required endpoints
- websockets for broadcasting events
- integration with MPC Nodes
- POC 


## RoadMap



## Features

- [x] Decentralized DB - functional for blocks/transactions in-progress for RFQs
- [x] API Endpoint: GetBlock(hash or Id)
- [x] API Endpoint: GetTx(hash) 
- [x] API Endpoint: PostTx(tx) complete for RFQ
- [x] Websockets for broadcasting rfqs
- [ ] Consensus: To be implemented currently using PoA
- [ ] API Endpoint: GetRFQs() in progress
- [ ] API Endpoint: GetRFQ(hash o