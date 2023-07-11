# RFQ Relayer ![Github Ci](https://github.com/OCAX-Labs/rfqrelayer/actions/workflows/go.yml/badge.svg)


## Overview

This is a proof-of-concept application for the Request For Quote relayer - a decentralized messaging/db system that coordinates all key activities in OCAX's RFQ marketplace. The primary objective of this POC application is to allow the testing and evaluation of alternative schemes that can be used for determining the best quotes submitted for an RFQ. Ultimately the key requirements of this system are as follows:

1. RFQs can be submitted by whitelisted market participants who have successfully passed the onboarding criteria for the marketplace - the RFQ will specify the details of the underlying token (contract address, decimals, symbol) as well as the volume that quotes are being requested on and the duration of the RFQ (length of time that bids will be accepted). The RFQ will not reveal the requestors' intentions with respect to either buying or selling.

2. The RFQ's identity will be represented by their OCAX wallet address used in the transaction - for the POC, we are assuming that the wallet address used for the transaction will be the requestors identifier - for our production application, we will be exploring various options to ensure some level of anonymity for the duration of an RFQ.

3. The Relayer will be responsible for validating the RFQ, including whether the underlying requestor has passed OCAX onboarding requirements to complete the transaction and whether the token details are correct (For the purpose of the POC only "mock" validation will be performed).

4. Once validated, the RFQ will be broadcast to OCAX whitelisted market makers by the relayer - and the relayer will be open to receive the best bid and ask for quotes for the RFQ for the specified RFQ duration. The broadcasted RFQ will include a required deadline for settlement should a quoter's bid be accepted. Under our current approach, where the requestor isn't revealing their intentions to buy or sell - the broadcasted quote will only be encrypted using TLS.

5. Each market maker, when ready to submit a bid under the POC - will have an endpoint on the relayer to get any necessary keys required for encrypting and signing submitted quotes - in production, OCAX will need to provide an SDK to facilitate the submission of bids - this POC is intended to allow the testing of a variety of encryption schemes for bid submission - our initial approach to be included in the POC is detailed below. The encryption scheme will be configurable as a plugin to the relayer. To allow the testing of alternate encryption schemes.

6. Received Quotes will be validated by the relayer using a similar approach to validation used for the "requestor." Quotes received after the designated rfq duration will be rejected by the relayer.

7. Upon the expiry of the RFQ auction period, the relayer creates and stores a "snapshot" of the rfq and the end of the Auction is broadcast. The auction snapshot can then be handed off to a pluggable matching engine whose role will be as follows:
   1. The matching engine will be responsible for determining the best bid and ask quotes for the RFQ.
   2. The matching engine will write a proof to a matching contract on the blockchain that will be used to validate the matching engine's determination of the best quotes.
   
8. The relayer will trigger the broadcast of the best quotes to the requestor. The requestor will then have a designated period of time to accept one of the quotes. If the requestor accepts a bid quote, they will be required to submit the underlying currency (USDC or other designated stablecoin tbd) to the settlement/escrow contract. If the requestor accepts an ask quote, they will be required to submit the tokens they wish to sell to the settlement/escrow contract. The relayer will listen for receipt of either of these tokens and then notify the winning bidder - that they must deliver the relevant tokens to settle the transaction.

8.  The relayer will then submit the best quotes to the Requestor, with a designated deadline for accepting either quote. If the requestor wishes to accept one of these quotes (bid or ask), they will either: 1) in the case of a bid quote, submit the underlying currency (USDC or other designated stablecoin tbd) to the settlement/escrow contract or 2) in the case of the best ask quote submit the tokens they wish to sell to the settlement/escrow contract. The relayer will listen for receipt of either of these tokens and then notify the winning bidder - that they must deliver the relevant tokens to settle the transaction.

9.  In the case of the quoter defaulting on the delivery of tokens for settlement - the requestor's funds would be released back to the requestor along with a portion of the bonding penalty (TBD).

## Pre-Requisites
- Golang 1.20+

## Installation and Setup

1) Clone the repo and create an .env file in the root directory to create a passphrase for the private key keystore (you an copy the .env.example file and rename it to .env)
2) Run ```make run``` to download dependencies and build and start the application

To simulate an auction you will need the following

  1) A websockets test client loaded in your browser to listen for rfqs and track broadcasts for rfq. quotes and auctions. Once the relayer is running you should open a websockets connection in your browser. A connection to the relayer can be created at http://localhost:9999
  2) An JSON Api client such as Postman and/or RapidApi that can be used to send json requests to the relayer app for rfqs and quotes. In the postman folder you will find a postman collection that can be imported into postman to test the api endpoints. Please note that data for quotes will need to be updated with a valid rfqTxHash and valid quote data. The rfqTxHash can be obtained by calling the GET /openRFQs endpoint or checking the broadcast logs for a new RFQ available within websockets.

Once the above items are in place RFQ auctions and quotes can be simulated by using the provided command line utilites available in the cmd folder. The following command line utilities are available:

```bash
# to create a new rfq run the following command from the project root directory:
go run cmd/rfq/main.go
```

To modify the parameters for an auction you can edit the main.go file in the cmd/rfq folder.

This will generate the necessary JSON (sample below) to create a new RFQ which you can paste into an API client and or curl to the relayer endpoint POST /rfqs

```bash
{
    "from": "0x10723B2f35Ca58EC256d34969e6369E6F3d34ceE",
    "data": {
        "requestorId": "dfce26694d",
        "baseTokenAmount": 820000000000000000000,
        "baseToken": {
            "Address": "0x9f8F72aA9304c8B593d555F12eF6589cC3A579A2",
            "Symbol": "MKR",
            "Decimals": 18
        },
        "quoteToken": {
            "Address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            "Symbol": "USDC",
            "Decimals": 6
        },
        "rfqDurationMs": 90000
    },
    "v": "0x0",
    "r": "0x754a01a1bb8bba3da5830f252f56185e46c005b2916f217ea031ea300e53b974",
    "s": "0x71f520d6b2625b772efb9e0a509c726b92fe6e3481b673ced27e1f5fd9d7aafe"
}
```

Once you have the rfqTxHash you can use the following command line utility to submit a quote for the rfq:

```bash
go run cmd/quote/main.go --rfqTxRef=8ee43f9f2704982d627ae8fedf688b8fb0d80739667d9bb4b438215913a7ec7f
Sending request to: http://localhost:9999/openRFQs/8ee43f9f2704982d627ae8fedf688b8fb0d80739667d9bb4b438215913a7ec7f
{
		"from": "0xc5b065AE043868Ef01d37C2FC75F6263A47C7284",
		"data": {
			"quoterId": "0xc5b065AE043868Ef01d37C2FC75F6263A47C7284",
			"rfqTxHash": "0x8ee43f9f2704982d627ae8fedf688b8fb0d80739667d9bb4b438215913a7ec7f",
			"quoteExpiryTime": 600000,
			"baseToken": {
				"address": "0x9f8F72aA9304c8B593d555F12eF6589cC3A579A2",
				"symbol": "MKR",
				"decimals": 18
			},
			"quoteToken": {
				"address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
				"symbol": "USDC",
				"decimals": 6
			},
			"baseTokenAmount": 275000000000000000000,
			"bidPrice": 1567454917524850212864,
			"askPrice": 1649952544763000389632,
			"encryptionPublicKeys": []
		},
		"signature": "953c85bebabcd6c3c2bbff56a69d2113b1675ce2fd2d47fdbc9fbd114f6a99b13bee61c025f6d0f78c1eac1ee40998497033ef80475c1ceb9abb82e8a655923400"
	}

```
The JSON above can be used to submit a quote to the relayer by pasting it into an API client and or curl to the relayer endpoint POST /quotes

Sample quotes are generated randomly by the command line utility should you wish to modify the quote data you can edit the main.go file in the cmd/quote folder. To add multiple quotes you can run the command line utility multiple times with the same rfqTxHash.

Depending on the auction time which is the variable ```RfqDurationTimeMs```submitted in the original RFQRequest. Quotes will be accepted by the relayer until this time expires. At which time the complete auction data will be available from the endpoint Get /closedRFQs.

You should note that the architecture assumes the following state flow for an RFQ:

RFQRequest -> OpenRFQ -> Quotes (appended to the OpenRFQ) -> ClosedRFQ -> MatchedRFQ -> SettledRFQ

Note that the current implementation will create the auction from RFQRequest to ClosedRFQ and matching engine and settlement implementation still needs to be completed, and will likely involve seperate services depending on how matching is implemented.

## Usage

### API Endpoints

- [x] API Endpoint: GET /block/:hashorid
- [x] API Endpoint: GET /headers/:height
- [x] API Endpoint: GET /tx/:hash
- [x] API Endpoint: POST /tx
- [x] API Endpoint: GET /rfqs
- [x] API Endpoint: POST /rfqs
- [x] API Endpoint: GET /openRFQs
- [x] API Endpoint: GET /openRFQs/:rfqTxHash
- [x] API Endpoint: POST /closedRFQs
- [x] API Endpoint: GET /quotes/:rfqTxHash (get quotes for an rfq)
- [x] API Endpoint: POST /quotes 
- [x] Websockets for broadcasting rfqs
## Testing

- to run test run `make test`

## Notes On The Relayer POC

### Decentralized DB

- The POC has been initially developed using an Ethereum-like blockchain and cryptography for persisting the RFQ data - with data stored in pebbleDB a simple key-value store - while this may be adequate for the POC - more research needs to be completed on the optimal underlying store to be used as other distributed databases may offer better performance for the relayer.

### Encryption of Quotes

As the encryption of bids is configurable, multiple options can be selected for an auction, depending on the privacy requirements of auction participants including no encryption, if desired.

For a secure mpc matching engine the following encryption scheme could be utilized:
1. **Symmetric Key Generation**: Each bidder generates a unique symmetric key for each bid.

2. **Bid Encryption**: The bid data is encrypted with the symmetric key.

3. **Asymmetric Encryption**: The symmetric key is then encrypted with the public keys of each MPC node.

4. **Bid Submission**: The bidders submit the symmetrically-encrypted bid and the asymmetrically-encrypted symmetric key to the relayer.

5. **Secret Sharing**: The relayer uses a secret sharing scheme like Shamir's to split the encrypted bids (and the encrypted symmetric keys) into shares. Each bid is split into n shares, where n is the number of MPC nodes. 

6. **Distribution of Shares**: The relayer distributes the shares to the MPC nodes such that each node receives one share of each bid. No node should receive more than one share of the same bid, and no node should receive all the shares of any bid.

7. **Bid Evaluation**: Each MPC node uses its private key to decrypt the symmetric key, which is then used to decrypt the share of the bid data. The nodes collaboratively reconstruct the bids and determine the highest bid.

8. **Key Storage for Audit**: After the auction, the symmetric keys used to encrypt the bids are encrypted with the auditor's public key and stored by the relayer. This allows the auditor to decrypt and review the bid data for any auction, but does not allow anyone else to do so.


## Architecture
the relayer is modeled on a decentralized blockchain with transactions limited to those required for the RFQ marketplace. The relayer is responsible for the following key functions:
- Providing json rpc endpoints to facilitate rfq transactions
- Validating RFQs
- Validating Quotes
- Monitoring the RFQ auction period
- Triggering the RFQ Matching Engine at the end of the auction period
- Listening for matched bids and asks from the RFQ Matching Engine and notifying the winning bidder(s) and requestor

The relayer currently operates as a POA chain however the intention is to move to a more decentralized consensus mechanism in the future.

## Development Tasks TODO
- add encryption plugin and determine signing requirements for RFQRequests and Quotes
- finalize required endpoints
- integration with matching engine
- development of matching engine

## Features/RoadMap

- [x] Decentralized DB - functional for blocks/transactions quotes and rfqs
- [x] API Endpoints - functional for blocks/transactions quotes and rfqs
- [x] Keystore - integration still required 
- [ ] Matching Engine: To be implemented
- [ ] Quote Encryption Plugin & SDK: To be implemented
- [ ] Consensus: To be implemented currently using PoA
- [ ] Monitoring: Refactor to allow validator to sign ClosedRFQs
- [ ] Storage Optimization: To be implemented including load on failure
- [ ] Performance Optimization: To be implemented
- [ ] Security Audit: To be implemented