# RFQ Relayer

## Overview

The RFQ Relayer is a decentralized application that coordinates the RFQ (Request for Quote) process in the OCAX RFQ MarketPlace. This auction technology allows users who are requesters to conduct a RFQ process for selling or buying an underlying ERC20 token in exchange for another ERC20 token. In the request for quote process the Requestor specifies the amount of a token he wishes to Buy or Sell and Quoters have the option of providing quotes in the requested underlying token. The Requestor then has the option to accept the winning Quote by delivering the required tokens to a Settlement/Escrow contract - which will settle the trade automatically provided the Quoter delivers their tokens within specified time limits to the underlying Settlement and Escrow contract.

In the OCAX marketplace, the intent is that privacy will be provided on transactions, specifically, such that market participants (Requestors and Quoters) can remain anonymous and that only a willing Quoter will know that they provided the best quote. In order to ensure that information is not leaked with respect to the quoting process, the following constraints are in place:

- data at rest has to be stored on an encrypted basis, with view keys available for auditing/verification purposes for regulatory compliance
- no quoter should be able to see or decrypt another quoters quotes
- once the time limit for an auction has expired an encrypted snapshot of the RFQ and resulting orders will be sent to MPC nodes to determine and compute the best quote that fulfills the rfq requirements once a best quote has been determined - the MPC nodes will write a ZK proof of the winning quote and rfq result information to the settlement/escrow smart contract to facilitate automated settlement should it be required

This application is currently being built out progressively as a POC
## Architecture





## Development Tasks

- decentralized database with designated block/transaction validators (in progress)
- TCP transport to GET/POST Data (in progress)
- finalize required endpoints
- websockets for broadcasting events
- integration with MPC Nodes
- POC 


## RoadMap