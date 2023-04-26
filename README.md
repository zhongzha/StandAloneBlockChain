# Blockchain Implementation with a Remote Client in Java
This project illustrates the tamper-evident design of blockchain technology through the implementation of a blockchain and a remote client interacts with a blockchain API using JSON messages over TCP sockets. The blockchain is implemented in Java and is capable of transferring "dscoin" between players.

## Getting Started
To get started with the project
1. Clone the repository: 'git clone https://github.com/zhongzha/ds_blockchain.git'
2. Run BlockchainServer.java then BlockchainClient.java under src/main/java folder using a Java IDE e.g. [IntelliJ](https://www.jetbrains.com/idea/).

## Usage
The blockchain is located on the server, while the client drives the menu-driven interaction and communicates with the server on the backend. Here are the menu options available:

0. View basic blockchain status.
1. Add a transaction to the blockchain.
2. Verify the blockchain.
3. View the blockchain.
4. Corrupt the chain.
5. Hide the corruption by repairing the chain.
6. Exit

## Course Details
This project is following the instruction provided by Carnegie Mellon University's 95702 Distributed Systems course

## Contributor
Samson Zhang | zhongzha@andrew.cmu.edu
