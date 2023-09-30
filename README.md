# ChatServer

#### Characteristics
- Message encryption using asynchronous (RSA 4096) and synchronous encryptions (AES 256), as well as, hashing (SHA 512)
- Password-protected private-key PEM files
- Config file for easy changes
- (future) "keychain" contact list of connected clients

#### Sources
[Cryptodome (synchronous/asynchronous hybrid encryption)](https://pycryptodome.readthedocs.io/en/latest/src/examples.html)

#### Todo
- Still need to add sockets to allow communication between peers
- Figure out how to ***NAT Holepunch***
