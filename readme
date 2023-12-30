This part has 3 modules-> 1. KDC server 2. Client 3. IRC Server

## KDC server
1) It has a database of all the clients and their long term keys.
2) It is listening on a port for any request from the client.
3) As soon as client requests for session key and ticket by providing client hello(userName:Nonce:) KDC generates a session key and ticket and sends it to the client.
4) The response sent is encrypted using the long term key of the client. Encryption is done using AES algorithm with a randomised IV so that the same message does not get encrypted to the same cipher text.
5) It also has a database of all the IRC servers and their long term keys.
6) Ticket sent to the client contains the session key and the userName of client along with IV of ticket ecnryption which is encrypted using the long term key of the IRC server.

## Client
1) Communicates with KDC server to get the session key and ticket.
2) It then connects to the IRC server and sends the ticket to the IRC server along with a challenge.
3) It then starts listening to the IRC server for any messages.
4) IRC sends client challenge response encrypted using the session key. By this challenge response the client verifies that the IRC server is the one it is supposed to connect to.
5) IRC also sends another challenge to the client which the client has to respond to.
6) Client responds to the challenge and the IRC server verifies that the client is the one it is supposed to connect to.

All the communication happening except the first client hello sent to kdc server is encrypted via AES algorithm and random IV is choosen everytime so that the same message does not get encrypted to the same cipher text.

## IRC Server
1) It listens on a port for any client to connect and send the ticket.
2) IRC server decrypts the ticket using its long term key and verifies that the ticket is not replayed.
3) IRC derives userName who is connecting and session key from the ticket.
4) IRC server also recieves a challenge from the client which it has to respond to which is encrypted using the session key.
5) IRC server responds to the challenge and client verifies that the IRC server is the one it is supposed to connect to.
6) IRC server also sends a challenge to the client which the client has to respond to encrypting it using the session key.
7) Client responds to the challenge and the IRC server verifies that the client is the one it is supposed to connect to.
8) IRC server then starts listening to the client for any messages.

## Serialisation formats used
1) Client to KDC server: userName:kdc:nonce
2) KDC server to client: ENCRYPTclientkey(nonce:sessionKey:ticket):IV
3) Client to IRC server: ticket
4) Client to IRC server: ENCRYPTsessionkey(challenge):IV
5) IRC server to client: ENCRYPTsessionkey(challengeResponse:challengeNew):IV
6) Client to IRC server: ENCRYPTsessionkey(challengeResponseNew):IV
7) Ticket: ENCRYPTirckey(sessionKey:userName):IV

## Threats prevented
1) Random IV is choosen everytime a message is supposed to be sent so that the same message does not get encrypted to the same cipher text. (wireshark can be used to check this)
2) Challenge response for authentication is not only done by server to authenticate client but also done by client to authenticate server so that a any attack is not possible and user is sure that he is communicating with the right server. (can be tested by sending wrong challenge response from either side)
3) Ticket can not be replayed again as irc server stores all the mappings of session key and user name and it verifies that the ticket is not replayed. So once user disconnects, he can not connect again with the same ticket.(can be tested by sending same ticket again to irc server from client)

In order to test for different users generate keys using below command and change username in the client code.
to generate keys:
```if=/dev/urandom bs=32 count=1 of={userName}```

## Installation
1) clone the repository
1) openssl library is required to run the code
2) run ```make``` in the directory
3) run ```./kdc``` in one terminal
4) run ```./irc``` in another terminal
5) run ```./client``` in another terminal
6) KDC server, IRC server and client are now running and you can see the communication happening in the terminals.
