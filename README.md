# Chat App With Public Key Cryptography

This is a multi-user chat application with mutual authentication using X.509 certificates.

### Assignment Description

You need to build upon the chat server (you can find basic chat server application [here] (https://github.com/HarishFulara07/NS-Basic-Web-Chat-Application)) with multiple users. Having worked with shared secret authentication, you now need to work with authentication using public private cryptography. 

To achieve the same, now your chat server model needs a centralized CA. The CA signs various certificate requests. The users can now send certificate signing requests (CSRs) to the CA who signs them. 

A user should be able to communicate with its peer using an encrypted TLS connection. The user communicates to the chat server to forward a request to the peer which starts listening process, waiting for connections on a certain port number. The user thereafter establishes a TLS connection to the peer’s listening port. The server (communication responder) responds with a regular TLS handshake which involves sending the server’s certificate to the client (connection initiator) who validates the certificate. Upon successful authentication a TLS connection is established which the two parties can now use to communicate securely.

Additionally, the communication responder peer could ask the the initiator for a certificate, to which the latter responds with its certificate. If the responder validates certificate, a shared TLS connection is established between the parties communicate. This is an example of mutual authentication.

<br>

**Note**: You can find detailed information in [readme.pdf] (https://github.com/HarishFulara07/NS-Chat-App-With-Public-Key-Cryptography/blob/master/README/readme.pdf) inside **README** directory.

<br>

## How to run the application?

<------Compile the code using the following command------>

make

<------First run the server using the following command------>

./server

<------Run the client in a new terminal window using the following command------>

./client

NOTE: To run multiple clients, run the above command in a new terminal window for each client
