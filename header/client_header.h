/*
	Header file for client.
*/
#include <openssl/ssl.h>
#include <openssl/err.h>

// Socket descriptors returned by the socket function.
int login_cli_sockfd;
// Structure to hold the client's socket information for login service.
struct sockaddr_in login_cli_sock;
// Buffer for reading message.
char read_buffer[1025];
// Buffer for sending message.
char write_buffer[1025];
// To hold the value returned by read() function.
int read_msg;
// To hold the value returned by write() function.
int write_msg;
// To logout client from chat portal.
int logout;

// Set of socket descriptors. It will be used to handle multiple connections at a time.
fd_set fds;
// Array to hold socket fd of connected sockets.
int sockets[20];
// Max number of chat connnections allowed by the client.
int max_sockets_num;
// Current number of chat connections.
int cur_sockets_num;
// Max value of socket descriptor in fd_set. It is used in select function.
int max_sd;
// Socket descriptor.
int sock_desc;
// SSL descriptor.
SSL * ssl[20];
char msg_to[20][41];

// For connect command
int connect_port[20];
char connect_ip[20][16];
char connect_to[20][41];

// Client's IP Address.
char ip_addr[16];

// Initiallizes the client to connect to server for login.
void initialize_client_for_login();
// Initializes the client as a TLS server.
int intitialize_client_for_tls_as_server(char *, char *, char *, int);
// Initializes the client as a TLS client.
int intitialize_client_for_tls_as_client(char *, char *, char *, int);