/*
	Header file for server.
*/

// Socket descriptors returned by the socket function.
int ser_sockfd;
/*
	* cli_sockfd is the client's socket descriptor.
	* it is returned when the server accepts a connection from the client.
	* all read-write operations will be done on this descriptor to communicate with the client.
*/
int cli_sockfd;
// Structure to hold the server's socket information.
struct sockaddr_in ser_sock;
// Structure to hold the client's socket information.
struct sockaddr_in cli_sock;
// To get size of the structure to hold the client's socket information.
int cli_sock_len;

// Buffer for reading message sent from client.
char read_buffer[1025];
// Buffer for sending message sent to client.
char write_buffer[1025];
// To hold the value returned by read() function.
int read_msg;
// To hold the value returned by write() function.
int write_msg;

// Set of socket descriptors. It will be used to handle multiple connections at a time.
fd_set fds;
// Array to hold socket fd of connected sockets.
int sockets[20];
// Max number of connnections allowed by the server.
int max_sockets_num;
// Current number of connections.
int cur_sockets_num;
// Max value of socket descriptor in fd_set. It is used in select function.
int max_sd;
// Socket descriptor.
int sock_desc;
// Logging all those users who are curently logged in.
char loggedin_users[20][41];
// Sockets fd of the users who are logged in.
// It will be used while processing 'msg' command.
int loggedin_users_sfd[20];

// Initiallizes the server.
void initialize_server();
// Conver int to string
char * int_to_str(int);