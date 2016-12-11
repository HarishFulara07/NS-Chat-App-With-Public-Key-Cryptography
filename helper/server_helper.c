/*
	Helper server program which is used by main server program to initialize the server, i.e,
	make the server ready for listening for connections.
*/

#include "../header/common_header.h"
#include "../header/server_header.h"

/* Initiallizes the server to listen to client requests. */
void initialize_server() {
	int i;
	// ser_port_no will be used to listen for chat requests.
	ser_port_no = 6060;

	// Max number of connnections allowed by the server is 20.
	max_sockets_num = 20;

	cur_sockets_num = 0;

	ip_num = 2;
	
	// Array to hold socket fd of connected sockets, initialized with 0.
	for (i = 0; i < max_sockets_num; ++i) {
		sockets[i] = 0;
		strcpy(loggedin_users[i], "\0");
		loggedin_users_sfd[i] = 0;
	}
	
	/*
		Create the sockets.
	*/	
	ser_sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	
	/*
		Check whether the sockets are created successfully.
	*/
	if(ser_sockfd < 0) {
		fprintf(stderr, "ERROR creating server socket.\n");
		exit(1);
	}

	/*
		Initialize the sockets.
	*/
	bzero((char *)&ser_sock, sizeof(ser_sock));
	
	ser_sock.sin_family = AF_INET;
	// Server's IP address is 127.0.0.1
	inet_pton(AF_INET, "127.0.0.1", &(ser_sock.sin_addr));
	ser_sock.sin_port = htons(ser_port_no);

	/*
		Bind the host address using bind() call
	*/
	if(bind(ser_sockfd, (struct sockaddr *)&ser_sock, sizeof(ser_sock)) < 0) {
		fprintf(stderr, "ERROR on binding server socket.\n");
		exit(1);
	}

	/* 
		* Now start listening for the clients.
		* Here process will go in sleep mode and will wait for the incoming connection
		* The process will be able to queue upto 1024 connections at a time.
   	*/
	if(listen(ser_sockfd, 1024) < 0) {
		fprintf(stderr, "SERVER ERROR in listening to clients.\n");
		exit(1);
	}
	else {
		fprintf(stdout, "\nServer listening to clients.\n\n");
	}
}

char * int_to_str(int n) {
	int len = 0;
	int tmp = n;
	int pos = 0;

	while(tmp > 0) {
		len++;
		tmp = tmp / 10;
	}

	tmp = n;

	int num[len];
	char * str = (char *)malloc((len+1) * sizeof(char)); 

	while(tmp > 0) {
		int rem = tmp % 10;
		num[pos] = rem;
		pos++;
		tmp = tmp / 10;
	}

	while(pos > 0) {
		pos--;
		str[len-pos-1] = num[pos] + '0';
	}

	str[len] = '\0';

	return str;
}