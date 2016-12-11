/*
	Helper client program which is used by main client program to initialize the client, i.e,
	make the client ready for connecting with the server and connecting with the peer it
	wants to chat with.
*/

#include "../header/common_header.h"
#include "../header/client_header.h"

#define OFF	0
#define ON	1

// Initiallizes the client to connect to server for login.
void initialize_client_for_login() {
	// ser_port_no is the port at which server listens for login requests.
	ser_port_no = 6060;

	// Max number of chat connnections allowed by the client is 20.
	max_sockets_num = 20;

	cur_sockets_num = 0;
	
	// Array to hold socket fd of connected sockets, initialized with 0.
	for (int i = 0; i < max_sockets_num; ++i) {
		sockets[i] = 0;
		ssl[i] = NULL;
		connect_port[i] = -1;
		strcpy(connect_ip[i], "\0");
		strcpy(connect_to[i], "\0");
		strcpy(msg_to[i], "\0");
	}

	/*
		Create the socket.
	*/
	login_cli_sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	/*
		Check whether the socket is created successfully.
	*/
	if(login_cli_sockfd < 0) {
		fprintf(stderr, "ERROR creating socket. Please try again.\n");
		exit(1);
	}

	/*
		Initialize the socket information.
	*/
	bzero((char *)&login_cli_sock, sizeof(login_cli_sock));

	login_cli_sock.sin_family = AF_INET;
	login_cli_sock.sin_port = htons(ser_port_no);

	/*
		Convert the localhost address (127.0.0.1) to a network address in IPv4 family.
		127.0.0.1 is the IP address of the server.
	*/
	if(inet_pton(AF_INET, "127.0.0.1", &(login_cli_sock.sin_addr)) <= 0) {
        fprintf(stderr,"ERROR: Invalid address.\n");
        exit(1);
    }

    /*
    	Connect to the server.
    */
    if(connect(login_cli_sockfd, (struct sockaddr *)&login_cli_sock,
    				sizeof(login_cli_sock)) < 0) {
    	fprintf(stderr, "ERROR connecting. Please try again.\n");
    	exit(1);
    }
}

int intitialize_client_for_tls_as_server(char * username, char * connect_with,
																 char * ip, int port) {
	int verify_peer = ON;
	const SSL_METHOD *server_meth;
	SSL_CTX *ssl_server_ctx;
	
	int serversocketfd;
	int clientsocketfd;
	int handshakestatus;

	struct sockaddr_in serveraddr;

	char ssl_rsa_cert[100], ssl_rsa_key[100], ssl_rsa_ca_cert[100];
	
	strcpy(ssl_rsa_cert, "Client_Cert/cert/");
	strcat(ssl_rsa_cert, username);
	strcat(ssl_rsa_cert, ".pem\0");

	strcpy(ssl_rsa_key, "Client_Cert/key/");
	strcat(ssl_rsa_key, username);
	strcat(ssl_rsa_key, ".pem\0");

	strcpy(ssl_rsa_ca_cert, "CA_Cert/cacert.pem");

	SSL_library_init();
	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();

	server_meth = SSLv23_server_method();
	ssl_server_ctx = SSL_CTX_new(server_meth);
	
	if(!ssl_server_ctx) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	
	if(SSL_CTX_use_certificate_file(ssl_server_ctx, ssl_rsa_cert, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		return -1;		
	}

	
	if(SSL_CTX_use_PrivateKey_file(ssl_server_ctx, ssl_rsa_key, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		return -1;		
	}
	
	if(SSL_CTX_check_private_key(ssl_server_ctx) != 1) {
		printf("Private Key and Certificate is not matching.\n");
		return -1;
	}

	if(verify_peer) {
		if(!SSL_CTX_load_verify_locations(ssl_server_ctx, ssl_rsa_ca_cert, NULL)) {
			ERR_print_errors_fp(stderr);
			return -1;		
		}
		SSL_CTX_set_verify(ssl_server_ctx, SSL_VERIFY_PEER, NULL);
		SSL_CTX_set_verify_depth(ssl_server_ctx, 1);
	}

	if((serversocketfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printf("Error on socket creation.\n");
		return -1;
	}

	bzero(&serveraddr, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(port);
	inet_pton(AF_INET, ip, &(serveraddr.sin_addr));

	if(bind(serversocketfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr))) {
		printf("server bind error.\n");
		return -1;
	}
	
	if(listen(serversocketfd, SOMAXCONN)) {
		printf("Error on listen.\n");
		return -1;
	}	

	SSL *serverssl;
	int ret;

	fprintf(stdout, "Waiting for %s to connect ... ", connect_with);
	fprintf(stdout, "You will be blocked untill %s connects.\n\n", connect_with);

	clientsocketfd = accept(serversocketfd, NULL, 0);
	serverssl = SSL_new(ssl_server_ctx);
	
	if(!serverssl) {
		printf("Error SSL_new\n");
		return -1;
	}

	SSL_set_fd(serverssl, clientsocketfd);
	
	if((ret = SSL_accept(serverssl))!= 1) {
		return -1;
	}

	fprintf(stdout, "Successfully CONNECTED with %s.\n", connect_with);
	
	if(verify_peer) {
		X509 *ssl_client_cert = NULL;

		ssl_client_cert = SSL_get_peer_certificate(serverssl);
		
		if(ssl_client_cert) {
			long verifyresult;

			verifyresult = SSL_get_verify_result(serverssl);
			if(verifyresult == X509_V_OK) {
				printf("\n%s certificate successfully VERIFIED.\n", connect_with); 
			}
			else {
				printf("\nCertificate Verify Failed.\n");
				return -1;
			}
			X509_free(ssl_client_cert);				
		}
		else {
			printf("\nThere is no client certificate.\n");
			return -1;
		}
	}

	fprintf(stdout, "\nTLS connection established. OK to chat with %s.\n\n", connect_with);

	for (int i = 0; i < max_sockets_num; ++i) {
		if (ssl[i] == NULL) {
			ssl[i] = serverssl;
			strcpy(msg_to[i], connect_with);
			sockets[i] = clientsocketfd;
			break;
		}
	}

	/*close(serversocketfd);
	SSL_CTX_free(ssl_server_ctx);*/

	return 0;
}

int intitialize_client_for_tls_as_client(char * username, char * connect_with,
																 char * ip , int port) {
	int verify_peer = ON;
	int clientsocketfd;
	struct sockaddr_in serveraddr;
	int handshakestatus;
	
	const SSL_METHOD *client_meth;
	SSL_CTX *ssl_client_ctx;
	
	SSL *clientssl;
	int ret;

	char ssl_rsa_cert[100], ssl_rsa_key[100], ssl_rsa_ca_cert[100];
	
	strcpy(ssl_rsa_cert, "Client_Cert/cert/");
	strcat(ssl_rsa_cert, username);
	strcat(ssl_rsa_cert, ".pem\0");

	strcpy(ssl_rsa_key, "Client_Cert/key/");
	strcat(ssl_rsa_key, username);
	strcat(ssl_rsa_key, ".pem\0");

	strcpy(ssl_rsa_ca_cert, "CA_Cert/cacert.pem");

	SSL_library_init();
	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();
	
	client_meth = SSLv23_client_method();
	ssl_client_ctx = SSL_CTX_new(client_meth);
	
	if(!ssl_client_ctx) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if(verify_peer) {	
		if(SSL_CTX_use_certificate_file(ssl_client_ctx, ssl_rsa_cert, SSL_FILETYPE_PEM) <= 0) {
			ERR_print_errors_fp(stderr);
			return -1;		
		}

		if(SSL_CTX_use_PrivateKey_file(ssl_client_ctx, ssl_rsa_key, SSL_FILETYPE_PEM) <= 0) {
			ERR_print_errors_fp(stderr);
			return -1;		
		}
	
		if(SSL_CTX_check_private_key(ssl_client_ctx) != 1) {
			printf("Private Key and Certificate is not matching\n");
			return -1;
		}	

		if(!SSL_CTX_load_verify_locations(ssl_client_ctx, ssl_rsa_ca_cert, NULL)) {
			ERR_print_errors_fp(stderr);
			return -1;		
		}

		SSL_CTX_set_verify(ssl_client_ctx, SSL_VERIFY_PEER, NULL);
		SSL_CTX_set_verify_depth(ssl_client_ctx, 1);
	}

	if((clientsocketfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printf("Error on socket creation\n");
		return -1;
	}

	bzero(&serveraddr, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(port);
	inet_pton(AF_INET, ip, &(serveraddr.sin_addr));
	
	connect(clientsocketfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr));	

	clientssl = SSL_new(ssl_client_ctx);
	if(!clientssl) {
		printf("Error SSL_new\n");
		return -1;
	}
	SSL_set_fd(clientssl, clientsocketfd);
		
	if((ret = SSL_connect(clientssl)) != 1) {
		printf("RET: %d\n", ret);
		printf("Handshake Error %d\n", SSL_get_error(clientssl, ret));
		return -1;
	}
	else {
		fprintf(stdout, "\nSuccessfully CONNECTED with %s.\n", connect_with);
	}

	if(verify_peer) {
		X509 *ssl_client_cert = NULL;

		ssl_client_cert = SSL_get_peer_certificate(clientssl);
			
		if(ssl_client_cert)
		{
			long verifyresult;

			verifyresult = SSL_get_verify_result(clientssl);
			if(verifyresult == X509_V_OK) {
				printf("\n%s certificate successfully VERIFIED.\n", connect_with); 
			}
			else {
				printf("\nCertificate Verify Failed\n");
				return -1;
			}
			X509_free(ssl_client_cert);				
		}
		else {
			printf("\nThere is no server certificate\n");
			return -1;
		}
	}

	fprintf(stdout, "\nTLS connection established. OK to chat with %s.\n\n", connect_with);

	for (int i = 0; i < max_sockets_num; ++i) {
		if (ssl[i] == NULL) {
			ssl[i] = clientssl;
			strcpy(msg_to[i], connect_with);
			sockets[i] = clientsocketfd;
			break;
		}
	}

	/*close(clientsocketfd);
	SSL_CTX_free(ssl_client_ctx);*/

	return 0;	
}