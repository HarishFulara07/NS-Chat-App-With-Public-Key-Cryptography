// Here i am using client's chat portal username as common name for the x509 certificate. 

#include "header/CA.h"
#include "header/common_header.h"
#include "header/client_header.h"

void read_from_console(char * str) {
	int flag = 0;
	int ind = 0;

	while(1) {
		char ch;
		scanf("%c", &ch);

		if(ch == '\n' && !flag) {
			flag = 1;
		}
		else if(ch == '\n' && flag) {
			str[ind] = '\0';
			break;
		}
		else {
			str[ind] = ch;
			ind++;
		}
	}
}

void communication() {
	int choice;
	/*
		Chat Portal Home Page.
	*/
	do {
		fprintf(stdout, "\n----------Welcome to the Chat Portal----------\n\n");
		fprintf(stdout, "Press 1 and hit Enter - to Login\n");
		fprintf(stdout, "Press 2 and hit Enter - to Exit\n\n");
		
		fprintf(stdout, "Enter your choice: ");
		fscanf(stdin, "%d", &choice);

		if (choice == 1) {
			initialize_client_for_login();

			bzero(read_buffer, 1025);
			read_msg = read(login_cli_sockfd, read_buffer, 1024);

			if(read_msg > 0) {
				if(strcmp(read_buffer, "-1") == 0) {
					fprintf(stdout, "\nERROR: server too busy. Please try again after sometime.\n");
					continue;
				}
				else {
					fprintf(stdout, "\nMessage from server: %s\n", read_buffer);
				}
			}
			else {
				fprintf(stderr, "\nERROR in receiving login ACK from the server.\n");
				exit(1);
			}

			char username[41];
			char password[41];
			
			fprintf(stdout, "\n--------------Log into Chat Portal--------------\n\n");
			fprintf(stdout, "Enter your username: ");
			fscanf(stdin, "%s", username);
			fprintf(stdout, "Enter your password: ");
			fscanf(stdin, "%s", password);

			// Sending login credentials to the server in 2:username:password format.
			bzero(write_buffer, 1025);
			strcpy(write_buffer, "1:");
			strcat(write_buffer, username);
			strcat(write_buffer, ":");
			strcat(write_buffer, password);
			strcat(write_buffer, "\0");

			write_msg = write(login_cli_sockfd, write_buffer, strlen(write_buffer));

			bzero(read_buffer, 1025);
			read_msg = read(login_cli_sockfd, read_buffer, 1024);

			if (read_msg > 0) {
				// IP address of the client.
				strcpy(ip_addr, "127.0.0.");
				strcat(ip_addr, read_buffer);
				strcat(ip_addr, "\0");
			}

			// Successfully logged in.
			fprintf(stdout, "\n----------Welcome to the Chat Portal----------\n\n");
			fprintf(stdout, "Hello!!! %s\n\n", username);	

			logout = 0;

			while(!logout) {
				char command[21];
				strcpy (command, "\0");

				fprintf(stdout, ">> ");
				fflush(stdout);

				// Clear the socket set.
				FD_ZERO(&fds);

				// Add the server socket to the set.
				FD_SET(login_cli_sockfd, &fds);
				// Add the standart input file descriptor to the set.
				FD_SET(STDIN_FILENO, &fds);

				if (login_cli_sockfd > STDIN_FILENO) {
					max_sd = login_cli_sockfd;
				}
				else {
					max_sd = STDIN_FILENO;
				}

				// Add chat sockets to fd_set.
				for (int i = 0 ; i < 20 ; i++) {
					sock_desc = sockets[i];

					// If valid socket descriptor then add to fd_set.
					if(sock_desc > 0) {
						FD_SET(sock_desc, &fds);
					}

					// Maximum value socket descriptor. It is used in select function.
					if(sock_desc > max_sd) {
						max_sd = sock_desc;
					}
				}

				/* Wait for an activity on the login sockets, timeout is NULL,
				so wait indefinitely. When a socket is ready to be read,
				select will return and fds will have those sockets
				which are ready to be read. */
				select(max_sd+1, &fds, NULL, NULL, NULL);

				// There is a message from server to be read.
				if(FD_ISSET(login_cli_sockfd, &fds)) {
					bzero(read_buffer, 1025);
					read_msg = read(login_cli_sockfd, read_buffer, 1024);

					if(read_msg > 0) {
						char * id;
						char delim[2] = ":";

						id = strtok(read_buffer, delim);

						// id = 1 means the message is a chat request message.
						if(strcmp(id, "1") == 0) {
							char * from = strtok(NULL, delim);
							char connect_with[41];
							strcpy(connect_with, from);

							fprintf(stdout, "\n\nReceived chat request from: %s\n", from);
							
							char port[10];
							fprintf(stdout, "\nOpen chat connection on port? : ");
							fscanf(stdin, "%s", port);

							// 'chat reply' command has id = 4.
							strcpy(write_buffer, "4:");
							strcat(write_buffer, username);
							strcat(write_buffer, ":");
							strcat(write_buffer, from);
							strcat(write_buffer, ":");
							strcat(write_buffer, ip_addr);
							strcat(write_buffer, ":");
							strcat(write_buffer, port);
							strcat(write_buffer, "\0");

							write_msg = write(login_cli_sockfd, write_buffer, strlen(write_buffer));

							if(write_msg < 0) {
								fprintf(stderr, "\nERROR in sending 'chat reply' to the server.\n");
								exit(1);
							}

							bzero(read_buffer, 1025);
							read_msg = read(login_cli_sockfd, read_buffer, 1024);

							if(read_msg < 0) {
								fprintf(stderr, "\nERROR in processing the 'chat reply' command by the server.\n");
								exit(1);
							}
							else {
								fprintf(stdout, "\n%s\n\n", read_buffer);
								// Open a port for TLS connection.
								intitialize_client_for_tls_as_server(username, connect_with, ip_addr, atoi(port));
							}
						}
						// id = 2 means message it is reply to the chat request we made earlier
						else if(strcmp(id, "2") == 0) {
							char * from = strtok(NULL, delim);
							char * ip = strtok(NULL, delim);
							char * port = strtok(NULL, delim);

							fprintf(stdout, "\n\nReceived reply from %s for our chat request.\n", from);
							fprintf(stdout, "\nIP Address of %s: %s\n", from, ip);
							fprintf(stdout, "%s is listening on port number: %s\n\n", from, port);

							// Save above to so that it can be used to connect with other party via TLS
							for (int i = 0; i < max_sockets_num; ++i) {
								if (connect_port[i] == -1) {
									connect_port[i] = atoi(port);
									strcpy(connect_ip[i], ip);
									strcpy(connect_to[i], from);
									break;
								}
							}
						}
						continue;
					}
				}
				// There is an input command to be read.
				if(FD_ISSET(STDIN_FILENO, &fds)) {
					bzero(command, 21);
					read(STDIN_FILENO, command, 20);
					command[strlen(command)-1] = '\0';
				}
				
				bzero(write_buffer, 1025);

				// Send the command to the server for processing.

				// Send the 'logout' command.
				if(strcmp(command, "logout") == 0 || strcmp(command, "/logout") == 0) {
					logout = 1;

					// 'logout' command has id = 2
					strcpy(write_buffer, "2:");
					strcat(write_buffer, username);
					strcat(write_buffer, "\0");

					write_msg = write(login_cli_sockfd, write_buffer, strlen(write_buffer));

					if(write_msg < 0) {
						fprintf(stderr, "\nERROR in sending 'logout' command to the server.\n");
						exit(1);
					}

					bzero(read_buffer, 1025);
					read_msg = read(login_cli_sockfd, read_buffer, 1024);

					if(read_msg < 0) {
						fprintf(stderr, "\nERROR in processing the 'logout' command by the server.\n");
						exit(1);
					}
					else {
						fprintf(stdout, "\n%s\n", read_buffer);
					}
				}
				// Send the 'chat request' command.
				else if(strcmp(command, "chat") == 0 || strcmp(command, "/chat") == 0) {
					// First check if client has a certificate.
					char cert_path[50];
					strcpy(cert_path, "Client_Cert/cert/");
					strcat(cert_path, username);
					strcat(cert_path, ".pem");
					strcat(cert_path, "\0");

					// Certificate file does not exist.
					if( access(cert_path, F_OK ) == -1 ) {
						fprintf(stdout, "\nUnable to find certificate '%s.pem' inside 'Client_Cert/cert' directory. ", username);
						fprintf(stdout, "Please create your certificate by choosing option 1 from the ");
						fprintf(stdout, "following options.\n\n");
						logout = 1;
						continue;
					}

					char chat_with[41];
					fprintf(stdout, "\nWhom do you want to chat with? : ");
					fscanf(stdin, "%s", chat_with);

					// Check if the receiver has a certificate.
					strcpy(cert_path, "Client_Cert/cert/");
					strcat(cert_path, chat_with);
					strcat(cert_path, ".pem");
					strcat(cert_path, "\0");

					// Certificate file does not exist.
					if( access(cert_path, F_OK ) == -1 ) {
						fprintf(stdout, "\nYou cannot send a chat request to %s because %s ", chat_with, chat_with);
						fprintf(stdout, "does not have a certificate.\n\n");
						continue;
					}
					
					// 'chat request' command has id = 3
					strcpy(write_buffer, "3:");
					strcat(write_buffer, username);
					strcat(write_buffer, ":");
					strcat(write_buffer, chat_with);
					strcat(write_buffer, "\0");

					write_msg = write(login_cli_sockfd, write_buffer, strlen(write_buffer));

					if(write_msg < 0) {
						fprintf(stderr, "\nERROR in sending 'chat' command to the server.\n");
						exit(1);
					}

					bzero(read_buffer, 1025);
					read_msg = read(login_cli_sockfd, read_buffer, 1024);

					if(read_msg < 0) {
						fprintf(stderr, "\nERROR in processing the 'chat' command by the server.\n");
						exit(1);
					}
					else {
						fprintf(stdout, "\n%s\n\n", read_buffer);
					}
				}
				// Send the 'connect' comand to connect to other user via TLS.
				else if(strcmp(command, "connect") == 0 || strcmp(command, "/connect") == 0) {
					int connect_flag = 0, i;
					char connect_with[41];
					
					fprintf(stdout, "\nWhom do you want to connect with? : ");
					fscanf(stdin, "%s", connect_with);

					for (i = 0; i < max_sockets_num; ++i) {
						if (strcmp(connect_with, connect_to[i]) == 0) {
							connect_flag = 1;
							break;
						}
					}

					if (connect_flag) {
						intitialize_client_for_tls_as_client(username, connect_with,
																	 connect_ip[i] , connect_port[i]);
					}
					else {
						fprintf(stdout, "\nCannot connect to %s. ", connect_with);
						fprintf(stdout, "Either %s has not accepted your chat request ", connect_with);
						fprintf(stdout, "or you have not sent a chat request to %s.\n\n", connect_with);
					}
				}
				// Send the 'msg' comand to message client.
				else if(strcmp(command, "msg") == 0 || strcmp(command, "/msg") == 0) {
					char to[41], msg[921];
				
					fprintf(stdout, "\nWhom do you want to message: ");
					scanf("%s", to);
					fprintf(stdout, "What is your message: ");
					fflush(stdout);
					read_from_console (msg);

					for (int i = 0; i < max_sockets_num; ++i) {
						if (strcmp(msg_to[i], to) == 0) {
							// write on the ssl connection.
							fprintf(stdout, "\n");
							SSL_write(ssl[i], msg, strlen(msg)+1);
							break;
						}
					}
				}

				for (int i = 0; i < max_sockets_num; ++i) {
					sock_desc = sockets[i];
					int read_blocked;
					int bytes_read;
					int ssl_error;

					if(sock_desc > 0 && FD_ISSET(sock_desc, &fds)) {
						do  {
							read_blocked = 0;
							bytes_read = SSL_read(ssl[i], read_buffer, sizeof(read_buffer));
							fprintf(stdout, "\n\nReceived message from: %s\n", msg_to[i]);
							fprintf(stdout, "\nMessage: %s\n\n", read_buffer);

							//check SSL errors
							switch(ssl_error = SSL_get_error(ssl[i],bytes_read)){
								case SSL_ERROR_NONE:
									//do our stuff with buffer_array here
								break;
								
								case SSL_ERROR_ZERO_RETURN:		
									//connection closed by client, clean up
								break;
								
								case SSL_ERROR_WANT_READ:
									//the operation did not complete, block the read
									read_blocked = 1;
								break;
								
								case SSL_ERROR_WANT_WRITE:
									//the operation did not complete
								break;
								
								case SSL_ERROR_SYSCALL:
									//some I/O error occured (could be caused by false start in Chrome for instance), disconnect the client and clean up
								break;
												
								default:
									//some other error, clean up
									break;

							}
						} while (SSL_pending(ssl[i]) && !read_blocked);
					}
				}
			}
		}
		else if (choice == 2) {
			fprintf(stdout, "\nExiting from Chat Portal.\n");
		}
		else {
			fprintf(stdout, "\nInvalid choice. Please try again.\n");
		}
	} while (choice != 2 && logout != 1);
}

int main() {
	int choice;

	do {
		fprintf(stdout, "\n----------Welcome----------\n\n");
		fprintf(stdout, "Press 1 and hit Enter - to send CSR to CA\n");
		fprintf(stdout, "Press 2 and hit Enter - to go to Chat Portal\n");
		fprintf(stdout, "Press 3 and hit Enter - to Exit\n\n");
		
		fprintf(stdout, "Enter your choice: ");
		fscanf(stdin, "%d", &choice);

		if (choice == 1) {
			char common_name[50];
			char country_code[3];
			char organization_name[50];

			fprintf(stdout, "\nPlease provide some information before sending CSR ");
			fprintf(stdout, "(Certificate Signing Request) to CA.\n\n");

			fprintf(stdout, "Chat Portal Username (without spaces): ");
			fscanf(stdin, "%s", common_name);

			/* Country code should be of only 2 characters. */
			fprintf(stdout, "Country Code (only 2 characters (Ex: IN)): ");
			fscanf(stdin, "%s", country_code);

			fprintf(stdout, "Organization Name (spaces allowed): ");
			fflush(stdout);
			/* Going via this approach because fscanf or scanf doesn't take spaces. */
			read_from_console (organization_name);
			
			/* Send CSR (Certificate Signing Request) to CA */
			int ret = csr(common_name, country_code, organization_name);

			if (ret == 1) {
				fprintf(stdout, "\nCertificate generated and signed by CA.\n");
			}
			else if (ret == 0) {
				fprintf(stdout, "\nCertificate already exists and is not expired.\n");	
			}
			else {
				fprintf(stdout,
					"\nError : Unable to generate and sign certificate by CA. Please try again.\n");	
			}
		}
		else if (choice == 2) {
			communication();
		}
		else if (choice == 3) {
			fprintf(stdout, "\nExiting.\n");
		}
		else {
			fprintf(stdout, "\nInvalid choice. Please try again.\n");
		}
	} while (choice != 3);
}