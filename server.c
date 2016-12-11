#include "header/common_header.h"
#include "header/server_header.h"

int main(void) {
	int i;

	// Initiallizes the server, i.e, start server to listen for login connections.
	initialize_server();

	while(1) {
		// Clear the socket set.
		FD_ZERO(&fds);

		// Add the login socket to the set.
		FD_SET(ser_sockfd, &fds);
		
		max_sd = ser_sockfd;

		// Add login sockets to fd_set.
		for (i = 0 ; i < max_sockets_num ; i++) {
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

		/* Wait for an activity on the login sockets, timeout is NULL, so wait indefinitely.
		when a socket is ready to be read, select will return and fds will have those sockets
		which are ready to be read. */
		select(max_sd + 1, &fds, NULL, NULL, NULL);

		// If something happened on the login socket.
		if(FD_ISSET(ser_sockfd, &fds)) {
			/*
				Accept the connection from the client.
			*/
			cli_sock_len = sizeof(cli_sock);
			cli_sockfd = accept(ser_sockfd, (struct sockaddr *)&cli_sock, &cli_sock_len);

			if(cli_sockfd < 0) {
				fprintf(stderr, "ERROR in accepting the connection.\n");
				exit(1);
			}
			// Server cannot process the incoming login request.
			else if(cur_sockets_num >= max_sockets_num) {
				bzero(write_buffer, 1025);
				strcpy(write_buffer, "-1\0");
				
				write_msg = write(cli_sockfd, write_buffer, strlen(write_buffer));

				if(write_msg < 0) {
					fprintf(stderr, "ERROR in sending 'server too busy' ACK to the client.\n");
					exit(1);
				}
				else {
					fprintf(stdout, "'server too busy' ACK sent to the client.\n\n");
				}
			}
			// Connection Accepted. Send ACK to the client.
			else {
				bzero(write_buffer, 1025);
				strcpy(write_buffer, "Connection Accepted. Client OK to login.\0");
				fprintf(stdout, "%s\n", write_buffer);
				write_msg = write(cli_sockfd, write_buffer, strlen(write_buffer));

				if(write_msg < 0) {
					fprintf(stderr, "ERROR in sending login ACK to the client.\n");
					exit(1);
				}
				else {
					fprintf(stdout, "Login ACK sent to the client.\n\n");
				}

				// Add new socket to array of sockets.
				for (i = 0; i < max_sockets_num; i++) {
					// If position is empty, add the new socket.
					if(sockets[i] == 0) {
						sockets[i] = cli_sockfd;
						cur_sockets_num++;
						break;
					}
				}
			}
		}

		// Else its some IO operation on some other socket.
		for (i = 0; i < max_sockets_num; i++) {
			sock_desc = sockets[i];

			// If there is something on the socket to be read.
			if(FD_ISSET(sock_desc, &fds)) {
				bzero(read_buffer, 1025);
				read_msg = read(sock_desc, read_buffer, 1024);
				
				// Check if it was for closing, if user presses ctrl+c or closes the terminal
				if(read_msg == 0) {
					close(sock_desc);
					sockets[i] = 0;
				}
				else if(read_msg > 0) {
					// Read message sent from the client.
					// Splitting the string on delimiter :
					const char delim[2] = ":";
					char * id;

					id = strtok(read_buffer, delim);

					// id = 1 means user wants to login.
					if(strcmp(id, "1") == 0) {
						char * username = strtok(NULL, delim);
						char * password = strtok(NULL, delim);

						int j;
						// Log user as logged-in in loggedin_users array.
						for (j = 0; j < max_sockets_num; j++) {
							// If position is empty.
							if(strcmp(loggedin_users[j], "\0") == 0) {
								strcpy(loggedin_users[j], username);
								strcat(loggedin_users[j], "\0");
								loggedin_users_sfd[j] = sock_desc;
								break;
							}
						}

						bzero(write_buffer, 1025);
						strcpy(write_buffer, int_to_str(ip_num));
						ip_num++;

						write_msg = write(sock_desc, write_buffer, strlen(write_buffer));

						if(write_msg < 0) {
							fprintf(stderr, "ERROR in sending login ACK to the client.\n");
							exit(1);
						}
						else {
							fprintf(stdout, "Login ACK sent to the client.\n\n");
						}
					}
					// id = 2 means user wants to logout.
					else if(strcmp(id, "2") == 0) {
						char * username = strtok(NULL, delim);
						
						int j;
						// Remove user from loggedin_users array.
						for (j = 0; j < max_sockets_num; j++) {
							// If username is found.
							if(strcmp(loggedin_users[j], username) == 0) {
								strcpy(loggedin_users[j], "\0");
								loggedin_users_sfd[j] = 0;
								break;
							}
						}

						bzero(write_buffer, 1025);
						strcpy(write_buffer, "Successfully logged out.\0");

						write_msg = write(sock_desc, write_buffer, strlen(write_buffer));

						if(write_msg < 0) {
							fprintf(stderr, "ERROR in sending logout ACK to the client.\n");
							exit(1);
						}
						else {
							fprintf(stdout, "Logout ACK sent to the client.\n\n");
						}

						// Close the socket if user wants to logout.
						// Mark as 0 in sockets array for reuse.
						close(sock_desc);
						sockets[i] = 0;
						cur_sockets_num--;
					}
					// id = 3 means user has sent "chat" command
					else if(strcmp(id, "3") == 0) {
						char * from = strtok(NULL, delim);
						char * to = strtok(NULL, delim);
						
						int j, is_online = 0, sfd;

						// Check whether the receiver is online or not.
						for (j = 0; j < max_sockets_num; j++) {
							// If user is online.
							if(strcmp(loggedin_users[j], to) == 0) {
								is_online = 1;
								sfd = loggedin_users_sfd[j];
								break;
							}
						}

						if(!is_online) {
							// Tell sender that receiver is not online
							bzero(write_buffer, 1025);
							strcpy(write_buffer, to);
							strcat(write_buffer, " is not online.\0");

							write_msg = write(sock_desc, write_buffer, strlen(write_buffer));

							if(write_msg < 0) {
								fprintf(stderr, "ERROR in sending chat fail ACK to the sender %s.\n", from);
								exit(1);
							}
							else {
								fprintf(stdout, "Chat fail sent ACK to the sender %s\n\n", from);
							}

							continue;
						}

						// Message being forwarded from server to the receiver.
						bzero(write_buffer, 1025);
						strcpy(write_buffer, "1:");
						strcat(write_buffer, from);
						strcat(write_buffer, "\0");

						write_msg = write(sfd, write_buffer, strlen(write_buffer));

						if(write_msg < 0) {
							fprintf(stderr, "ERROR in sending chat request to the receiver %s.\n", to);
							exit(1);
						}
						else {
							fprintf(stdout, "Chat request sent to the receiver %s.\n\n", to);
						}

						// Sending ACK to the sender.
						bzero(write_buffer, 1025);
						strcpy(write_buffer, "Chat request sent successfully.");
						strcat(write_buffer, "\0");

						write_msg = write(sock_desc, write_buffer, strlen(write_buffer));

						if(write_msg < 0) {
							fprintf(stderr, "ERROR in sending chat request ACK to the sender %s.\n", from);
							exit(1);
						}
						else {
							fprintf(stdout, "Chat request ACK sent to the sender %s.\n\n", from);
						}
					}
					// id = 4 means user has sent reply for chat request.
					else if(strcmp(id, "4") == 0) {
						char * from = strtok(NULL, delim);
						char * to = strtok(NULL, delim);
						char * ip_addr = strtok(NULL, delim);
						char * port = strtok(NULL, delim);

						int j, sfd;

						for (j = 0; j < max_sockets_num; j++) {
							if(strcmp(loggedin_users[j], to) == 0) {
								sfd = loggedin_users_sfd[j];
								break;
							}
						}
						
						// Message being forwarded from server to the receiver.
						bzero(write_buffer, 1025);
						strcpy(write_buffer, "2:");
						strcat(write_buffer, from);
						strcat(write_buffer, ":");
						strcat(write_buffer, ip_addr);
						strcat(write_buffer, ":");
						strcat(write_buffer, port);
						strcat(write_buffer, "\0");

						write(sfd, write_buffer, strlen(write_buffer));

						// Sending ACK to the sender.
						bzero(write_buffer, 1025);
						strcpy(write_buffer, "Reply to chat request from ");
						strcat(write_buffer, to);
						strcat(write_buffer, " sent successfully.");
						strcat(write_buffer, "\0");

						write(sock_desc, write_buffer, strlen(write_buffer));
					}
				}
			}
		}
	}
}