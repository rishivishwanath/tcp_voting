#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int main(void)
{
    int socket_desc;
    struct sockaddr_in server_addr;
    char server_message[2000], client_message[2000];

    // Clean buffers:
    memset(server_message, '\0', sizeof(server_message));
    memset(client_message, '\0', sizeof(client_message));

    // Initialize OpenSSL
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    // Create SSL context
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) {
        printf("Error creating SSL context\n");
        exit(EXIT_FAILURE);
    }

    // Create socket:
    socket_desc = socket(AF_INET, SOCK_STREAM, 0);

    if (socket_desc < 0) {
        printf("Unable to create socket\n");
        exit(EXIT_FAILURE);
    }

    printf("Socket created successfully\n");

    // Set port and IP the same as server-side:
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(2000);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Send connection request to server:
    if (connect(socket_desc, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        printf("Unable to connect\n");
        exit(EXIT_FAILURE);
    }
    printf("Connected with server successfully\n");

    // Create SSL object
    SSL *ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        printf("Error creating SSL structure\n");
        close(socket_desc);
        SSL_CTX_free(ssl_ctx);
        exit(EXIT_FAILURE);
    }

    // Attach SSL to the socket
    if (SSL_set_fd(ssl, socket_desc) <= 0) {
        printf("Error attaching SSL to socket\n");
        SSL_free(ssl);
        close(socket_desc);
        SSL_CTX_free(ssl_ctx);
        exit(EXIT_FAILURE);
    }

    // SSL Handshake
    if (SSL_connect(ssl) <= 0) {
        printf("SSL handshake error\n");
        SSL_free(ssl);
        close(socket_desc);
        SSL_CTX_free(ssl_ctx);
        exit(EXIT_FAILURE);
    }

    // send name
    printf("Enter Name (with exact punctuation): ");
    fgets(client_message, sizeof(client_message), stdin);

    // Send the message to server:
    if (SSL_write(ssl, client_message, strlen(client_message)) < 0) {
        printf("Unable to send message\n");
        exit(EXIT_FAILURE);
    }

    // send VOTER ID
    printf("Enter VOTER ID: ");
    fgets(client_message, sizeof(client_message), stdin);

    // Send the message to server:
    if (SSL_write(ssl, client_message, strlen(client_message)) < 0) {
        printf("Unable to send message\n");
        exit(EXIT_FAILURE);
    }

    // Receive the server's response:
    if (SSL_read(ssl, server_message, sizeof(server_message)) < 0) {
        printf("Error while receiving server's msg\n");
        exit(EXIT_FAILURE);
    }
    printf("\n\n\nServer's response: %s\n", server_message);
    char hi[100];
    strcpy(hi, server_message);

    if (strcmp(hi, "Welcome") == 0) {
        printf("\nThe Candidates of each party are:\n\n");
        printf("Michael Lee :: (Symbol: EAGLE)\n");
        printf("Emily Smith :: (Symbol: STAR)\n");
        printf("David Brown :: (Symbol: FLAG)\n");
        int m;
        char *message;
    l1:
        printf("Enter 1 to vote for EAGLE, \nEnter 2 to vote for STAR ,\nEnter 3 to vote for FLAG \n\n");
        scanf("%d", &m);
        switch (m) {
            case 1:
                message = "EAGLE";
                break;
            case 2:
                message = "STAR";
                break;
            case 3:
                message = "FLAG";
                break;
            default:
                printf("invalid number");
                goto l1;
                break;
        }
        printf("\n\n%s", message);
        memset(client_message, 0, sizeof(client_message));
        strcpy(client_message, message);
        if (SSL_write(ssl, client_message, strlen(client_message)) < 0) {
            printf("Unable to send message\n");
            exit(EXIT_FAILURE);
        }

        printf("\n\n");
        printf("\nCurrent results:\n\n");
        if (SSL_read(ssl, server_message, sizeof(server_message)) < 0) {
            printf("Error while receiving server's msg\n");
            exit(EXIT_FAILURE);
        }
        printf("\n\nServer's response: %s\n", server_message);
        
        printf("\n\n 	Thank you for your visit. Happy Voting\n");

    } else {
        printf("\n\nWe couldn't find your information or vote under this id is already casted. \nPlease re-check your credentials at Indian Voter Service Portal(IVSP), by visiting www.ivsp.gov.in \n\n");
        printf("\n\n 	Thank you for your visit. Happy Voting\n");
    }

    // Close SSL connection and free SSL context
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);

    // Close socket
    close(socket_desc);

    return 0;
}
