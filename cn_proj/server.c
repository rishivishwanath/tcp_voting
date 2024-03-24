#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_LENGTH 100 // Maximum length for string inputs

// Function to check name and ID in a file
int checkNameAndID(const char *filename, const char *search_name, const char *search_id) {
    FILE *file = fopen(filename, "r"); // Open file for reading
    if (file == NULL) {
        printf("Could not open file %s\n", filename);
        return 0; // Return failure
    }

    char line[MAX_LENGTH]; // Buffer for reading lines from the file
    while (fgets(line, MAX_LENGTH, file) != NULL) { // Read each line
        // Split the line by comma
        char *name = strtok(line, ",");
        char *id_str = strtok(NULL, ",");
        if (name != NULL && id_str != NULL) {
            name[strcspn(name, "\n")] = '\0'; // Remove newline character
            id_str[strcspn(id_str, "\n")] = '\0'; // Remove newline character
            if (strcmp(name, search_name) == 0 && strcmp(id_str, search_id) == 0) {
                fclose(file);
                return 1; // Return success
            }
        }
    }
    fclose(file);
    return 0; // Return failure
}

// Function to append data to a file
void appendToFile(const char *filename, const char *name, const char *id, const char *symbol) {
    FILE *file = fopen(filename, "a"); // Open file for appending
    if (file == NULL) {
        printf("Could not open file %s\n", filename);
        return;
    }
    fprintf(file, "%s,%s,%s\n", name, id, symbol); // Write data to the file
    fclose(file);
}

// Function to extract the last string in a file and count occurrences
char* extract_last_string(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Error opening file");
        return NULL;
    }
    int eagle_count = 0;
    int star_count = 0;
    int flag_count = 0;
    char line[MAX_LENGTH];
    char last_string[MAX_LENGTH];

    while (fgets(line, sizeof(line), file) != NULL) {
        char *last_comma = strrchr(line, ',');
        strcpy(last_string, last_comma + 1);
        char *newline = strchr(last_string, '\n');
        if (newline != NULL) {
            *newline = '\0';
        }
        if(strcmp("EAGLE",last_string)==0)
            eagle_count++;
        else if(strcmp("STAR",last_string)==0)
            star_count++;
        else if(strcmp("FLAG",last_string)==0)
            flag_count++;     
    }
    fclose(file);
    char *count_string = malloc(100 * sizeof(char)); // Allocate memory for the string
    if (count_string == NULL) {
        perror("Memory allocation error");
        return NULL;
    }
    
    sprintf(count_string, "\nEAGLE count: %d \nSTAR count: %d \nFLAG count: %d", eagle_count, star_count, flag_count);
    
    return count_string;
}

// Structure for passing arguments to thread function
struct ThreadArgs {
    int client_sock;
    struct sockaddr_in client_addr;
    SSL *ssl;
};

// Function to handle client connections in a separate thread
void *processClient(void *args) {
    struct ThreadArgs *threadArgs = (struct ThreadArgs *)args;
    int client_sock = threadArgs->client_sock;
    struct sockaddr_in client_addr = threadArgs->client_addr;
    SSL *ssl = threadArgs->ssl;

    // Buffer for receiving and sending messages
    char server_message[2000], client_message[2000], NAME[2000], VID[2000];
    memset(server_message, '\0', sizeof(server_message));
    memset(client_message, '\0', sizeof(client_message));

    // Receiving name from client
    if (SSL_read(ssl, client_message, sizeof(client_message)) < 0) {
        printf("Couldn't receive\n");
        close(client_sock);
        free(threadArgs);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        pthread_exit(NULL);
    }
    strcpy(NAME, client_message);
    NAME[strlen(NAME) - 1] = '\0';
    printf("Msg from client: %s\n", NAME);

    // Receiving ID from client
    memset(client_message, 0, sizeof(client_message));
    if (SSL_read(ssl, client_message, sizeof(client_message)) < 0) {
        printf("Couldn't receive\n");
        close(client_sock);
        free(threadArgs);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        pthread_exit(NULL);
    }
    strcpy(VID, client_message);
    VID[strlen(VID) - 1] = '\0';
    printf("Msg from client: %s\n", VID);
    memset(client_message, 0, sizeof(client_message));

    // Check if voter is eligible and hasn't voted already
    int check1 = checkNameAndID("voters_list.txt", NAME, VID);
    int check2 = checkNameAndID("voted_list.txt", NAME, VID);
    if (check1 == 1 && check2 != 1) {
        printf("Found\n");
        char server_message[2000], client_message[2000];
        memset(server_message, '\0', sizeof(server_message));
        memset(client_message, '\0', sizeof(client_message));
        
        // Send welcome message to client
        strcpy(server_message, "Welcome");
        if (SSL_write(ssl, server_message, strlen(server_message)) < 0) {
            printf("Can't send\n");
            close(client_sock);
            free(threadArgs);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            pthread_exit(NULL);
        }

        // Receive symbol from client and append to voted list
        if (SSL_read(ssl, client_message, sizeof(client_message)) < 0) {
            printf("Couldn't receive\n");
            close(client_sock);
            free(threadArgs);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            pthread_exit(NULL);
        }
        if (client_message != NULL) {
            appendToFile("voted_list.txt", NAME, VID, client_message);
            printf("Output Done\n\n\n\n\n");
        }
        
        // Extract counts and send to client
        char *buff = extract_last_string("voted_list.txt");
        strcpy(server_message, buff);
        free(buff);

        if (SSL_write(ssl, server_message, strlen(server_message)) < 0) {
            printf("Can't send\n");
            close(client_sock);
            free(threadArgs);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            pthread_exit(NULL);
        }
    } else {
        printf("Not Found, Server will shut down\n");
        char server_message[2000];
        memset(server_message, '\0', sizeof(server_message));
        strcpy(server_message, "\nVOTER NOT ELIGIBLE TO VOTE\n");
        if (SSL_write(ssl, server_message, strlen(server_message)) < 0) {
            printf("Can't send\n");
            close(client_sock);
            free(threadArgs);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            pthread_exit(NULL);
        }
        exit(EXIT_FAILURE);
    }

    close(client_sock);
    free(threadArgs);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    pthread_exit(NULL);
}

int main() {
    int socket_desc, client_sock, client_size;
    struct sockaddr_in server_addr, client_addr;

    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Create SSL context
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Load certificate
    if (SSL_CTX_use_certificate_file(ssl_ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Load private key
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Create socket
    socket_desc = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_desc < 0) {
        printf("Error while creating socket\n");
        exit(EXIT_FAILURE);
    }
    printf("Socket created successfully\n");

    // Configure server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(2000);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Bind socket
    if (bind(socket_desc, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        printf("Couldn't bind to the port\n");
        exit(EXIT_FAILURE);
    }
    printf("Done with binding\n");

    // Listen for connections
    if (listen(socket_desc, 1) < 0) {
        printf("Error while listening\n");
        exit(EXIT_FAILURE);
    }
    printf("\nListening for incoming connections.....\n");

    // Accept incoming connections and create threads to handle them
    while (1) {
        client_size = sizeof(client_addr);
        client_sock = accept(socket_desc, (struct sockaddr *)&client_addr, &client_size);
        if (client_sock < 0) {
            printf("Can't accept\n");
            exit(EXIT_FAILURE);
        }
        printf("Client connected at IP: %s and port: %i\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        // Create SSL object
        SSL *ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, client_sock);

        // Perform SSL handshake
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            close(client_sock);
            SSL_free(ssl);
            continue;
        }

        // Create thread arguments
        struct ThreadArgs *threadArgs = (struct ThreadArgs *)malloc(sizeof(struct ThreadArgs));
        if (threadArgs == NULL) {
            perror("Memory allocation error");
            exit(EXIT_FAILURE);
        }
        threadArgs->client_sock = client_sock;
        threadArgs->client_addr = client_addr;
        threadArgs->ssl = ssl;

        // Create thread to handle client
        pthread_t thread;
        if (pthread_create(&thread, NULL, processClient, (void *)threadArgs) != 0) {
            perror("Error creating thread");
            exit(EXIT_FAILURE);
        }

        pthread_detach(thread);
    }

    // Close socket and free resources
    close(socket_desc);
    SSL_CTX_free(ssl_ctx);
    EVP_cleanup();
    ERR_free_strings();
    return 0;
}

