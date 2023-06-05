#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>
#include <sys/types.h>
#include <math.h>
#include <ctype.h>

#define DEBUG 0
#define BUF_SIZE 8
#define PORT 8000
#define PORT2 8001
#define BLOCK_SIZE 8
#define KEY_SIZE 16
#define MAX_LEN 1024
#define MAXSIZE 1000000
#define M_ITERATION 15

typedef struct GlobalInfo
{
    int prime;
    int generator;
} GlobalInfo;

int main(int argc, char **argv);

int GeneratePrime();
int GeneratePrimitiveRoot(int p);
int MillerRabinTest(int value, int iteration);
int compute_exp_modulo(int a, int b, int p);
void run_server();
void run_client();
void encrypt(unsigned char *plaintext, unsigned char *key, unsigned char *ciphertext);
void decrypt(unsigned char *ciphertext, unsigned char *key, unsigned char *plaintext);

int main(int argc, char **argv)
{

    if (argc != 2)
    {
        printf("Usage: %s <option>\n", argv[0]);
        printf("Options:\n");
        printf("\t-S: Start as server\n");
        printf("\t-c <message>: Start as client and send <message>\n");
        return -1;
    }

    if (strcmp(argv[1], "-S") == 0)
    {
        printf("Starting as server...\n");
        run_server();
    }
    else if (strcmp(argv[1], "-c") == 0)
    {
        run_client();
    }
    else
    {
        printf("Invalid option\n");
        return -1;
    }

    return 0;
}

void run_server()
{
    int server_fd, new_socket, valread;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[BUF_SIZE];
    unsigned char decrypted_plaintext[BLOCK_SIZE];

    GlobalInfo g;

    // Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Set socket options
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // Bind socket to port
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (DEBUG)
    {
        printf("Listen for connection\n", NULL);
    }
    //  Listen for connections
    if (listen(server_fd, 3) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    // Accept incoming connections and receive messages
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0)
    {
        perror("accept");
        exit(EXIT_FAILURE);
    }
    if (DEBUG)
    {
        printf("Accepted connection\n", NULL);
    }
    int data[3];
    if (recv(new_socket, data, sizeof(data), 0) < 0)
    {
        perror("recv() failed");
        exit(1);
    }
    if (DEBUG)
    {
        printf("Recieved data on 8000\n", NULL);
    }
    int client_public_key = data[0];
    g.generator = data[1];
    g.prime = data[2];

    if (DEBUG)
    {
        printf("Client public key %d\n", client_public_key);
    }
    /* Compute shared key and caesar key */ /* public key is clients*/
    /* Generate server private key and public key */
    int server_private_key = rand() % (g.prime - 1) + 1;
    if (DEBUG)
    {
        printf("*** Server private key : %d\n", server_private_key);
    }
    int server_public_key = compute_exp_modulo(g.generator, server_private_key, g.prime);
    int server_shared_key = compute_exp_modulo(client_public_key, server_private_key, g.prime);
    printf("**** Server Shared key : %d\n", server_shared_key);

    if (DEBUG)
    {
        printf("**** Server public key : %d\n\n", server_public_key);
    }
    int sockfd_client;
    struct sockaddr_in servaddr;
    if (DEBUG)
    {
        printf("Creating a socket for %s\n", PORT2);
    }
    //  Create a socket for the client
    sockfd_client = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd_client == -1)
    {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    if (DEBUG)
    {
        printf("Created socket for %s \n", PORT2);
    }
    //  Set the server address
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(PORT2);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, "127.0.0.1", &servaddr.sin_addr) <= 0)
    {
        perror("inet_pton error occured");
        exit(EXIT_FAILURE);
    }
    if (DEBUG)
    {
        printf("Connecting to PORT2\n", NULL);
    }
    //  Connect to the server
    if (connect(sockfd_client, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0)
    {
        perror("connection with the server failed");
        exit(EXIT_FAILURE);
    }
    sleep(2);
    if (DEBUG)
    {
        printf("sending data \n", NULL);
    }
    int data1[1] = {server_public_key};
    // send public key
    if (send(sockfd_client, data1, sizeof(data1), 0) < 0)
    {
        perror("send() failed");
        exit(1);
    }

    sleep(2);
    close(sockfd_client);
    printf("Received message: ");
    while (1)
    {
        // Receive 8-byte string from client
        memset(buffer, 0, sizeof(buffer));
        valread = read(new_socket, buffer, sizeof(buffer));

        if (valread < 0)
        {
            perror("read");
            exit(EXIT_FAILURE);
        }

        if (valread == 0)
        {
            printf("Connection closed by client\n");
            break;
        }
        unsigned char str_server_shared_key[KEY_SIZE];
        sprintf(str_server_shared_key, "%d", server_shared_key % 10000);
        decrypt(buffer, str_server_shared_key, decrypted_plaintext);
        printf("%.7s", decrypted_plaintext);
    }

    close(new_socket);
    close(server_fd);
}

void run_client()
{
    int sockfd;
    struct sockaddr_in servaddr1;
    // Create a socket for the client
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Set the server address
    memset(&servaddr1, 0, sizeof(servaddr1));
    servaddr1.sin_family = AF_INET;
    servaddr1.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, "127.0.0.1", &servaddr1.sin_addr) <= 0)
    {
        perror("inet_pton error occured");
        exit(EXIT_FAILURE);
    }
    // Connect to the server
    if (connect(sockfd, (struct sockaddr *)&servaddr1, sizeof(servaddr1)) != 0)
    {
        perror("connection with the server failed");
        exit(EXIT_FAILURE);
    }
    if (DEBUG)
    {
        printf("connected to the server\n", NULL);
    }
    //  DIFFIE HELLMAN

    /* Generate a prime number and its primitive root (publicly known) */
    GlobalInfo g1;
    g1.prime = GeneratePrime();
    if (DEBUG)
    {
        printf("** Global prime - %d\n", g1.prime);
    }
    g1.generator = GeneratePrimitiveRoot(g1.prime);
    if (DEBUG)
    {
        printf("** Global primitive root - %d\n\n", g1.generator);
    }
    /* Choose a private key for the client */
    int private_key = rand() % (g1.prime - 1) + 1;
    int public_key = compute_exp_modulo(g1.generator, private_key, g1.prime);
    if (DEBUG)
    {
        printf("*** Client private key : %d\n", private_key);
    }
    if (DEBUG)
    {
        printf("*** Client public key : %d\n\n", public_key);
    }

    if (DEBUG)
    {
        printf("Send data on 8000\n", NULL);
    }
    int data[3] = {public_key, g1.generator, g1.prime};

    if (send(sockfd, data, sizeof(data), 0) < 0)
    {
        perror("send() failed");
        exit(1);
    }
    if (DEBUG)
    {
        printf("finished sending data\n", NULL);
    }
    // Recieve server public key
    int server_fd1,
        new_socket1;
    int opt1 = 1;
    struct sockaddr_in address1;
    int addrlen1 = sizeof(address1);
    if (DEBUG)
    {
        printf("Create socket for PORT2\n", NULL);
    }
    //  Create socket file descriptor
    if ((server_fd1 = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    if (DEBUG)
    {
        printf("Set socket options for PORT2\n", NULL);
    }
    //  Set socket options
    if (setsockopt(server_fd1, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt1, sizeof(opt1)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // Bind socket to port
    address1.sin_family = AF_INET;
    address1.sin_addr.s_addr = INADDR_ANY;
    address1.sin_port = htons(PORT2);
    if (DEBUG)
    {
        printf("Binding on PORT2\n", NULL);
    }
    if (bind(server_fd1, (struct sockaddr *)&address1, sizeof(address1)) < 0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (DEBUG)
    {
        printf("listening on PORT2\n", NULL);
    }
    //  Listen for connections
    if (listen(server_fd1, 3) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    if (DEBUG)
    {
        printf("prepare for acceptnig data\n", NULL);
    }
    //  Accept incoming connections and receive messages
    if ((new_socket1 = accept(server_fd1, (struct sockaddr *)&address1, (socklen_t *)&addrlen1)) < 0)
    {
        perror("accept");
        exit(EXIT_FAILURE);
    }
    if (DEBUG)
    {
        printf("Accepted connection on PORT2\n", NULL);
    }
    if (DEBUG)
    {
        printf("Recv data on PORT2\n", NULL);
    }
    int data1_c[1];
    if (recv(new_socket1, data1_c, sizeof(data1_c), 0) < 0)
    {
        perror("recv() failed");
        exit(1);
    }
    int server_public_key = data1_c[0];
    if (DEBUG)
    {
        printf("Server public key %d \n ", server_public_key);
    }

    int client_shared_key = compute_exp_modulo(server_public_key, private_key, g1.prime);
    printf("***** Client Shared key : %d\n", client_shared_key);

    close(server_fd1);
    unsigned char str_client_shared_key[KEY_SIZE];
    sprintf(str_client_shared_key, "%d", client_shared_key % 10000);

    // Continuously take input from the user and send to the server
    char buffer[BUF_SIZE];
    unsigned char ciphertext[BLOCK_SIZE];

    printf("Enter a string: ");
    while (1)
    {
        fgets(buffer, 6, stdin);
        printf("Input : %s\n", buffer);

        encrypt(buffer, str_client_shared_key, ciphertext);

        // Send 8-byte chunks of the string to the server
        int i;
        for (i = 0; i < strlen(ciphertext); i += 8)
        {
            if (write(sockfd, ciphertext + i, 8) == -1)
            {
                perror("write error occured");
                exit(EXIT_FAILURE);
            }
        }

        // Check if the user wants to quit
        if (strncmp(buffer, "quit", 4) == 0)
        {
            break;
        }
    }

    // Close the socket
    close(sockfd);
}

// Define the encryption function
void encrypt(unsigned char *plaintext, unsigned char *key, unsigned char *ciphertext)
{
    // Create a copy of the plaintext
    unsigned char block[BLOCK_SIZE];
    memcpy(block, plaintext, BLOCK_SIZE);

    // Perform the XOR operation with the key
    for (int i = 0; i < BLOCK_SIZE; i++)
    {
        block[i] ^= key[i % KEY_SIZE];
    }

    // Copy the result into the ciphertext
    memcpy(ciphertext, block, BLOCK_SIZE);
}

// Define the decryption function
void decrypt(unsigned char *ciphertext, unsigned char *key, unsigned char *plaintext)
{
    // Create a copy of the ciphertext
    unsigned char block[BLOCK_SIZE];
    memcpy(block, ciphertext, BLOCK_SIZE);

    // Perform the XOR operation with the key
    for (int i = 0; i < BLOCK_SIZE; i++)
    {
        block[i] ^= key[i % KEY_SIZE];
    }

    // Copy the result into the plaintext
    memcpy(plaintext, block, BLOCK_SIZE);
}
/* Function to compute (a ^ b) mod p */
int compute_exp_modulo(int a, int b, int p)
{
    long long x = 1, y = a;
    while (b > 0)
    {
        if (b % 2 == 1)
            x = (x * y) % p;
        y = (y * y) % p;
        b /= 2;
    }
    return (int)(x % p);
}

/* Function to check primality of random generated numbers using Miller-Rabin Test */
int MillerRabinTest(int value, int iteration)
{
    if (value < 2)
        return 0;
    int q = value - 1, k = 0;
    while (!(q % 2))
    {
        q /= 2;
        k++;
    }
    for (int i = 0; i < iteration; i++)
    {
        int a = rand() % (value - 1) + 1;
        int current = q;
        int flag = 1;
        int mod_result = compute_exp_modulo(a, current, value);
        for (int i = 1; i <= k; i++)
        {
            if (mod_result == 1 || mod_result == value - 1)
            {
                flag = 0;
                break;
            }
            mod_result = (int)((long long)mod_result * mod_result % value);
        }
        if (flag)
            return 0;
    }
    return 1;
}

/* Generate a prime number that is going to be shared
 * globally between client and server
 */
int GeneratePrime()
{
    if (DEBUG)
    {
        printf("* Running Miller-Rabin test to find a large prime number...\n\n", NULL);
    }
    srand(time(NULL));
    while (1)
    {
        int current_value = rand() % INT_MAX;
        if (!(current_value % 2))
            current_value++;
        if (MillerRabinTest(current_value, M_ITERATION) == 1)
            return current_value;
    }
}

/* Generate the primitive root by checking for random numbers */
int GeneratePrimitiveRoot(int p)
{
    /* Construct sieve of primes */
    int sieve[MAXSIZE];
    memset(sieve, 0, sizeof(sieve));
    sieve[0] = sieve[1] = 1;
    for (int i = 4; i < MAXSIZE; i += 2)
        sieve[i] = 1;
    for (int i = 3; i < MAXSIZE; i += 2)
    {
        if (!sieve[i])
        {
            for (int j = 2 * i; j < MAXSIZE; j += i)
                sieve[j] = 1;
        }
    }
    while (1)
    {
        int a = rand() % (p - 2) + 2;
        int phi = p - 1, flag = 1, root = sqrt(phi);
        for (int i = 2; i <= root; i++)
        {
            if (!sieve[i] && !(phi % i))
            {
                int mod_result = compute_exp_modulo(a, phi / i, p);
                if (mod_result == 1)
                {
                    flag = 0;
                    break;
                }
                if (MillerRabinTest(phi / i, M_ITERATION) && !(phi % (phi / i)))
                {
                    int mod_result = compute_exp_modulo(a, phi / (phi / i), p);
                    if (mod_result == 1)
                    {
                        flag = 0;
                        break;
                    }
                }
            }
        }
        if (flag)
            return a;
    }
}
