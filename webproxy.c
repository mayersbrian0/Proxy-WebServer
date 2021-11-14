/*
Web Proxy
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>      
#include <strings.h>    
#include <unistd.h>      
#include <sys/socket.h>  
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/stat.h>
#include <time.h>

#define MAX_URL_SIZE 500
#define MAX_REQ_SIZE 1024
#define PACKET_SIZE 1024

typedef enum {
    BAD_REQUEST,
    NOT_FOUND,
} ERROR;

//pass mutex and connection fd for threads
typedef struct {

} thread_args;

//hold req info
typedef struct {

} HTTP_REQUEST;

//holds get info
typedef struct {
    
} HTTP_RESPONSE;

/*
Function to bind the server to a port
*/
int open_serverfd(int port) {

    int serverfd, optval=1;
    struct sockaddr_in serveraddr;
  
    /* Create a socket descriptor */
    if ((serverfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) return -1;

    //Get rid of "already in use" error
    if (setsockopt(serverfd, SOL_SOCKET, SO_REUSEADDR,  (const void *)&optval , sizeof(int)) < 0) return -1;

    //bulild serveraddr
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET; 
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY); 
    serveraddr.sin_port = htons((unsigned short)port); 
    if (bind(serverfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) < 0) return -1;

    //reading to accept connection requests
    if (listen(serverfd, 1024) < 0) return -1;
    printf("Proxy Server Listening on Port: %d\n", port);

    return serverfd;
}


void handle_error(int connection_fd, ERROR e) {
    printf("IN ERROR %d\n", e);
}

/*
Sets up a new TCP connection for with the intended server
*/
int contact_server(char *http_req, struct hostent* host, char* url, int port_num, int connection_fd, int req_size) {
    int sockfd, connfd;
    struct sockaddr_in servaddr, cli;
    char file_contents[PACKET_SIZE];
    ssize_t n = 0;
    FILE *fp;
    fp = fopen("index.html", "wb+");

    //setup TCP connection with server
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) return -1;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    memcpy(&servaddr.sin_addr, host->h_addr_list[0], host->h_length);
    servaddr.sin_port = htons(port_num);
    if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) != 0) return -1;

    //pass on http_req to server
    write(sockfd, http_req, req_size);

    /*
    Parse the http response
    */
    
   
    //get the file(s) from the server
    n =1;
    while (n != 0) {
        memset(file_contents, 0, PACKET_SIZE);
        n = read(sockfd, file_contents, PACKET_SIZE);
        write(connection_fd, 1, n);
        printf("%d\n", n);
    }
}

/*
Function parses http req from client and then retransmits it to the server
*/
void get_req(int connection_fd) {
    char method[10], url[MAX_URL_SIZE], new_url[MAX_URL_SIZE], version[10]; //retrieve relevant info about the request
    char http_req[MAX_REQ_SIZE];
    struct hostent* host;
    int i = 0, port_num = 80, content_len;

    memset(http_req, 0, MAX_REQ_SIZE);
    int n = read(connection_fd, http_req, MAX_REQ_SIZE);
    //get relevant info and check if its a GET request (only get supported)
    if (sscanf(http_req, "%s %s %s", method, url, version) != 3)  { handle_error(connection_fd, BAD_REQUEST); return; }
    if (strncmp(method, "GET", 3) != 0) { handle_error(connection_fd, BAD_REQUEST); return; }

    //Extract hostname from the request (assume http only)
    if (strncmp("http://", url, 7) == 0) {
        memcpy(url, url+7, strlen(url));
        i = strcspn(url, "/");
    }

    i = strcspn(url, "/");
    memmove(new_url, url, i); 
    new_url[i] = '\0';

    //get port number and find out the name of the host server
    for (char* p = new_url; *p; p++) {
        if (*p == ':') {
            port_num = atoi(p +1); //get the port number 
            *p = '\0'; //null out port info
            break;
        }
    }


    //check if a valid hostname
    if ((host = gethostbyname(new_url)) == NULL) { handle_error(connection_fd, NOT_FOUND); return; }

    //send new HTTP message
    if ( contact_server(http_req, host, url, port_num, connection_fd, n) == -1) exit(0);
    //printf("%s\n", method);
    //printf("%s\n", url);
    //printf("%s\n", version);
}

/*
thread routine
*/
void *handle_connection(void *thread_args) {
    int connection_fd = *((int *)thread_args);
    pthread_detach(pthread_self()); //no need to call pthread_join()
    free(thread_args); //free space
    get_req(connection_fd);
    close(connection_fd); //client can now stop waiting
    return NULL;
}


int main(int argc, char** argv) {
    
    int serverfd, *connect_fd, port, clientlen=sizeof(struct sockaddr_in);
    struct sockaddr_in clientaddr;
    char *ptr;
    pthread_t thread_id;

    if (argc < 2) {
        fprintf(stderr, "Usage %s <port> <timeout>\n", argv[0]);
        exit(0);
    }

    port = strtol(argv[1], &ptr, 10);
    if (*ptr != '\0' || port <= 1024) { printf("Invalid Port Number\n"); exit(0); } //check for errors

    serverfd = open_serverfd(port);
    if (serverfd < 0) { printf("Error connecting to port %d\n", port); exit(0); }
    //server terminates on ctl-c
    while (1) {
        connect_fd = malloc(sizeof(int)); //allocate space for pointer
        *connect_fd = accept(serverfd, (struct sockaddr *)&clientaddr, &clientlen); //start accepting requests
        pthread_create(&thread_id, NULL, handle_connection, connect_fd); //pass new file descripotr to thread routine
    }
    return 0;
}