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
#include <openssl/md5.h>

#define MAX_URL_SIZE 500
#define MAX_REQ_SIZE 8192
#define PACKET_SIZE 1024

pthread_mutex_t ip_mutex;

typedef enum {
    BAD_REQUEST,
    NOT_FOUND,
    FORBIDDEN
} ERROR;

//pass mutex and connection fd for threads
typedef struct {
    int conn_fd;
    pthread_mutex_t ip_mutex;
    pthread_mutex_t cache_mutex;
} thread_args;

//hold req info
typedef struct {
    char msg[MAX_REQ_SIZE];
    char method[10];
    char path[MAX_URL_SIZE];
    char version[15];
    char hostname[MAX_URL_SIZE];
    char full_url[MAX_URL_SIZE]; //gets full http:// url (we will cahce this value)
    int port;
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

/*
Get relevant HTTP REQ info
*/
void parse_req(char * http_req, HTTP_REQUEST *new_request, int connection_fd) {
    char url[MAX_URL_SIZE], new_url[MAX_URL_SIZE];
    int port_num = 80, i = 0, new_port = 0;

    if (sscanf(http_req, "%s %s %s", new_request->method, url, new_request->version) != 3)  { handle_error(connection_fd, BAD_REQUEST); return; }
    if (strncmp(new_request->method, "GET", 3) != 0) { handle_error(connection_fd, BAD_REQUEST); return; }

    strncpy(new_request->full_url, url, strlen(url));
    //Extract hostname from the request (assume http only)
    if (strncmp("http://", url, 7) == 0) {
        memcpy(url, url+7, strlen(url));
        i = strcspn(url, "/");
    }

    i = strcspn(url, "/");
    memcpy(new_url, url, i); 
    new_url[i] = '\0';
    memmove(url, url+i, strlen(url));
    strncpy(new_request->path, url, strlen(url));

    //get port number and find out the name of the host server
    for (char* p = new_url; *p; p++) {
        if (*p == ':') {
            port_num = atoi(p +1); //get the port number 
            *p = '\0'; //null out port info
            new_port = 1;
            break;
        }
    }

    strncpy(new_request->msg, http_req, MAX_REQ_SIZE -1);
    strncpy(new_request->hostname, new_url, MAX_URL_SIZE -1);
    new_request->port = port_num;
}

/*
Check blacklisted names in blocked.txt
NOTE: I'm assuming that this file does not change while the program is running hence no thread synchronization
*/
int check_blacklisted(char* ip_addr, char* hostname) {
    FILE* fp;
    char* line = NULL;
    ssize_t ret;
    size_t len;
    int i = 0, blocked = 0;

    fp = fopen("blocked.txt", "r");
    if (fp == NULL) return 1; 

    //check if it matches the IP or the hostname in the file
    while( (ret = getline(&line, &len, fp)) > 0) {
        if (strncmp(hostname, line, strlen(hostname)) == 0) { blocked=1; break;}
        if (strncmp(ip_addr,line, strlen(ip_addr)) == 0) {blocked = 1; break;}
    }
    if (line != NULL) free(line);
    if ( blocked == 1) return 1;

    fclose(fp);
    return 0;
}
 
/*
Check if hostname is cached
*/
int check_ip_cache(char* hostname, char* ip) {
    char* line = NULL;
    ssize_t ret;
    size_t len;
    int found = 0;

    FILE* fp = fopen("ip_cache.txt", "a+");
    if (fp == NULL) return 1;

    pthread_mutex_lock(&ip_mutex); //lock

    fseek(fp, 0, 0); //move to start of file
    //search for ip address in file
    while (ret = getline(&line, &len, fp) > 0) {
        sscanf(line, "%*s %s", ip);
        strtok(line, " ");
        if (strncmp(hostname, line, strlen(hostname)) == 0) {found =1; break;}
    }

    pthread_mutex_unlock(&ip_mutex); //unlock

    if (line != NULL) free(line);
    if (found == 1) return 0;

    fclose(fp);
    return 1;
}

/*
Store cached ip addresses in a file
*/
void add_ip_cache(char* hostname, char* ip_addr) {
    FILE* fp = fopen("ip_cache.txt", "a");
    fprintf(fp, "%s %s \n", hostname, ip_addr); //add line to the file
    fclose(fp);
}


/*
Send Error Messagesm Choice
*/
void handle_error(int connection_fd, ERROR e) {
    char error_msg[500];
    memset(error_msg, 0, 500);
    switch (e) {
        case 0:
            sprintf(error_msg, "HTTP/1.1 400 Bad Request\n");
            break;
        case 1:
            sprintf(error_msg, "HTTP/1.1 404 Not Found\n");
            break;
        case 2:
            sprintf(error_msg, "HTTP/1.1 403 Forbidden\n");
            break;
    }

    write(connection_fd, error_msg, strlen(error_msg));
}

/*
Sets up a new TCP connection for with the intended server
*/
int contact_server(char* ip_addr, char* url, char* version, char* hostname, int port_num, int connection_fd, int req_size) {
    int sockfd, connfd, b_read = 0, b_write = 0;
    struct sockaddr_in servaddr, cli;
    char file_contents[PACKET_SIZE];
    char request_buffer[512]; //build the response
    int n;

    //setup TCP connection with server
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) return -1;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    inet_pton(AF_INET, ip_addr, &(servaddr.sin_addr));
    //memcpy(&servaddr.sin_addr, inet_addr(ip_addr), strlen(ip_addr));
    //memcpy(&servaddr.sin_addr, host->h_addr_list[0], host->h_length);
    servaddr.sin_port = htons(port_num);
    if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) != 0) return -1;

    //build a new HTTP REQ Close the connection once the page is recieved 
    bzero(request_buffer, 512);
    sprintf(request_buffer, "GET %s %s\r\nhost: %s\r\nConnection: close\r\n\r\n", url, version, hostname);

    //pass on http_req to server   
    write(sockfd, request_buffer, strlen(request_buffer));
    

    while ( (n = read(sockfd, file_contents, PACKET_SIZE)) > 0) {
        write(connection_fd, file_contents, n);
    }

    close(sockfd); //close connection after read
}

/*
Function parses http req from client and then retransmits it to the server
*/
void get_req(int connection_fd) {
    char http_req[MAX_REQ_SIZE];
    struct hostent* host;

    HTTP_REQUEST *new_req = (HTTP_REQUEST*) malloc(sizeof(HTTP_REQUEST));
    char* ip_addr = (char *)malloc(sizeof(20));


    memset(http_req, 0, MAX_REQ_SIZE);
    int n = read(connection_fd, http_req, MAX_REQ_SIZE);
    parse_req(http_req, new_req, connection_fd);

    //check if cached
    if (check_ip_cache(new_req->hostname, ip_addr) == 0);
    //DNS lookup if not cached
    else if  ((host = gethostbyname(new_req->hostname)) == NULL) { handle_error(connection_fd, NOT_FOUND); return; }
    //convert to dotted noation and cache
    else { ip_addr = inet_ntoa(*((struct in_addr*) host->h_addr_list[0])); add_ip_cache(new_req->hostname, ip_addr);}
    //check if IP/hostname is blacklisted
    if (check_blacklisted(ip_addr, new_req->hostname) == 1) { handle_error(connection_fd, FORBIDDEN); return;}
    //send new HTTP message
    if ( contact_server(ip_addr, new_req->path, new_req->version, new_req->hostname, new_req->port, connection_fd, n) == -1) exit(0);

    free(new_req);
}

/*
thread routine
*/
void *handle_connection(void *thread_args) {
    int connection_fd = *((int *)thread_args);
    pthread_detach(pthread_self()); //no need to call pthread_join()
    free(thread_args); 
    get_req(connection_fd);
    close(connection_fd); //client can now stop waiting
    return NULL;
}


int main(int argc, char** argv) {
    int serverfd, *connect_fd, port, clientlen=sizeof(struct sockaddr_in), timeout = -1;
    struct sockaddr_in clientaddr;
    char *ptr;
    pthread_t thread_id;

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage %s <port> <timeout>\n", argv[0]);
        exit(0);
    }

    if (argc == 3) {
        timeout = strtol(argv[2], &ptr, 10);
        if (*ptr != '\0') { printf("Invalid Timeout\n"); exit(0); } //check for errors
    }

    port = strtol(argv[1], &ptr, 10);
    if (*ptr != '\0' || port <= 1024) { printf("Invalid Port Number\n"); exit(0); } //check for errors

    serverfd = open_serverfd(port);
    if (serverfd < 0) { printf("Error connecting to port %d\n", port); exit(0); }

    pthread_mutex_init(&ip_mutex, NULL);

    //server terminates on ctl-c
    while (1) {
        connect_fd = malloc(sizeof(int)); //allocate space for pointer
        *connect_fd = accept(serverfd, (struct sockaddr *)&clientaddr, &clientlen); //start accepting requests
        pthread_create(&thread_id, NULL, handle_connection, connect_fd); //pass new file descripotr to thread routine
    }

    //TODO: free with sigint handler (NOTE infinte loop)

    return 0;
}