/* 
 * udpserver.c - A simple UDP echo server 
 * usage: udpserver <port>
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>

#define BUFSIZE 1024
#define SMALL_BUFSIZE 30
#define CHECK(X) ({int __val = (X); (__val == (-1) ? ({fprintf(stderr, "ERROR ("__FILE__":%d) -- %s\n", __LINE__, strerror(errno)); exit(-1); -1;}) : __val);})

typedef struct dfc_conf_info{
    char account[2][40];
    char hostname[20];
    char folder[20];
    int portno;
} dfc_conf_info_t;


typedef struct account {
    char user[40];
    char pass[40];
}account_t;


typedef struct packet_info {
    char command[10];
    char filename[40];
    uint32_t chunk_idx;
    uint32_t content_len; 
    account_t user_info;
}packet_info_t;

/*
 * error - wrapper for perror
 */
void error(char *msg) {
  perror(msg);
  exit(1);
}

void show_packet_info(packet_info_t pkt_info){
    printf("\n============pkt_info=============\n");
    printf("user: %s",pkt_info.user_info.user);
    printf("password: %s\n", pkt_info.user_info.pass);
    printf("command: %s\n", pkt_info.command);
    printf("filename: %s\n", pkt_info.filename);
    printf("chunk_idx: %d\n", pkt_info.chunk_idx);
    printf("content_length: %d\n", pkt_info.content_len);
}

void show_user_info(account_t user_info){
  printf("user: %s\n",user_info.user);
  printf("password: %s\n", user_info.pass);
}
 

bool verify_authentication(int sockfd, struct sockaddr_in clientaddr){
    bool verified = false;  
    FILE *fp;
    size_t len =0;
    socklen_t clientlen;
    account_t user_info;
    char *line, user[40], pass[40];
    clientlen = sizeof(clientaddr);
    memset(&user_info,0,sizeof(user_info));
    
    CHECK(recvfrom(sockfd, &user_info, sizeof(user_info), 0,(struct sockaddr *) &clientaddr, &clientlen));
    printf("User authenticating...\n");
    fp = fopen("dfs.conf", "r");
    if(fp==NULL)
      error("no dfs.conf");
    while (getline(&line, &len, fp) != -1) {
      sscanf(line, "%s %s",user,pass);
      strcat(user, "\n");
      if(!strcmp(user_info.user,user)&&!strcmp(user_info.pass,pass)){
        verified = true;
        printf("User authenticated\n");
        break;
      }
    }
    CHECK(sendto(sockfd, &verified, sizeof(verified), 0, (struct sockaddr *) &clientaddr, clientlen));
    return verified;
}

void socket_config(int *sockfd, int portno, struct sockaddr_in *serveraddr){
    int optval; /* flag value for setsockopt */
    *sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (*sockfd < 0) 
    error("ERROR opening socket");

    optval = 1;
    setsockopt(*sockfd, SOL_SOCKET, SO_REUSEADDR, 
            (const void *)&optval , sizeof(int));

    /*
    * build the server's Internet address
    */
    bzero((char *) serveraddr, sizeof(*serveraddr));
    (*serveraddr).sin_family = AF_INET;
    (*serveraddr).sin_addr.s_addr = htonl(INADDR_ANY);
    (*serveraddr).sin_port = htons((unsigned short)portno);

    /* 
    * bind: associate the parent socket with a port 
    */
    if (bind(*sockfd, (struct sockaddr *) &(*serveraddr), 
        sizeof(*serveraddr)) < 0) 
    error("ERROR on binding");

}
void handle_put_cmd(int sockfd, struct sockaddr_in clientaddr,packet_info_t pkt_info, char DFS[20]){
  socklen_t clientlen = sizeof(clientaddr);
  char user_folder[SMALL_BUFSIZE], filename[SMALL_BUFSIZE], *file_content;
  show_packet_info(pkt_info);
  CHECK(snprintf(user_folder, SMALL_BUFSIZE, "%s/%s", DFS, pkt_info.user_info.user));
  CHECK(snprintf(filename, SMALL_BUFSIZE, "%s.%d", pkt_info.filename, pkt_info.chunk_idx));
  mkdir(user_folder, 0777);
  printf("filename %s\nuserfolder %s", filename,user_folder);
  file_content = (char *)malloc(pkt_info.content_len*sizeof(char));
  CHECK(recvfrom(sockfd, file_content, pkt_info.content_len*sizeof(char), 0,(struct sockaddr *) &clientaddr, &clientlen));
  printf("Content:\n%s", file_content);
  free(file_content);
}



void handle_cmds( int sockfd,struct sockaddr_in clientaddr, char DFS[20]){
  packet_info_t pkt_info;
  memset(&pkt_info, 0, sizeof(pkt_info));
  socklen_t clientlen = sizeof(clientaddr);
  if(!verify_authentication(sockfd, clientaddr)){
    printf("authentication failed, try again\n");
    return;
  }
  CHECK(recvfrom(sockfd, &pkt_info, sizeof(pkt_info), 0,(struct sockaddr *) &clientaddr, &clientlen));
  printf("recived info from client\n");
  
  if(!strcmp(pkt_info.command,"PUT")){
    handle_put_cmd(sockfd, clientaddr, pkt_info,DFS);
    memset(&pkt_info, 0, sizeof(pkt_info));
    CHECK(recvfrom(sockfd, &pkt_info, sizeof(pkt_info), 0,(struct sockaddr *) &clientaddr, &clientlen));  
    handle_put_cmd(sockfd, clientaddr, pkt_info,DFS);   
  }else if(!strcmp(pkt_info.command,"GET")){
    printf("GET\n");
  }else if(!strcmp(pkt_info.command, "LIST")){
    printf("LIST\n");
  }else{
    printf("Invalid command %s\n",pkt_info.command);
  }
}

int main(int argc, char **argv) {
  int sockfd; /* socket */
  int portno; /* port to listen on */
  struct sockaddr_in serveraddr; /* server's addr */
  struct sockaddr_in clientaddr; /* client addr */
  char DFS[20] = "../"; 
  if (argc != 3) {
    fprintf(stderr, "usage: %s <folder> <port>\n", argv[0]);
    exit(1);
  }
  portno = atoi(argv[2]);
  socket_config(&sockfd, portno, &serveraddr);
  strcat(DFS, argv[1]);
  mkdir(DFS, 0777);
  while (1) {
    handle_cmds(sockfd,clientaddr,DFS);
  }
}
