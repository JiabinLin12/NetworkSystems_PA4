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
#include <assert.h>
#include <dirent.h>
#include <openssl/md5.h>

#define BUFSIZE 1024
#define SMALL_BUFSIZE 60
#define SMLBUFF 60
#define NUM_DFS 4
#define LISTENQ 1024
#define CHECK(X) ({int __val = (X); (__val == (-1) ? ({fprintf(stderr, "ERROR ("__FILE__":%d) -- %s\n", __LINE__, strerror(errno)); exit(-1); -1;}) : __val);})
#define SET_BIT(BYTE, NBIT) ((BYTE) |= (1<<(NBIT)))
#define CLEAR_BIT(BYTE, NBIT) ((BYTE) &= ~(1<<(NBIT)))
#define CHECK_BIT(BYTE, NBIT) ((((BYTE) & (1<<(NBIT))) !=0)  ? 1 : 0)

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


typedef struct getfile{
    char filename[40]; 
    uint8_t cidx;
}getfile_info_t;

typedef struct packet_info {
    char command[10];
    char filename[40];
    char foldername[40];
    uint32_t chunk_idx;
    uint32_t content_len; 
    account_t user_info;
    getfile_info_t gf[NUM_DFS];
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

//ref: https://stackoverflow.com/questions/7627723/how-to-create-a-md5-hash-of-a-string-in-c
void md5_str(char* str, char* md5buf){
  unsigned char md5sum[16];
  MD5_CTX ctx;
  MD5_Init(&ctx);
  MD5_Update(&ctx, str, strlen(str));
  MD5_Final(md5sum, &ctx);

  for(int i = 0; i < 16; ++i){
    sprintf(md5buf+i*2, "%02x", (unsigned int)md5sum[i]);
  }
}
void encrypt_decrypt(int option, char *pass, char *fc, int len){
    unsigned char pass_md5[SMLBUFF];
    uint32_t hex_digest = 0, shift_amount=0;
    md5_str(pass, pass_md5);
    for(int i = 0; i < 4; i++) {
        hex_digest = hex_digest | (pass_md5[i] << 8 * (3-i));
    }

    shift_amount = (hex_digest % NUM_DFS)+1;
    switch(option){
        case 0:
            for(int i=0; (i<len && (fc[i]!='\0'));i++){
                fc[i] = fc[i] + shift_amount;
            }
            break;
        case 1:
            for(int i=0; (i<len && (fc[i]!='\0'));i++){
                fc[i] = fc[i] - shift_amount;
            }
            break;
        default:
            printf("wrong option\n");
    }
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
      user[strcspn(user, "\n")] = 0;
      pass[strcspn(pass, "\n")] = 0;
      user_info.user[strcspn(user_info.user, "\n")] = 0;
      user_info.pass[strcspn(user_info.pass, "\n")] = 0;
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


//printf("filename %s\nuserfolder %s\nfile_path %s\n", filename,user_folder,file_path);
void handle_put_cmd(int sockfd, struct sockaddr_in clientaddr,packet_info_t pkt_info, char DFS[20]){
  int  n=0;
  socklen_t clientlen = sizeof(clientaddr);
  char user_folder[SMALL_BUFSIZE], filename[SMALL_BUFSIZE], file_path[SMALL_BUFSIZE];
  char *file_content = (char *)malloc(sizeof(char));
  show_packet_info(pkt_info);
  
  /*create folder and file*/
  CHECK(n = snprintf(user_folder, SMALL_BUFSIZE, "%s/%s", DFS, pkt_info.user_info.user));
  user_folder[strlen(user_folder)-1] = 0;
  if(pkt_info.foldername[0]!='\0'){
    strcat(user_folder, pkt_info.foldername);
  }
  printf("put user_folder: %s\n", user_folder);
  CHECK(snprintf(filename, SMALL_BUFSIZE, ".%s.%d", pkt_info.filename, pkt_info.chunk_idx));
  CHECK(snprintf(file_path, SMALL_BUFSIZE, "%s/%s", user_folder, filename));
  mkdir(user_folder, 0777);
  
  //get file content from client
  file_content = realloc(file_content, pkt_info.content_len);
  
  CHECK(n=recvfrom(sockfd, file_content, pkt_info.content_len, 0,(struct sockaddr *) &clientaddr, &clientlen));

  /*write content to file*/
  FILE *fp = fopen(file_path, "wb");
  if(fp==NULL)
    error("fopen failed");
  encrypt_decrypt(1, pkt_info.user_info.pass, file_content, pkt_info.content_len);
  fwrite(file_content,sizeof(char), n, fp);
  free(file_content);
  fclose(fp);
}

void handle_get_cmd(int sockfd, struct sockaddr_in clientaddr,packet_info_t pkt_info, char DFS[20]){
  socklen_t clientlen = sizeof(clientaddr);
  char user_folder[SMALL_BUFSIZE], file_path[SMALL_BUFSIZE];
  FILE *fp;
  int filefound = 0, n=0;
  /*create folder and file*/
  CHECK(snprintf(user_folder, SMALL_BUFSIZE, "%s/%s", DFS, pkt_info.user_info.user));
  user_folder[strlen(user_folder)-1] = 0;
  if(pkt_info.foldername[0]!='\0'){
    strcat(user_folder, pkt_info.foldername);
  }
  printf("get user_folder: %s\n", user_folder);
  for(int i=0; i<NUM_DFS; i++){
    CHECK(snprintf(file_path, SMALL_BUFSIZE, "%s/%s", user_folder, pkt_info.gf[i].filename));
    
    fp = fopen (file_path, "rb");
    filefound = (fp==NULL)? 0:1;
    CHECK(sendto(sockfd, &filefound, sizeof(filefound), 0, (struct sockaddr *)&clientaddr, clientlen));
    if (fp == NULL) 
        continue;
    
    strcpy(pkt_info.filename,pkt_info.gf[i].filename);
    pkt_info.gf[i].cidx = i;
    /*get file size*/
    fseek(fp, 0,SEEK_END);
    pkt_info.content_len = ftell(fp);  
    fseek(fp,0,SEEK_SET);
    
    pkt_info.chunk_idx = i;
    show_packet_info(pkt_info);
    CHECK(sendto(sockfd, &pkt_info, sizeof(pkt_info), 0, (struct sockaddr *)&clientaddr, clientlen));
    char fc[pkt_info.content_len];
    CHECK(n = fread(fc, 1, pkt_info.content_len, fp));
    CHECK(sendto(sockfd, fc, n, 0, (struct sockaddr *)&clientaddr, clientlen));
    fclose(fp);
  }
}


void handle_list_cmd(int sockfd, struct sockaddr_in clientaddr,packet_info_t pkt_info, char DFS[20]){
  int pkt_offset=0,n=0;
  
  struct dirent *dir;
  char lcontent[BUFSIZE]; 
  socklen_t clientlen = sizeof(clientaddr);
  char user_folder[SMALL_BUFSIZE], filename[SMALL_BUFSIZE], file_path[SMALL_BUFSIZE];

  CHECK(snprintf(user_folder, SMALL_BUFSIZE, "%s/%s", DFS, pkt_info.user_info.user));
  user_folder[strlen(user_folder)-1] = 0;
  if(pkt_info.foldername[0]!='\0'){
    strcat(user_folder, pkt_info.foldername);
  }
  printf("list user_folder: %s\n", user_folder);
  DIR *d = opendir(user_folder);
  if(!d){
    printf("%s does not exist\n", user_folder);
    strncpy(lcontent, "n", 1);
    CHECK(sendto(sockfd, lcontent, 1, 0, (struct sockaddr *) &clientaddr, clientlen));
    return;
  }
  while((dir = readdir(d))!=NULL){
    if( !(strcmp(dir->d_name, ".")) || !(strcmp(dir->d_name, "..")) || \
          (dir->d_type==DT_DIR))
      continue;
    printf("dirnanme %s", dir->d_name);
    pkt_offset += sprintf(lcontent + pkt_offset,"%s_", dir->d_name); 
  }
  closedir(d);
  
  CHECK(sendto(sockfd, lcontent, strlen(lcontent), 0, (struct sockaddr *) &clientaddr, clientlen));
}

void handle_mkdir_cmd(int sockfd, struct sockaddr_in clientaddr,packet_info_t pkt_info, char DFS[20]){
  socklen_t clientlen = sizeof(clientaddr);
  char user_folder[SMALL_BUFSIZE], filename[SMALL_BUFSIZE], folder_path[SMALL_BUFSIZE];
  CHECK(snprintf(user_folder, SMALL_BUFSIZE, "%s/%s", DFS, pkt_info.user_info.user));
  user_folder[strlen(user_folder)-1] = 0;
  CHECK(snprintf(folder_path, SMALL_BUFSIZE, "%s/%s", user_folder, pkt_info.foldername));
  mkdir(folder_path, 0777);
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
  
  if(!strcmp(pkt_info.command,"PUT")||!strcmp(pkt_info.command,"put")){
    
    handle_put_cmd(sockfd, clientaddr, pkt_info,DFS);
    memset(&pkt_info, 0, sizeof(pkt_info));
    CHECK(recvfrom(sockfd, &pkt_info, sizeof(pkt_info), 0,(struct sockaddr *) &clientaddr, &clientlen));  
    handle_put_cmd(sockfd, clientaddr, pkt_info,DFS);   
  
  }else if(!strcmp(pkt_info.command,"GET") || !strcmp(pkt_info.command, "get")){
    handle_get_cmd(sockfd,clientaddr, pkt_info, DFS);

  }else if(!strcmp(pkt_info.command, "LIST") || !strcmp(pkt_info.command, "list")){
    handle_list_cmd(sockfd, clientaddr, pkt_info, DFS);
  
  }else if (!strcmp(pkt_info.command, "MKDIR") || !strcmp(pkt_info.command, "mkdir")) {
    handle_mkdir_cmd(sockfd, clientaddr, pkt_info, DFS);

  }else{
    printf("Invalid command %s\n",pkt_info.command);
  }
}

int main(int argc, char **argv) {
  int sockfd;
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
