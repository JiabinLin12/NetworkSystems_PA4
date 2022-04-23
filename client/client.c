/* 
 * udpclient.c - A simple UDP client
 * usage: udpclient <host> <port>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <stdbool.h>
#include <errno.h>
#include <openssl/md5.h>
#define MD5_DIGEST_LENGTH 16

#define BUFSIZE 1024
#define NUM_DFS 4
#define ACTIVE_DFS NUM_DFS
#define CHUCK_NUM 2
#define ARG_MAX_SIZE 1024
#define SET_BIT(BYTE, NBIT) ((BYTE) |= (1<<(NBIT)))
#define CLEAR_BIT(BYTE, NBIT) ((BYTE) &= (1<<(NBIT)))
#define CHECK_BIT(BYTE, NBIT) ((((BYTE) & (1<<(NBIT))) !=0)  ? 1 : 0)
//#define CHECK_BIT(BYTE,NBIT)  (((BYTE & (1 << NBIT)) != 0) ? 1 : 0)

#define CHECK(X) ({int __val = (X); (__val == (-1) ? ({fprintf(stderr, "ERROR ("__FILE__":%d) -- %s\n", __LINE__, strerror(errno)); exit(-1); -1;}) : __val);})

/*idx1: seq; idx2 chunk; idx3 dfs*/
const uint8_t lookup_dis[4][4][2] = {
  {{0,3}, {0,1}, {1,2}, {2,3}},
  {{0,1}, {1,2}, {2,3}, {0,3}},
  {{1,2}, {2,3}, {0,3}, {0,1}},
  {{2,3}, {0,3}, {0,1}, {1,2}}
};

typedef struct dfc_conf_info{
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
void usage(){
    printf("\n############Usage:############\nPUT [file]\nGET [file]\nLIST\n#############end##############\n");
}

void show_packet_info(packet_info_t pkt_info){
    printf("\n============pkt_info=============\n");
    printf("user: %s",pkt_info.user_info.user);
    printf("password: %s\n", pkt_info.user_info.pass);
    printf("command: %s\n", pkt_info.command);
    printf("filename: %s\n", pkt_info.filename);
    printf("chunk_idx: %d\n", pkt_info.chunk_idx);
}

void error(char *msg) {
    perror(msg);
    exit(0);
}

bool get_user_input(packet_info_t *pkt_info){
    char argopt[ARG_MAX_SIZE],*cmd, *filename;
    usage();
    bzero(argopt, ARG_MAX_SIZE);
    fgets(argopt, ARG_MAX_SIZE, stdin);
    cmd = strtok(argopt, " \n\r\0");
    filename = strtok(NULL, " \n\r\0");
    if(cmd == NULL){ 
      printf("error: no input command\n");
      return false;
    } 
    strcpy(pkt_info->command, cmd);
    if(filename!=NULL)
      strcpy(pkt_info->filename, filename);
    else
      pkt_info->filename[0] = '\0'; 
    
    return true;
}


//Ref:https://stackoverflow.com/questions/14295980/md5-reference-error
void md5_file(char *filename, int *patten_seq){
    unsigned char digest[MD5_DIGEST_LENGTH],data[1024];
    MD5_CTX mdContext;
    uint32_t hash_hex_digest= 0;
    int bytes;

    FILE *fp = fopen (filename, "rb");
    if (fp == NULL) {
        printf ("%s can't be opened.\n", filename);
        return;
    }


    MD5_Init (&mdContext);
    while ((bytes = fread (data, 1, 1024, fp)) != 0)
        MD5_Update (&mdContext, data, bytes);
    MD5_Final (digest,&mdContext);


    for(int i = 0; i < 4; i++) {
        hash_hex_digest = hash_hex_digest | (digest[i] << 8 * (3-i));
    }
    *patten_seq = hash_hex_digest % NUM_DFS;
    fclose (fp);
}

// void socket_close(int sfd){
//     if(sfd==-1)
//         return;
//     CHECK(shutdown(sfd, SHUT_RDWR));
//     close(sfd);
// }

void egain_recv(int n, int idx, uint8_t *vflag){
    int errno_cp = errno;
    if((n == -1)){ 
        if(errno_cp!= EAGAIN){
            error("Error in recvfrom");
        }else{
            printf("dfs%d is down\n",idx+1);
        }
    }
}

void send_authentications(account_t user_info, int sockfd[NUM_DFS], struct sockaddr_in serveraddr[NUM_DFS],uint8_t *vflag){
    struct timeval timeout[2] = {{1,0},{0,0}};
    int n =0;
    
    socklen_t serverlen = sizeof(serveraddr[0]);
    bool verify;
    for(int i=0;i<NUM_DFS;i++){
        verify = false;
        CHECK(sendto(sockfd[i], &user_info, sizeof(user_info), 0, (struct sockaddr *)&serveraddr[i], serverlen));
        CHECK(setsockopt(sockfd[i],SOL_SOCKET,SO_RCVTIMEO,(char*)&timeout[0],sizeof(struct timeval))); 
        n = recvfrom(sockfd[i], &verify, sizeof(verify), 0, (struct sockaddr *)&serveraddr[i], &serverlen);
        CHECK(setsockopt(sockfd[i],SOL_SOCKET,SO_RCVTIMEO,(char*)&timeout[1],sizeof(struct timeval))); 
        egain_recv(n, i, vflag);
        if(!verify){
            printf("dfs%d: Invalid Username/Password. Please try again.\n", i+1);
            continue;
        }
        printf("sock %d\n", sockfd[i]);
        *vflag = SET_BIT(*vflag,  i);
    }
}





//printf("folder=%s\nhostname=%s\nportno=%d\n\n",(*conf_info).folder,(*conf_info).hostname,(*conf_info).portno);
//printf("%s\n",(*conf_info).account[acc_idx]);
void conf_parse(char *filename, dfc_conf_info_t conf_info[NUM_DFS], char account[2][40] ){
    FILE *fp;
    ssize_t rd_size=0;
    size_t len =0;
    char *server_info, *account_info, *token, portno[20],temp[20],*line = NULL;
    int counter = 0, idx=0;
    fp = fopen(filename, "r");
    if(fp==NULL){
        printf("file not exists");
        exit(-1);
    }
    while ((rd_size = getline(&line, &len, fp)) != -1) {
        if(counter<NUM_DFS){
            server_info = strstr(line, " ");
            if(server_info){
                sscanf(server_info, "%s %s", (conf_info[counter]).folder,temp);
                token = strtok(temp, ":");
                if(token)
                    strcpy((conf_info[counter]).hostname, token);
                token = strtok(NULL, ":");
                if(token){
                    strcpy(portno, token);
                    sscanf(portno, "%d",&((conf_info[counter]).portno));
                }
                printf("folder=%s\nhostname=%s\nportno=%d\n\n",conf_info[counter].folder,conf_info[counter].hostname,conf_info[counter].portno);
            }
            counter++;
        }else{
            account_info = strstr(line, " ");
            //printf("%s",account_info);
            if(account_info && account_info+1){
                strcpy(account[idx], account_info+1);
                printf("%s\n",account[idx]);
                idx = (idx<2) ? idx+1:0;
            }
        }
    }
}

void connect_server(int *sockfd, char *hostname, struct sockaddr_in *serveraddr, int portno){
    struct hostent *server;
    /* socket: create the socket */
    *sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (*sockfd < 0) 
        error("ERROR opening socket");

    /* gethostbyname: get the server's DNS entry */
    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host as %s\n", hostname);
        exit(0);
    }

    /* build the server's Internet address */
    bzero((char *) &(*serveraddr), sizeof(*serveraddr));
    (*serveraddr).sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
	  (char *)&(*serveraddr).sin_addr.s_addr, server->h_length);
    (*serveraddr).sin_port = htons(portno);
}


void handle_put_cmd(int sockfd[NUM_DFS], struct sockaddr_in serveraddr[NUM_DFS],packet_info_t pkt_info, int patten_seq, uint8_t vflag ){
    size_t file_size = 0;
    struct timeval timeout[2] = {{1,0},{0,0}};
    uint32_t packet_size=0, remain_size =0, sidx[2] = {-1,-1};
    socklen_t serverlen = sizeof(serveraddr[0]);
    char *file_content;
    FILE *fp = fopen (pkt_info.filename, "rb");
    if (fp == NULL) {
        printf ("%s can't be opened.\n", pkt_info.filename);
        return;
    }

    md5_file(pkt_info.filename, &patten_seq);

    /*get file size*/
    fseek(fp, 0,SEEK_END);
    file_size = ftell(fp);  
    fseek(fp,0,SEEK_SET);  

    packet_size = file_size/NUM_DFS;
    remain_size = file_size%NUM_DFS;
    show_packet_info(pkt_info);

    for(int i=0; i<NUM_DFS;i++){
        sidx[0] = lookup_dis[patten_seq][i][0];
        sidx[1] = lookup_dis[patten_seq][i][1];

        pkt_info.chunk_idx = i;
        pkt_info.content_len = (i==NUM_DFS-1)? packet_size+remain_size:packet_size;
        if(CHECK_BIT(vflag, sidx[0])){
            CHECK(sendto(sockfd[sidx[0]], &pkt_info, sizeof(pkt_info), 0, (struct sockaddr *)&serveraddr[i], serverlen));
            printf("1. pkt send to dfs%d sockfd=%d\n",sidx[0], sockfd[sidx[0]]);
        }        
        if(CHECK_BIT(vflag, sidx[1])){
            printf("2. pkt send to dfs%d sockfd=%d\n",sidx[1], sockfd[sidx[1]]);
            CHECK(sendto(sockfd[sidx[1]], &pkt_info, sizeof(pkt_info), 0, (struct sockaddr *)&serveraddr[i], serverlen));
        }
        // file_content = (char *)malloc(pkt_info.content_len*sizeof(char));
        // CHECK(fread(file_content, 1, pkt_info.content_len, fp));
        // CHECK(n = sendto(sockfd[sidx[0]], &file_content, sizeof(file_content), 0, (struct sockaddr *)&serveraddr[i], serverlen));
        // CHECK(n = sendto(sockfd[sidx[1]], &file_content, sizeof(file_content), 0, (struct sockaddr *)&serveraddr[i], serverlen));
        // free(file_content);
    }
}

void handle_cmds(packet_info_t pkt_info, int sockfd[NUM_DFS],struct sockaddr_in serveraddr[NUM_DFS]){
    int patten_seq=-1;
    uint8_t vflag = 0;
    if((!strcmp(pkt_info.command,"PUT") || !strcmp(pkt_info.command,"put")) && !(access(pkt_info.filename, F_OK))){
        send_authentications(pkt_info.user_info,sockfd,serveraddr, &vflag);
        if(vflag==0){
            printf("vflag is 0");
            return;
        }
        md5_file(pkt_info.filename, &patten_seq);
        
        handle_put_cmd(sockfd, serveraddr, pkt_info, patten_seq, vflag);     
    }else if(!strcmp(pkt_info.command,"GET")){
        printf("GET\n");
    }else if(!strcmp(pkt_info.command, "LIST")){
        printf("LIST\n");
    }else{
        printf("Invalid command or file does not exit\n");
    }

}

int main(int argc, char **argv) {
    int sockfd[NUM_DFS] = {-1,-1,-1,-1};
    struct sockaddr_in serveraddr[NUM_DFS];
    dfc_conf_info_t conf_info[NUM_DFS];
    //account_t userinfo;
    packet_info_t pkt_info;
    char user_info[2][40];
    bool verified_user=false;
    //memset(&userinfo, 0, sizeof(userinfo));
    memset(&pkt_info, 0, sizeof(pkt_info));
    /* check command line arguments */
    if (argc != 2) {
       fprintf(stderr,"usage: %s <dfc.conf>\n", argv[0]);
       exit(0);
    }
    conf_parse(argv[1],conf_info, user_info);
    strcpy(pkt_info.user_info.user,user_info[0]);
    strcpy(pkt_info.user_info.pass,user_info[1]);

    for(int i=0; i<ACTIVE_DFS; i++){
        connect_server(&sockfd[i], conf_info[i].hostname, &serveraddr[i], conf_info[i].portno);
    }


    while(1){
        if(!get_user_input(&pkt_info)) continue;
        handle_cmds(pkt_info, sockfd,serveraddr);
    }
    
    return 0;
}
