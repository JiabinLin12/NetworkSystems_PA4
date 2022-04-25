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
#include <dirent.h>
#include <sys/stat.h>

#define MD5_DIGEST_LENGTH 16

#define BUFSIZE 1024
#define SMLBUFF 60
#define NUM_DFS 4
#define ACTIVE_DFS NUM_DFS
#define CHUCK_DUP 2
#define CHUCK_NUM 4
#define ARG_MAX_SIZE 1024
#define SET_BIT(BYTE, NBIT) ((BYTE) |= (1<<(NBIT)))
#define CLEAR_BIT(BYTE, NBIT) ((BYTE) &= ~(1<<(NBIT)))
#define CHECK_BIT(BYTE, NBIT) ((((BYTE) & (1<<(NBIT))) !=0)  ? 1 : 0)
//#define CHECK_BIT(BYTE,NBIT)  (((BYTE & (1 << NBIT)) != 0) ? 1 : 0)

#define CHECK(X) ({int __val = (X); (__val == (-1) ? ({fprintf(stderr, "ERROR ("__FILE__":%d) -- %s\n", __LINE__, strerror(errno)); exit(-1); -1;}) : __val);})

/*idx1: seq; idx2 chunk; idx3 dfs*/
const uint8_t lookup_dis[4][4][2] = {
  {{0,1}, {1,2}, {2,3}, {0,3}},
  {{3,0}, {0,1}, {1,2}, {2,3}},
  {{2,3}, {3,0}, {0,1}, {1,2}},
  {{1,2}, {2,3}, {3,0}, {0,1}}
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

typedef struct store_s {
    char *chunk[NUM_DFS];
    int chunk_len[NUM_DFS];
    int chunk_avl_pool;
    int chunk_not_wrtn;
    int next_wchunk;
}store_t;

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


typedef struct flcheck {
    char filename[SMLBUFF][40];
    uint8_t fl_complete[SMLBUFF];
    uint8_t fname_num;
}flcheck_t;



/* 
 * error - wrapper for perror
 */
void usage(){
    printf("\n############Usage:############\nPUT [file]\nGET [file]\nMKDIR [folder]\nLIST\n#############end##############\n");
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

void error(char *msg) {
    perror(msg);
    exit(0);
}

bool get_user_input(packet_info_t *pkt_info){
    char argopt[ARG_MAX_SIZE],*cmd, *filename, *foldername;
    usage();
    bzero(argopt, ARG_MAX_SIZE);
    fgets(argopt, ARG_MAX_SIZE, stdin);
    cmd = strtok(argopt, " \n\r\0");
    filename = strtok(NULL, " \n\r\0");
    foldername = strtok(NULL, " \n\r\0");

    if(cmd == NULL){ 
      printf("error: no input command\n");
      return false;
    } 
    strcpy(pkt_info->command, cmd);
    if((!strcmp(pkt_info->command, "mkdir") || !strcmp(pkt_info->command, "MKDIR"))&&
       filename==NULL){
          printf("no subfolder input");
          return false;
    }
    if((!strcmp(pkt_info->command, "list") || 
       !strcmp(pkt_info->command, "LIST")   ||
       !strcmp(pkt_info->command, "mkdir")  || 
       !strcmp(pkt_info->command, "MKDIR")) &&
       filename!=NULL){
        pkt_info->filename[0] = '\0'; 
        strcpy(pkt_info->foldername, filename);
    }else if(filename!=NULL){
      strcpy(pkt_info->filename, filename);
      if(foldername!=NULL){
        strcpy(pkt_info->foldername, foldername);
      }
    }else{
        pkt_info->filename[0] = '\0'; 
        pkt_info->foldername[0] = '\0'; 
    }
    return true;
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

void is_egain_recv(int n){
    int errno_cp = errno;
    if((n == -1) && (errno_cp!= EAGAIN)){ 
        error("Error in recvfrom");
    }
}



void send_authentication(account_t user_info, int sockfd, struct sockaddr_in serveraddr,bool *verify){
    struct timeval timeout[2] = {{1,0},{0,0}};
    int n =0;
    socklen_t serverlen = sizeof(serveraddr);
    user_info.user[strcspn(user_info.user, "\n")] = 0;
    user_info.pass[strcspn(user_info.pass, "\n")] = 0;
    CHECK(sendto(sockfd, &user_info, sizeof(user_info), 0, (struct sockaddr *)&serveraddr, serverlen));
    CHECK(setsockopt(sockfd,SOL_SOCKET,SO_RCVTIMEO,(char*)&timeout[0],sizeof(struct timeval))); 
    n = recvfrom(sockfd, verify, sizeof(*verify), 0, (struct sockaddr *)&serveraddr, &serverlen);
    CHECK(setsockopt(sockfd,SOL_SOCKET,SO_RCVTIMEO,(char*)&timeout[1],sizeof(struct timeval))); 
    is_egain_recv(n);    
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

void get_chunks(packet_info_t *pkt_info,char *fc[NUM_DFS],uint32_t c_len[NUM_DFS],FILE *fp){
    uint32_t packet_size=0, remain_size =0,file_size=0;
    
    /*get file size*/
    fseek(fp, 0,SEEK_END);
    file_size = ftell(fp);  
    fseek(fp,0,SEEK_SET);  

    packet_size = file_size/NUM_DFS;
    remain_size = file_size%NUM_DFS;

    for(int i=0; i<CHUCK_NUM; i++){
        c_len[i] = (i==CHUCK_NUM-1)? packet_size+remain_size:packet_size;
        fc[i] = (char *)malloc(c_len[i]);
        CHECK(fread(fc[i], 1, c_len[i], fp));
        encrypt_decrypt(0, pkt_info->user_info.pass, fc[i], c_len[i]);
    }
}

void free_chucks(char *fc[NUM_DFS]){
    for(int i=0; i<NUM_DFS;i++){
        free(fc[i]);
    }
}
//printf("1.cidx %d dfs%d, seq %d, %s\n", cidx[0], i,patten_seq,fc[cidx[0]]);
//printf("2.cidx %d dfs%d, seq  %d, %s\n", cidx[1], i,patten_seq,fc[cidx[1]]);
void handle_put_cmd(int sockfd[NUM_DFS], struct sockaddr_in serveraddr[NUM_DFS],packet_info_t pkt_info){
    uint32_t cidx[2] = {-1,-1}, c_len[NUM_DFS];
    socklen_t serverlen = sizeof(serveraddr[0]);
    char *fc[NUM_DFS];
    int patten_seq; 
    bool verify = false;
    FILE *fp = fopen (pkt_info.filename, "rb");
    if (fp == NULL) {
        printf ("%s can't be opened.\n", pkt_info.filename);
        return;
    }
    md5_file(pkt_info.filename, &patten_seq);
    get_chunks(&pkt_info,fc,c_len,fp);
    for(int i=0; i<NUM_DFS; i++){
        verify = false;
        send_authentication(pkt_info.user_info, sockfd[i],serveraddr[i],&verify);
        if(!verify) 
            continue;

        cidx[0] = lookup_dis[patten_seq][i][0];
        pkt_info.chunk_idx = cidx[0];
        pkt_info.content_len = c_len[cidx[0]];
        CHECK(sendto(sockfd[i], &pkt_info, sizeof(pkt_info), 0, (struct sockaddr *)&serveraddr[i], serverlen));
        CHECK(sendto(sockfd[i], fc[cidx[0]], pkt_info.content_len, 0, (struct sockaddr *)&serveraddr[i], serverlen));

        cidx[1] = lookup_dis[patten_seq][i][1];
        pkt_info.chunk_idx = cidx[1];
        pkt_info.content_len = c_len[cidx[1]];
        CHECK(sendto(sockfd[i], &pkt_info, sizeof(pkt_info), 0, (struct sockaddr *)&serveraddr[i], serverlen));
        CHECK(sendto(sockfd[i], fc[cidx[1]], pkt_info.content_len, 0, (struct sockaddr *)&serveraddr[i], serverlen));
    }
    free_chucks(fc);
    fclose(fp);
}



void write_chunk(char *fcontent, FILE *fp, store_t *wh,packet_info_t pkt_info){
    wh->chunk_len[pkt_info.chunk_idx] = pkt_info.content_len;
    if(pkt_info.chunk_idx==wh->next_wchunk){
        //encrypt_decrypt(1, pkt_info.user_info.pass, fcontent,wh->chunk_len[pkt_info.chunk_idx]);
        fwrite(fcontent,sizeof(char), wh->chunk_len[pkt_info.chunk_idx], fp);
        wh->next_wchunk++;
        wh->chunk_not_wrtn= CLEAR_BIT(wh->chunk_not_wrtn,pkt_info.chunk_idx);
    }else{
        wh->chunk[pkt_info.chunk_idx] = realloc(wh->chunk[pkt_info.chunk_idx], wh->chunk_len[pkt_info.chunk_idx]);
        memcpy(wh->chunk[pkt_info.chunk_idx], fcontent, wh->chunk_len[pkt_info.chunk_idx]);
        wh->chunk_avl_pool= SET_BIT(wh->chunk_avl_pool,pkt_info.chunk_idx);
        wh->chunk_not_wrtn= SET_BIT(wh->chunk_not_wrtn,pkt_info.chunk_idx);
    }
    while(CHECK_BIT(wh->chunk_avl_pool,wh->next_wchunk) && CHECK_BIT(wh->chunk_not_wrtn,wh->next_wchunk)){
        //encrypt_decrypt(1, pkt_info.user_info.pass, wh->chunk[wh->next_wchunk],wh->chunk_len[wh->next_wchunk]);
        fwrite(wh->chunk[wh->next_wchunk],sizeof(char), wh->chunk_len[wh->next_wchunk], fp);
        wh->next_wchunk++;
        wh->chunk_not_wrtn= CLEAR_BIT(wh->chunk_not_wrtn,pkt_info.chunk_idx);
    }
}

void handle_get_cmd(int sockfd[NUM_DFS], struct sockaddr_in serveraddr[NUM_DFS],packet_info_t pkt_info, bool file_exist){
    struct timeval timeout[2] = {{1,0},{0,0}};
    int n =0,filefound = false;
    bool verify = false;
    socklen_t serverlen = sizeof(serveraddr[0]);
    packet_info_t finfo;
    store_t wearhouse;
    char download_path[SMLBUFF], *fc = (char *)malloc(sizeof(char));
    if(!file_exist){
        printf("File does not exist\n");
        return;
    }
    
    memset(&wearhouse, 0, sizeof(wearhouse));
    if(pkt_info.filename[0]=='\0'){
        printf("no filename provided for command: get");
        return;
    }
    mkdir("./download", 0777);
    CHECK(snprintf(download_path, SMLBUFF, "%s/%s", "./download", pkt_info.filename));
    FILE *fp = fopen (download_path, "wb");
    if(fp==NULL){
        printf("file failed to open");
        return;
    }

    for(int i=0;i<NUM_DFS;i++){
        CHECK(snprintf(pkt_info.gf[i].filename, 40, ".%s.%d", pkt_info.filename, i));
        pkt_info.gf[i].cidx = 0;
        wearhouse.chunk[i] = (char *)malloc(sizeof(char));
    }

    for(int i=0; i<NUM_DFS; i++){
        verify = false;
        send_authentication(pkt_info.user_info, sockfd[i],serveraddr[i],&verify);
        if(!verify) 
            continue;
        CHECK(sendto(sockfd[i], &pkt_info, sizeof(pkt_info), 0, (struct sockaddr *)&serveraddr[i], serverlen));
        CHECK(setsockopt(sockfd[i],SOL_SOCKET,SO_RCVTIMEO,(char*)&timeout[0],sizeof(struct timeval))); 
        for(int j=0; j<NUM_DFS; j++){
            n = recvfrom(sockfd[i], &filefound, sizeof(filefound), 0, (struct sockaddr *)&serveraddr[i], &serverlen); 
            is_egain_recv(n);
            if(!filefound)
                continue;           
                
            n = recvfrom(sockfd[i], &finfo, sizeof(finfo), 0, (struct sockaddr *)&serveraddr[i], &serverlen); 
            is_egain_recv(n);           
            fc = realloc(fc, finfo.content_len);
            n = recvfrom(sockfd[i], fc, finfo.content_len, 0, (struct sockaddr *)&serveraddr[i], &serverlen); 
            is_egain_recv(n);
            write_chunk(fc,fp, &wearhouse,finfo);
        }
        CHECK(setsockopt(sockfd[i],SOL_SOCKET,SO_RCVTIMEO,(char*)&timeout[1],sizeof(struct timeval))); 
    }
    for(int i=0; i<NUM_DFS; i++){
        free(wearhouse.chunk[i]);
    }
    free(fc);
    fclose(fp);
}



void check_set_filename_flag(char *tmp_fn, flcheck_t *flist_buf, int cidx){
    int fnum = flist_buf->fname_num;
    for(int i=0; i<fnum; i++){
        if(!strcmp(flist_buf->filename[i], tmp_fn)){
            flist_buf->fl_complete[i] = SET_BIT(flist_buf->fl_complete[i], cidx);
            return;
        }
    }
    strncpy(flist_buf->filename[fnum],tmp_fn,strlen(tmp_fn) );
    flist_buf->fl_complete[fnum] = SET_BIT(flist_buf->fl_complete[fnum], cidx);
    flist_buf->fname_num++;
}

void checklist(char buf[NUM_DFS][BUFSIZE], flcheck_t *flist_buf){
    char *p, tmp_fn[40] = {0};
    int cidx, j=0, name_len;
    for(int i=0; i<NUM_DFS; i++){
        if(buf[i]==NULL)
            continue;

        p = strtok(buf[i], "_");
        while(p!=0){
            name_len = strlen(p);
            strncpy(tmp_fn, p, name_len-2);
            sscanf(p+(name_len-1), "%d", &cidx);
            check_set_filename_flag(tmp_fn, flist_buf, cidx);
            memset(tmp_fn, 0, 40*sizeof(char));
            p = strtok(NULL, "_");
        }
        j=0;
    }
}

void handle_list_cmd(int sockfd[NUM_DFS], struct sockaddr_in serveraddr[NUM_DFS],\
                    packet_info_t pkt_info, bool isget, bool *file_exist){
    bool verify = false;
    char buf[NUM_DFS][BUFSIZE] = {0}, tmp[SMLBUFF]=".";
    flcheck_t flist_buf;
    memset(&flist_buf, 0, sizeof(flcheck_t));
    memset(buf,0,sizeof(buf[0][0] * NUM_DFS * NUM_DFS));
    socklen_t serverlen = sizeof(serveraddr[0]); 
    if(isget){
        strcpy(pkt_info.command, "list");
        strcat(tmp, pkt_info.filename);
    }
    for(int i=0; i<NUM_DFS; i++){
        verify = false;
        send_authentication(pkt_info.user_info, sockfd[i],serveraddr[i],&verify);
        if(!verify) 
            continue;
        CHECK(sendto(sockfd[i], &pkt_info, sizeof(pkt_info), 0, (struct sockaddr *)&serveraddr[i], serverlen));
        CHECK(recvfrom(sockfd[i], buf[i], BUFSIZE, 0, (struct sockaddr *)&serveraddr[i], &serverlen));        
        if(!strcmp(buf[i],"n")){
            return;
        }
    }
    checklist(buf, &flist_buf);
    show_packet_info(pkt_info);
    for(int i=0; i<flist_buf.fname_num; i++){
        if(!isget && flist_buf.fl_complete[i]==15){
            printf("%s\n",flist_buf.filename[i]);
        }else if (!isget){
            printf("%s [incomplete]\n",flist_buf.filename[i]);
        }
        if( isget && (!strcmp(flist_buf.filename[i],tmp)) && 
            (flist_buf.fl_complete[i]==15)){
            *file_exist = 1;
        }
    }
}

void handle_mkdir_cmd(int sockfd[NUM_DFS], struct sockaddr_in serveraddr[NUM_DFS],packet_info_t pkt_info){
    bool verify = false;
    socklen_t serverlen = sizeof(serveraddr[0]); 
    for(int i=0; i<NUM_DFS; i++){
        verify = false;
        send_authentication(pkt_info.user_info, sockfd[i],serveraddr[i],&verify);
        if(!verify) 
            continue;
        CHECK(sendto(sockfd[i], &pkt_info, sizeof(pkt_info), 0, (struct sockaddr *)&serveraddr[i], serverlen));
    }
}
void handle_cmds(packet_info_t pkt_info, int sockfd[NUM_DFS],struct sockaddr_in serveraddr[NUM_DFS]){
    bool file_exist = 0, dummy=0;
    if((!strcmp(pkt_info.command,"PUT") || !strcmp(pkt_info.command,"put"))){        
        handle_put_cmd(sockfd, serveraddr, pkt_info);     
    
    }else if(!strcmp(pkt_info.command,"GET") || !strcmp(pkt_info.command, "get")){
        handle_list_cmd(sockfd, serveraddr, pkt_info,1,&file_exist);
        handle_get_cmd(sockfd, serveraddr, pkt_info,file_exist);
    
    }else if(!strcmp(pkt_info.command, "LIST") || !strcmp(pkt_info.command, "list")){
        handle_list_cmd(sockfd, serveraddr,pkt_info,0,&dummy);
    
    }else if(!strcmp(pkt_info.command, "mkdir") || !strcmp(pkt_info.command, "MKDIR")){
        handle_mkdir_cmd(sockfd, serveraddr, pkt_info);

    }else{
        printf("Invalid command\n");
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
