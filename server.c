//  server
//
//  Created by Liu Yuqi on 14/11/24.
//  Copyright (c) 2014年 Liu Yuqi. All rights reserved.
//

#include <stdio.h>
#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/pem.h"
#include "openssl/x509.h"
#include "openssl/crypto.h"
#include "openssl/rsa.h"
#include "openssl/rand.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define SERVER_PORT    1234
#define SERVER "127.0.0.1"

int  main ()
{
    
    
    //initialization//
    struct sockaddr_in client;
    SSL_CTX *ctx;       //init CTX
    SSL_METHOD *meth;   //init the way communicate
    SSL *ssl;           //init for build socket
    
    void SSL_load_error_strings(void);    // registers the error strings for libcrypto and libssl
    SSL_library_init();                 //register the cipher and message
    OpenSSL_add_all_algorithms();
    meth =(SSL_METHOD*) SSLv3_server_method();  //choose the communicate method to be SSLv3
    ctx = SSL_CTX_new (meth);   //create a new context str for SSL
    
    if (ctx==NULL)
    {
        printf("SSL_CTX_new failed.\n");
        return -1;
    }
    // set cipher list and mode
    
    SSL_CTX_set_cipher_list(ctx,"RC4-SHA");
    SSL_CTX_set_mode(ctx,SSL_MODE_AUTO_RETRY);
    
    
    // create a new socket
    ssl=SSL_new(ctx);
    if(NULL == ssl)
        return -1;
    
    
    
    //creating and setting up the socket
    struct sockaddr_in sa_serv;
    
    int listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHK_ERR(listen_sock, "socket");
    
    memset(&sa_serv, 0, sizeof(sa_serv));
    sa_serv.sin_family      = AF_INET;
    sa_serv.sin_addr.s_addr = INADDR_ANY;
    sa_serv.sin_port        = htons(SERVER_PORT);      /* Server Port number */
    
    int err = bind(listen_sock, (struct sockaddr*)&sa_serv,sizeof(sa_serv));
    CHK_ERR(err, "bind");
    
    /* Receive a TCP connection. */
    err = listen(listen_sock, 5);
    CHK_ERR(err, "listen");
            
    //Establishing the connection
    struct sockaddr_in sa_cli;
    int client_len=0;

    int sock = accept(listen_sock, (struct sockaddr*)&sa_cli, &client_len);
    printf( "Connection from %lx, port %x\n",
               sa_cli.sin_addr.s_addr, sa_cli.sin_port);
    
    //setting up the socket BIO
            
    SSL_set_fd(ssl,sock);
    
    //setting the accept state for server
    
    SSL_set_accept_state(ssl);
            
    //read encrypted challenge from the client
    
    int PRNGNum=128;
    unsigned char encrypchal[512];
    SSL_read(ssl,encrypchal,512);
    
    // generate RSA structure
    
    FILE *fp;
    fp=fopen("private.pem","rb");
    RSA *rsa=NULL;
    rsa = PEM_read_RSAPrivateKey(fp,rsa,NULL,NULL);
    
    
    //get privatekey from file, its the common key
    char *privKey;
    char ch;
    long size=0;
    fp=fopen("private.pem","rb");
    ch=fgetc(fp);
    while(ch!=EOF)
    {
        size=size+1;
        ch=fgetc(fp);
    }
    privKey=calloc(1,size+1);
    fread(privKey,size,1,fp);
    
    fclose(fp);

    //decrypt the encrypted challenge with privatekey
    
    char decrp[512];
    
    int dflag=RSA_private_decrypt(PRNGNum,encrypchal,decrp,rsa,RSA_NO_PADDING);
    
    if (dflag<0)
    {
        ERR_print_errors_fp(stderr);
        printf("decrypt failed.\n");
    }

    //hash the challenge
    int hashlength=20;
    unsigned char hashbuf[hashlength];
    
    
    SHA1(decrp, PRNGNum,hashbuf);
    
    //encrypt the hashed challenge
    unsigned char encryp[512]={};
    int eflag=RSA_private_encrypt(hashlength,hashbuf,encryp,rsa,RSA_PKCS1_PADDING);
    if (eflag<0)
    {
        ERR_print_errors_fp(stderr);
        printf("encrypt failed.\n");
    }
    
    //send the encrypted message to client
    SSL_write(ssl, encryp, 512);
    
    //after the authentication waiting for the command of client
    char command[20];
    SSL_read(ssl,command,20);
    if (strcmp(command,"receive"))
{
    //receive file step.1 create file to store data
    
    fp=fopen("sample.txt","ab");
    if(NULL== fp)
    {
        printf("error opening file.\n");
    }
    
    //receive file step.2 receive data in chunks of 256 bytes
    char recvBuff[256];
    int bytesReceived=0;
    memset(recvBuff,’0’,sizeof(recvBuff));
    while((bytesReceived = read(sock, recvBuff, 256)) > 0)
        
    {
        printf("Bytes received %d\n",bytesReceived);
        fwrite(recvBuff, 1,bytesReceived,fp);
        // printf("%s \n", recvBuff);
    }
    
    if(bytesReceived < 0)
    {
        printf("\n Read Error \n");
    }
}

    else if(strcmp(command,"send"))
{
    //send file step.1 open the file that wish to transfer
               
    fp=fopen("sample.txt","rb");
    if(fp==NULL)
    {
        printf("File open failed");
        return -1;
    }
               
    //send file step.2 read data from file and send it
               
    while(1)
    {
        unsigned char buff[256]={0};
        int nread=fread(buff,1,256,fp);
        printf("Bytes read %d \n", nread);
                   
        if(nread>0)
            {
                printf("Sending \n");
                write(sock,buff,nread);
            }
                   
        if(nread<256)
            {
                if (foe(fp))
                printf("End of file\n");
                break;
            }
    }
}
    else
    {
        printf("Command received wrong.\n");
    }
               

printf("hello world\n");
SSL_shutdown(ssl);
SSL_free(ssl);
SSL_CTX_free(ctx);
return(0);
}
    
    
    
