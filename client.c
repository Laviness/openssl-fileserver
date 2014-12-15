//  client
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

#define MSGLENGTH 1024

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
    struct sockaddr_in server_addr;
    
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(sock< 0)
    {
        printf("socket establishment fail.\n");
    }
    
    
    memset (&server_addr, '\0', sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT); /* Server Port number */
    server_addr.sin_addr.s_addr = inet_addr(SERVER); /* Server IP */
    
    err = connect(sock, (struct sockaddr*) &server_addr, sizeof(server_addr));
    if(err< 0)
    {
        printf("connect fail.\n");
    }
    
            
    //setting up the socket BIO
            
        SSL_set_fd(ssl,sock);
        
    //setting the connect state for client
            
        SSL_set_connect_state(ssl);
            
-------------------------------------------------------------------
    //generate challenge by PRNG
        int PRNGNum=128;
        char buffer[128];
        int cflag = RAND_bytes(buffer, sizeof(buffer));
        unsigned long err = ERR_get_error();
        if(cflag == 1)
        {
            printf("RAND_bytes success.\n");
                   
        }
    //hash the challenge for compare the receive one
            unsigned char ohash[20];
            unsigned char *hash=SHA1(buffer,128,ohash);
            ohash[20]=‘\0’;
                       
                       
    // generate RSA structure
                       
            FILE *fp;
            fp=fopen("public.pem","rb")
            RSA *rsa=NULL;
            rsa = PEM_read_RSAPubilcKey(fp,rsa,NULL,NULL);
                                
    //encrypt challenge using public key
            char encrp[512];
                                
            int eflag=RSA_public_encrypt(PRNGNum,buffer,encrp,rsa,RSA_NO_PADDING);
                                
            if (eflag<0)
            {
                ERR_print_errors_fp(stderr);
                printf("Encrypt failed.\n");
            }
                                
    //read hashed info from server
                                
            unsigned char encryphash[512];
            SSL_read(ssl,encryphash,512);
                                
    //decrypt the data
            unsigned char obuf[20];
            int dflag=RSA_public_derypt(512,encryphash,obuf,rsa,RSA_PKCS1_PADDING);
                                
                                
                                
    //compare the data with the original challenge
            int cflag=0;
            cflag=strcmp(obuf,ohash);
            if (flag==0)
            {
                printf("authentication successful.\n");
            }
            else
            {
                printf("Authentication failed. Preparing for Disconnection.\n");
                SSL_shutdown(ssl);
            }
                                
    //after the authentication
    
    //send command to the server
            
            char command[20];
            printf("Type the command ('send' or 'receive')");
            scanf("%s",command);
            SSL_write(ssl,command,strlen(command));
                   
    if(strcmp(command,"receive")==0)
    
{
    //receive file step.1 create file to store data
                                
            fp=fopen("sample.txt","ab");
            if(NULL== fp)
            {
                printf("error opening file");
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
                                           
    else if (strcmp(command,"send"))
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
                        if (fp==EOF)
                        {
                        printf("End of file\n");
                        break;
                        }
                    }
            }
}
    else
    {
        printf("Command input error,try again.\n");
    }
                                           
printf("hello world\n");
SSL_shutdown(ssl);
SSL_free(ssl);
SSL_CTX_free(ctx);
return(0);

}
                                                  }
