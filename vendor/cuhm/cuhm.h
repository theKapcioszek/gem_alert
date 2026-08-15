#pragma once

#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <openssl/ssl.h>

#define BUF_LEN 1048577 //1MB + 1B buffer
#define RESP_HEAD_LEN 1024

typedef struct {
    char *data;
    size_t count;
} StringView;

typedef struct {

  SSL *ssl;
  SSL_CTX* ctx;
  int sockfd;

} SslCtxSock;

typedef struct {
  int code;
  int content_length;
  StringView header;

} HeaderData;

void sv_chop_left(StringView *sv, size_t n);
void sv_chop_right(StringView *sv, size_t n);
StringView sv_chop_by_delim(StringView *sv, char delim);
void sv_to_cstring(char *cstring,StringView *sv);

SslCtxSock CUHM_ConnectToServiceSSL(char* hostname, char* port);
HeaderData CUHM_RetrieveHeaderHTTP(char* hostname, char* path, SslCtxSock *le_sockets);
HeaderData CUHM_RetrieveHeaderGemini(char* hostname, char* path, SslCtxSock *le_sockets);
int CUHM_RetrieveFileHTTP(SslCtxSock *le_sockets, HeaderData *header_data, FILE* fp, float *progress);
int CUHM_RetrieveFileGemini(SslCtxSock *le_sockets, FILE* fp);
void CUHM_Cleanup(SSL *ssl, SSL_CTX *ctx,int sockfd);

#if defined(CUHM_IMPLEMENTATION)

void sv_chop_left(StringView *sv, size_t n){
  
  if(n > sv->count) n = sv->count;
  sv->count -= n;
  sv->data += n;

  return;
}

void sv_chop_right(StringView *sv, size_t n){
  
  if(n > sv->count) n = sv->count;
  sv->count -= n;

  return;
}


StringView sv_chop_by_delim(StringView *sv, char delim){

  if(strchr(sv->data,delim) == NULL) return *sv;
  size_t i = 0;
  while (i < sv->count && sv->data[i] != delim){
    i += 1;
  }
  if(i < sv->count){
    StringView result = {0};
    result.data = sv->data;
    result.count = i;
    
    sv_chop_left(sv, i+1);
    return result;
  }
}

void sv_to_cstring(char *cstring,StringView *sv){
  for(int i = 0; i < sv->count; i++){
    cstring[i] = sv->data[i];
  }
  return;
}

SslCtxSock CUHM_ConnectToServiceSSL(char* hostname, char* port){

  SslCtxSock struct_to_return = {0};

  SSL_library_init();
  SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());

  struct addrinfo hints, *result;
  int le_socket = 0;

  memset(&hints, 0, sizeof(hints));

  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  if (getaddrinfo(hostname,port,&hints,&result) != 0 ) return struct_to_return;

  le_socket = socket(result->ai_family,result->ai_socktype,result->ai_protocol);
  connect(le_socket,result->ai_addr,result->ai_addrlen);

  freeaddrinfo(result);

  SSL *ssl = SSL_new(ctx);
  SSL_set_fd(ssl,le_socket);
  SSL_set_tlsext_host_name(ssl, hostname);
  SSL_connect(ssl);

  struct_to_return.ssl = ssl;
  struct_to_return.ctx = ctx;
  struct_to_return.sockfd = le_socket;

  return struct_to_return;

}

SslCtxSock CUHM_ConnectToService(char* hostname, char* port){

  SslCtxSock struct_to_return = {0};

  struct addrinfo hints, *result;
  int le_socket = 0;

  memset(&hints, 0, sizeof(hints));

  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  if (getaddrinfo(hostname,port,&hints,&result) != 0 ) return struct_to_return;
 
  le_socket = socket(result->ai_family,result->ai_socktype,result->ai_protocol);
  connect(le_socket,result->ai_addr,result->ai_addrlen);

  freeaddrinfo(result);

  struct_to_return.ssl = NULL;
  struct_to_return.ctx = NULL;
  struct_to_return.sockfd = le_socket;

  return struct_to_return;
}

HeaderData CUHM_RetrieveHeaderHTTP(char* hostname, char* path, SslCtxSock *le_sockets){

  char buffer[1024]; memset(&buffer, 0, sizeof(buffer));
  char message[1024]; memset(&message, 0 ,sizeof(message));
  char recieved_header[RESP_HEAD_LEN]; memset(&recieved_header, 0, sizeof(recieved_header));
  strcpy(message,"GET /");strcat(message,path);strcat(message," HTTP/1.1\r\nHost: ");strcat(message,hostname);strcat(message,"\r\nConnection: close\r\n\r\n");
  size_t bytes_read = 0;
  if (le_sockets->ssl != NULL){
    SSL_write(le_sockets->ssl,message,strlen(message));
    while(SSL_read(le_sockets->ssl,buffer,1) != 0){
      ++bytes_read;
      if (bytes_read >= RESP_HEAD_LEN) break;
      strcat(recieved_header,buffer);
      if (strstr(recieved_header,"\r\n\r\n") != NULL) break;
    }
  }
  else{
    write(le_sockets->sockfd,message,strlen(message));
    while(read(le_sockets->sockfd,buffer,1) != 0){
      ++bytes_read;
      if (bytes_read >= RESP_HEAD_LEN) break;
      strcat(recieved_header,buffer);
      if (strstr(recieved_header,"\r\n\r\n") != NULL) break;
    }
  }

  HeaderData result = {0};
  result.header.data = recieved_header; //Potentially dangerous
  strcpy(result.header.data,recieved_header);
  result.header.count = strlen(recieved_header);

  int chop_amount = strlen("HTTP/1.1 ");
  sv_chop_left(&result.header,chop_amount);
  result.header.count = 3;
  char cs_code[4]; sv_to_cstring(cs_code,&result.header);
  result.code = atoi(cs_code);

  result.header.data -= chop_amount;
  result.header.count = strlen(recieved_header);

  char *cs_chopped_header = strstr(result.header.data,"Content-Length: ");
  
  if (cs_chopped_header != NULL){
    StringView sv_chopped_header = {0};
    sv_chopped_header.data = cs_chopped_header;
    sv_chopped_header.count = strlen(cs_chopped_header);

    sv_chop_by_delim(&sv_chopped_header,' ');
    StringView sv_content_length = sv_chop_by_delim(&sv_chopped_header, '\n');
    char cs_content_length[100];
    sv_to_cstring(cs_content_length,&sv_content_length);

    result.content_length = atoi(cs_content_length);
  }else{
    result.content_length = 0;
  }
  return result;

}

HeaderData CUHM_RetrieveHeaderGemini(char* hostname, char* path, SslCtxSock *le_sockets){

  char buffer[1024]; memset(&buffer, 0, sizeof(buffer));
  char message[1024]; memset(&message, 0 ,sizeof(message));
  char recieved_header[RESP_HEAD_LEN]; memset(&recieved_header, 0, sizeof(recieved_header));
  strcpy(message,"gemini://");strcat(message,hostname);strcat(message,"/");strcat(message,path);strcat(message,"\r\n");

  size_t bytes_read = 0;
  if (le_sockets->ssl != NULL){
    SSL_write(le_sockets->ssl,message,strlen(message));
    while(SSL_read(le_sockets->ssl,buffer,1) != 0){
      ++bytes_read;
      if (bytes_read >= RESP_HEAD_LEN) break;
      strcat(recieved_header,buffer);
      if (strstr(recieved_header,"\r\n") != NULL) break;
    }
  }
  else{
    write(le_sockets->sockfd,message,strlen(message));
    while(read(le_sockets->sockfd,buffer,1) != 0){
      ++bytes_read;
      if (bytes_read >= RESP_HEAD_LEN) break;
      strcat(recieved_header,buffer);
      if (strstr(recieved_header,"\r\n") != NULL) break;
    }
  }
  HeaderData result = {0};
  result.header.data = recieved_header;//Potentially dangerous
  result.header.count = strlen(recieved_header);

  char cs_code[2] = {0};
  cs_code[0] = result.header.data[0];
  cs_code[1] = result.header.data[1];

  result.code = atoi(cs_code);

  return result;

}

int CUHM_RetrieveFileHTTP(SslCtxSock *le_sockets, HeaderData *header_data, FILE* fp, float *progress){

  char buffer[BUF_LEN]; memset(&buffer, 0, sizeof(buffer));
  size_t read_bytes = 0;
  size_t bytes_recieved = 0;
  size_t bytes_to_recieve = header_data->content_length;

  while(1){
    if(progress != NULL) *progress = ((double)bytes_recieved/bytes_to_recieve) * 100;
    read_bytes = le_sockets->ssl != NULL ? SSL_read(le_sockets->ssl,buffer,BUF_LEN-1) : read(le_sockets->sockfd,buffer,BUF_LEN-1);
    bytes_recieved += read_bytes;
    fwrite(buffer,1,read_bytes,fp);
    if(bytes_recieved >= bytes_to_recieve) break;
  }

  return 0;

}

int CUHM_RetrieveFileGemini(SslCtxSock *le_sockets, FILE* fp){

  char buffer[BUF_LEN]; memset(&buffer, 0, sizeof(buffer));
  size_t read_bytes = 0;

  while(1){
     read_bytes = le_sockets->ssl != NULL ? SSL_read(le_sockets->ssl,buffer,BUF_LEN-1) : read(le_sockets->sockfd,buffer,BUF_LEN-1);
     fwrite(buffer,1,read_bytes,fp);
     if(read_bytes <= 0) break;
  }

  return 0;

}

void CUHM_Cleanup(SSL *ssl, SSL_CTX *ctx,int sockfd){

  SSL_shutdown(ssl);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  shutdown(sockfd,1);

  return;
}

#endif //CUHM_IMPLEMENTATION
