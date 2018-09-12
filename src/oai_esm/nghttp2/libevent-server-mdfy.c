#ifdef __sgi
#define errx(exitcode, format, args...)                                        \
{                                                                            \
    warnx(format, ##args);                                                     \
    exit(exitcode);                                                            \
}
#define warn(format, args...) warnx(format ": %s", ##args, strerror(errno))
#define warnx(format, args...) fprintf(stderr, format "\n", ##args)
#endif

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <sys/types.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif /* HAVE_SYS_SOCKET_H */
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif /* HAVE_NETDB_H */
#include <signal.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <sys/stat.h>
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif /* HAVE_FCNTL_H */
#include <ctype.h>
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif /* HAVE_NETINET_IN_H */
#include <netinet/tcp.h>
#ifndef __sgi
#include <err.h>
#endif
#include <string.h>
#include <errno.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>

#include <event.h>
#include <event2/event.h>
#include <event2/bufferevent_ssl.h>
#include <event2/listener.h>

#include <nghttp2/nghttp2.h>


#include <pthread.h>
#include <unistd.h>
#include<stdlib.h>
#include<math.h>
#include<float.h>
#include<ctype.h>
#include"mem2str2mem.h"
#include"cJSON.h"
//#include"hashAPI.h"
#include<stdbool.h>
#include"log.h"
#include"EsmCause.h"
#include"AdditionalUpdateType.h"
#include"NasRequestType.h"
#include"common_types.h"
#include"3gpp_24.008.h"
#include"3gpp_29.274.h"
#include"emmData.h"
#include"esm_data.h"
#include"esm_proc.h"
#include"esm_cause.h"

void JsonDataParserAndProd(char*);
char * dataRTN ;//client request need to be returned

char * url ;//url requested by client
char * q=NULL;
int rdy_rd=0;


#define OUTPUT_WOULDBLOCK_THRESHOLD (1 << 16)

#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

#define MAKE_NV_SERVER(NAME, VALUE)                                                   \
{                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1,    \
    NGHTTP2_NV_FLAG_NONE                                                   \
}

//#define SERVER_IP "127.0.0.1:10020"



struct app_context;
typedef struct app_context app_context;

typedef struct http2_stream_data_server {
    struct http2_stream_data_server *prev, *next;
    char *request_path;
    int32_t stream_id;
    int fd;
} http2_stream_data_server;

typedef struct http2_session_data_server {
    struct http2_stream_data_server root;
    struct bufferevent *bev;
    app_context *app_ctx;
    nghttp2_session *session;
    char *client_addr;
} http2_session_data_server;

struct app_context {
    SSL_CTX *ssl_ctx;
    struct event_base *evbase;
};

#define DEBUG 1

static unsigned char next_proto_list[256];
static size_t next_proto_list_len;

static int next_proto_cb(SSL *ssl, const unsigned char **data,
        unsigned int *len, void *arg) {
    (void)ssl;
    (void)arg;

    *data = next_proto_list;
    *len = (unsigned int)next_proto_list_len;
    return SSL_TLSEXT_ERR_OK;
}

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
static int alpn_select_proto_cb(SSL *ssl, const unsigned char **out,
        unsigned char *outlen, const unsigned char *in,
        unsigned int inlen, void *arg) {
    int rv;
  (void)ssl;
  (void)arg;

  rv = nghttp2_select_next_protocol((unsigned char **)out, outlen, in, inlen);

  if (rv != 1) {
    return SSL_TLSEXT_ERR_NOACK;
  }

  return SSL_TLSEXT_ERR_OK;
}
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L

/* Create SSL_CTX. */
static SSL_CTX *create_ssl_ctx_server(const char *key_file, const char *cert_file) {
  SSL_CTX *ssl_ctx;
  EC_KEY *ecdh;

  ssl_ctx = SSL_CTX_new(SSLv23_server_method());
  if (!ssl_ctx) {
    errx(1, "Could not create SSL/TLS context: %s",
         ERR_error_string(ERR_get_error(), NULL));
  }
  SSL_CTX_set_options(ssl_ctx,
                      SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                          SSL_OP_NO_COMPRESSION |
                          SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

  ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (!ecdh) {
    errx(1, "EC_KEY_new_by_curv_name failed: %s",
         ERR_error_string(ERR_get_error(), NULL));
  }
  SSL_CTX_set_tmp_ecdh(ssl_ctx, ecdh);
  EC_KEY_free(ecdh);

  if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1) {
    errx(1, "Could not read private key file %s", key_file);
  }
  if (SSL_CTX_use_certificate_chain_file(ssl_ctx, cert_file) != 1) {
    errx(1, "Could not read certificate file %s", cert_file);
  }

  next_proto_list[0] = NGHTTP2_PROTO_VERSION_ID_LEN;
  memcpy(&next_proto_list[1], NGHTTP2_PROTO_VERSION_ID,
         NGHTTP2_PROTO_VERSION_ID_LEN);
  next_proto_list_len = 1 + NGHTTP2_PROTO_VERSION_ID_LEN;

  SSL_CTX_set_next_protos_advertised_cb(ssl_ctx, next_proto_cb, NULL);

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
  SSL_CTX_set_alpn_select_cb(ssl_ctx, alpn_select_proto_cb, NULL);
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L

  return ssl_ctx;
}

/* Create SSL object */
static SSL *create_ssl(SSL_CTX *ssl_ctx) {
  SSL *ssl;
  ssl = SSL_new(ssl_ctx);
  if (!ssl) {
    errx(1, "Could not create SSL/TLS session object: %s",
         ERR_error_string(ERR_get_error(), NULL));
  }
  return ssl;
}

static void add_stream(http2_session_data_server *session_data,
                       http2_stream_data_server *stream_data) {
  stream_data->next = session_data->root.next;
  session_data->root.next = stream_data;
  stream_data->prev = &session_data->root;
  if (stream_data->next) {
    stream_data->next->prev = stream_data;
  }
}

static void remove_stream(http2_session_data_server *session_data,
                          http2_stream_data_server *stream_data) {
  (void)session_data;

  stream_data->prev->next = stream_data->next;
  if (stream_data->next) {
    stream_data->next->prev = stream_data->prev;
  }
}

static http2_stream_data_server *
create_http2_stream_data_server(http2_session_data_server *session_data, int32_t stream_id) {
  http2_stream_data_server *stream_data;
  stream_data = malloc(sizeof(http2_stream_data_server));
  memset(stream_data, 0, sizeof(http2_stream_data_server));
  stream_data->stream_id = stream_id;
  stream_data->fd = -1;

  add_stream(session_data, stream_data);
  return stream_data;
}

static void delete_http2_stream_data_server(http2_stream_data_server *stream_data) {
  if (stream_data->fd != -1) {
    close(stream_data->fd);
  }
  free(stream_data->request_path);
  free(stream_data);
}

static http2_session_data_server *create_http2_session_data_server(app_context *app_ctx,
                                                     int fd,
                                                     struct sockaddr *addr,
                                                     int addrlen) {
  int rv;
  http2_session_data_server *session_data;
  SSL *ssl;
  char host[NI_MAXHOST];
  int val = 1;

  ssl = create_ssl(app_ctx->ssl_ctx);
  session_data = malloc(sizeof(http2_session_data_server));
  memset(session_data, 0, sizeof(http2_session_data_server));
  session_data->app_ctx = app_ctx;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&val, sizeof(val));
  session_data->bev = bufferevent_openssl_socket_new(
      app_ctx->evbase, fd, ssl, BUFFEREVENT_SSL_ACCEPTING,
      BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
  bufferevent_enable(session_data->bev, EV_READ | EV_WRITE);
  rv = getnameinfo(addr, (socklen_t)addrlen, host, sizeof(host), NULL, 0,
                   NI_NUMERICHOST);
  if (rv != 0) {
    session_data->client_addr = strdup("(unknown)");
  } else {
    session_data->client_addr = strdup(host);
  }

  return session_data;
}

static void delete_http2_session_data_server(http2_session_data_server *session_data) {
  http2_stream_data_server *stream_data;
  SSL *ssl = bufferevent_openssl_get_ssl(session_data->bev);
  /*fprintf(stderr, "%s disconnected\n", session_data->client_addr);*/
  if (ssl) {
    SSL_shutdown(ssl);
  }
  bufferevent_free(session_data->bev);
  nghttp2_session_del(session_data->session);
  for (stream_data = session_data->root.next; stream_data;) {
    http2_stream_data_server *next = stream_data->next;
    delete_http2_stream_data_server(stream_data);
    stream_data = next;
  }
  free(session_data->client_addr);
  free(session_data);
}

/* Serialize the frame and send (or buffer) the data to
   bufferevent. */
static int session_send_server(http2_session_data_server *session_data) {
  //fprintf(stderr,"session_send_server\n");
  int rv;
  rv = nghttp2_session_send(session_data->session);//这句话是别的库了
  if (rv != 0) {
    warnx("Fatal error: %s", nghttp2_strerror(rv));
    return -1;
  }
  return 0;
}

/* Read the data in the bufferevent and feed them into nghttp2 library
   function. Invocation of nghttp2_session_mem_recv() may make
   additional pending frames, so call session_send_server() at the end of the
   function. */
static int session_recv(http2_session_data_server *session_data) {
  ssize_t readlen;
  struct evbuffer *input = bufferevent_get_input(session_data->bev);
  size_t datalen = evbuffer_get_length(input);
  unsigned char *data = evbuffer_pullup(input, -1);

  readlen = nghttp2_session_mem_recv(session_data->session, data, datalen);
  //printf("data\t%s\n",data);
  if (readlen < 0) {
    warnx("Fatal error: %s", nghttp2_strerror((int)readlen));
    return -1;
  }
  if (evbuffer_drain(input, (size_t)readlen) != 0) {
    warnx("Fatal error: evbuffer_drain failed");
    return -1;
  }
  if (session_send_server(session_data) != 0) {
    return -1;
  }
  return 0;
}

static ssize_t send_callback_server(nghttp2_session *session, const uint8_t *data,
                             size_t length, int flags, void *user_data) {
  http2_session_data_server *session_data = (http2_session_data_server *)user_data;
  struct bufferevent *bev = session_data->bev;
  (void)session;
  (void)flags;

  /* Avoid excessive buffering in server side. */
  if (evbuffer_get_length(bufferevent_get_output(session_data->bev)) >=
      OUTPUT_WOULDBLOCK_THRESHOLD) {
    return NGHTTP2_ERR_WOULDBLOCK;
  }
  //fprintf(stderr,"send_callback_server\n");
  bufferevent_write(bev, data, length);
  return (ssize_t)length;
}

/* Returns nonzero if the string |s| ends with the substring |sub| */
static int ends_with(const char *s, const char *sub) {
  size_t slen = strlen(s);
  size_t sublen = strlen(sub);
  if (slen < sublen) {
    return 0;
  }
  return memcmp(s + slen - sublen, sub, sublen) == 0;
}

/* Returns int value of hex string character |c| */
static uint8_t hex_to_uint(uint8_t c) {
  if ('0' <= c && c <= '9') {
    return (uint8_t)(c - '0');
  }
  if ('A' <= c && c <= 'F') {
    return (uint8_t)(c - 'A' + 10);
  }
  if ('a' <= c && c <= 'f') {
    return (uint8_t)(c - 'a' + 10);
  }
  return 0;
}

/* Decodes percent-encoded byte string |value| with length |valuelen|
   and returns the decoded byte string in allocated buffer. The return
   value is NULL terminated. The caller must free the returned
   string. */
static char *percent_decode(const uint8_t *value, size_t valuelen) {
  char *res;

  res = malloc(valuelen + 1);
  if (valuelen > 3) {
    size_t i, j;
    for (i = 0, j = 0; i < valuelen - 2;) {
      if (value[i] != '%' || !isxdigit(value[i + 1]) ||
          !isxdigit(value[i + 2])) {
        res[j++] = (char)value[i++];
        continue;
      }
      res[j++] =
          (char)((hex_to_uint(value[i + 1]) << 4) + hex_to_uint(value[i + 2]));
      i += 3;
    }
    memcpy(&res[j], &value[i], 2);
    res[j + 2] = '\0';
  } else {
    memcpy(res, value, valuelen);
    res[valuelen] = '\0';
  }
  return res;
}

static ssize_t file_read_callback(nghttp2_session *session, int32_t stream_id,
                                  uint8_t *buf, size_t length,
                                  uint32_t *data_flags,
                                  nghttp2_data_source *source,
                                  void *user_data) {
  int fd = source->fd;
  ssize_t r;
  (void)session;
  (void)stream_id;
  (void)user_data;


      int i=0;
      for(int i=0;i<2000;i++)
      {
          buf[i]=0;
      }
      memcpy(buf,dataRTN,strlen(dataRTN));
      /*printf("发送给client的消息:%s\n",p);*/
      r=strlen(dataRTN);
      free(dataRTN);
	  *data_flags |= NGHTTP2_DATA_FLAG_EOF;

  if (r == -1) {
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
  }
  if (r == 0) {
      *data_flags |= NGHTTP2_DATA_FLAG_EOF;
  }
  return r;
}

static int send_response(nghttp2_session *session, int32_t stream_id,
                         nghttp2_nv *nva, size_t nvlen, int fd) {
  int rv;
  nghttp2_data_provider data_prd;
  data_prd.source.fd = fd;
  data_prd.read_callback = file_read_callback;
  //fprintf(stderr,"send-response\n");
  rv = nghttp2_submit_response(session, stream_id, nva, nvlen, &data_prd);
  if (rv != 0) {
    warnx("Fatal error: %s", nghttp2_strerror(rv));
    return -1;
  }
  return 0;
}

/*static const char ERROR_HTML[] = "<html><head><title>404</title></head>"*/
                                 /*"<body><h1>404 Not Found</h1></body></html>";*/

char ERROR_HTML[] = "EORROR_HTML 没有你的请求文件\n";//注意 \0并不会打断发送
static int error_reply(nghttp2_session *session,
                       http2_stream_data_server *stream_data) {
  int rv;
  ssize_t writelen;
  int pipefd[2];
  nghttp2_nv hdrs[] = {MAKE_NV_SERVER(":status", "404")};

  rv = pipe(pipefd);
  if (rv != 0) {
    warn("Could not create pipe");
    rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                   stream_data->stream_id,
                                   NGHTTP2_INTERNAL_ERROR);
    if (rv != 0) {
      warnx("Fatal error: %s", nghttp2_strerror(rv));
      return -1;
    }
    return 0;
  }


  writelen = write(pipefd[1], ERROR_HTML, strlen(ERROR_HTML) );
  close(pipefd[1]);
  if (writelen != strlen(ERROR_HTML)) {
      close(pipefd[0]);
      return -1;
  }

  /*free(INPUT);//free*/
  stream_data->fd = pipefd[0];

  if (send_response(session, stream_data->stream_id, hdrs, ARRLEN(hdrs),
                    pipefd[0]) != 0) {
    close(pipefd[0]);
    return -1;
  }
  return 0;
}

/* nghttp2_on_header_callback: Called when nghttp2 library emits
   single header name/value pair. */
static int on_header_callback_server(nghttp2_session *session,
                              const nghttp2_frame *frame, const uint8_t *name,
                              size_t namelen, const uint8_t *value,
                              size_t valuelen, uint8_t flags, void *user_data) {
  http2_stream_data_server *stream_data;
  const char PATH[] = ":path";
  (void)flags;
  (void)user_data;
  //printf("name\t%s\n",name);
  //printf("value start\t%s\n",value);
  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
    if (frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
      break;
    }
    stream_data =
        nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
    if (!stream_data || stream_data->request_path) {
      break;
    }
    if (namelen == sizeof(PATH) - 1 && memcmp(PATH, name, namelen) == 0) {
      size_t j;
      for (j = 0; j < valuelen && value[j] != '?'; ++j)
        ;
     // printf("value\t%s\n",value);
	  url = (char *)malloc(sizeof(char)*strlen(value));
	  memcpy(url,value,strlen(value));
	  //printf("url\t%s\n",url);
      stream_data->request_path = percent_decode(value, j);
    }
    break;
  }
  return 0;
}

static int on_begin_headers_callback_server(nghttp2_session *session,
                                     const nghttp2_frame *frame,
                                     void *user_data) {
  http2_session_data_server *session_data = (http2_session_data_server *)user_data;
  http2_stream_data_server *stream_data;

  if (frame->hd.type != NGHTTP2_HEADERS ||
      frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
    return 0;
  }
  stream_data = create_http2_stream_data_server(session_data, frame->hd.stream_id);
  nghttp2_session_set_stream_user_data(session, frame->hd.stream_id,
                                       stream_data);
  return 0;
}

/* Minimum check for directory traversal. Returns nonzero if it is
   safe. */
static int check_path(const char *path) {
  //fprintf(stderr,"check-path\n");
  /* We don't like '\' in url. */
  return path[0] && path[0] == '/' && strchr(path, '\\') == NULL &&
         strstr(path, "/../") == NULL && strstr(path, "/./") == NULL &&
         !ends_with(path, "/..") && !ends_with(path, "/.");
}

static int on_request_recv(nghttp2_session *session,//这一个函数打开了文件
                           http2_session_data_server *session_data,
                           http2_stream_data_server *stream_data) {
  int fd;
  nghttp2_nv hdrs[] = {MAKE_NV_SERVER(":status", "200")};
  //printf("on_request_recv\n");
  char *rel_path;
    if (!stream_data->request_path) {
		//printf("----------------------dukl server requested url---------------\n");
		//printf("%s\n",stream_data->request_path);
    if (error_reply(session, stream_data) != 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
  }
  /*fprintf(stderr, "%s GET %s\n", session_data->client_addr,*/
          /*stream_data->request_path);*/
  if (!check_path(stream_data->request_path)) {
    if (error_reply(session, stream_data) != 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
  }
  for (rel_path = stream_data->request_path; *rel_path == '/'; ++rel_path)
    ;
  fd = popen(rel_path,"r");
  if (fd == -1) {// 打开文件失败
    if (error_reply(session, stream_data) != 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
  }
  stream_data->fd = fd;//记录文件描述,这个函数return之后，通过文件描述来 访问文件

  if (send_response(session, stream_data->stream_id, hdrs, ARRLEN(hdrs), fd) !=//如果gg了，就关闭文件描述
      0) {
    close(fd);
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

static int on_frame_recv_callback_server(nghttp2_session *session,
                                  const nghttp2_frame *frame, void *user_data) {
  http2_session_data_server *session_data = (http2_session_data_server *)user_data;
  http2_stream_data_server *stream_data;
  //printf("on_frame_recv\n");
  switch (frame->hd.type) {
  case NGHTTP2_DATA:
	  //printf("data\n");
    /* Check that the client request has finished */
    if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
		//printf("test\n");
      stream_data =
          nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
      /* For DATA and HEADERS frame, this callback may be called after
         on_stream_close_callback. Check that stream still alive. */
      if (!stream_data) {
        return 0;
      }
	  //printf("run\n");
      return on_request_recv(session, session_data, stream_data);
    }
	  break;
	  //stream_data = nghttp2_session_get_stream_user_data(session,frame->hd.stream_id);
	  //return on_request_recv(session,session_data,stream_data);
  case NGHTTP2_HEADERS:
	  //printf("header\n");
    /* Check that the client request has finished */
    if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
		//printf("test\n");
      stream_data =
          nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
      /* For DATA and HEADERS frame, this callback may be called after
         on_stream_close_callback. Check that stream still alive. */
      if (!stream_data) {
        return 0;
      }
	  //printf("run\n");
      return on_request_recv(session, session_data, stream_data);
    }
    break;
  default:
    break;
  }
  return 0;
}

static int on_stream_close_callback_server(nghttp2_session *session, int32_t stream_id,
                                    uint32_t error_code, void *user_data) {
  http2_session_data_server *session_data = (http2_session_data_server *)user_data;
  http2_stream_data_server *stream_data;
  (void)error_code;

  stream_data = nghttp2_session_get_stream_user_data(session, stream_id);
  if (!stream_data) {
    return 0;
  }
  remove_stream(session_data, stream_data);
  delete_http2_stream_data_server(stream_data);
  return 0;
}
static int data_recv_callback(nghttp2_session * session,uint8_t flags,int32_t stream_id,const uint8_t * data,ssize_t len,void * user_data){
    //printf("data_recv_callback\n"); 
	//printf("data\t%s\n",data);
	char * data_recv = (char*)malloc(len+1);
	//memcpy(data_recv,(char*)data,len);
	for(int i=0;i<len;i++){
		data_recv[i] = data[i];
	}
	data_recv[len] = '\0';
	printf("len\t%d\n",len);
	printf("data_recv\t%s\n",data_recv);
	JsonDataParserAndProd(data_recv);
	free(data_recv);
	//send_response(session,stream_id,NULL,0,0);

}
static void initialize_nghttp2_session_server(http2_session_data_server *session_data) {
  nghttp2_session_callbacks *callbacks;

  nghttp2_session_callbacks_new(&callbacks);

  nghttp2_session_callbacks_set_send_callback(callbacks, send_callback_server);

  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
                                                       on_frame_recv_callback_server);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks,
			                                           data_recv_callback);

  nghttp2_session_callbacks_set_on_stream_close_callback(
      callbacks, on_stream_close_callback_server);

  nghttp2_session_callbacks_set_on_header_callback(callbacks,
                                                   on_header_callback_server);

  nghttp2_session_callbacks_set_on_begin_headers_callback(
      callbacks, on_begin_headers_callback_server);

  nghttp2_session_server_new(&session_data->session, callbacks, session_data);

  nghttp2_session_callbacks_del(callbacks);
}

/* Send HTTP/2 client connection header, which includes 24 bytes
   magic octets and SETTINGS frame */
static int send_server_connection_header(http2_session_data_server *session_data) {
  nghttp2_settings_entry iv[1] = {
      {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
  int rv;

  rv = nghttp2_submit_settings(session_data->session, NGHTTP2_FLAG_NONE, iv,
                               ARRLEN(iv));
  if (rv != 0) {
    warnx("Fatal error: %s", nghttp2_strerror(rv));
    return -1;
  }
  return 0;
}

/* readcb_server for bufferevent after client connection header was
   checked. */
static void readcb_server(struct bufferevent *bev, void *ptr) {
  http2_session_data_server *session_data = (http2_session_data_server *)ptr;
  (void)bev;

  if (session_recv(session_data) != 0) {
    delete_http2_session_data_server(session_data);
    return;
  }
}

/* writecb_server for bufferevent. To greaceful shutdown after sending or
   receiving GOAWAY, we check the some conditions on the nghttp2
   library and output buffer of bufferevent. If it indicates we have
   no business to this session, tear down the connection. If the
   connection is not going to shutdown, we call session_send_server() to
   process pending data in the output buffer. This is necessary
   because we have a threshold on the buffer size to avoid too much
   buffering. See send_callback(). */
static void writecb_server(struct bufferevent *bev, void *ptr) {
  http2_session_data_server *session_data = (http2_session_data_server *)ptr;
  if (evbuffer_get_length(bufferevent_get_output(bev)) > 0) {
    return;
  }
  if (nghttp2_session_want_read(session_data->session) == 0 &&
      nghttp2_session_want_write(session_data->session) == 0) {
    delete_http2_session_data_server(session_data);
    return;
  }
  if (session_send_server(session_data) != 0) {
    delete_http2_session_data_server(session_data);
    return;
  }
}

/* eventcb_server for bufferevent */
static void eventcb_server(struct bufferevent *bev, short events, void *ptr) {
  http2_session_data_server *session_data = (http2_session_data_server *)ptr;
  if (events & BEV_EVENT_CONNECTED) {
    const unsigned char *alpn = NULL;
    unsigned int alpnlen = 0;
    SSL *ssl;
    (void)bev;

    /*fprintf(stderr, "%s connected\n", session_data->client_addr);*/

    ssl = bufferevent_openssl_get_ssl(session_data->bev);

    SSL_get0_next_proto_negotiated(ssl, &alpn, &alpnlen);
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
    if (alpn == NULL) {
      SSL_get0_alpn_selected(ssl, &alpn, &alpnlen);
    }
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L

    if (alpn == NULL || alpnlen != 2 || memcmp("h2", alpn, 2) != 0) {
      /*fprintf(stderr, "%s h2 is not negotiated\n", session_data->client_addr);*/
      delete_http2_session_data_server(session_data);
      return;
    }

    initialize_nghttp2_session_server(session_data);

    if (send_server_connection_header(session_data) != 0 ||
        session_send_server(session_data) != 0) {
      delete_http2_session_data_server(session_data);
      return;
    }

    return;
  }
  if (events & BEV_EVENT_EOF) {
    /*fprintf(stderr, "%s EOF\n", session_data->client_addr);*/
  } else if (events & BEV_EVENT_ERROR) {
    /*fprintf(stderr, "%s network error\n", session_data->client_addr);*/
  } else if (events & BEV_EVENT_TIMEOUT) {
    /*fprintf(stderr, "%s timeout\n", session_data->client_addr);*/
  }
  delete_http2_session_data_server(session_data);
}

/* callback for evconnlistener */
static void acceptcb(struct evconnlistener *listener, int fd,
                     struct sockaddr *addr, int addrlen, void *arg) {
  app_context *app_ctx = (app_context *)arg;
  http2_session_data_server *session_data;

  session_data = create_http2_session_data_server(app_ctx, fd, addr, addrlen);
  bufferevent_setcb(session_data->bev, readcb_server, writecb_server, eventcb_server, session_data);
}

static void start_listen(struct event_base *evbase, const char *service,
                         app_context *app_ctx) {
  int rv;
  struct addrinfo hints;
  struct addrinfo *res, *rp;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
#ifdef AI_ADDRCONFIG
  hints.ai_flags |= AI_ADDRCONFIG;
#endif /* AI_ADDRCONFIG */

  rv = getaddrinfo(NULL, service, &hints, &res);
  //fprintf(stderr,"%s\n",res->ai_canonname);
  if (rv != 0) {
    errx(1, "Could not resolve server address");
  }
  //char addrstr[100];
  //char str[100];
  for (rp = res; rp; rp = rp->ai_next) {
    struct evconnlistener *listener;
    listener = evconnlistener_new_bind(
        evbase, acceptcb, app_ctx, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
        16, rp->ai_addr, (int)rp->ai_addrlen);
    if (listener) {
      freeaddrinfo(res);

      return;
    }
  }
  errx(1, "Could not start listener");
}

static void initialize_app_context(app_context *app_ctx, SSL_CTX *ssl_ctx,
                                   struct event_base *evbase) {
  memset(app_ctx, 0, sizeof(app_context));
  app_ctx->ssl_ctx = ssl_ctx;
  app_ctx->evbase = evbase;
}

static void runServer(const char *service, const char *key_file,
                const char *cert_file) {
  SSL_CTX *ssl_ctx;
  app_context app_ctx;
  struct event_base *evbase;

  ssl_ctx = create_ssl_ctx_server(key_file, cert_file);//key and cert files 和发送的内容 无关 ,所以 ssl_ctx与发送内容无关
  evbase = event_base_new();//evbase 也和发送的内容没什么关系
  initialize_app_context(&app_ctx, ssl_ctx, evbase);
  start_listen(evbase, service, &app_ctx);//这句应该是干么？开始听port？
  //start_listen(evbase,"1202",&app_ctx);
  /*printf("event_base_loop begin\n");*/
  event_base_loop(evbase, 0);//这句话在开启服务期
  /*printf("event_base_loop end!\n");*/
  event_base_free(evbase);
  SSL_CTX_free(ssl_ctx);
}

void *thread_a(void *);
void *thread_b(void *);

char*argv1;
char* argv2="privkey.pem";//认证文件
char* argv3="cacert.pem";
void Server(char*port)
{
  printf("Main:\n");
  argv1 = (char*)malloc(sizeof(char)*strlen(port));
  strcpy(argv1,port);

    struct sigaction act;
    memset(&act, 0, sizeof(struct sigaction));
    act.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &act, NULL);

    SSL_load_error_strings();
    SSL_library_init();//这个库没找到
    runServer(argv1, argv2, argv3);//这一步在输出
}



void JsonDataParserAndProd(char * recvData){
   cJSON * json = cJSON_Parse(recvData);
   int task = -1;
   int isRemove = 0;
   char * gutiStr = NULL;
   char * esm_data_str = NULL;
   char * esm_rtn_str = NULL;
   int apn_mlen;
   int apn_slen;
   int apn_data_len;
   char * apn_data_str;
   int isApnNull = 0;
   int isApnDataNull = 0;
   int isPdnTypeMdfy = 0;
   int isApnMdfy = 0;
   int isPcoMdfy = 0;
   int is_esm_data_mdfy = 0;
   for(cJSON * tmp = json->child;tmp!=NULL;tmp=tmp->next){
	   if(memcmp("task",tmp->string,strlen("task"))==0){
		   task = tmp->valueint;
	   }else if(memcmp("guti",tmp->string,strlen("guti"))==0){
		   gutiStr = (char*)calloc(1,sizeof(guti_t)*2+1);
           memcpy(gutiStr,tmp->valuestring,strlen(tmp->valuestring));
	   }else if(memcmp("esm_data",tmp->string,strlen("esm_data"))==0){
		   esm_data_str = (char*)malloc(sizeof(struct esm_proc_data_s)*2+1);
		   memcpy(esm_data_str,tmp->valuestring,strlen(tmp->valuestring));
		   esm_data_str[strlen(tmp->valuestring)] = '\0';
	   }else if(memcmp("esm_ctx_rtn",tmp->string,strlen("esm_ctx_rtn"))==0){
		   esm_rtn_str = (char*)malloc(sizeof(struct esm_context_s)*2+1);
		   memcpy(esm_rtn_str,tmp->valuestring,strlen(tmp->valuestring));
		   esm_rtn_str[strlen(tmp->valuestring)] = '\0';
	   }else if(memcmp("isRemove",tmp->string,strlen("isRemove"))==0){
		   isRemove = tmp->valueint;
	   }else if(memcmp("esm_data_apn_mlen",tmp->string,strlen("esm_data_apn_mlen"))==0){
		   apn_mlen = tmp->valueint;
	   }else if(memcmp("esm_data_apn_slen",tmp->string,strlen("esm_data_apn_slen"))==0){
		   apn_slen = tmp->valueint;
	   }else if(memcmp("esm_data_apn_data_length",tmp->string,strlen("esm_data_apn_data_length"))==0){
		   apn_data_len = tmp->valueint;
	   }else if(memcmp("esm_data_apn_data",tmp->string,strlen("esm_data_apn_data"))==0){
		   apn_data_str = (char*)calloc(1,strlen(tmp->valuestring)+1);
		   memcpy(apn_data_str,tmp->valuestring,strlen(tmp->valuestring));
	   }else if(memcmp("isApnNull",tmp->string,strlen("isApnNull"))==0){
		   isApnNull = tmp->valueint;
	   }else if(memcmp("isApnDataNull",tmp->string,strlen("isApnDataNull"))==0){
		   isApnDataNull = tmp->valueint;
	   }else if(memcmp("isPdnTypeMdfy",tmp->string,strlen("isPdnTypeMdfy"))==0){
		   isPdnTypeMdfy = tmp->valueint;
	   }else if(memcmp("isApnMdfy",tmp->string,strlen("isApnMdfy"))==0){
		   isApnMdfy = tmp->valueint;
	   }else if(memcmp("isPcoMdfy",tmp->string,strlen("isPcoMdfy"))==0){
		   isPcoMdfy = tmp->valueint;
	   }else if(memcmp("is_esm_data_mdfy",tmp->string,strlen("is_esm_data_mdfy"))==0){
		   is_esm_data_mdfy = tmp->valueint;
	   }
   }
   if(task == -1){
	   return;
   }
   if(!gutiStr){
	   return;
   }
   printf("task\t%d\n",task);
   printf("gutiStr\t%s\n",gutiStr);
   guti_t guti;
   void * temp;
   temp = str2mem(gutiStr);
   memcpy(&guti,temp,sizeof(guti_t));
   free(temp);
   struct esm_context_s * esm_p;
   esm_get_inplace(guti,&esm_p);
   char * msg;
   if(!esm_p && task != 6){
		msg = "error";
		dataRTN = (char*)malloc(strlen(msg)+1);
		memcpy(dataRTN,msg,strlen(msg));
        dataRTN[strlen(msg)] = '\0';
		printf("dataRTN\t%s\n",dataRTN);
	   return;
   }
   pdn_cid_t pid = RETURNerror;
   struct esm_context_s esm_ctx;
   struct esm_proc_data_s * esm_data;
   struct esm_context_s * esm_ctx_rtn;
   cJSON * apn_esm_data;
   cJSON * esm_esmData_apn;
   char * rtn_str;
   char * esm_p_str;
   char * esm_proc_data_str;
   unsigned char * apn_data;
   bstring apn;
   switch(task){
	   case 3:
		   esm_p->T3489.id = NAS_TIMER_INACTIVE_ID;
		   msg = "ok";
		   dataRTN = (char*)malloc(strlen(msg)+1);
		   memcpy(dataRTN,msg,strlen(msg));
           dataRTN[strlen(msg)] = '\0';
		   free(gutiStr);
		   gutiStr = NULL;
		   break;
	   case 1:
		   esm_p->n_pdns += 1;
		   msg = "ok";
		   dataRTN = (char*)calloc(1,strlen(msg)+1);
		   memcpy(dataRTN,msg,strlen(msg));
           //dataRTN[strlen(msg)] = '\0';
		   free(gutiStr);gutiStr = NULL;
		   break;
	   case 2:
		   esm_p->n_pdns -= 1;
		   msg = "ok";
		   dataRTN = (char*)calloc(1,strlen(msg)+1);
		   memcpy(dataRTN,msg,strlen(msg));
           //dataRTN[strlen(msg)] = '\0';
		   free(gutiStr);gutiStr = NULL;
		   break;
	   case 6:
		   printf("task6");
           esm_init_context(&esm_ctx);
		   esm_insert(guti,esm_ctx);
		   //esm_get_inplace(guti,&esm_p);
		   msg = "ok";
		   dataRTN = (char*)malloc(strlen(msg)+1);
		   memcpy(dataRTN,msg,strlen(msg));
           dataRTN[strlen(msg)] = '\0';
		   free(gutiStr);gutiStr = NULL;
		   break;
	   case 9:
		   esm_p->n_active_ebrs += 1;
		   msg = "ok";
		   dataRTN = (char*)calloc(1,strlen(msg)+1);
		   memcpy(dataRTN,msg,strlen(msg));
           dataRTN[strlen(msg)] = '\0';
		   free(gutiStr);gutiStr = NULL;
		   break;
	   case 10:
		   esm_p->is_emergency = true;
		   msg = "ok";
		   dataRTN = (char*)calloc(1,strlen(msg)+1);
		   memcpy(dataRTN,msg,strlen(msg));
           dataRTN[strlen(msg)] = '\0';
		   free(gutiStr);gutiStr = NULL;
		   break;
	   case 11:
		   if(is_esm_data_mdfy){
				temp = str2mem(esm_data_str);
				esm_p->esm_proc_data->pdn_cid = ((struct esm_proc_data_s*)temp)->pdn_cid;
				esm_p->esm_proc_data->bearer_qos.qci = ((struct esm_proc_data_s*)temp)->bearer_qos.qci;
				esm_p->esm_proc_data->bearer_qos.pci = ((struct esm_proc_data_s*)temp)->bearer_qos.pci;
				esm_p->esm_proc_data->bearer_qos.pl = ((struct esm_proc_data_s*)temp)->bearer_qos.pl;
				esm_p->esm_proc_data->bearer_qos.pvi = ((struct esm_proc_data_s*)temp)->bearer_qos.pvi;
				esm_p->esm_proc_data->bearer_qos.gbr.br_ul = ((struct esm_proc_data_s*)temp)->bearer_qos.gbr.br_ul;
				esm_p->esm_proc_data->bearer_qos.gbr.br_dl = ((struct esm_proc_data_s*)temp)->bearer_qos.gbr.br_dl;
				esm_p->esm_proc_data->bearer_qos.mbr.br_ul = ((struct esm_proc_data_s*)temp)->bearer_qos.mbr.br_ul;
				esm_p->esm_proc_data->bearer_qos.mbr.br_dl = ((struct esm_proc_data_s*)temp)->bearer_qos.mbr.br_dl;
		   }
		   msg = "ok";
		   dataRTN = (char*)calloc(1,strlen(msg)+1);
		   memcpy(dataRTN,msg,strlen(msg));
           dataRTN[strlen(msg)] = '\0';
		   free(gutiStr);free(esm_data_str);free(temp);
		   gutiStr = NULL;esm_data_str = NULL;
		   break;
	   case 12:
		   //set dataRTN as esm_p value
           dataRTN = mem2str((void*)esm_p,sizeof(struct esm_context_s));
		   free(gutiStr);gutiStr = NULL;
		   break;
	   case 13:
		   //memcpy(esm_ctx_rtn,str2mem(esm_rtn_str),sizeof(struct esm_context_s));
		   temp = str2mem(esm_rtn_str);
		   //memcpy(esm_p,temp,sizeof(struct esm_context_s));
		   esm_p->T3489.id = ((struct esm_context_s*)temp)->T3489.id;
		   if(isRemove){
			   esm_remove(guti);
			   isRemove = 0;
		   }
		   msg = "ok";
		   dataRTN = (char*)malloc(strlen(msg)+1);
		   memcpy(dataRTN,msg,strlen(msg));
           dataRTN[strlen(msg)] = '\0';
		   free(gutiStr);free(temp);free(esm_rtn_str);
		   gutiStr = NULL;esm_rtn_str = NULL;
		   break;
	   case 14:
		   if(!esm_p->esm_proc_data){
			   printf("????????????????????????????????????\n");
			   esm_p->esm_proc_data = (struct esm_proc_data_s*)calloc(1,sizeof(struct esm_proc_data_s));
		   }
		   dataRTN = mem2str((void*)esm_p->esm_proc_data,sizeof(struct esm_proc_data_s));
		   printf("dataRTN\t%s\n",dataRTN);
		   free(gutiStr);gutiStr = NULL;
		   break;
	   case 15:		 
		   apn_esm_data = cJSON_CreateObject();
		   if(!esm_p->esm_proc_data->apn){
			   cJSON_AddNumberToObject(apn_esm_data,"isApnNull",1);
		   }else{
				cJSON_AddNumberToObject(apn_esm_data,"apn_mlen",esm_p->esm_proc_data->apn->mlen);
				cJSON_AddNumberToObject(apn_esm_data,"apn_slen",esm_p->esm_proc_data->apn->slen);
				apn_data_str = mem2str((void*)esm_p->esm_proc_data->apn->data,strlen(esm_p->esm_proc_data->apn->data));
				cJSON_AddStringToObject(apn_esm_data,"apn_data",apn_data_str);
				cJSON_AddNumberToObject(apn_esm_data,"apn_data_length",strlen(esm_p->esm_proc_data->apn->data));
				free(apn_data_str);
		   }
		   esm_proc_data_str = mem2str((void*)esm_p->esm_proc_data,sizeof(struct esm_proc_data_s));
		   cJSON_AddStringToObject(apn_esm_data,"esm_proc_data",esm_proc_data_str);
		   free(esm_proc_data_str);
		   rtn_str = cJSON_Print(apn_esm_data);
		   printf("rtn_str\t%s\n",rtn_str);
		   dataRTN = (char*)calloc(1,strlen(rtn_str)+1);
		   memcpy(dataRTN,rtn_str,strlen(rtn_str));
		   free(gutiStr);gutiStr = NULL;
		   free(rtn_str);free(apn_esm_data);
		   break;
	   case 16:
		   if((!isApnNull)&&(isApnMdfy)){
				temp = str2mem(apn_data_str);
				apn_data = (unsigned char *)calloc(1,apn_data_len+1);
				memcpy(apn_data,temp,apn_data_len);
				free(temp);
				apn = (bstring)calloc(1,sizeof(struct tagbstring));
				apn->mlen = apn_mlen;
				apn->slen = apn_slen;
				apn->data = apn_data;
				free(apn_data_str);
		   }
		   temp = str2mem(esm_data_str);
		   //memcpy(esm_p->esm_proc_data,temp,sizeof(struct esm_proc_data_s));
		   esm_p->esm_proc_data->pti = ((struct esm_proc_data_s*)temp)->pti;
		   esm_p->esm_proc_data->request_type = ((struct esm_proc_data_s*)temp)->request_type;
		   if(isPdnTypeMdfy){
			   esm_p->esm_proc_data->pdn_type = ((struct esm_proc_data_s*)temp)->pdn_type;
		   }
		   if(isPcoMdfy){
			   memcpy(&(esm_p->esm_proc_data->pco),&(((struct esm_proc_data_s*)temp)->pco),sizeof(protocol_configuration_options_t));
		   }
		   if((!isApnNull)&&(isApnMdfy)){
				memcpy(esm_p->esm_proc_data->apn->data,apn_data,strlen(apn_data_len));
				esm_p->esm_proc_data->apn->mlen = apn->mlen;
				esm_p->esm_proc_data->apn->slen = apn->slen;
				free(apn_data);free(apn);
		   }
		   msg = "ok";
		   dataRTN = (char*)calloc(1,strlen(msg)+1);
		   memcpy(dataRTN,msg,strlen(msg));
           dataRTN[strlen(msg)] = '\0';
		   free(temp);free(esm_data_str);free(gutiStr);gutiStr = NULL;
		   isApnNull = 0;
		   break;
	   case 17:
		   esm_esmData_apn = cJSON_CreateObject();
		   esm_p_str = mem2str((void*)esm_p,sizeof(struct esm_context_s));
		   cJSON_AddStringToObject(esm_esmData_apn,"esm_p",esm_p_str);
		   if(!esm_p->esm_proc_data){
			   cJSON_AddNumberToObject(esm_esmData_apn,"isProcDataNull",1);
		   }else{
			   esm_proc_data_str = mem2str((void*)esm_p->esm_proc_data,sizeof(struct esm_proc_data_s));
			   cJSON_AddStringToObject(esm_esmData_apn,"esm_proc_data",esm_proc_data_str);
			   if(!esm_p->esm_proc_data->apn){
				   cJSON_AddNumberToObject(esm_esmData_apn,"isApnNull",1);
			   }else{
				   cJSON_AddNumberToObject(esm_esmData_apn,"apn_mlen",esm_p->esm_proc_data->apn->mlen);
				   cJSON_AddNumberToObject(esm_esmData_apn,"apn_slen",esm_p->esm_proc_data->apn->slen);
				   apn_data_str = mem2str((void*)esm_p->esm_proc_data->apn->data,strlen(esm_p->esm_proc_data->apn->data));
				   cJSON_AddStringToObject(apn_esm_data,"apn_data",apn_data_str);
				   cJSON_AddNumberToObject(apn_esm_data,"apn_data_length",strlen(esm_p->esm_proc_data->apn->data));
				   free(apn_data_str);
			   }
			   free(esm_proc_data_str);
		   }
		   free(esm_p_str);
		   rtn_str = cJSON_Print(esm_esmData_apn);
		   printf("rtn_str\t%s\n",rtn_str);
		   dataRTN = (char*)calloc(1,strlen(rtn_str)+1);
		   memcpy(dataRTN,rtn_str,strlen(rtn_str));
		   free(gutiStr);gutiStr = NULL;
		   free(rtn_str);free(esm_esmData_apn);
		   break;
	   case 18:
		   temp = str2mem(esm_rtn_str);
		   //memcpy(esm_p,temp,sizeof(struct esm_context_s));
		   esm_p->T3489.id = ((struct esm_context_s*)temp)->T3489.id;
		   free(temp);
		   temp = str2mem(esm_data_str);
		   //memcpy(esm_p->esm_proc_data,temp,sizeof(struct esm_proc_data_s));
		   esm_p->esm_proc_data->pco = ((struct esm_proc_data_s*)temp)->pco;
		   free(temp);
		   if(isApnNull){
			   esm_p->esm_proc_data->apn = NULL;
			   isApnNull = 0;
		   }else{
               esm_p->esm_proc_data->apn->mlen = apn_mlen;
			   esm_p->esm_proc_data->apn->slen = apn_slen;
			   temp = str2mem(apn_data_str);
			   memcpy(esm_p->esm_proc_data->apn->data,temp,apn_data_len);
			   free(temp);
		   }
		   if(isRemove){
			   esm_remove(guti);
			   isRemove = 0;
		   }
		   msg = "ok";
		   dataRTN = (char*)malloc(strlen(msg)+1);
		   memcpy(dataRTN,msg,strlen(msg));
           dataRTN[strlen(msg)] = '\0';
		   free(gutiStr);free(esm_rtn_str);
		   gutiStr = NULL;esm_rtn_str = NULL;
		   break;
	   case 19:
		   dataRTN = mem2str((void*)esm_p->esm_proc_data,sizeof(struct esm_proc_data_s));
		   printf("dataRTN\t%s\n",dataRTN);
		   free(gutiStr);gutiStr = NULL;
		   break;
	   default:
		   break;



   }
   free(json);
}
