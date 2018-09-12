#ifdef __sgi
#define errx(exitcode, format, args...)                                        \
{                                                                            \
    warnx(format, ##args);                                                     \
    exit(exitcode);                                                            \
}
#define warn(format, args...) warnx(format ": %s", ##args, strerror(errno))
#define warnx(format, args...) fprintf(stderr, format "\n", ##args)
char *strndup(const char *s, size_t size);
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

#include "http_parser.h"
#include <stdio.h>

struct evconnlistener *listener_port1 ;
struct evconnlistener *listener_port2;


//char * p_server=NULL;
char * p_server = "hello";//msg sent to client
char * url ;//url requested by client
char * q=NULL;
int rdy_rd=0;

char* p_client=NULL;

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
  fprintf(stderr,"session_send_server\n");
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
  fprintf(stderr,"send_callback_server\n");
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


  /*while ((r = read(fd, buf, length)) == -1 && errno == EINTR)//这个位置是在读取内容,而且读1-2次*/

    /*;*/

  /*printf("进入了read read_callback函数\n");*/
  fprintf(stderr,"get into file read callback\n");
  static int flag=0;
  if(flag==1)
  {
      r=0;
      flag=0;
  }
  else
  {
	  fprintf(stderr,"ready to send msg\n");
      int i=0;
      for(int i=0;i<100;i++)
      {
          buf[i]=0;
      }
      rdy_rd=1;
      /*printf("这里是read_callback中q是NULL\n");*/
      //while(q==NULL)
      //{
      //    usleep(1);
      //}

      //mark
      memcpy(buf,p_server,strlen(p_server));
      /*printf("发送给client的消息:%s\n",p);*/
      r=strlen(p_server);
      //free(p_server);
      q=NULL;
      //p_server=NULL;
      rdy_rd=0;
      flag=1;
	  fprintf(stderr,"send message to client\n");
  }

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
  fprintf(stderr,"send-response\n");
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
  /*static int turn0=0;*/

  /*if(turn0 ==0)*/
  /*{*/
      /*writelen = write(pipefd[1], ERROR_HTML, sizeof(ERROR_HTML) - 1);*/
      /*turn0 =1;*/
      /*close(pipefd[1]);*/
      /*if (writelen != sizeof(ERROR_HTML) - 1) {*/
          /*close(pipefd[0]);*/
          /*return -1;*/
      /*}*/
  /*}else*/
  /*{*/
      /*writelen = write(pipefd[1], SEND, sizeof(SEND) - 1);*/
      /*turn0 =0;*/
      /*close(pipefd[1]);*/
      /*if (writelen != sizeof(SEND) - 1) {*/
          /*close(pipefd[0]);*/
          /*return -1;*/
      /*}*/
  /*}*/

  /*const static int LEN=1000;*/
  /*char *INPUT=(char*) malloc(sizeof(char)*LEN);//be freed in the following*/
  /*for(int i=0;i<LEN;i++)*/
  /*{*/
      /*INPUT[i]=0;*/
  /*}*/
  /*printf("Input what you want to send(characters less than %d):",LEN);*/
  /*gets(INPUT);*/


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
  //printf("value\t%s\n",value);
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
      printf("value\t%s\n",value);
	  url = (char *)malloc(sizeof(char)*strlen(value));
	  memcpy(url,value,strlen(value));
	  printf("url\t%s\n",url);
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
  fprintf(stderr,"check-path\n");
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
  //mark
  /*printf("%s\n",rel_path);*/
  //fd = popen(rel_path, O_RDONLY);//这个地方是file打开的位置,返回文件描述.linux 通过文件描述来访问文件
  /*return 0;//这个地方直接默认打开了文件*/
  /*fd=123;*/

  fprintf(stderr,"on_request_recv\n");
  printf("----------------------dukl server requested url---------------\n");
  printf("%s\n",stream_data->request_path);
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
  switch (frame->hd.type) {
  case NGHTTP2_DATA:
  case NGHTTP2_HEADERS:
    /* Check that the client request has finished */
    if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
      stream_data =
          nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
      /* For DATA and HEADERS frame, this callback may be called after
         on_stream_close_callback. Check that stream still alive. */
      if (!stream_data) {
        return 0;
      }
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

static void initialize_nghttp2_session_server(http2_session_data_server *session_data) {
  nghttp2_session_callbacks *callbacks;

  nghttp2_session_callbacks_new(&callbacks);

  nghttp2_session_callbacks_set_send_callback(callbacks, send_callback_server);

  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
                                                       on_frame_recv_callback_server);

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

  fprintf(stderr,"get request\n");

  //(void)listener;
  //struct sockaddr_in * client = (sockaddr_in *)addr;
  //int r = memcmp(listener,listener_port1,sizeof(struct evconnlistener));
  /*
  if(listener == listener_port1)
    fprintf(stderr,"hello\n");
  else if(listener  == listener_port2)
	fprintf(stderr,"ooooo\n");
  else
	fprintf(stderr,"others\n");
	*/
  //char * data = (char *)(listener->user_data);
  //fprintf(stderr,"%s\n",data);
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
	//inet_ntop (rp->ai_family, rp->ai_addr->sa_data, addrstr, 100);
	//inet_pton (rp->ai_family, addrstr,str);
	//fprintf(stderr,"%s\n",addrstr);
	//fprintf(stderr,"%s\n",str);
    struct evconnlistener *listener;
    listener = evconnlistener_new_bind(
        evbase, acceptcb, app_ctx, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
        16, rp->ai_addr, (int)rp->ai_addrlen);
	//struct sockaddr_in sin;
	//memcpy(&sin,rp->ai_addr,sizeof(sin));
	//fprintf(stderr,"%s\n",inet_ntoa(sin.sin_addr));
	/*
	fprintf(stderr,"dukl:%d\n",sin.sin_port);
	if(sin.sin_port == 45316)
	  listener_port1 = listener;
	if(sin.sin_port == 45572)
	  listener_port2 = listener;
	  */
    //listener_port1 = (struct evconnlistener *)malloc(sizeof(struct evconnlistener));
	//memcpy(listener_port1,listener,sizeof(struct evconnlistener));
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
  /*struct app_context {*/
  /*SSL_CTX *ssl_ctx;*/
  /*struct event_base *evbase;*/
  /*};*/
  //q = "hello";
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

//char* argv1="10020";//服务器端的端口
char*argv1;
char* argv2="privkey.pem";//认证文件
char* argv3="cacert.pem";
/*
void *thread_a(void* a)
{
    //printf("进入线程\n");
    int len=100;//p_server buf size
    while(1)
    {
        while(rdy_rd==0)
        {
            usleep(1);
        }
        rdy_rd=0;
        p_server=(char*)malloc(len);
        for(int i=0;i<100;i++)
        {
            p_server[i]=0;
        }
        printf("You can input text\n");
        gets(p_server);
        q=p_server;
        if(q!=NULL)
        {
            //printf("q不指向NULL:%s\n",q);
        }
    }
    return NULL;
}

void *thread_b(void *b)
{
    struct sigaction act;
    memset(&act, 0, sizeof(struct sigaction));
    act.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &act, NULL);

    SSL_load_error_strings();
    SSL_library_init();//这个库没找到
    runServer(argv1, argv2, argv3);//这一步在输出
    //printf("thread_b end\n");
    return NULL;
}

*/
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
    //printf("thread_b end\n");

  //printf("\n%s\n",argv1);
  //create a thread
  /*
  pthread_t t0;
  pthread_t t1;
  
  if(pthread_create(&t0,NULL,thread_a,NULL)==-1)
  {
      exit(1);
  }
  
  if(pthread_create(&t1,NULL,thread_b,NULL)==-1)
  {
      exit(1);
  }
  //runServer(argv[1], argv[2], argv[3]);//这一步在输出
  void* result;
  
  if(pthread_join(t0,&result)==-1)
  {
      exit(1);
  }
  
  if(pthread_join(t1,&result)==-1)
  {
      exit(1);
  }
  */
}

typedef struct {
  /* The NULL-terminated URI string to retrieve. */
  const char *uri;
  /* Parsed result of the |uri| */
  struct http_parser_url *u;
  /* The authority portion of the |uri|, not NULL-terminated */
  char *authority;
  /* The path portion of the |uri|, including query, not
     NULL-terminated */
  char *path;
  /* The length of the |authority| */
  size_t authoritylen;
  /* The length of the |path| */
  size_t pathlen;
  /* The stream ID of this stream */
  int32_t stream_id;
} http2_stream_data_client;

typedef struct {
  nghttp2_session *session;
  struct evdns_base *dnsbase;
  struct bufferevent *bev;
  http2_stream_data_client *stream_data;
} http2_session_data_client;

static http2_stream_data_client *create_http2_stream_data_client(const char *uri,
                                                   struct http_parser_url *u) {
  /* MAX 5 digits (max 65535) + 1 ':' + 1 NULL (because of snprintf) */
  size_t extra = 7;
  http2_stream_data_client *stream_data = malloc(sizeof(http2_stream_data_client));

  stream_data->uri = uri;
  stream_data->u = u;
  stream_data->stream_id = -1;

  stream_data->authoritylen = u->field_data[UF_HOST].len;
  stream_data->authority = malloc(stream_data->authoritylen + extra);
  memcpy(stream_data->authority, &uri[u->field_data[UF_HOST].off],
         u->field_data[UF_HOST].len);
  if (u->field_set & (1 << UF_PORT)) {
    stream_data->authoritylen +=
        (size_t)snprintf(stream_data->authority + u->field_data[UF_HOST].len,
                         extra, ":%u", u->port);
  }

  /* If we don't have path in URI, we use "/" as path. */
  stream_data->pathlen = 1;
  if (u->field_set & (1 << UF_PATH)) {
    stream_data->pathlen = u->field_data[UF_PATH].len;
  }
  if (u->field_set & (1 << UF_QUERY)) {
    /* +1 for '?' character */
    stream_data->pathlen += (size_t)(u->field_data[UF_QUERY].len + 1);
  }

  stream_data->path = malloc(stream_data->pathlen);
  if (u->field_set & (1 << UF_PATH)) {
    memcpy(stream_data->path, &uri[u->field_data[UF_PATH].off],
           u->field_data[UF_PATH].len);
  } else {
    stream_data->path[0] = '/';
  }
  if (u->field_set & (1 << UF_QUERY)) {
    stream_data->path[stream_data->pathlen - u->field_data[UF_QUERY].len - 1] =
        '?';
    memcpy(stream_data->path + stream_data->pathlen -
               u->field_data[UF_QUERY].len,
           &uri[u->field_data[UF_QUERY].off], u->field_data[UF_QUERY].len);
  }

  return stream_data;
}

static void delete_http2_stream_data_client(http2_stream_data_client *stream_data) {
  free(stream_data->path);
  free(stream_data->authority);
  free(stream_data);
}

/* Initializes |session_data| */
static http2_session_data_client *
create_http2_session_data_client(struct event_base *evbase) {
  http2_session_data_client *session_data = malloc(sizeof(http2_session_data_client));

  memset(session_data, 0, sizeof(http2_session_data_client));
  session_data->dnsbase = evdns_base_new(evbase, 1);
  return session_data;
}

static void delete_http2_session_data_client(http2_session_data_client *session_data) {
  SSL *ssl = bufferevent_openssl_get_ssl(session_data->bev);

  if (ssl) {
    SSL_shutdown(ssl);
  }
  bufferevent_free(session_data->bev);
  session_data->bev = NULL;
  evdns_base_free(session_data->dnsbase, 1);
  session_data->dnsbase = NULL;
  nghttp2_session_del(session_data->session);
  session_data->session = NULL;
  if (session_data->stream_data) {
    delete_http2_stream_data_client(session_data->stream_data);
    session_data->stream_data = NULL;
  }
  free(session_data);
}

static void print_header(FILE *f, const uint8_t *name, size_t namelen,
                         const uint8_t *value, size_t valuelen) {
  /*fwrite(name, 1, namelen, f);*/
  /*fprintf(f, ": ");*/
  /*fwrite(value, 1, valuelen, f);*/
  /*fprintf(f, "\n");*/
}

/* Print HTTP headers to |f|. Please note that this function does not
   take into account that header name and value are sequence of
   octets, therefore they may contain non-printable characters. */
static void print_headers(FILE *f, nghttp2_nv *nva, size_t nvlen) {
  size_t i;
  for (i = 0; i < nvlen; ++i) {
    print_header(f, nva[i].name, nva[i].namelen, nva[i].value, nva[i].valuelen);
  }
  fprintf(f, "\n");
}

/* nghttp2_send_callback. Here we transmit the |data|, |length| bytes,
   to the network. Because we are using libevent bufferevent, we just
   write those bytes into bufferevent buffer. */
static ssize_t send_callback_client(nghttp2_session *session, const uint8_t *data,
                             size_t length, int flags, void *user_data) {
  http2_session_data_client *session_data = (http2_session_data_client *)user_data;
  struct bufferevent *bev = session_data->bev;
  (void)session;
  (void)flags;

  bufferevent_write(bev, data, length);
  return (ssize_t)length;
}

/* nghttp2_on_header_callback: Called when nghttp2 library emits
   single header name/value pair. */
static int on_header_callback_client(nghttp2_session *session,
                              const nghttp2_frame *frame, const uint8_t *name,
                              size_t namelen, const uint8_t *value,
                              size_t valuelen, uint8_t flags, void *user_data) {
  http2_session_data_client *session_data = (http2_session_data_client *)user_data;
  (void)session;
  (void)flags;

  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
    if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
        session_data->stream_data->stream_id == frame->hd.stream_id) {
      /* Print response headers for the initiated request. */
      print_header(stderr, name, namelen, value, valuelen);
      break;
    }
  }
  return 0;
}

/* nghttp2_on_begin_headers_callback: Called when nghttp2 library gets
   started to receive header block. */
static int on_begin_headers_callback_client(nghttp2_session *session,
                                     const nghttp2_frame *frame,
                                     void *user_data) {
  http2_session_data_client *session_data = (http2_session_data_client *)user_data;
  (void)session;

  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
    if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
        session_data->stream_data->stream_id == frame->hd.stream_id) {
      /*fprintf(stderr, "Response headers for stream ID=%d:\n",*/
              /*frame->hd.stream_id);*/
    }
    break;
  }
  return 0;
}

/* nghttp2_on_frame_recv_callback: Called when nghttp2 library
   received a complete frame from the remote peer. */
static int on_frame_recv_callback_client(nghttp2_session *session,
                                  const nghttp2_frame *frame, void *user_data) {
  http2_session_data_client *session_data = (http2_session_data_client *)user_data;
  (void)session;
  printf("on_fream_recv_callback_client\n");
  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
    if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
        session_data->stream_data->stream_id == frame->hd.stream_id) {
      /*fprintf(stderr, "All headers received\n");*/
        ;
    }
    break;
  }
  return 0;
}

/* nghttp2_on_data_chunk_recv_callback: Called when DATA frame is
   received from the remote peer. In this implementation, if the frame
   is meant to the stream we initiated, print the received data in
   stdout, so that the user can redirect its output to the file
   easily. */
static int on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags,
                                       int32_t stream_id, const uint8_t *data,
                                       size_t len, void *user_data) {
  http2_session_data_client *session_data = (http2_session_data_client *)user_data;
  (void)session;
  (void)flags;
  printf("on_data-chunk_recv_callback\n");
  if (session_data->stream_data->stream_id == stream_id) {
    /*fwrite(data, 1, len, stdout);*/
    /*for(int i=0;i<strlen(data);i++)*/
    /*{*/
        /*printf("%c",data[i]);*/
    /*}*/
    /*printf("\n");*/
    /*printf("len:%d\tstrlen(data):%d\n",len,strlen(data));*/
    /*p=(char*)malloc(strlen(data)+1);*/
      //mark
    p_client=(char*)malloc(len+1);
    for(int i=0;i<len+1;i++)
    {
        p_client[i]=0;
    }
    memcpy(p_client,data,len);
    /*printf("on_data_chunk\t\tdata:\t%s\n",p);*/
    /*printf("on_data_chunk\t\tp:\t%s\n",p);*/
    /*printf("In the data_chunk_recv_callbacl:%s",p);*/
  }
  return 0;
}

/* nghttp2_on_stream_close_callback: Called when a stream is about to
   closed. This example program only deals with 1 HTTP request (1
   stream), if it is closed, we send GOAWAY and tear down the
   session */
static int on_stream_close_callback_client(nghttp2_session *session, int32_t stream_id,
                                    uint32_t error_code, void *user_data) {
  http2_session_data_client *session_data = (http2_session_data_client *)user_data;
  int rv;
  printf("on_stream_close_callback\n");
  if (session_data->stream_data->stream_id == stream_id)
  {
      /*fprintf(stderr, "Stream %d closed with error_code=%u\n", stream_id,*/
      /*error_code);*/
      rv = nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);
      if (rv != 0)
      {
          return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
  }
  return 0;
}

/* NPN TLS extension client callback. We check that server advertised
   the HTTP/2 protocol the nghttp2 library supports. If not, exit
   the program. */
static int select_next_proto_cb(SSL *ssl, unsigned char **out,
                                unsigned char *outlen, const unsigned char *in,
                                unsigned int inlen, void *arg) {
  (void)ssl;
  (void)arg;

  if (nghttp2_select_next_protocol(out, outlen, in, inlen) <= 0) {
    errx(1, "Server did not advertise " NGHTTP2_PROTO_VERSION_ID);
  }
  return SSL_TLSEXT_ERR_OK;
}
/* Create SSL_CTX. */
static SSL_CTX *create_ssl_ctx_client(void) {
  SSL_CTX *ssl_ctx;
  ssl_ctx = SSL_CTX_new(SSLv23_client_method());
  if (!ssl_ctx) {
    errx(1, "Could not create SSL/TLS context: %s",
         ERR_error_string(ERR_get_error(), NULL));
  }
  SSL_CTX_set_options(ssl_ctx,
                      SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                          SSL_OP_NO_COMPRESSION |
                          SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
  SSL_CTX_set_next_proto_select_cb(ssl_ctx, select_next_proto_cb, NULL);

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
  SSL_CTX_set_alpn_protos(ssl_ctx, (const unsigned char *)"\x02h2", 3);
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L

  return ssl_ctx;
}
static void initialize_nghttp2_session_client(http2_session_data_client *session_data) {
  nghttp2_session_callbacks *callbacks;

  nghttp2_session_callbacks_new(&callbacks);

  nghttp2_session_callbacks_set_send_callback(callbacks, send_callback_client);

  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
                                                       on_frame_recv_callback_client);

  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
      callbacks, on_data_chunk_recv_callback);

  nghttp2_session_callbacks_set_on_stream_close_callback(
      callbacks, on_stream_close_callback_client);

  nghttp2_session_callbacks_set_on_header_callback(callbacks,
                                                   on_header_callback_client);

  nghttp2_session_callbacks_set_on_begin_headers_callback(
      callbacks, on_begin_headers_callback_client);

  nghttp2_session_client_new(&session_data->session, callbacks, session_data);

  nghttp2_session_callbacks_del(callbacks);
}

static void send_client_connection_header(http2_session_data_client *session_data) {
  nghttp2_settings_entry iv[1] = {
      {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
  int rv;

  /* client 24 bytes magic string will be sent by nghttp2 library */
  rv = nghttp2_submit_settings(session_data->session, NGHTTP2_FLAG_NONE, iv,
                               ARRLEN(iv));
  if (rv != 0) {
    errx(1, "Could not submit SETTINGS: %s", nghttp2_strerror(rv));
  }
}

#define MAKE_NV(NAME, VALUE, VALUELEN)                                         \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, VALUELEN,             \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

#define MAKE_NV2(NAME, VALUE)                                                  \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1,    \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

/* Send HTTP request to the remote peer */
static void submit_request(http2_session_data_client *session_data) {
  int32_t stream_id;
  http2_stream_data_client *stream_data = session_data->stream_data;
  const char *uri = stream_data->uri;
  const struct http_parser_url *u = stream_data->u;
  nghttp2_nv hdrs[] = {
      MAKE_NV2(":method", "GET"),
      MAKE_NV(":scheme", &uri[u->field_data[UF_SCHEMA].off],
              u->field_data[UF_SCHEMA].len),
      MAKE_NV(":authority", stream_data->authority, stream_data->authoritylen),
      MAKE_NV(":path", stream_data->path, stream_data->pathlen)};
  /*fprintf(stderr, "Request headers:\n");*/
  /*print_headers(stderr, hdrs, ARRLEN(hdrs));*/
  printf("submit_request\n");
  stream_id = nghttp2_submit_request(session_data->session, NULL, hdrs,
                                     ARRLEN(hdrs), NULL, stream_data);
  if (stream_id < 0) {
    errx(1, "Could not submit HTTP request: %s", nghttp2_strerror(stream_id));
  }

  stream_data->stream_id = stream_id;
}
/* Serialize the frame and send (or buffer) the data to
 *    bufferevent. */
static int session_send_client(http2_session_data_client *session_data) {
	  int rv;
      printf("session_send_client\n");
	    rv = nghttp2_session_send(session_data->session);
		  if (rv != 0) {
			      warnx("Fatal error: %s", nghttp2_strerror(rv));
				      return -1;
					    }
		    return 0;
}

/* readcb_client for bufferevent. Here we get the data from the input buffer
   of bufferevent and feed them to nghttp2 library. This may invoke
   nghttp2 callbacks. It may also queues the frame in nghttp2 session
   context. To send them, we call session_send_server() in the end. */
static void readcb_client(struct bufferevent *bev, void *ptr) {
  http2_session_data_client *session_data = (http2_session_data_client *)ptr;
  ssize_t readlen;
  struct evbuffer *input = bufferevent_get_input(bev);
  size_t datalen = evbuffer_get_length(input);
  unsigned char *data = evbuffer_pullup(input, -1);
  printf("readcb_client\n");
  readlen = nghttp2_session_mem_recv(session_data->session, data, datalen);
  if (readlen < 0) {
    warnx("Fatal error: %s", nghttp2_strerror((int)readlen));
    delete_http2_session_data_client(session_data);
    return;
  }
  if (evbuffer_drain(input, (size_t)readlen) != 0) {
    warnx("Fatal error: evbuffer_drain failed");
    delete_http2_session_data_client(session_data);
    return;
  }
  if (session_send_client(session_data) != 0) {
    delete_http2_session_data_client(session_data);
    return;
  }
}

/* writecb_client for bufferevent. To greaceful shutdown after sending or
   receiving GOAWAY, we check the some conditions on the nghttp2
   library and output buffer of bufferevent. If it indicates we have
   no business to this session, tear down the connection. */
static void writecb_client(struct bufferevent *bev, void *ptr) {
  http2_session_data_client *session_data = (http2_session_data_client *)ptr;
  (void)bev;
  printf("writecb_client\n");
  if (nghttp2_session_want_read(session_data->session) == 0 &&
      nghttp2_session_want_write(session_data->session) == 0 &&
      evbuffer_get_length(bufferevent_get_output(session_data->bev)) == 0) {
    delete_http2_session_data_client(session_data);
  }
}

/* eventcb_client for bufferevent. For the purpose of simplicity and
   readability of the example program, we omitted the certificate and
   peer verification. After SSL/TLS handshake is over, initialize
   nghttp2 library session, and send client connection header. Then
   send HTTP request. */
static void eventcb_client(struct bufferevent *bev, short events, void *ptr) {
  http2_session_data_client *session_data = (http2_session_data_client *)ptr;
  if (events & BEV_EVENT_CONNECTED) {
    int fd = bufferevent_getfd(bev);
    int val = 1;
    const unsigned char *alpn = NULL;
    unsigned int alpnlen = 0;
    SSL *ssl;
    printf("eventcb_client\n");
    /*fprintf(stderr, "Connected\n");*/

    ssl = bufferevent_openssl_get_ssl(session_data->bev);

    SSL_get0_next_proto_negotiated(ssl, &alpn, &alpnlen);
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
    if (alpn == NULL) {
      SSL_get0_alpn_selected(ssl, &alpn, &alpnlen);
    }
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L

    if (alpn == NULL || alpnlen != 2 || memcmp("h2", alpn, 2) != 0) {
      /*fprintf(stderr, "h2 is not negotiated\n");*/
      delete_http2_session_data_client(session_data);
      return;
    }

    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&val, sizeof(val));
    initialize_nghttp2_session_client(session_data);
    send_client_connection_header(session_data);
    submit_request(session_data);
    if (session_send_client(session_data) != 0) {
      delete_http2_session_data_client(session_data);
    }
    return;
  }
  if (events & BEV_EVENT_EOF) {
    warnx("Disconnected from the remote host");
  } else if (events & BEV_EVENT_ERROR) {
    warnx("Network error");
  } else if (events & BEV_EVENT_TIMEOUT) {
    warnx("Timeout");
  }
  delete_http2_session_data_client(session_data);
}

/* Start connecting to the remote peer |host:port| */
static void initiate_connection(struct event_base *evbase, SSL_CTX *ssl_ctx,
                                const char *host, uint16_t port,
                                http2_session_data_client *session_data) {
  int rv;
  struct bufferevent *bev;
  SSL *ssl;
  printf("initiate_connection\n");
  ssl = create_ssl(ssl_ctx);
  bev = bufferevent_openssl_socket_new(
      evbase, -1, ssl, BUFFEREVENT_SSL_CONNECTING,
      BEV_OPT_DEFER_CALLBACKS | BEV_OPT_CLOSE_ON_FREE);
  bufferevent_enable(bev, EV_READ | EV_WRITE);
  bufferevent_setcb(bev, readcb_client, writecb_client, eventcb_client, session_data);
  rv = bufferevent_socket_connect_hostname(bev, session_data->dnsbase,
                                           AF_UNSPEC, host, port);

  if (rv != 0) {
    errx(1, "Could not connect to the remote host %s", host);
  }
  session_data->bev = bev;
}

/* Get resource denoted by the |uri|. The debug and error messages are
   printed in stderr, while the response body is printed in stdout. */
static void runClient(const char *uri) {
  struct http_parser_url u;
  char *host;
  uint16_t port;
  int rv;
  SSL_CTX *ssl_ctx;
  struct event_base *evbase;
  http2_session_data_client *session_data;

  /* Parse the |uri| and stores its components in |u| */
  rv = http_parser_parse_url(uri, strlen(uri), 0, &u);
  if (rv != 0) {
    errx(1, "Could not parse URI %s", uri);
  }
  host = strndup(&uri[u.field_data[UF_HOST].off], u.field_data[UF_HOST].len);
  if (!(u.field_set & (1 << UF_PORT))) {
    port = 443;
  } else {
    port = u.port;
  }

  ssl_ctx = create_ssl_ctx_client();

  evbase = event_base_new();

  session_data = create_http2_session_data_client(evbase);
  session_data->stream_data = create_http2_stream_data_client(uri, &u);

  initiate_connection(evbase, ssl_ctx, host, port, session_data);
  free(host);
  host = NULL;

  event_base_loop(evbase, 0);//这一步输出了结果

  event_base_free(evbase);
  SSL_CTX_free(ssl_ctx);
}
/*
void GetMessage(char* path,char*server_ip)
{
    char http_path[100];
    for(int i=0;i<100;i++)
    {
        http_path[i]=0;
    }
    //char * pre="https://"SERVER_IP"/";
	char pre[30];
	strcpy(pre,"https://");
	strcat(pre,server_ip);
	strcat(pre,"/");
	//printf("%s",strcat(strcat("https://",server_ip),"/"));
	printf("%s\n",pre);
    for(int i=0;i<strlen(pre);i++)
    {
        http_path[i]=pre[i];
    }
    int len=strlen(pre);
    for(int i=0;i<strlen(path);i++)
    {
        http_path[i+len]=path[i];
    }
    printf("请求地址:%s\n",http_path);
    runClient(http_path);
}
*/
void Client(char*url)
{
    struct sigaction act;
    memset(&act, 0, sizeof(struct sigaction));
    act.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &act, NULL);

    SSL_load_error_strings();
    SSL_library_init();

    //char http2_path[100];
    printf("%s\n",url);
    runClient(url);
    //char* q="ABCDE?ABFGHIJKLMN=12312312";
    //GetMessage(q,ip_port);
    printf("收到信息:%s\n",p_client);
    //free(p_client);
    //p_client=NULL;

}






