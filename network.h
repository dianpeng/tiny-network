#ifndef NETWORK_H_
#define NETWORK_H_
#include <stddef.h>

#ifdef _WIN32
#define FD_SETSIZE 1024
#include <WinSock2.h>
#include <windows.h>
typedef SOCKET socket_t;
typedef int socklen_t;
#define invalid_socket_handler INVALID_SOCKET
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
typedef int socket_t;
#define invalid_socket_handler -1
#define closesocket close
#endif /* _WIN32 */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * All these value will _ONLY_ set in the event parameter
 * and error code parameter in callback will set the errno
 * value or getsockopt SO_ERROR value 
 */

enum {
    NET_EV_NULL  = 0,
    NET_EV_READ  = 1,
    NET_EV_WRITE = 1 << 1,
    NET_EV_LINGER = 1 << 2,
    NET_EV_CLOSE = 1 << 3 ,
    NET_EV_REMOVE= 1 << 4 ,
    NET_EV_EOF   = 1 << 5 ,
    NET_EV_CONNECT = 1 << 6,
    NET_EV_TIMEOUT = 1 << 7,
    NET_EV_IDLE = 1 << 15,

    /* error code */
    NET_EV_ERR_READ = 1<<16,
    NET_EV_ERR_WRITE= 1<<17,
    NET_EV_ERR_ACCEPT=1<<18,
    NET_EV_ERR_CONNECT = 1 << 19,

    NET_EV_WS_ABORT = 1 << 20

};

struct net_buffer {
    void* mem;
    size_t consume_pos;
    size_t produce_pos;
    size_t capacity;
};

struct net_connection;

typedef int (*net_ccb_func)( int , int , struct net_connection* );

struct net_connection {
    struct net_connection* next; /* private field */
    struct net_connection* prev; /* private field */
    void* user_data;
    socket_t socket_fd;
    struct net_buffer in; /* in buffer is the buffer for reading */
    struct net_buffer out;/* out buffer is the buffer for sending */
    net_ccb_func cb;
    int pending_event;     /* private field */
    int timeout;
};

struct net_server;

typedef int (*net_acb_func)( int err_code , struct net_server* , struct net_connection* connection );

struct net_server {
    void* user_data;
    socket_t listen_fd;
    struct net_connection conns;
    socket_t ctrl_fd;
    net_acb_func cb;
    int last_io_time;
    void* reserve_buffer;
};

void net_init();

/* server function */
int net_server_create( struct net_server* , const char* addr , net_acb_func cb );
void net_server_destroy( struct net_server* );
int net_server_poll( struct net_server* ,int , int* );
int net_server_wakeup( struct net_server* );

/* client function */
socket_t net_block_client_connect( const char* addr , int msec );

/* connect to a specific server */
int net_non_block_client_connect( struct net_server* server ,
    const char* addr ,
    net_ccb_func cb ,
    void* udata ,
    int timeout );

int net_non_block_connect( struct net_connection* conn , const char* addr , int timeout );

/* timer and other socket function */
struct net_connection* net_timer( struct net_server* server , net_ccb_func cb , void* udata , int timeout );
struct net_connection* net_fd( struct net_server* server , net_ccb_func cb , void* udata , socket_t fd , int pending_event );

/* cancle another connection through struct net_connection_t* object , after this pointer is 
 * invalid, so do not store this pointer after calling this function */
void net_stop( struct net_connection* conn );
void net_post( struct net_connection* conn , int ev );

/* buffer function */
void* net_buffer_consume( struct net_buffer* , size_t* );
void* net_buffer_peek( struct net_buffer*  , size_t* );
void net_buffer_produce( struct net_buffer* , const void* data , size_t );
struct net_buffer* net_buffer_create( size_t cap , struct net_buffer* );
void net_buffer_clean( struct net_buffer* );
#define net_buffer_readable_size(b) ((b)->produce_pos - (b)->consume_pos)
#define net_buffer_writeable_size(b) ((b)->capacity - (b)->produce_pos)

/* helper function */
int net_timout_read( socket_t fd , void* buf , size_t sz, int msec );
int net_timeout_write( socket_t fd , const void* buf , size_t len , int msec );

void net_hex_dump( const char* title , const void* data , size_t sz );

/* =================================
 * Web socket 
 * ================================*/

#define NETWORK_MAX_WEBSOCKET_MESSAGE_LENGTH 1024*1024 /* 1MB for a single message package */

/* The user should pay attention to the truth that :
 * If an accept callback receive NET_EV_CONNECT, it means the server side
 * handshake has been sent out ; the connected callback receive a NET_EV_CONNECT
 * means the server side handshake package has been received and verified */

struct net_ws_conn;
typedef int (*net_ws_callback)( int ev , int ec , struct net_ws_conn* );

/* This is the interface that you could use to attach a websocket layer on 
 * TCP layer. The usage is 1) create a websocket on accept callback 2)
 * create a websocket on connected callback. 
 * Notes:
 * If the return value is NET_EV_NULL, it means FAIL to create websocket 
 * otherwise a valid NET_EV event is return and you MUST return it as the
 * return value for struct net_connection_t callback function */

int net_ws_create_server( struct net_connection* conn , 
                                 net_ws_callback cb , 
                                 void* data );

int net_ws_create_client( struct net_connection* conn ,
                                 net_ws_callback cb ,
                                 void* data , 
                                 const char* path ,
                                 const char* host);

void* net_ws_get_udata( struct net_ws_conn* ws );
void net_ws_set_udata( struct net_ws_conn* ws , void* data );

/* If you create a server connection, then these 2 functions will return
 * the corresponding header in HTTP request, otherwise NULL string */
const char* net_ws_get_path( struct net_ws_conn* ws );
const char* net_ws_get_host( struct net_ws_conn* ws );

/* User could use these 2 APIs to set the timeout for a connection
 * regarding the next network intention */
void net_ws_set_timeout( struct net_ws_conn* ws , int timeout );
int net_ws_get_timeout( struct net_ws_conn* ws );

/* this memory needs to be freed after using it. This function must be called inside
 * of the callback function. You better check the event type to see whether it is OK
 * to recv the data now. If you call net_ws_recv while no NET_EV_READ event happened,
 * it will return NULL. However if a NET_EV_READ happened, but you don't call this
 * function, you may not get the data in the next callback function since the data
 * you haven't consumed will be wiped out and make space for the new pending data */

void* net_ws_recv( struct net_ws_conn* ws , size_t* len );

/* Send the data through WebSocket to peer side. This function will return the
 * event that you needs to feed the callback function return */
int net_ws_send( struct net_ws_conn* ws , void* data, size_t sz);

/* Blocking version API for web socket at client side */
struct ws_client {
    socket_t fd;
    struct net_buffer buf;
    int state; /* private part */
};

#define net_ws_client_init(c) \
    do { \
        (c)->fd = invalid_socket_handler; \
        (c)->msec= -1; \
        (c)->state=0; \
    } while(0)

int net_ws_fd_connect( struct ws_client* , const char* addr , const char* path , const char* host , int timeout );
int net_ws_fd_send( struct ws_client* , void* data , size_t sz );

/* This recv function will return a buffer that allocated on heap,
 * so free it after using it. The EOF notification for recv is through
 * return NULL + buf_sz  set to 0, otherwise an error will only make 
 * this function return NULL but not set buf_sz to 0. */

void* net_ws_fd_recv( struct ws_client*, size_t* buf_sz );

int net_ws_fd_close( struct ws_client* );
int net_ws_fd_ping( struct ws_client* );


#ifdef __cplusplus
}
#endif // __cplusplus

#endif // NETWORK_H_
