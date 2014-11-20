#include "network.h"
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <ctype.h>

#ifndef _WIN32
#include <sys/select.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#endif /* _WIN32 */

#ifdef _WIN32
#define strccamp stricmp
#else
#define strccamp strcasecmp
#endif /* _WIN32 */


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define SERVER_CONTROL_DATA_LENGTH 128

#define MAXIMUM_IPV4_PACKET_SIZE 65536

#ifndef NDEBUG
#define VERIFY assert
#else
#define VERIFY(cond) do { \
    if(!cond) { \
    fprintf(stderr,"die:" #cond); abort(); }} while(0)
#endif /* NDEBUG */

#ifndef MULTI_SERVER_ENABLE
static char single_server_internal_buffer[MAXIMUM_IPV4_PACKET_SIZE];
#endif

#define cast(x,p) ((x)(p))

#ifndef MIN
#define MIN(x,y) ((x) < (y) ? (x) : (y))
#endif /* min */

#ifndef MAX
#define MAX(x,y) ((x) > (y) ? (x) : (y))
#endif /* MAX */

/* Internal message for linger options */
enum {
    NET_EV_TIMEOUT_AND_CLOSE = 1 << 10
};

static void* mem_alloc( size_t cap ) {
    void* ret = malloc(cap);
    VERIFY(ret);
    return ret;
}

static void mem_free( void* ptr ) {
    assert(ptr);
    free(ptr);
}

static void* mem_realloc( void* ptr , size_t cap ) {
    void* ret;
    assert(cap !=0);
    ret = realloc(ptr,cap);
    VERIFY(ret);
    return ret;
}

static int str_to_sockaddr( const char* str , struct sockaddr_in* addr ) {
    int c1,c2,c3,c4,port;
    int ret = sscanf(str,"%u.%u.%u.%u:%u",&c1,&c2,&c3,&c4,&port);
    if( ret != 5 )  return -1;
    memset(addr,0,sizeof(*addr));
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    addr->sin_addr.s_addr = htonl((c1<<24)+(c2<<16)+(c3<<8)+c4);
    return 0;
}

static void exec_socket( socket_t sock ) {
    assert(sock);
#ifdef _WIN32
    SetHandleInformation((HANDLE) sock, HANDLE_FLAG_INHERIT, 0);
#else
    fcntl(sock, F_SETFD, FD_CLOEXEC);
#endif
}

static void nb_socket( socket_t sock ) {
#ifdef _WIN32
    unsigned long on = 1;
    ioctlsocket(sock, FIONBIO, &on);
#else
    int f = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, f | O_NONBLOCK);
#endif /* _WIN32 */
}

static void reuse_socket( socket_t sock ) {
    int on = 1;
#ifdef _WIN32
    setsockopt(sock,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,cast(const char*,&on),sizeof(int));
#endif /* _WIN32 */
    setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,cast(const char*,&on),sizeof(int));
}

/* platform error */
static int net_has_error() {
#ifdef _WIN32
    int ret = WSAGetLastError();
    if( ret == 0 ) return 0;
    else {
        if( ret == WSAEWOULDBLOCK || ret == WSAEINTR )
            return 0;
        else
            return ret;
    }
#else
    if( errno == 0 ) return 0;
    else if( errno != EAGAIN &&
        errno != EWOULDBLOCK &&
        errno != EINTR &&
        errno != EINPROGRESS &&
        errno != 0 ) return errno;
    else return 0;
#endif
}

static int get_time_millisec() {
#ifndef _WIN32
    struct timeval tv;
    gettimeofday(&tv,NULL);
    return (int)(tv.tv_sec*1000 + (tv.tv_usec/1000));
#else
    static const uint64_t EPOCH = ((uint64_t) 116444736000000000ULL);
    SYSTEMTIME  system_time;
    FILETIME    file_time;
    uint64_t    time;
    GetSystemTime( &system_time );
    SystemTimeToFileTime( &system_time, &file_time );
    time =  ((uint64_t)file_time.dwLowDateTime )      ;
    time += ((uint64_t)file_time.dwHighDateTime) << 32;
    return (int)(system_time.wMilliseconds + (time - EPOCH) / 10000L);
#endif
}

/* buffer internal data structure
 * [--- write buffer -- -- extra ---]
 *       read_pos
 *                   write_pos
 *                                  capacity */


struct net_buffer_t* net_buffer_create( size_t cap , struct net_buffer_t* buf ) {
    if( cap == 0 )
        buf->mem = NULL;
    else
        buf->mem = mem_alloc(cap);
    buf->consume_pos = buf->produce_pos = 0;
    buf->capacity = cap;
    return buf;
}

void net_buffer_clean( struct net_buffer_t* buf ) {
    if(buf->mem)
        mem_free(buf->mem);
    buf->consume_pos = buf->produce_pos = buf->capacity = 0;
}

void* net_buffer_consume( struct net_buffer_t* buf , size_t* size ) {
    int consume_size;
    void* ret;
    if( buf->mem == NULL ) { *size = 0 ; return NULL; }
    else {
        consume_size = MIN(*size,net_buffer_readable_size(buf));
        if( consume_size == 0 ) { *size = 0 ; return NULL; }
        ret = cast(char*,buf->mem) + buf->consume_pos;
        /* advance the internal read pointer */
        buf->consume_pos += consume_size;
        /* checking if we can rewind or not */
        if( buf->consume_pos == buf->produce_pos ) {
            buf->consume_pos = buf->produce_pos = 0;
        }
        *size = consume_size;
        return ret;
    }
}

void* net_buffer_peek( struct net_buffer_t*  buf , size_t* size ) {
    int consume_size;
    void* ret;
    if( buf->mem == NULL ) { *size = 0 ; return NULL; }
    else {
        consume_size = MIN(*size,net_buffer_readable_size(buf));
        if( consume_size == 0 ) { *size = 0 ; return NULL; }
        ret = cast(char*,buf->mem) + buf->consume_pos;
        *size = consume_size;
        return ret;
    }
}

void net_buffer_produce( struct net_buffer_t* buf , const void* data , size_t size ) {
    if( buf->capacity < size + buf->produce_pos ) {
        /* We need to expand the memory */
        size_t cap = size + buf->produce_pos;
        buf->mem = mem_realloc(buf->mem,cap);
        buf->capacity = cap;
    }
    /* Write the data to the buffer position */
    memcpy(cast(char*,buf->mem) + buf->produce_pos , data , size);
    buf->produce_pos += size;
}

static void* net_buffer_consume_peek( struct net_buffer_t* buf ) {
    if( buf->mem == NULL )
        return NULL;
    else {
        if( buf->consume_pos == buf->produce_pos )
            return NULL;
        else
            return cast(char*,buf->mem) + buf->consume_pos;
    }
}

static void net_buffer_consume_advance( struct net_buffer_t* buf , size_t size ) {
    if( buf->mem == NULL || buf->produce_pos < buf->consume_pos + size )
        return;
    buf->consume_pos += size;
    if(buf->consume_pos == buf->produce_pos) {
        buf->consume_pos = buf->produce_pos = 0;
    }
}

#define net_buffer_clear(buf) \
    do { \
        (buf)->capacity=(buf)->produce_pos=(buf)->consume_pos=0; \
        (buf)->mem = NULL; \
    } while(0)

/* connection */

static void connection_cb( int ev , int ec , struct net_connection_t* conn ) {
    if( conn->cb != NULL ) {
        conn->pending_event = conn->cb(ev,ec,conn);
    }
}

static struct net_connection_t* connection_create( socket_t fd ) {
    struct net_connection_t* conn = mem_alloc(sizeof(struct net_connection_t));
    conn->socket_fd = fd;
    net_buffer_clear(&(conn->in));
    net_buffer_clear(&(conn->out));
    conn->cb = NULL;
    conn->user_data = NULL;
    conn->timeout = -1;
    conn->pending_event = NET_EV_NULL;
    return conn;
}

/* we always add the connection to the end of the list since this will
 * make the newly added socket being inserted into the poll fdset quicker */
#define connection_add(server,conn) \
    do { \
        conn->prev = server->conns.prev; \
        server->conns.prev->next = conn; \
        server->conns.prev = conn; \
        conn->next = &((server)->conns); \
    }while(0)

static struct net_connection_t* connection_destroy( struct net_connection_t* conn ) {
    struct net_connection_t* ret = conn->prev;
    /* closing the underlying socket and this must be called at once */
    conn->prev->next = conn->next;
    conn->next->prev = conn->prev;
    net_buffer_clean(&(conn->in));
    net_buffer_clean(&(conn->out));
    mem_free(conn);
    return ret;
}

static struct net_connection_t* connection_close( struct net_connection_t* conn ) {
    socket_t fd = conn->socket_fd;
    struct net_connection_t* ret = connection_destroy(conn);
    if( fd != invalid_socket_handler )
        closesocket(fd);
    return ret;
}

/* server */
int net_server_create( struct net_server_t* server, const char* addr , net_acb_func cb ) {
    struct sockaddr_in ipv4;
    server->conns.next = &(server->conns);
    server->conns.prev = &(server->conns);
    server->cb = cb;
    server->user_data = NULL;
    server->last_io_time = 0;
    if( addr != NULL ) {
        if( str_to_sockaddr(addr,&ipv4) != 0 )
            return -1;
        /* socket stream */
        server->listen_fd = socket(AF_INET,SOCK_STREAM,0);
        if( server->listen_fd == invalid_socket_handler )
            return -1;
        nb_socket(server->listen_fd);
        exec_socket(server->listen_fd);
        /* reuse the addr */
        reuse_socket(server->listen_fd);
        /* bind */
        if( bind(server->listen_fd,cast(struct sockaddr*,&ipv4),sizeof(ipv4)) != 0 ) {
            closesocket(server->listen_fd);
            server->listen_fd = invalid_socket_handler;
            return -1;
        }
        /* listen */
        if( listen(server->listen_fd,SOMAXCONN) != 0 ) {
            closesocket(server->listen_fd);
            return -1;
        }
    } else {
        /* We don't have a dedicated listen server here */
        server->cb = NULL;
        server->ctrl_fd = server->listen_fd = invalid_socket_handler;
    }

    /* control socket */
    server->ctrl_fd = socket(AF_INET,SOCK_DGRAM,0);
    if( server->ctrl_fd == invalid_socket_handler ) {
        if( server->listen_fd != invalid_socket_handler )
            closesocket(server->listen_fd);
        return -1;
    }
    nb_socket(server->ctrl_fd);
    exec_socket(server->ctrl_fd);
    memset(&ipv4,0,sizeof(ipv4));
    /* setting the localhost address for the ctrl udp */
    ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(0);
    if( bind(server->ctrl_fd,cast(struct sockaddr*,&ipv4),sizeof(ipv4)) != 0 ) {
        if( server->listen_fd != invalid_socket_handler )
            closesocket(server->listen_fd);
        closesocket(server->ctrl_fd);
        server->listen_fd = invalid_socket_handler;
        server->ctrl_fd = invalid_socket_handler;
        return -1;
    }
#ifndef MULTI_SERVER_ENABLE
    server->reserve_buffer = single_server_internal_buffer;
#else
    server->reserve_buffer = mem_alloc(MAXIMUM_IPV4_PACKET_SIZE);
#endif /* MULTI_SERVER_ENABLE */
    return 0;
}

static void server_close_all_conns( struct net_server_t* server ) {
    struct net_connection_t* next = server->conns.next;
    struct net_connection_t* temp = NULL;
    while( next != &(server->conns) ) {
        temp = next->next;
        connection_close(temp);
        next = temp;
    }
}

void net_server_destroy( struct net_server_t* server ) {
    server_close_all_conns(server);
    if( server->ctrl_fd != invalid_socket_handler )
        closesocket(server->ctrl_fd);
    if( server->listen_fd != invalid_socket_handler )
        closesocket(server->listen_fd);
    server->conns.next = &(server->conns);
    server->conns.prev = &(server->conns);
    server->ctrl_fd = server->listen_fd = invalid_socket_handler;
#ifdef MULTI_SERVER_ENABLE
    if( server->reserve_buffer != NULL )
        mem_free(server->reserve_buffer);
#endif /* MULTI_SERVER_ENABLE */
}

int net_server_wakeup( struct net_server_t* server ) {
    char buffer[SERVER_CONTROL_DATA_LENGTH];
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

    assert(server->ctrl_fd != invalid_socket_handler &&  server->listen_fd != invalid_socket_handler );
    memset(&addr,0,sizeof(addr));
    if( getsockname(server->ctrl_fd,cast(struct sockaddr*,&addr),&len) !=0 )
        return -1;
    return sendto(server->ctrl_fd,buffer,
        SERVER_CONTROL_DATA_LENGTH,0,cast(struct sockaddr*,&addr),len) >0 ? 1 : 0;
}

static void do_accept( struct net_server_t* server );
static void do_control( struct net_server_t* server );
static int do_write( struct net_connection_t* conn , int* error_code );
static int do_read( struct net_server_t* server , int* error_code , struct net_connection_t* conn );
static int do_connected( struct net_connection_t* conn , int* error_code );

#define ADD_FSET(fs,fd,mfd) \
    do { \
        FD_SET(fd,fs); \
        if( *(mfd) < fd ) { *(mfd) = fd; } \
    }while(0)

static int prepare_linger( struct net_connection_t* conn , fd_set* write , socket_t* max_fd ) {
    if( net_buffer_readable_size(&(conn->out)) ) {
        FD_SET(conn->socket_fd,write);
        if( *max_fd < conn->socket_fd )
            *max_fd = conn->socket_fd;
        return 0;
    }
    return -1;
}

static void prepare_fd( struct net_server_t* server , fd_set* read_set , fd_set* write_set , int* millis , socket_t* max_fd ) {
    struct net_connection_t* conn;
    /* adding the whole connection that we already have to the sets */
    for( conn = server->conns.next ; conn != &(server->conns) ; conn = conn->next ) {
        if( conn->pending_event & NET_EV_IDLE )
            continue;
        /* timeout is a always configurable event */
        if( (conn->pending_event & NET_EV_TIMEOUT) ||
            (conn->pending_event & NET_EV_TIMEOUT_AND_CLOSE) ) {
            if( conn->timeout >= 0 ) {
                if( (*millis >=0 && *millis > conn->timeout) || *millis < 0 ) {
                    *millis = conn->timeout;
                }
            }
        }
        /* read/write , connect , lingerXXX , close */
        if( (conn->pending_event & NET_EV_READ) || (conn->pending_event & NET_EV_WRITE) ) {
            assert( !(conn->pending_event & NET_EV_LINGER) &&
                !(conn->pending_event & NET_EV_LINGER_SILENT) &&
                !(conn->pending_event & NET_EV_CONNECT) &&
                !(conn->pending_event & NET_EV_CLOSE) );
            if( conn->pending_event & NET_EV_READ ) {
                ADD_FSET(read_set,conn->socket_fd,max_fd);
            }
            if( conn->pending_event & NET_EV_WRITE ) {
                ADD_FSET(write_set,conn->socket_fd,max_fd);
            }
        } else {
            if( (conn->pending_event & NET_EV_LINGER) || (conn->pending_event & NET_EV_LINGER_SILENT) ) {
                assert( !(conn->pending_event & NET_EV_CONNECT) &&
                    !(conn->pending_event & NET_EV_CLOSE) );
                if( prepare_linger(conn,write_set,max_fd) !=0 ) {
                    if( conn->pending_event & NET_EV_LINGER ) {
                        connection_cb(NET_EV_LINGER,0,conn);
                    }
                    if( conn->pending_event & NET_EV_TIMEOUT && conn->timeout > 0 )
                        conn->pending_event = NET_EV_TIMEOUT_AND_CLOSE;
                    else
                        conn->pending_event = NET_EV_CLOSE;
                }
            } else if( conn->pending_event & NET_EV_CONNECT ) {
                assert( !(conn->pending_event & NET_EV_CLOSE) );
                ADD_FSET(write_set,conn->socket_fd,max_fd);
            } else {
                /* We just need to convert a NET_EV_CLOSE|NET_EV_TIMEOUT to
                 * internal NET_EV_TIMEOUT_AND_CLOSE operations */
                if( conn->pending_event & NET_EV_CLOSE && 
                    conn->pending_event & NET_EV_TIMEOUT && 
                    conn->timeout >0 ) {
                    conn->pending_event = NET_EV_TIMEOUT_AND_CLOSE;
                }
            }
        }
    }
}

static int dispatch( struct net_server_t* server , fd_set* read_set , fd_set* write_set , int time_diff ) {
    struct net_connection_t* conn;
    int ev , rw , ret ,ec;
    /* 1. checking if we have control operation or not */
    if( FD_ISSET(server->ctrl_fd,read_set) ) {
        do_control(server);
        return 1;
    }
    /* 2. checking the accept operation is done or not */
    if( server->listen_fd != invalid_socket_handler && FD_ISSET(server->listen_fd,read_set) ) {
        do_accept(server);
    }
    /* 3. looping through all the received events in the list */
    for( conn = server->conns.next ; conn != &(server->conns) ; conn = conn->next ) {
        if( conn->pending_event & NET_EV_IDLE )
            continue;
        ev = 0; ec = 0;
        /* timeout */
        if( (conn->pending_event & NET_EV_TIMEOUT) ||
            (conn->pending_event & NET_EV_TIMEOUT_AND_CLOSE) ) {
            if( conn->timeout <= time_diff ) {
                ev |= (conn->pending_event & NET_EV_TIMEOUT) ? NET_EV_TIMEOUT : NET_EV_TIMEOUT_AND_CLOSE;
            } else {
                conn->timeout -= time_diff;
            }
        }
        /* connect */
        if( (conn->pending_event & NET_EV_CONNECT) && FD_ISSET(conn->socket_fd,write_set) ) {
            /* connection operation done, notify our user */
            if( do_connected(conn,&ec) == 0 ) {
                ev |= NET_EV_CONNECT;
                connection_cb(ev,0,conn);
            } else {
                ev |= NET_EV_ERR_CONNECT;
                connection_cb(ev,ec,conn);
            }
            continue;
        }
        /* read/write */
        if( (conn->pending_event & NET_EV_WRITE) || (conn->pending_event & NET_EV_READ) ) {
            rw = 0; ec = 0;
            /* checking read */
            if( (conn->pending_event & NET_EV_READ) && FD_ISSET(conn->socket_fd,read_set) ) {
                ret = do_read(server,&ec,conn);
                if( ret == 0 ) {
                    ev |= NET_EV_EOF;
                } else if( ret < 0 ) {
                    ev |= NET_EV_ERR_READ;
                } else {
                    ev |= NET_EV_READ;
                }
                ++rw;
            }
            /* checking write */
            if( !(ev & NET_EV_ERR_READ) && (conn->pending_event & NET_EV_WRITE) && FD_ISSET(conn->socket_fd,write_set) ) {
                ret = do_write(conn,&ec);
                if( ret < 0 ) {
                    ev |= NET_EV_ERR_WRITE;
                } else {
                    ev |= NET_EV_WRITE;
                }
                ++rw;
            }
            /* call the connection callback function here */
            if( rw != 0 ) connection_cb(ev,ec,conn);
            continue;
        }
        /* linger */
        if( ((conn->pending_event & NET_EV_LINGER) || (conn->pending_event & NET_EV_LINGER_SILENT)) && FD_ISSET(conn->socket_fd,write_set) ) {
            ec = 0;
            ret = do_write(conn,&ec);
            if( ret <= 0 ) {
                conn->pending_event = NET_EV_CLOSE;
            } else if( net_buffer_readable_size(&(conn->out)) == 0 ) {
                if( conn->pending_event & NET_EV_LINGER ) {
                    connection_cb(NET_EV_LINGER,ec,conn);
                }
                if( (conn->pending_event & NET_EV_TIMEOUT) && (conn->timeout >0) ) {
                    conn->pending_event = NET_EV_TIMEOUT_AND_CLOSE;
                } else {
                    conn->pending_event = NET_EV_CLOSE;
                }
            }
            continue;
        }
        /* if we reach here means only timeout is specified */
        if( (conn->pending_event & NET_EV_TIMEOUT) && (ev & NET_EV_TIMEOUT) ) {
            connection_cb(NET_EV_TIMEOUT,0,conn);
        } else if( (conn->pending_event & NET_EV_TIMEOUT_AND_CLOSE) && (ev & NET_EV_TIMEOUT_AND_CLOSE) ) {
            /* need to close this socket here */
            conn->pending_event = NET_EV_CLOSE;
        }
    }
    return 0;
}

static void reclaim_socket( struct net_server_t* server ) {
    struct net_connection_t* conn;
    /* reclaim all the socket that has marked it as CLOSE operation */
    for( conn = server->conns.next ; conn != &(server->conns) ; conn = conn->next ) {
        if( conn->pending_event & NET_EV_CLOSE ) {
            conn = connection_close(conn);
        } else if( conn->pending_event & NET_EV_REMOVE ) {
            conn = connection_destroy(conn);
        }
    }
}

int net_server_poll( struct net_server_t* server , int millis , int* wakeup ) {
    fd_set read_set , write_set;
    socket_t max_fd = invalid_socket_handler;
    int active_num , return_num;
    struct timeval tv;
    int time_diff;
    int cur_time;

    FD_ZERO(&read_set);
    FD_ZERO(&write_set);

    /* adding the listen_fd and ctrl_fd */
    if( server->listen_fd != invalid_socket_handler )
        ADD_FSET(&read_set,server->listen_fd,&max_fd);
    ADD_FSET(&read_set,server->ctrl_fd,&max_fd);

    prepare_fd(server,&read_set,&write_set,&millis,&max_fd);

    /* setting the timer */
    if( millis >= 0 ) {
        tv.tv_sec = millis / 1000;
        tv.tv_usec = (millis % 1000) * 1000;
    }

    if( server->last_io_time == 0 )
        server->last_io_time = get_time_millisec();
    /* start our polling mechanism */
    if( max_fd == invalid_socket_handler )
        max_fd = 0;
    active_num = select(max_fd+1,&read_set,&write_set,NULL,millis >= 0 ? &tv : NULL);
    if( active_num < 0 ) {
        int err = net_has_error();
        if( err == 0 )
          return 0;
        else
          return -1;
    }
    return_num = active_num;
    cur_time = get_time_millisec();
    time_diff = cur_time - server->last_io_time;
    if( millis < 0 ) {
        server->last_io_time = cur_time;
    } else {
        if( time_diff > 0 )
            server->last_io_time = cur_time;
    }
    /* if we have errno set to EWOULDBLOCK EINTER which typically
     * require us to re-enter the loop, we don't need to do this
     * what we need to do is just put this poll into the loop , so
     * no need to worry about the problem returned by the select */

    if( active_num >= 0 ) {
        int w;
        if( time_diff == 0 )
            time_diff = 1;
        w = dispatch(server,&read_set,&write_set,time_diff);
        if( wakeup != NULL )
            *wakeup = w;
    }
    /* 4. reclaim all the socket that has marked it as CLOSE operation */
    reclaim_socket(server);
    return return_num;
}

#undef ADD_FSET

static void do_accept( struct net_server_t* server ) {
    struct net_connection_t* conn;
    int error_code;
    do {
        socket_t sock = accept(server->listen_fd,NULL,NULL);
        if( sock == invalid_socket_handler ) {
            error_code = net_has_error();
            if( error_code != 0 ) {
                server->cb(error_code,server,NULL);
            }
            return;
        } else {
            int pending_ev;
            nb_socket(sock);
            conn = connection_create(sock);
            connection_add(server,conn);
            conn->pending_event = NET_EV_CLOSE;
            pending_ev = server->cb(0,server,conn);
            if( conn->cb == NULL )
                conn->pending_event = NET_EV_CLOSE;
            else
                conn->pending_event = pending_ev;
        }
    } while(1);
}

static int do_read( struct net_server_t* server , int* error_code , struct net_connection_t* conn ) {
    int rd = recv( conn->socket_fd , server->reserve_buffer , MAXIMUM_IPV4_PACKET_SIZE , 0 );
    if( rd <= 0 ) {
        *error_code = net_has_error();
        return rd;
    } else {
        net_buffer_produce( &(conn->in) , server->reserve_buffer , rd );
        return rd;
    }
}

static int do_write( struct net_connection_t* conn , int* error_code ) {
    void* out = net_buffer_consume_peek(&(conn->out));
    int snd;
    if( out == NULL ) return 0;
    snd = send(conn->socket_fd,out,net_buffer_readable_size(&(conn->out)),0);
    if( snd <= 0 ) {
        *error_code = net_has_error();
        return snd;
    } else {
        net_buffer_consume_advance(&(conn->out),snd);
        return snd;
    }
}

static void do_control( struct net_server_t* server ) {
    char buffer[SERVER_CONTROL_DATA_LENGTH];
    recvfrom(server->ctrl_fd,buffer,SERVER_CONTROL_DATA_LENGTH,0,NULL,NULL);
}

static int do_connected( struct net_connection_t* conn , int* error_code ) {
    int val;
    socklen_t len = sizeof(int);
    /* before we do anything we need to check whether we have connected to the socket or not */
    getsockopt(conn->socket_fd,SOL_SOCKET,SO_ERROR,cast(char*,&val),&len);
    if( val != 0 ) {
        *error_code = val;
        return -1;
    } else {
        return 0;
    }
}

/* client function */
socket_t net_block_client_connect( const char* addr ) {
    struct sockaddr_in ipv4;
    int ret;
    socket_t sock;
    if( str_to_sockaddr(addr,&ipv4) != 0 ) {
        return invalid_socket_handler;
    } else {
        sock = socket(AF_INET,SOCK_STREAM,0);
        if( sock == invalid_socket_handler )
            return sock;
        reuse_socket(sock);
        ret = connect(sock,cast(struct sockaddr*,&ipv4),sizeof(ipv4));
        if( ret != 0 ) {
            closesocket(sock);
            return invalid_socket_handler;
        }
        return sock;
    }
}

int net_non_block_client_connect(struct net_server_t* server ,
    const char* addr ,
    net_ccb_func cb ,
    void* udata ,
    int timeout ) {
        struct net_connection_t* conn = connection_create(invalid_socket_handler);
        connection_add(server,conn);
        conn->cb = cb;
        conn->user_data = udata;
        if( net_non_block_connect(conn,addr,timeout) == NET_EV_REMOVE ) {
            if( conn->socket_fd == invalid_socket_handler ) {
                /* error */
                connection_close(conn);
                return -1;
            }
        }
        return 0;
}

int net_non_block_connect( struct net_connection_t* conn , const char* addr , int timeout ) {
    int ret;
    struct sockaddr_in ipv4;
    socket_t fd;
    if( str_to_sockaddr(addr,&ipv4) != 0 )
        return NET_EV_REMOVE;
    fd = socket(AF_INET,SOCK_STREAM,0);
    if( fd == invalid_socket_handler ) {
        return NET_EV_REMOVE;
    }
    nb_socket(fd);
    exec_socket(fd);
    reuse_socket(fd);
    ret = connect( fd , cast(struct sockaddr*,&ipv4) , sizeof(ipv4));
    if( ret != 0 && net_has_error() != 0 )  {
        closesocket(fd);
        return NET_EV_REMOVE;
    }
    conn->socket_fd = fd;
    conn->pending_event = NET_EV_CONNECT;
    if( ret != 0 && timeout >= 0 ) {
        conn->pending_event |= NET_EV_TIMEOUT;
        conn->timeout=  timeout;
    } else if( ret == 0 ) {
        connection_cb(NET_EV_CONNECT,0,conn);
        return conn->pending_event;
    }
    return conn->pending_event;
}

/* timer and socket */
struct net_connection_t* net_timer( struct net_server_t* server , net_ccb_func cb , void* udata , int timeout ) {
    struct net_connection_t* conn = connection_create(invalid_socket_handler);
    connection_add(server,conn);
    conn->cb = cb;
    conn->user_data = udata;
    conn->timeout = timeout;
    conn->pending_event = NET_EV_TIMEOUT;
    return conn;
}

struct net_connection_t* net_fd( struct net_server_t* server, net_ccb_func cb , void* data ,  socket_t fd , int pending_event ) {
    struct net_connection_t* conn = connection_create(fd);
    nb_socket(fd);
    exec_socket(fd);
    conn->cb = cb;
    conn->user_data = data;
    conn->pending_event = pending_event;
    return conn;
}

void net_stop( struct net_connection_t* conn ) {
    conn->pending_event = NET_EV_CLOSE;
}

void net_post( struct net_connection_t* conn , int ev ) {
    conn->pending_event = ev;
}

/* platform problem */
void net_init() {
#ifdef _WIN32
    WSADATA data;
    WSAStartup(MAKEWORD(2, 2), &data);
#endif /* _WIN32 */
}

/* Web Socket Implementation */

/* Base64 encode/decode */

static
size_t b64_encode( const char *src, size_t src_len, char *dst ) {
    static const char *B64LOOKUP =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i, j;
    int b1,b2,b3;
    const unsigned char* usrc = (const unsigned char*)(src);

    for ( i = j = 0; i < src_len; i += 3 ) {
        b1 = usrc[i];
        b2 = i + 1 >= src_len ? 0 : usrc[i + 1];
        b3 = i + 2 >= src_len ? 0 : usrc[i + 2];

        dst[j++] = B64LOOKUP[b1 >> 2];
        dst[j++] = B64LOOKUP[((b1 & 3) << 4) | (b2 >> 4)];
        if (i + 1 < src_len) {
            dst[j++] = B64LOOKUP[(b2 & 15) << 2 | (b3 >> 6)];
        }
        if (i + 2 < src_len) {
            dst[j++] = B64LOOKUP[b3 & 63];
        }
    }

    /* tail */
    switch( j % 4 ) {
    case '2':
        dst[j+1] = '=';
        dst[j+2] = '=';
        j += 2;
        break;
    case '3':
        dst[j+1] = '=';
        ++j;
        break;
    default:
        break;
    }
    /* done */
    return j;
}

int b64_decode( const char *src, size_t src_len, char *dst , size_t dst_len ) {
    static char B64LOOKUP[] = {
        255,255,255,255,255,255,255,255,255,255,255,
        255,255,255,255,255,255,255,255,255,255,255,
        255,255,255,255,255,255,255,255,255,255,255,
        255,255,255,255,255,255,255,255,255,255,62, 
        255, 255, 255,63,52, 53, 54, 55, 56, 57, 58, 
        59, 60, 61, 255, 255, 255, 254, /* = */
        255, 255, 255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
        10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25, 
        255, 255, 255, 255, 255, 255, 26,27,28,29,30,31,
        32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,
        48,49,50,51, 255, 255, 255, 255, 
        255,255,255,255,255,255,255,255,255,255,255,255,
        255,255,255,255,255,255,255,255,255,255,255,255,
        255,255,255,255,255,255,255,255,255,255,255,255,
        255,255,255,255,255,255,255,255,255,255,255,255,
        255,255,255,255,255,255,255,255,255,255,255,255,
        255,255,255,255,255,255,255,255,255,255,255,255,
        255,255,255,255,255,255,255,255,255,255,255,255,
        255,255,255,255,255,255,255,255,255,255,255,255,
        255,255,255,255,255,255,255,255,255,255,255,255,
        255,255,255,255,255,255,255,255,255,255,255,255,
        255,255,255,255,255,255,255,255
    };

    unsigned char b1,b2,b3,b4;
    char* sdst = dst;

    while( src_len >=4 && 
          (b1 = B64LOOKUP[src[0]]) != 255 &&
          (b2 = B64LOOKUP[src[1]]) != 255 &&
          (b3 = B64LOOKUP[src[2]]) != 255 && 
          (b4 = B64LOOKUP[src[3]]) != 255 ) {
        /* rule out the broken stream here */
        if( b1 == 254 || b2 == 254 ) 
            return -1; 

        *dst = b1 << 2 | b2 >> 4;
        /* = */
        if (b3 == 254) break;
        *dst++ = b2 << 4 | b3 >> 2;
        /* = */
        if (b4 == 254) break;

        *dst++ = b3 << 6 | b4;
        
        src_len -= 4;
        src+=4;
    }

    /* done */
    return dst - sdst;
}

/* Sha1 hash , by Steve Reid 100% public domain */
typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    uint8_t  buffer[64];
} SHA1_CTX;

#define SHA1_DIGEST_SIZE 20

void SHA1_Init(SHA1_CTX* context);
void SHA1_Update(SHA1_CTX* context, const uint8_t* data, const size_t len);
void SHA1_Final(SHA1_CTX* context, uint8_t digest[SHA1_DIGEST_SIZE]);


void SHA1_Transform(uint32_t state[5], const uint8_t buffer[64]);

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */
/* FIXME: can we do this in an endian-proof way? */

#if 0

#ifdef WORDS_BIGENDIAN
#define blk0(i) block->l[i]
#else
#define blk0(i) (block->l[i] = (rol(block->l[i],24)&0xFF00FF00) \
    |(rol(block->l[i],8)&0x00FF00FF))
#endif

#endif 

/* Workaround the endian macro */

static int is_big_endian(void) {
    static const int n = 1;
    return ((char *) &n)[0] == 0;
}

typedef union {
    uint8_t c[64];
    uint32_t l[16];
} CHAR64LONG16;

static uint32_t blk0(CHAR64LONG16 *block, int i) {
    if (!is_big_endian()) {
        block->l[i] = (rol(block->l[i], 24) & 0xFF00FF00) |
            (rol(block->l[i], 8) & 0x00FF00FF);
    }
    return block->l[i];
}

#define blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15] \
    ^block->l[(i+2)&15]^block->l[i&15],1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(block,i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);

/* Hash a single 512-bit block. This is the core of the algorithm. */
void SHA1_Transform(uint32_t state[5], const uint8_t buffer[64])
{
    uint32_t a, b, c, d, e;
    CHAR64LONG16* block;

    block = (CHAR64LONG16*)buffer;

    /* Copy context->state[] to working vars */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

    /* 4 rounds of 20 operations each. Loop unrolled. */
    R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
    R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
    R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
    R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
    R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
    R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
    R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
    R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
    R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
    R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
    R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
    R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
    R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
    R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
    R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
    R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
    R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
    R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
    R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
    R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);

    /* Add the working vars back into context.state[] */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;

    /* Wipe variables */
    a = b = c = d = e = 0;
}


/* SHA1Init - Initialize new context */
void SHA1_Init(SHA1_CTX* context)
{
    /* SHA1 initialization constants */
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = context->count[1] = 0;
}


/* Run your data through this. */
void SHA1_Update(SHA1_CTX* context, const uint8_t* data, const size_t len)
{
    size_t i, j;

    j = (context->count[0] >> 3) & 63;
    if ((context->count[0] += len << 3) < (len << 3)) context->count[1]++;
    context->count[1] += (len >> 29);
    if ((j + len) > 63) {
        memcpy(&context->buffer[j], data, (i = 64-j));
        SHA1_Transform(context->state, context->buffer);
        for ( ; i + 63 < len; i += 64) {
            SHA1_Transform(context->state, data + i);
        }
        j = 0;
    }
    else i = 0;
    memcpy(&context->buffer[j], &data[i], len - i);

}

/* Add padding and return the message digest. */
void SHA1_Final(SHA1_CTX* context, uint8_t digest[SHA1_DIGEST_SIZE])
{
    uint32_t i;
    uint8_t  finalcount[8];

    for (i = 0; i < 8; i++) {
        finalcount[i] = (unsigned char)((context->count[(i >= 4 ? 0 : 1)]
        >> ((3-(i & 3)) * 8) ) & 255);  /* Endian independent */
    }
    SHA1_Update(context, (uint8_t *)"\200", 1);
    while ((context->count[0] & 504) != 448) {
        SHA1_Update(context, (uint8_t *)"\0", 1);
    }
    SHA1_Update(context, finalcount, 8);  /* Should cause a SHA1_Transform() */
    for (i = 0; i < SHA1_DIGEST_SIZE; i++) {
        digest[i] = (uint8_t)
            ((context->state[i>>2] >> ((3-(i & 3)) * 8) ) & 255);
    }

    /* Wipe variables */
    i = 0;
    memset(context->buffer, 0, 64);
    memset(context->state, 0, 20);
    memset(context->count, 0, 8);
    memset(finalcount, 0, 8);	/* SWR */
}


#define MAX_HOST_NAME 256
#define MAX_DIR_NAME 256
#define MAX_HTTP_HEADER_LINE 31
static const char* WS_KEY_COOKIE="258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/* This object is _SENT_ from client but it needs to parsed out by server */
struct ws_cli_handshake_t {
    char ws_key[16];
    char host[MAX_HOST_NAME];
    char dir [MAX_DIR_NAME];
    /* bits field for status information */
    unsigned char upgrade: 1;
    unsigned char connection: 1;
    unsigned char ws_version:1;
    unsigned char line_num:5; /* the 5 bits is used for storing HTTP line number 
                               * which is way more than enough for web socket */
};

#define INITIALIZE_WS_CLI_HANDSHAKE(c) \
    do { \
        (c)->ws_key[0] = 0; \
        (c)->host[0] = 0; \
        (c)->dir[0] = 0; \
        (c)->upgrade=0; \
        (c)->connection=0; \
        (c)->ws_version=0; \
        (c)->line_num = 0; \
    } while(0)

/* 
 * Our parsing routine just trying find out the related field inside of the
 * header, once everything is collected, we are trying to find out the EOL,
 * If a EOF is found, the eof will be set to 1
 */

static
int http_readline( const char* c , size_t len , int* eof ) {
    /* read until /r/n is find out */
    size_t i = 0;
    *eof = 0;
    for ( ; i < len ; ++i )
        if ( c[i] == '\r' && (i+1 < len && c[i+1]== '\n') ) {
            i+=2;
            if( (i < len && c[i] == '\r') && (i+1 < len && c[i+1]== '\n') ) {
                *eof = 1;
            }
            return i;
        }
    return -1;
}

/* Websocket server side HTTP part operation */
enum {
    WS_UNKNOWN_METHOD = -1,
    WS_NOT_SUPPORT_HTTP_VERSION = -2,
    WS_TOO_LARGE_URI = -3,
    WS_UNKNOWN_UPGRADE_VALUE = -4,
    WS_UNKNOWN_CONNECTION_VALUE = -5,
    WS_UNKNOWN_WS_VERSION = -6,
    WS_UNKNOWN_WS_KEY = -7,
    WS_TOO_LARGE_HOST = -8,
    WS_UNKNOWN_HOST = -9,
    WS_TOO_LARGE_HTTP_HEADER = -10,
    WS_UNKNOWN_REQUEST_HEADER = -11
};

/* Parsing the very first line of HTTP header */
static
int http_ser_check_first_line( const char* data , size_t len , char* dir ) {
    enum {
        METHOD,
        URI,
        HTTP
    };

    int state = METHOD;
    const char* end = data+len;

    while(1) {
        switch(state) {
        case METHOD:
            if (end-data <4)
                return WS_UNKNOWN_METHOD;
            if (data[0] == 'G'&&data[1] == 'E'&&data[2] == 'T')
                data+=4; /* skip the extra space */
            else
                return WS_UNKNOWN_METHOD;
            state = URI;
            break;
        case URI: {
            /* we don't parse URI, but instead , just find the first space */
            const char* p = strchr(data,' ');
            if ( p-data >= MAX_DIR_NAME )
                return WS_TOO_LARGE_URI;
            else {
                memcpy(dir,data,p-data+1);
            }
            data = p+1;
            state = HTTP;
            break;
        }
        case HTTP:
            /* HTTP/1.X */
            if( end-data < 8 ) {
                return -1;
            } else {
                if( data[0] == 'H' && data[1] == 'H' && 
                    data[2] == 'T' && data[3] == 'P' &&
                    data[4] == ' ' && data[5] == '1' && data[6] == '.' ) {
                        int x = data[7] - '0';
                        /* minimum websocket needs 1.1 */
                        if( x == 1 )
                            return 0;
                        else
                            return WS_NOT_SUPPORT_HTTP_VERSION;
                }
                return WS_NOT_SUPPORT_HTTP_VERSION;
            }
        default: assert(0);return-1;
        }
    }
}

/* We politely skip the whitespace although RFC doesn't show any evidence 
 * to allow such behavior */
static int http_strcmp( const char* lhs , const char* rhs ) {
    int i = 0;
    for( ; lhs[i] ; ++i ) {
        if( !isspace(lhs[i]) )
            return strcmp( lhs+i,rhs );
    }
    return -1;
}

/*
 * return value:
 * 0 represent we are done
 * positive number means how many data has been consumed
 * -1 represent error 
 * 6 headers are supported here(HARDCODE):
 * Host:
 * Upgrade:
 * Connection:
 * Sec-WebSocket-Version
 * Sec-WebSocket-Key
 * Set-Cookie
 */

static 
int http_ser_parse( const char* data , size_t len , struct ws_cli_handshake_t* hs ) {
    const char* s = data;
    int eof;

    do {
        int num = http_readline(data,len,&eof);
        if (num == -1)
            return data-s;
        /* we have at least one line data now */
        if ( hs->line_num == 0 ) {
            int ret;
            /* do a small modification here */
            cast(char*,data)[num-2] = 0;
            ret = http_ser_check_first_line(data,num-2,hs->dir);
            if( ret != 0 )
                return ret;
            cast(char*,data)[num-2] = '\r';
        } else {
            const char* semicon;
            cast(char*,data)[num-2] = 0;
            semicon = strchr(data,':');
            *cast(char*,semicon) = 0;

            if( strccamp(data,"Upgrade") == 0 ) {
                if( hs->upgrade || http_strcmp(semicon+1,"websocket") != 0 )
                    return WS_UNKNOWN_UPGRADE_VALUE;
                hs->upgrade = 1;
                goto again;
            } else if ( strccamp(data,"Connection") == 0 ) {
                if( hs->connection ||http_strcmp(semicon+1,"Upgrade") != 0 )
                    return WS_UNKNOWN_CONNECTION_VALUE;
                hs->connection = 1;
                goto again;
            } else if( strccamp(data,"Sec-WebSocket-Version") == 0 ) {
                if( hs->ws_version || http_strcmp(semicon+1,"13") != 0 )
                    return WS_UNKNOWN_WS_VERSION;
                hs->ws_version = 1;
                goto again;
            } else if( strccamp(data,"Sec-WebSocket-Key") == 0 ) {
                int i = 1;
                if( hs->ws_key[0] )
                    return WS_UNKNOWN_WS_KEY;
                /* find the start of the key by skipping potential whitespace */
                for( ; semicon[i] ; ++i ) {
                    if( !isspace(semicon[i]) )
                        break;
                }
                /* now we can copy the key into the buffer now */
                if( strlen(semicon+i) < 16 )
                    return WS_UNKNOWN_WS_KEY;
                memcpy( hs->ws_key , semicon , 16 );
                goto again;
            } else if( strccamp(data,"Host") == 0 ) {
                int i = 1;
                if( hs->host[0] )
                    return WS_UNKNOWN_HOST;
                for( ; semicon[i] ; ++i ) {
                    if( !isspace(semicon[i]) )
                        break;
                }
                /* too large host name */
                if( strlen(semicon+i) >= MAX_HOST_NAME )
                    return WS_TOO_LARGE_HOST;
                strcpy(hs->host,semicon+i);
                goto again;
            } else {
                /* skip all the other header , pay attention, we skip the ORIGIN
                 * header attribute since we don't do any security check here */
                goto loop;
            }
again:      /* for quick skip the next if-else chain and also recover the string */
            cast(char*,data)[num-2] = '\r';
            *cast(char*,semicon) = ':';
        }
loop:   /* move to next line, hopefully */
        data += num;
        ++hs->line_num;
        if( hs->line_num == MAX_HTTP_HEADER_LINE ) {
            return WS_TOO_LARGE_HTTP_HEADER;
        }
    } while( !eof );

    /* checking the EOF problem */
    if( hs->upgrade && hs->connection && hs->ws_version && hs->ws_key[0] && hs->host[0] ) {
        return 0;
    } else {
        return WS_UNKNOWN_REQUEST_HEADER;
    }
}

/* Generate Websocket reply for successful upgrade */
static
size_t http_ser_reply( struct ws_cli_handshake_t* hs , char ret[1024] ) {
    static const char* WS_FORMAT = \
        "HTTP/1.1 101 Switching Protocols\r\n" \
        "Upgrade:websocket\r\n" \
        "Connection:Upgrade\r\n" \
        "Sec-WebSocket-Accept:";

    static const size_t WS_FORMAT_LEN = strlen(WS_FORMAT);

    char buf[128];
    SHA1_CTX shal_ctx;
    uint8_t digest[SHA1_DIGEST_SIZE];
    size_t len = cast(size_t, sprintf(buf,"%s%s",hs->ws_key,WS_KEY_COOKIE) );

    /* shal1 these key */
    SHA1_Init(&shal_ctx);
    SHA1_Update(&shal_ctx,cast(const uint8_t*,buf),len);
    SHA1_Final(&shal_ctx,digest);

    /* encode it into base64 */
    len = b64_encode(cast(const char*,digest),SHA1_DIGEST_SIZE,buf);
    assert( len + WS_FORMAT_LEN + 4 < 1024 );

    /* now write to the output buffer */

    memcpy(ret,WS_FORMAT,WS_FORMAT_LEN);
    memcpy(ret+WS_FORMAT_LEN,buf,len);

    ret[WS_FORMAT_LEN+len+1]= '\r';
    ret[WS_FORMAT_LEN+len+2]= '\n';
    ret[WS_FORMAT_LEN+len+3]= '\r';
    ret[WS_FORMAT_LEN+len+4]= '\n';

    return len + 4 + WS_FORMAT_LEN;
}


/* This data structure represent a data frame on the wire for WS 
 * We notify the user at least we know the header length */
enum {
    WS_TEXT = 1 , /* unsupported , dumb RFC definition */
    WS_BINARY=2 , /* supported */
    /* reserved 3-7 */
    WS_CLOSE = 8 ,
    WS_PING  = 9 ,
    WS_PONG  = 10,
    /* reserved 11-15 */
    SIZE_OF_WS_FRAME_TYPE
};

enum {
    WS_FP_FIRST_BYTE,
    WS_FP_LENGTH,
    WS_FP_LENGTH_MID,
    WS_FP_LENGTH_LONG,
    WS_FP_MASK,
    WS_FP_PAYLOAD,
    WS_FP_DONE
};

enum {
    WS_FP_ERR_RESERVE_BIT = -1,
    WS_FP_ERR_NOT_SUPPORT_FRAME = -2 ,
    WS_FP_ERR_TOO_LARGE_PAYLOAD = -3
};

struct ws_frame_t {
    unsigned char op :4;
    unsigned char fin:1;
    unsigned char m:3;
    char mask[4];
    /* the maximum possible length of a package size which is DUMB */
    uint64_t data_len;
    void* data;
    size_t data_sz;
    /* private area for frame parser */
    int state;
};

#define INITIALIZE_WS_FRAME(fr) \
    do { \
        (fr)->state = WS_FP_FIRST_BYTE; \
    } while(0)

/* this ws frame parser is a stream parser, feed it as small as 1 byte
 * will also produce valid result and not hurt any other one */
static 
int ws_frame_parse( const char* data , size_t len , struct ws_frame_t* fr ) {
    const char* s = data;
    char byte;
    size_t l;

    assert(len >0);

    do {
        switch(fr->state) {
        case WS_FP_FIRST_BYTE:
            byte = *data;
            fr->fin = byte & 1; /* fin */

            byte >>=1;
            if( (byte & (7<<1)) )
                return WS_FP_ERR_RESERVE_BIT; /* the reserve bit _MUST_ be zero */

            byte >>=3;
            fr->op = (byte & (~15)); /* get the op */

            /* checking if these OP is supported by us */
            switch(fr->op) {
            case WS_BINARY:
            case WS_PING:
            case WS_PONG:
            case WS_CLOSE:
                break;
            default:
                return WS_FP_ERR_NOT_SUPPORT_FRAME;
            }
            fr->state = WS_FP_LENGTH;

            ++data;
            --len;
            if( len == 0 )
                return data-s;

            break;
        case WS_FP_LENGTH:
            byte = *data;
            fr->m = byte & 1;
            byte >>= 1;

            /* the length of the frame */
            switch(byte) {
            case 126:
                fr->state = WS_FP_LENGTH_MID;
                break;
            case 127:
                fr->state = WS_FP_LENGTH_LONG;
            default:
                fr->data_len = byte;
                if( fr->m )
                    fr->state = WS_FP_MASK;
                else
                    fr->state = WS_FP_PAYLOAD;
                break;
            }
            
            ++data;
            --len;
            if( len == 0 )
                return data-s;
            break;

        case WS_FP_LENGTH_MID:
            if( len < 2 )
                return data-s;
            fr->data_len = cast(uint64_t,ntohs( *cast(uint16_t*,data) ));
            fr->data_sz = 0;
            fr->data = mem_alloc(fr->data_len);

            if( fr->m )
                fr->state = WS_FP_MASK;
            else
                fr->state = WS_FP_PAYLOAD;

            data += 2;
            len -= 2;
            if( len == 0 )
                return data-s;
            break;

        case WS_FP_LENGTH_LONG:
            if( len < 8 )
                return data-s;

            fr->data_len = cast(uint64_t,ntohll( *cast(uint64_t*,data) ) );
            fr->data_sz = 0;

            if( fr->data_len > NETWORK_MAX_WEBSOCKET_MESSAGE_LENGTH )
                return WS_FP_ERR_TOO_LARGE_PAYLOAD;

            fr->data = mem_alloc( fr->data_len );
            
            if( fr->m )
                fr->state = WS_FP_MASK;
            else
                fr->state = WS_FP_PAYLOAD;

            data += 8;
            len -= 8;
            if( len == 0 )
                return data-s;
            break;

        case WS_FP_MASK:
            if( len < 4 )
                return data-s;

            /* I have no idea that the mask should be encoded with which endian
             * It can be treated as a octets group like STUN, or it should be 
             * treated as a numeric value using network endian */

            fr->mask[0] = data[0];
            fr->mask[1] = data[1];
            fr->mask[2] = data[2];
            fr->mask[3] = data[3];

            len -=4;
            data+=4;

            fr->state = WS_FP_PAYLOAD;

            if( len == 4 )
                return data-s;

            break;
        case WS_FP_PAYLOAD:
            /* it is possible that 2 frames reached tail followed by another head
             * We should not touch the data that is belonged to the second packets */
            l = MIN(len,fr->data_len - fr->data_sz);
            memcpy( cast(char*,fr->data) + fr->data_sz , data , l );

            data += l;
            len -= l;

            fr->data_sz += l;
            if( fr->data_sz == fr->data_len ) {
                fr->state = WS_FP_DONE;
                /* unmask the data at last if there is a mask presents */
                if( fr->m ) {
                    int i;
                    for( i = 0 ; i < fr->data_len ; ++i ) {
                        cast(char*,fr->data)[i] ^= fr->mask[i%4];
                    }
                }
            }
            return data-s;

        default: assert(0); return -1;
        }
    } while(1);
}

/* Web socket connection */

enum {
    WS_CONNECTING,
    WS_CONNECTED,
    WS_WANT_FRAG,
    WS_CLOSE
};

struct ws_conn_t {
    struct ws_cli_handshake_t ws_hs;
    struct ws_frame_t ws_frame;
    int ws_state;
    net_ws_callback cb;
    void* user_data;
    struct net_connection_t* trans;
};




#ifdef __cplusplus
}
#endif /* __cplusplus */
