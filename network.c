#include "network.h"
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <limits.h>

#ifndef _WIN32
#include <sys/select.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#endif /* _WIN32 */

#ifdef _WIN32
#define strccamp _stricmp
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

static void nonblock_socket( socket_t sock ) {
#ifdef _WIN32
    unsigned long on = 1;
    ioctlsocket(sock, FIONBIO, &on);
#else
    int f = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, f | O_NONBLOCK);
#endif /* _WIN32 */
}

static void block_socket( socket_t sock ) {
#ifdef _WIN32
    unsigned long off = 0;
    ioctlsocket(sock,FIONBIO,&off);
#else
    int f = fcntl(sock,F_GETFL,0);
    f &= ~O_NONBLOCK;
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
        if( ret == WSAEWOULDBLOCK || 
            ret == WSAEINTR ||
            ret == WSAECONNRESET )
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
        errno != ECONNABORTED &&
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

void net_hex_dump ( const char *desc, const void *addr, size_t len) {
    size_t i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;
    if (desc != NULL)
        printf ("%s:\n", desc);
    for (i = 0; i < len; i++) {
        if ((i % 16) == 0) {
            if (i != 0)
                printf ("  %s\n", buff);
            printf ("  %04x ", i);
        }
        printf (" %02x", pc[i]);
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }
    printf ("  %s\n", buff);
}

/* buffer internal data structure
 * [--- write buffer -- -- extra ---]
 *       read_pos
 *                   write_pos
 *                                  capacity */

#define net_buffer_ptr(buf) ((buf)->mem)

struct net_buffer* net_buffer_create( size_t cap , struct net_buffer* buf ) {
    if( cap == 0 )
        buf->mem = NULL;
    else
        buf->mem = mem_alloc(cap);
    buf->consume_pos = buf->produce_pos = 0;
    buf->capacity = cap;
    return buf;
}

void net_buffer_clean( struct net_buffer* buf ) {
    if(buf->mem)
        free(buf->mem);
    buf->mem = NULL;
    buf->consume_pos = buf->produce_pos = buf->capacity = 0;
}

void* net_buffer_consume( struct net_buffer* buf , size_t* size ) {
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

void* net_buffer_peek( struct net_buffer*  buf , size_t* size ) {
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

void net_buffer_produce( struct net_buffer* buf , const void* data , size_t size ) {
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

static void* net_buffer_consume_peek( struct net_buffer* buf ) {
    if( buf->mem == NULL )
        return NULL;
    else {
        if( buf->consume_pos == buf->produce_pos )
            return NULL;
        else
            return cast(char*,buf->mem) + buf->consume_pos;
    }
}

static void net_buffer_consume_advance( struct net_buffer* buf , size_t size ) {
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

static void connection_cb( int ev , int ec , struct net_connection* conn ) {
    if( conn->cb != NULL ) {
        conn->pending_event = conn->cb(ev,ec,conn);
    }
}

static struct net_connection* connection_create( socket_t fd ) {
    struct net_connection* conn = mem_alloc(sizeof(struct net_connection));
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

static struct net_connection* connection_destroy( struct net_connection* conn ) {
    struct net_connection* ret = conn->prev;
    /* closing the underlying socket and this must be called at once */
    conn->prev->next = conn->next;
    conn->next->prev = conn->prev;
    net_buffer_clean(&(conn->in));
    net_buffer_clean(&(conn->out));
    free(conn);
    return ret;
}

static struct net_connection* connection_close( struct net_connection* conn ) {
    socket_t fd = conn->socket_fd;
    struct net_connection* ret = connection_destroy(conn);
    if( fd != invalid_socket_handler )
        closesocket(fd);
    return ret;
}

/* server */
int net_server_create( struct net_server* server, const char* addr , net_acb_func cb ) {
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
        nonblock_socket(server->listen_fd);
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
    nonblock_socket(server->ctrl_fd);
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

static void server_close_all_conns( struct net_server* server ) {
    struct net_connection* next = server->conns.next;
    struct net_connection* temp = NULL;
    while( next != &(server->conns) ) {
        temp = next->next;
        connection_close(temp);
        next = temp;
    }
}

void net_server_destroy( struct net_server* server ) {
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
        free(server->reserve_buffer);
#endif /* MULTI_SERVER_ENABLE */
}

int net_server_wakeup( struct net_server* server ) {
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

static void do_accept( struct net_server* server );
static void do_control( struct net_server* server );
static int do_write( struct net_connection* conn , int* error_code );
static int do_read( struct net_server* server , int* error_code , struct net_connection* conn );
static int do_connected( struct net_connection* conn , int* error_code );

#define ADD_FSET(fs,fd,mfd) \
    do { \
        FD_SET(fd,fs); \
        if( *(mfd) < fd ) { *(mfd) = fd; } \
    }while(0)

static int prepare_linger( struct net_connection* conn , fd_set* write , socket_t* max_fd ) {
    if( net_buffer_readable_size(&(conn->out)) ) {
        FD_SET(conn->socket_fd,write);
        if( *max_fd < conn->socket_fd )
            *max_fd = conn->socket_fd;
        return 0;
    }
    return -1;
}

static void prepare_fd( struct net_server* server , fd_set* read_set , fd_set* write_set , int* millis , socket_t* max_fd ) {
    struct net_connection* conn;
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
                !(conn->pending_event & NET_EV_CONNECT) &&
                !(conn->pending_event & NET_EV_CLOSE) );
            if( conn->pending_event & NET_EV_READ ) {
                ADD_FSET(read_set,conn->socket_fd,max_fd);
            }
            if( conn->pending_event & NET_EV_WRITE ) {
                ADD_FSET(write_set,conn->socket_fd,max_fd);
            }
        } else {
            if( conn->pending_event & NET_EV_LINGER ) {
                assert( !(conn->pending_event & NET_EV_CONNECT) &&
                    !(conn->pending_event & NET_EV_CLOSE) );
                if( prepare_linger(conn,write_set,max_fd) !=0 ) {
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

static int dispatch( struct net_server* server , fd_set* read_set , fd_set* write_set , int time_diff ) {
    struct net_connection* conn;
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
        if( (conn->pending_event & NET_EV_LINGER) && FD_ISSET(conn->socket_fd,write_set) ) {
            ec = 0;
            ret = do_write(conn,&ec);
            if( ret <= 0 ) {
                conn->pending_event = NET_EV_CLOSE;
            } else if( net_buffer_readable_size(&(conn->out)) == 0 ) {
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

static void reclaim_socket( struct net_server* server ) {
    struct net_connection* conn;
    /* reclaim all the socket that has marked it as CLOSE operation */
    for( conn = server->conns.next ; conn != &(server->conns) ; conn = conn->next ) {
        if( conn->pending_event & NET_EV_CLOSE ) {
            conn = connection_close(conn);
        } else if( conn->pending_event & NET_EV_REMOVE ) {
            conn = connection_destroy(conn);
        }
    }
}

int net_server_poll( struct net_server* server , int millis , int* wakeup ) {
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

static void do_accept( struct net_server* server ) {
    struct net_connection* conn;
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
            nonblock_socket(sock);
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

static int do_read( struct net_server* server , int* error_code , struct net_connection* conn ) {
    int rd = recv( conn->socket_fd , server->reserve_buffer , MAXIMUM_IPV4_PACKET_SIZE , 0 );
    if( rd <= 0 ) {
        *error_code = net_has_error();
        return rd;
    } else {
        net_buffer_produce( &(conn->in) , server->reserve_buffer , rd );
        return rd;
    }
}

static int do_write( struct net_connection* conn , int* error_code ) {
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

static void do_control( struct net_server* server ) {
    char buffer[SERVER_CONTROL_DATA_LENGTH];
    recvfrom(server->ctrl_fd,buffer,SERVER_CONTROL_DATA_LENGTH,0,NULL,NULL);
}

static int do_connected( struct net_connection* conn , int* error_code ) {
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

/* ==========================================
 * Timeout blocking version socket API 
 * =========================================*/

/* The following function serves as a advanced version for socket
 * API since it can be assigned with a timeout value to the underlying
 * socket operations. The resolution for these timers are seconds.
 * These functions will use select function to append the timeout 
 * attributes for each underlying operations. */

static
int connect_tm( socket_t fd , const char* addr , const struct timeval* tm ) {
    /* Using select to issue connect is something that make sense
     * since this make the socket much more robust since if an 
     * interruption happened, YOU CANNOT CALL connect again. Only
     * select can help you properly block on it and learn there
     * will be a sensible events gonna happen */
    struct sockaddr_in sock;
    int ret;
    FD_SET write;
    int val;
    size_t len;

    /* The address cannot be parsed into the sockaddr_in struct */
    if( str_to_sockaddr(addr,&sock) != 0 ) 
        return -1;

    if( tm == NULL ) {
        /* When we reach here, it means that we don't have to do anything
         * since the semantic underlying represents a BLOCK CONNECT */
        return connect(fd,cast(const struct sockaddr*,&sock),sizeof(sock));
    }

    ret = connect(fd,cast(const struct sockaddr*,&sock),sizeof(sock));

    /*
     * This should return at once since the fd is a non blocking
     * fd , and we put an assertion here to help user figure out
     * what they have messed up */
#ifdef _WIN32
    assert( ret == WSAEWOULDBLOCK || ret == 0 );
#else
    assert( ret == EINPROGRESSqa|| ret == 0 );
#endif /* _WIN32 */

    /* On some platform, the connect will succeed immdietaly 
     * so we need to handle situation that the ret is just zero */
    if( ret == 0 ) {
        return 0;
    }

    /* We push the connect fd into the write set, and by using
     * getsockopt SO_ERROR to figure out whether the connection
     * has been done or just failed */
    FD_ZERO(&write);
    FD_SET(fd,&write);

    do {
        ret = select(fd+1,NULL,&write,NULL,tm);
    } while( ret <0 && net_has_error() == 0 );

    if( ret <= 0 ) {
        /* Timeout or error happened , anyway we are not connected */
        return -1;
    }

    assert( ret == 1 && FD_ISSET(fd,&write) );

    /* We are not sure whether it is the ERROR that wake me up or the
     * successfully connection wakes me up. We will figure this out by
     * using getsockopt to get the pending error. */
    len = sizeof(int);
    getsockopt(fd,SOL_SOCKET,SO_ERROR,cast(char*,&val),&len);

    if( val !=0 ) {
        return -1;
    }

    return 0;
}

/* The following read/write function will assume that the fd 
 * is already a non blocking fd, so no non blocking/blocking
 * version fd switch will happen here. The net_timeout_read/write
 * is a wrapper around these 2 functions since it will modify
 * the blocking semantic for that socket and then modify it 
 * _BACK_ */

static
int read_tm( socket_t fd , void* data , size_t sz , const struct timeval* tm ) {
    FD_SET read;
    int ret;

    FD_ZERO(&read);
    FD_SET(fd,&read);

    do {
        ret = select(fd+1,&read,NULL,NULL,tm);
    } while( ret <0 && net_has_error() == 0 );

    if( ret <= 0 ) {
        return ret;
    } else {
        assert( ret == 1 && FD_ISSET(fd,&read) );
        return recv(fd,data,sz,0);
    }
}

static
int write_tm( socket_t fd , const void* data , size_t sz , const struct timeval* tm ) {
    FD_SET write;
    int ret;

    FD_ZERO(&write);
    FD_SET(fd,&write);

    do {
        ret = select(fd+1,NULL,&write,NULL,tm);
    } while( ret <0 && net_has_error() == 0 );

    if( ret <= 0 ) {
        return ret;
    } else {
        assert( ret == 1 && FD_ISSET(fd,&write) );
        return send(fd,data,sz,0);
    }
}

int net_timeout_read( socket_t fd , void* buf , size_t sz, int msec ) {
    int ret;
    struct timeval tv;
    tv.tv_sec = msec/1000;
    tv.tv_usec= (msec%1000)*1000;

    nonblock_socket(fd);
    ret = read_tm(fd,buf,sz,msec < 0 ? NULL : &tv);
    block_socket(fd);

    return ret;
}

int net_timeout_write( socket_t fd , const void* buf , size_t sz , int msec ) {
    int ret;
    struct timeval tv;
    tv.tv_sec = msec/1000;
    tv.tv_usec= (msec%1000)*1000;

    nonblock_socket(fd);
    ret = write_tm(fd,buf,sz, msec < 0 ? NULL : &tv);
    block_socket(fd);

    return ret;
}

/* client function */
socket_t net_block_client_connect( const char* addr , int msec ) {
    int ret;
    socket_t sock;
    struct timeval tv;

    tv.tv_sec = msec/1000;
    tv.tv_usec= (msec%1000)*1000;

    sock = socket(AF_INET,SOCK_STREAM,0);
    if( sock == invalid_socket_handler )
        return sock;

    reuse_socket(sock);
    
    if( msec >= 0 ) {
        /* Although this API expose blocking semantic but we simulate it
         * through non blocking version and this really make our life 
         * easier when we want to handle timeout */
        nonblock_socket(sock);
    }

    ret = connect_tm(sock,addr,msec < 0 ? NULL : &tv);

    if( msec >= 0 ) {
        /* set the socket back to blocking model */
        block_socket(sock);
    }

    if( ret != 0 ) {
        closesocket(sock);
        return invalid_socket_handler;
    }

    return sock;
}

int net_non_block_client_connect(struct net_server* server ,
                                 const char* addr ,
                                 net_ccb_func cb ,
                                 void* udata ,
                                 int timeout ) {
    struct net_connection* conn = connection_create(invalid_socket_handler);
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

int net_non_block_connect( struct net_connection* conn , const char* addr , int timeout ) {
    int ret;
    struct sockaddr_in ipv4;
    socket_t fd;
    if( str_to_sockaddr(addr,&ipv4) != 0 )
        return NET_EV_REMOVE;
    fd = socket(AF_INET,SOCK_STREAM,0);
    if( fd == invalid_socket_handler ) {
        return NET_EV_REMOVE;
    }
    nonblock_socket(fd);
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
struct net_connection* net_timer( struct net_server* server , net_ccb_func cb , void* udata , int timeout ) {
    struct net_connection* conn = connection_create(invalid_socket_handler);
    connection_add(server,conn);
    conn->cb = cb;
    conn->user_data = udata;
    conn->timeout = timeout;
    conn->pending_event = NET_EV_TIMEOUT;
    return conn;
}

struct net_connection* net_fd( struct net_server* server, net_ccb_func cb , void* data ,  socket_t fd , int pending_event ) {
    struct net_connection* conn = connection_create(fd);
    nonblock_socket(fd);
    exec_socket(fd);
    conn->cb = cb;
    conn->user_data = data;
    conn->pending_event = pending_event;
    return conn;
}

void net_stop( struct net_connection* conn ) {
    conn->pending_event = NET_EV_CLOSE;
}

void net_post( struct net_connection* conn , int ev ) {
    conn->pending_event = ev;
}

/* platform problem */
void net_init() {
#ifdef _WIN32
    WSADATA data;
    WSAStartup(MAKEWORD(2, 2), &data);
#endif /* _WIN32 */
    srand(cast(unsigned int,time(NULL)));
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
    case 2:
        dst[j] = '=';
        dst[j+1] = '=';
        j += 2;
        break;
    case 3:
        dst[j] = '=';
        ++j;
        break;
    default:
        break;
    }
    /* done */
    return j;
}

static
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
    unsigned char* sdst = dst;
    const unsigned char* usrc = cast(const unsigned char*,src);

    while( src_len >=4 && 
          (b1 = B64LOOKUP[usrc[0]]) != 255 &&
          (b2 = B64LOOKUP[usrc[1]]) != 255 &&
          (b3 = B64LOOKUP[usrc[2]]) != 255 && 
          (b4 = B64LOOKUP[usrc[3]]) != 255 ) {
        /* rule out the broken stream here */
        if( b1 == 254 || b2 == 254 ) 
            return -1; 

        *dst++ = b1 << 2 | b2 >> 4;
        --dst_len;
        if( dst_len == 0 )
            break;

        /* = */
        if (b3 == 254) break;
        *dst++ = b2 << 4 | b3 >> 2;
        --dst_len;
        if( dst_len == 0 )
            break;
        
        /* = */
        if (b4 == 254) break;

        *dst++ = b3 << 6 | b4;
        --dst_len;
        if( dst_len == 0 )
            break;
        
        src_len -= 4;
        usrc+=4;
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
static
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
static
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
static
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
static
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


#define WS_MAX_HOST_NAME 256
#define WS_MAX_DIR_NAME 256
#define WS_MAX_HTTP_ATTRIBUTE_LINE_NUMBER 31
#define WS_FAIL_TIMEOUT_CLOSE 1000
static const char* WS_KEY_COOKIE="258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
#define WS_CONCATE_KEY_LEN 52

/* This object is _SENT_ from client but it needs to parsed out by server */
struct ws_cli_handshake {
    char ws_key[16];
    char host[WS_MAX_HOST_NAME];
    char dir [WS_MAX_DIR_NAME];
    /* bits field for status information */
    unsigned char upgrade: 1;
    unsigned char connection: 1;
    unsigned char ws_version:1;
    unsigned char done:1;
    unsigned char line_num:4; /* the 4 bits is used for storing HTTP line number 
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
        (c)->done = 0 ; \
        (c)->line_num = 0; \
    } while(0)

/* 
 * Our parsing routine just trying find out the related field inside of the
 * header, once everything is collected, we are trying to find out the EOL,
 * If a EOF is found, the eof will be set to 1
 */

static
int http_readline( const char* c , size_t len , int* eof ) {
    /* read until \r\n is find out */
    size_t i = 0;
    const void* pos;
    *eof = 0;

    if( len == 0 )
        return -1;

    pos = memchr(c,'\n',len);
    if( pos == NULL )
        return -1;
    /* Checking the \r\n and \r\n\r\n pattern */
    if( *(cast(const char*,pos)-1) == '\r' ) {
        /* Checking if we meet the end of the header */
        if( cast(const char*,pos) - c + 2 <= cast(int,len) ) {
            const char* nc = cast(const char*,pos)+1;
            if( nc[0]== '\r' && nc[1] == '\n' )
                *eof = 1;
        }
        /* tell the caller that we have got at least one line */
        return cast(const char*,pos)-c+1;
    } else {
        return -1;
    }
}

/* WebSocket server side HTTP part operation */
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
    WS_UNKNOWN_REQUEST_HEADER = -11,
    WS_HANDSHAKE_FAIL = -12
};

/* Parsing the very first line of HTTP header */
static
int http_skip( const char* data , int c ) {
    int i = 0;
    for( ; data[i] == c ; ++i );
    return i;
}

static
int ws_cli_handshake_check_first_line( const char* data , char* dir ) {
    int start,end;
    const char* c;
    /* We cannot use sscanf here since the URI is unknown size and may be
     * causing overflow into the buffer. Therefore, a better way to handle
     * it is to do it manually by our hand. */

    /* 1. Parsing METHOD and it must be GET */
    if( data[0] != 'G' || data[1] != 'E' || data[2] != 'T' || data[3] != ' ' )
        return WS_UNKNOWN_METHOD;

    /* 2. Parsing the URI */
    data += 3;
    start = http_skip(data,' ');
    c = strchr(data+start,' ');
    if( c == NULL )
        return WS_UNKNOWN_REQUEST_HEADER;
    end = c-data;
    if( end-start >= WS_MAX_DIR_NAME )
        return WS_TOO_LARGE_URI;
    memcpy(dir,data+start,end-start);
    dir[end-start]=0;
    data = c;

    /* 3. Parsing HTTP */
    data += http_skip(data,' ');
    if( data[0] != 'H' || data[1] != 'T' || data[2] != 'T' && data[3] !='P' && data[4] != '/' )
        return WS_UNKNOWN_REQUEST_HEADER;
    data +=5;

    if( data[0] != '1' || data[1] != '.' || data[2] != '1' )
        return WS_NOT_SUPPORT_HTTP_VERSION;

    return 0;
}

/* We politely skip the whitespace although RFC doesn't show any evidence 
 * to allow such behavior */
static int http_strcmp( const char* lhs , const char* rhs ) {
    lhs += http_skip(lhs,' ');
    return strcmp( lhs ,rhs );
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
int ws_cli_handshake_parse( const char* data , size_t len , struct ws_cli_handshake* hs ) {
    const char* s = data;
    int eof;
    int ret;
    int num;

    do {
        num = http_readline(data,len,&eof);
        if (num == -1) {
            return data-s;
        } else if( num == 2 ) {
            /* EOF with a single line only contains \r\n */
            break;
        }
        cast(char*,data)[num-2] = 0;
        /* we have at least one line data now */
        if ( hs->line_num == 0 ) {
            /* do a small modification here */
            ret = ws_cli_handshake_check_first_line(data,hs->dir);
            if( ret != 0 )
                goto fail;
        } else {
            const char* semicon;
            semicon = strchr(data,':');
            if( semicon == NULL ) {
                ret = WS_UNKNOWN_REQUEST_HEADER;
                goto fail;
            }
            *cast(char*,semicon) = 0;

            if( strccamp(data,"Upgrade") == 0 ) {
                if( hs->upgrade || http_strcmp(semicon+1,"websocket") != 0 ) {

                    ret = WS_UNKNOWN_UPGRADE_VALUE;
                    *cast(char*,semicon) = ':';
                    goto fail;
                }
                hs->upgrade = 1;
                goto again;
            } else if ( strccamp(data,"Connection") == 0 ) {
                if( hs->connection || http_strcmp(semicon+1,"Upgrade") != 0 ) {

                    ret = WS_UNKNOWN_CONNECTION_VALUE;
                    *cast(char*,semicon) = ':';
                    goto fail;
                }
                hs->connection = 1;
                goto again;
            } else if( strccamp(data,"Sec-WebSocket-Version") == 0 ) {
                if( hs->ws_version || http_strcmp(semicon+1,"13") != 0 ) {

                    ret = WS_UNKNOWN_WS_VERSION;
                    *cast(char*,semicon) = ':';
                    goto fail;
                }
                hs->ws_version = 1;
                goto again;
            } else if( strccamp(data,"Sec-WebSocket-Key") == 0 ) {
                int i = 1;

                if( hs->ws_key[0] ) {
                    ret = WS_UNKNOWN_WS_KEY;
                    *cast(char*,semicon) = ':';
                    goto fail;
                }
                i = http_skip(semicon+1,' ')+1;
                /* now we can copy the key into the buffer now */
                if( strlen(semicon+i) < 24 ){
                    ret = WS_UNKNOWN_WS_KEY;
                    *cast(char*,semicon) = ':';
                    goto fail;
                }
                b64_decode(semicon+i,24,hs->ws_key,16);
                goto again;
            } else if( strccamp(data,"Host") == 0 ) {
                int i = 1;
                if( hs->host[0] ){
                    ret = WS_UNKNOWN_HOST;
                    *cast(char*,semicon) = ':';
                    goto fail;
                }
                i = http_skip(semicon+1,' ')+1;
                /* too large host name */
                if( strlen(semicon+i) >= WS_MAX_HOST_NAME ){
                    ret = WS_TOO_LARGE_HOST;
                    *cast(char*,semicon) = ':';
                    goto fail;
                }
                strcpy(hs->host,semicon+i);
                goto again;
            } else {
                /* skip all the other header , pay attention, we skip the ORIGIN
                 * header attribute since we don't do any security check here */
                goto loop;
            }
again:      /* for quick skip the next if-else chain and also recover the string */
            *cast(char*,semicon) = ':';
        }
loop:   /* move to next line */
        cast(char*,data)[num-2] = '\r';
        data += num;
        len -= num;
        ++hs->line_num;
        if( hs->line_num == WS_MAX_HTTP_ATTRIBUTE_LINE_NUMBER ) {
            ret = WS_TOO_LARGE_HTTP_HEADER;
            goto fail;
        }
    } while( !eof );

    /* checking the EOF */
    if( hs->upgrade && hs->connection && hs->ws_version && hs->ws_key[0] && hs->host[0] ) {
        hs->done = 1;
        return 0;
    } else {
        return WS_UNKNOWN_REQUEST_HEADER;
    }
    
fail: /* done */
    cast(char*,data)[num-2] = '\r';
    return ret;
}

/* Generate WebSocket reply for successful upgrade */
static
size_t ws_handshake_ser_reply( const char ws_key[16] , char ret[1024] ) {
    static const char WS_FORMAT[] = \
        "HTTP/1.1 101 Switching Protocols\r\n" \
        "Upgrade:websocket\r\n" \
        "Connection:Upgrade\r\n" \
        "Sec-WebSocket-Accept:";

    static const size_t WS_FORMAT_LEN = sizeof(WS_FORMAT)-1;

    char buf[128];
    SHA1_CTX shal_ctx;
    uint8_t digest[SHA1_DIGEST_SIZE];
    size_t len;

    memcpy(buf,ws_key,16);
    strcpy(buf+16,WS_KEY_COOKIE);

    /* shal1 these key */
    SHA1_Init(&shal_ctx);
    SHA1_Update(&shal_ctx,cast(const uint8_t*,buf),WS_CONCATE_KEY_LEN);
    SHA1_Final(&shal_ctx,digest);

    /* encode it into base64 */
    len = b64_encode(cast(const char*,digest),SHA1_DIGEST_SIZE,buf);
    assert( len + WS_FORMAT_LEN + 4 < 1024 );

    /* now write to the output buffer */
    memcpy(ret,WS_FORMAT,WS_FORMAT_LEN);
    memcpy(ret+WS_FORMAT_LEN,buf,len);

    ret[WS_FORMAT_LEN+len]= '\r';
    ret[WS_FORMAT_LEN+len+1]= '\n';
    ret[WS_FORMAT_LEN+len+2]= '\r';
    ret[WS_FORMAT_LEN+len+3]= '\n';

    return len + 4 + WS_FORMAT_LEN;
}

static
void ws_handshake_generate_key( char b64_buf[25] , char key[16] ) {
    int i;
    for( i = 0 ; i < 16 ; ++i ) {
        key[i] = 1;
    }
    b64_encode(key,16,b64_buf);
    b64_buf[24] = 0;
}

static
size_t ws_handshake_cli_request( char rand_key[16] ,  const char* path , const char* host , char ret[1024] ) {
    static const char WS_FORMAT[]= \
        "GET %s HTTP/1.1\r\n" \
        "Upgrade:websocket\r\n" \
        "Connection:Upgrade\r\n" \
        "Sec-WebSocket-Version:13\r\n" \
        "Host:%s\r\n"\
        "Sec-WebSocket-Key:%s\r\n\r\n";
    static const size_t WS_FORMAT_LEN = sizeof(WS_FORMAT)-1;

    char b64_buf[25];
    int sz;

    assert( strlen(host) < WS_MAX_HOST_NAME || strlen(path) < WS_MAX_DIR_NAME );

    ws_handshake_generate_key(b64_buf,rand_key);
    sz = sprintf(ret,WS_FORMAT,path,host,b64_buf);

    assert( sz > 0 );
    return cast(size_t,sz);
}

/* Server side handshake object */
#define WS_SEC_KEY_LENGTH 28

struct ws_ser_handshake {
    char key[SHA1_DIGEST_SIZE]; /* A 20 bytes SHA1 code */
    unsigned char upgrade : 1;
    unsigned char connection : 1;
    unsigned char done: 1;
    unsigned char line_num : 5;
};

#define INITIALIZE_WS_SER_HANDSHAKE(hs) \
    do { \
        (hs)->key[0] = 0; \
        (hs)->connection = 0; \
        (hs)->line_num = 0; \
        (hs)->done = 0; \
    } while(0)

static int ws_ser_handshake_check_first_line( const char* data ) {
    /* 1. Checking HTTP header line */
    if( data[0] != 'H' || data[1] != 'T' || data[2] != 'T' ||
        data[3] != 'P' || data[4] != '/' || data[5] != '1' ||
        data[6] != '.' || data[7] != '1' )
        return WS_NOT_SUPPORT_HTTP_VERSION;

    /* 2. Checking status code */
    data += 8;
    data += http_skip( data , ' ' );
    if( data[0] != '1' || data[1] != '0' || data[2] != '1' )
        return WS_HANDSHAKE_FAIL;

    return 0;
}

static
int ws_ser_handshake_parse( const char* data , size_t len , struct ws_ser_handshake* hs ) {
    int eof;
    int ret;
    int num;
    const char* s = data;

    do {
        num = http_readline(data,len,&eof);
        if( num < 0 ) {
            return data-s;
        } else if( num == 2 ) {
            /* EOF with a single line only contains \r\n */
            break;
        }
        cast(char*,data)[num-2] = 0;

        if( hs->line_num == 0 ) {
            /* read the first status line */
            ret = ws_ser_handshake_check_first_line(data);
            if( ret < 0 ) {
                goto fail;
            }
            goto loop;
        } else {
            const char* semicon = strchr(data,':');
            if( semicon == NULL ) {
                ret = WS_TOO_LARGE_HTTP_HEADER;
                goto fail;
            }
            *cast(char*,semicon) = 0;

            if( strccamp(data,"Upgrade") == 0 ) {
                if( hs->upgrade || http_strcmp(semicon+1,"websocket") != 0 ) {
                    ret = WS_UNKNOWN_UPGRADE_VALUE;
                    *cast(char*,semicon) = ':';
                    goto fail;
                }
                hs->upgrade = 1;
                goto again;
            } else if( strccamp(data,"Connection") == 0 ) {
                if( hs->connection || http_strcmp(semicon+1,"Upgrade") != 0 ) {
                    ret = WS_UNKNOWN_CONNECTION_VALUE;
                    *cast(char*,semicon) = ':';
                    goto fail;
                }
                hs->connection = 1;
                goto again;
            } else if( !hs->key[0] && strccamp(data,"Sec-WebSocket-Accept") == 0 ) {
                /* copy the key into the buffer */
                int start = 1 + http_skip(semicon+1,' ');
                /* copy the next 28 bytes into the buffer but we _MUST_ ensure that
                 * we have such data in the buffer */
                if( num-1-start < 28 ) {
                    ret = WS_UNKNOWN_WS_KEY;
                    *cast(char*,semicon) = ':';
                    goto fail;
                }
                b64_decode(semicon+start,28,hs->key,20);
                goto again;
            } else {
                /* skip the unknown attribute in HTTP request */
                goto again;
            }
again:     
            *cast(char*,semicon) = ':';
        }
loop:
        cast(char*,data)[num-2] = '\r';
        data += num;
        ++hs->line_num;
        len -= num;
        if( hs->line_num > WS_MAX_HTTP_ATTRIBUTE_LINE_NUMBER ) {
            ret = WS_TOO_LARGE_HTTP_HEADER;
            goto fail;
        }
    } while( !eof );

    /* checking EOF */
    if( hs->connection && hs->upgrade && hs->key[0] ) {
        hs->done = 1;
        return 0;
    } else { 
        return WS_UNKNOWN_REQUEST_HEADER;
    }

fail:
    cast(char*,data)[num-2] = '\r';
    return ret;
}

static
const char* WS_HS_FAIL_REPLY="HTTP/1.1 400 Bad request\r\n\r\n";

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

struct ws_frame {
    unsigned char op :4;
    unsigned char fin:1;
    unsigned char has_mask:1;
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
        (fr)->data = NULL; \
    } while(0)

#define DESTROY_WS_FRAME(fr) \
    do { \
        if( (fr)->data != NULL ) { \
            free( (fr)->data ); \
            (fr)->data = NULL; \
        } \
        (fr)->state = WS_FP_FIRST_BYTE; \
    } while(0)

#define REINITIALIZE_WS_FRAME(fr) \
    do { \
        DESTROY_WS_FRAME(fr); \
        INITIALIZE_WS_FRAME(fr); \
    } while(0)

/* this ws frame parser is a stream parser, feed it as small as 1 byte
 * will also produce valid result and not hurt any other one */
static 
int ws_frame_parse( void * d , size_t len , struct ws_frame* fr ) {
    const char* s = d;
    const unsigned char* data = d;
    unsigned char byte;
    size_t l;

    assert(len >0);

    do {
        switch(fr->state) {
        case WS_FP_FIRST_BYTE:
            byte = *data;
            fr->fin = byte & 1; /* fin */

            byte >>=1;
            if( (byte & 248) & 7 )
                return WS_FP_ERR_RESERVE_BIT; /* the reserve bit _MUST_ be zero */

            byte >>=3;
            fr->op = byte; /* get the op */

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
            fr->has_mask = byte & 1;
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
                fr->data = mem_alloc( cast(size_t,fr->data_len) );
                fr->data_sz = 0;
                if( fr->has_mask )
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
            fr->data = mem_alloc(cast(size_t,fr->data_len));

            if( fr->has_mask )
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

            fr->data = mem_alloc( cast(size_t,fr->data_len) );
            
            if( fr->has_mask )
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

            if( len == 0 )
                return data-s;

            break;
        case WS_FP_PAYLOAD:
            /* Quick check the data length is zero, this is possible for control package */
            if( fr->data_len == 0 ) {
                fr->data = NULL;
                fr->data_sz = 0;
                fr->state = WS_FP_DONE;
                return data-s;
            }
            /* it is possible that 2 frames reached tail followed by another head
             * We should not touch the data that is belonged to the second packets */
            l = MIN(len,cast(size_t,fr->data_len) - fr->data_sz);
            memcpy( cast(char*,fr->data) + fr->data_sz , data , l );

            data += l;
            len -= l;

            fr->data_sz += l;
            if( fr->data_sz == fr->data_len ) {
                fr->state = WS_FP_DONE;
                /* unmask the data at last if there is a mask presents */
                if( fr->has_mask ) {
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

enum {
    WS_FR_NORMAL,
    WS_FR_FRAG_INIT,
    WS_FR_FRAG_PACKET,
    WS_FR_FRAG_TERM,
};
static
void* ws_frame_make( void* data , size_t* len , int mask , int frame_type , int frag ) {
    /* encode a chunk of data into a web socket frame */
    size_t frame_sz = 2 + (mask ? 4 : 0) + *len;
    char payload_val;
    char m[4];
    char* ret;
    char* pos;

    /* checking the frame_type value is correct or not */
    assert( frame_type > 0 && frame_type < SIZE_OF_WS_FRAME_TYPE );

    if( *len < 126 ) {
        payload_val = *len;
    } else if( *len >= 126 && *len <= USHRT_MAX ) {
        payload_val = 126;
        frame_sz += 2;
    } else {
        payload_val = 127;
        frame_sz += 8;
    }

    pos = (ret = mem_alloc(frame_sz));

    switch( frag ) {
    case WS_FR_FRAG_INIT: /* start fragmentation */
        pos[0] = 0 | (frame_type<<4);
        break;
    case WS_FR_FRAG_PACKET:
        pos[0] = 0;
        break;
    case WS_FR_FRAG_TERM:
        pos[0] = 1 ;
        break;
    case WS_FR_NORMAL:
        pos[0] = 1 | (frame_type<<4);
        break;
    default: assert(0);
    }

    pos[1] = (payload_val << 1) | ((mask ? 1:0));
    pos += 2;

    /* payload length */
    if( payload_val == 126 ) {
        *cast(unsigned short*,pos) = htons(cast(unsigned short,*len));
        pos += 2;
    } else if( payload_val == 127 ) {
        *cast(uint64_t*,pos) = htonll(cast(uint64_t,len));
        pos += 8;
    }
    /* mask if we need to */
    if( mask ) {

        m[0] = (pos[0] = rand() % 256);
        srand(pos[0]);
        m[1] = (pos[1] = rand() % 256);
        srand(pos[1]);
        m[2] = (pos[2] = rand() % 256);
        srand(pos[2]);
        m[3] = (pos[3] = rand() % 256);
        srand(pos[3]);
        pos += 4;
    }

    if( mask ) {
        size_t i ;
        /* mask the content in the frame.
         * Using vector to optimize it ? */
        for( i = 0 ; i < *len ; ++i ) {
            pos[i] = cast(char*,data)[i] ^ m[i%4];
        }
    } else {
        if( data != NULL )
            memcpy(pos,data,*len);
    }

    *len = frame_sz;
    return ret;
}

/* This specific helper function is used to form the close frame which needs to be used
 * in 1) Normal close ( Active issued or passive issued ) 2) Abortion ( When a connected
 * connection detects error , no matter it is protocol or the content is too large */

enum {
    WS_CLOSE_NORMAL = 1000 , 
    WS_CLOSE_PROTO_ERROR = 1002 ,
    WS_CLOSE_PROTO_NOT_SUPPORT = 1003 ,
    WS_CLOSE_GENERAL_ERROR = 1008 ,
    WS_CLOSE_PROTO_DATA_TOO_LARGE = 1009
};

static
void* ws_close_frame_make( int server , int error_code , size_t* len ) {
    uint16_t val = htons( cast(uint16_t,error_code) );
    *len = sizeof(val);
    /* Based on the RFC, it says the close frame MAY contain
     * a reason phrase in UTF-8 encoding , here we just do not
     * contain these phrase to save some bandwitdh */
    return ws_frame_make(&val,len,server ?0:1,WS_CLOSE,WS_FR_NORMAL);
}

/* Web socket connection */

enum {
    WS_HANDSHAKE_RECV,
    WS_HANDSHAKE_SEND,
    WS_OPEN,
    WS_WANT_FRAG,
    WS_ACTIVE_CLOSE_SEND,
    WS_ACTIVE_CLOSE_RECV,
    WS_CLOSED   /* this socket has been SHUTDOWN */
};

/* Web socket server connection */
struct net_ws_ser_conn {
    struct ws_cli_handshake ws_hs;
    struct ws_frame ws_frame;

    void* pending_data;
    size_t pending_data_sz;

    unsigned int ws_state : 30;
    unsigned int ws_ping_send : 1;
    unsigned int ws_in_frag: 1;

    net_ws_callback cb;
    void* user_data;
    struct net_connection* trans;
};

/* Web socket client connection */
struct net_ws_cli_conn {
    struct ws_ser_handshake ws_hs;
    struct ws_frame ws_frame;

    char rand_key[16];

    void* pending_data;
    size_t pending_data_sz;

    unsigned int ws_state : 30;
    unsigned int ws_ping_send : 1;
    unsigned int ws_in_frag: 1;

    net_ws_callback cb;
    void* user_data;
    struct net_connection* trans;
};

enum {
    WS_SERVER,
    WS_CLIENT
};

struct net_ws_conn {
    unsigned int type :31;
    unsigned int detached : 1; /* When this flag is on, the user is entirely treat the underlying
                                * websocket has been closed. This is needed since we _NEED_ to send
                                * the close frame and put the websocket into valid status */
    int timeout;
    union {
        struct net_ws_ser_conn* server;
        struct net_ws_cli_conn* client;
    } ptr;
};

static
void net_ws_destroy( struct net_ws_conn* conn ) {
    if( conn->type == WS_SERVER ) {
        struct net_ws_ser_conn* ser = conn->ptr.server;
        DESTROY_WS_FRAME( &(ser->ws_frame) );
        if( ser->pending_data != NULL )
            free(ser->pending_data);
    } else {
        struct net_ws_cli_conn* cli = conn->ptr.client;
        DESTROY_WS_FRAME( &(cli->ws_frame) );
        if( cli->pending_data != NULL )
            free(cli->pending_data);
    }
    free(conn);
}

static
int ws_ser_conn_callback( int ev , int ec , struct net_connection* conn );

static
int ws_cli_conn_callback( int ev , int ec , struct net_connection* conn );

static
int ws_abort( struct net_connection* conn , struct net_ws_conn* ws_conn , int error_code ) {
    /* Abortion means that the peer side has sent something that we don't 
     * understand, so we send back a close frame (Recommended by RFC) and
     * then _Fail the connection_ . */
    size_t close_seg_sz;
    void* close_seg = ws_close_frame_make( ws_conn->type == WS_SERVER ? 1 : 0 , error_code , &close_seg_sz );
    net_buffer_produce(&(conn->out),close_seg,close_seg_sz);
    net_ws_destroy(ws_conn);
    free(close_seg);
    conn->user_data = NULL;
    return NET_EV_LINGER;
}

static
int ws_passive_close( struct net_connection* conn , int server , int error_code ) {
    /* When we receive a CLOSE message, we need to send a CLOSE message 
     * back and silently CLOSE the TCP connection. This job doesn't need
     * users involvement */

    void* close_seg;
    size_t close_seg_sz;
    close_seg = ws_close_frame_make(server,WS_CLOSE_NORMAL,&close_seg_sz);
    net_buffer_produce(&(conn->out),close_seg,close_seg_sz);
    free(close_seg);

    /*
     * Recommended by RFC, server side should initialize the TCP closing
     * to put itself into TIME_WAIT. 
     */

    if( server ) {
        return NET_EV_LINGER;
    } else {
        conn->timeout = WS_FAIL_TIMEOUT_CLOSE;
        return NET_EV_LINGER | NET_EV_TIMEOUT;
    }
}

/* This function will _PUT_ the ws_conntion into the WS_ACTIVE_CLOSE_SEND status, and waiting
 * for the close reply fragment from the peer side. Once the callback function notified,
 * then the ws_close_finish should be called to _FINISH_ the close transaction */

static
int ws_active_close_init( struct net_ws_conn* ws_conn , struct net_connection* conn ) {
    int server = ws_conn->type == WS_SERVER ? 1 : 0;
    size_t close_seg_sz;
    void* close_seg = ws_close_frame_make( server , WS_CLOSE_NORMAL , &close_seg_sz );
    net_buffer_produce(&(conn->out),close_seg,close_seg_sz);
    free(close_seg);
    if( server ) {
        ws_conn->ptr.server->ws_state = WS_ACTIVE_CLOSE_SEND;
    } else {
        ws_conn->ptr.client->ws_state = WS_ACTIVE_CLOSE_SEND;
    }
    ws_conn->detached = 1;
    return NET_EV_WRITE;
}

static
int ws_close_finish( struct net_ws_conn* ws_conn , struct net_connection* conn , struct ws_frame* fr ) {
    int server = ws_conn->type == WS_SERVER ? 1 : 0;
    int ret;
    int close_code;
    if( fr->data_len != 0 )
        close_code = ntohs(*cast(uint16_t*,fr->data));
    else
        close_code = WS_CLOSE_NORMAL;

    /* Checking the status code here */
    if( server ) {
        switch( ws_conn->ptr.server->ws_state ) {
        case WS_ACTIVE_CLOSE_RECV:
            net_ws_destroy(ws_conn);
            return NET_EV_CLOSE;
        case WS_OPEN:
            ret = ws_passive_close(conn,1,WS_CLOSE_NORMAL);

            if( close_code != WS_CLOSE_NORMAL )
                ws_conn->ptr.server->cb(NET_EV_WS_ABORT,0,ws_conn);
            else
                ws_conn->ptr.server->cb(NET_EV_EOF,0,ws_conn);

            net_ws_destroy(ws_conn);
            return ret;

        case WS_WANT_FRAG:
            ret = ws_passive_close(conn,1,WS_CLOSE_PROTO_ERROR);
            ws_conn->ptr.server->cb( NET_EV_ERR_READ , 0 , ws_conn );
            net_ws_destroy(ws_conn);
            return NET_EV_CLOSE;

        default:
            net_ws_destroy(ws_conn);
            /* unexceptional status comes here */
            return NET_EV_CLOSE;
        }
    } else {
        switch( ws_conn->ptr.client->ws_state ) {
        case WS_ACTIVE_CLOSE_RECV:
            net_ws_destroy(ws_conn);
            /* For a client, we cannot issue close directly, by RFC , it wants
             * server entering TIME_WAIT , so we need to issue a timeout close */
            conn->timeout = WS_FAIL_TIMEOUT_CLOSE;
            return NET_EV_CLOSE | NET_EV_TIMEOUT;
        case WS_OPEN:
            ret = ws_passive_close(conn,1,WS_CLOSE_NORMAL);

            if( close_code != WS_CLOSE_NORMAL )
                ws_conn->ptr.client->cb(NET_EV_WS_ABORT,0,ws_conn);
            else
                ws_conn->ptr.client->cb(NET_EV_EOF,0,ws_conn);

            return NET_EV_CLOSE;
        case WS_WANT_FRAG:
            ret = ws_passive_close(conn,0,WS_CLOSE_PROTO_ERROR);
            ws_conn->ptr.client->cb( NET_EV_ERR_READ , 0 , ws_conn );
            net_ws_destroy(ws_conn);
            return NET_EV_CLOSE;

        default:
            net_ws_destroy(ws_conn);
            return NET_EV_CLOSE;
        }
    }
}

static
int ws_conn_pending_event( int ev , struct net_ws_conn* ws_conn , struct net_connection* conn ) {

    /* Here we need to handle the CLOSE intention initialized by the
     * user side. The user could initialize close intention by :
     * NET_EV_CLOSE , NET_EV_LINGER_SILENT .
     * For NET_EV_CLOSE, we just need to issue a CLOSE package and
     * then linger it silently; however for NET_EV_LINGER_SILENT, 
     * we need to insert one more frame as close frame on the network */
    
    if( ev & NET_EV_CLOSE ) {
        /* This means the user want to issue an active close here */
        return ws_active_close_init(ws_conn,conn);

    } else if(  ev & NET_EV_LINGER ) {
        /*
         * The linger event is a little bit tricky to simulate, we need to
         * insert a close frame after user's send buffer and also need to 
         * reserve the user's semantic regarding NET_EV_LINTER, like timeout.
         */

        /* 1. Append a close frame after user's callback function */
        void* close_seg;
        size_t close_seg_sz = 0;
        close_seg = ws_close_frame_make( ws_conn->type == WS_SERVER ? 1 : 0 , WS_CLOSE_NORMAL , &close_seg_sz );
        net_buffer_produce(&(conn->out),close_seg,close_seg_sz);
        free(close_seg);

        /* 2. Setting the status to the WS_ACTIVE_CLOSE_SEND */
        if( ws_conn->type == WS_SERVER )
            ws_conn->ptr.server->ws_state = WS_ACTIVE_CLOSE_SEND;
        else
            ws_conn->ptr.client->ws_state = WS_ACTIVE_CLOSE_SEND;

        /* 3. We reserve the timeout semantic here , but _ANY_ timeout that is
         * handled by us will directly return NET_EV_CLOSE to fail the connection */

        ws_conn->detached = 1;
        conn->timeout = ws_conn->timeout;
        return NET_EV_WRITE | NET_EV_TIMEOUT;
    } else {
        /* For all the other operations , just forward the timeout and event */
        conn->timeout = ws_conn->timeout;
        return ev;
    }
}

static
int ws_ser_handle_handshake( struct net_ws_conn* ws_conn , struct net_connection* conn ) {
    void* data;
    size_t len = net_buffer_readable_size(&(conn->in));
    struct net_ws_ser_conn* c = ws_conn->ptr.server;
    int ret;

    data = net_buffer_peek(&(conn->in),&len);
    ret = ws_cli_handshake_parse(cast(const char*,data),len,&(c->ws_hs));

    if( ret < 0 ) {
        /* This part is part of HTTP transaction, although RFC doesn't directly
         * mention how to handle the failure in the handshake, a typical error
         * reply in HTTP transaction will be fine here and also we close this
         * connection directly without timeout defined by RFC */

        /* sending the failed reply */
        net_buffer_produce(&(conn->out),WS_HS_FAIL_REPLY,strlen(WS_HS_FAIL_REPLY));
        /* avoid the return value */
        c->cb( NET_EV_ERR_CONNECT , -1 , ws_conn );
        /* destroy the web socket connection */
        net_ws_destroy(ws_conn);
        /* fail the connection */
        return NET_EV_LINGER;

    } else if( ret == 0 ) {
        if( c->ws_hs.done ) {
            char reply[1024];
            size_t size = ws_handshake_ser_reply(c->ws_hs.ws_key,reply);
            /* handshake done , we just need to send the reply */
            net_buffer_produce(&(conn->out),reply,size);
            /* consume the data now */
            len = net_buffer_readable_size(&(conn->in));
            net_buffer_consume(&(conn->in),&len);
            /* moving the state of this web socket */
            c->ws_state = WS_HANDSHAKE_SEND;
            return NET_EV_WRITE;
        } else {
            return NET_EV_READ;
        }
    } else {
        /* pending */
        len = cast(size_t,ret);
        net_buffer_consume(&(conn->in),&len);
        return NET_EV_READ;
    }
}


static
int ws_do_frag( struct ws_frame* fr , int* state ) {
    if( *state == WS_OPEN ) {
        /* we are not in fragmentation states, so we can ACCEPT a fragmentation */
        if( !fr->fin ) {
            *state = WS_WANT_FRAG;
        }
        return 0;
    } else if( *state == WS_WANT_FRAG ) {
        if( fr->fin ) {
            if( fr->op == 0 ) {
                /* last segment */
                *state = WS_OPEN;
            } else {
                return -1;
            }
        } else {
            if( fr->op != 0 ) {
                return -1;
            }
        }
        return 0;
    } else {
        assert(0);
        return -1;
    }
}

static
int ws_do_pingpong( struct ws_frame* fr , struct net_connection* conn , int* send_ping , int* pev ) {
    char* pong_msg;
    size_t pong_msg_sz = 0;
    /* Handle the ping-pong message here */
    switch(fr->op) {
    case WS_PING:
        pong_msg = ws_frame_make(NULL,&pong_msg_sz,0,WS_PONG,WS_FR_NORMAL);
        net_buffer_produce(&(conn->out),pong_msg,pong_msg_sz);
        free(pong_msg);
        *pev |= NET_EV_WRITE;
        /* A ping message MAY carry data, so we cannot return here,
        * we need to let the reset of the code to check whether we
        * have and pending data or not */
        return 0;
    case WS_PONG:
        if( *send_ping ) {
            /* PONG message will not have any data , so just silently
                * ignore it and move on */
            *send_ping = 0;
            /* Destroy this PONG message even if it carries data */
            REINITIALIZE_WS_FRAME(fr);
            return 0;
        } else {
            /* Error here, we need to close this connection */
            return -1;
        }
    default:assert(0); return -1;
    }
}

static
int ws_ser_do_read( struct net_ws_conn* ws_conn , struct net_connection* conn , int ev ) {
    struct net_ws_ser_conn* s = ws_conn->ptr.server;
    size_t len = net_buffer_readable_size(&(conn->in));
    void* data = net_buffer_peek(&(conn->in),&len);
    int ret = ws_frame_parse(cast(const char*,data),len,&(s->ws_frame));
    int ret_ev = 0;
    int state;
    size_t pong_msg_sz = 0;
    int send_ping = s->ws_ping_send;

    if( ret < 0 ) {
        /* This means a frame error happened */
        goto fail;
    } else {
        if( s->ws_frame.state == WS_FP_DONE ) {
            switch(s->ws_frame.op) {
            case WS_PING:
            case WS_PONG:
                if( ws_do_pingpong(&(s->ws_frame),conn,&send_ping,&ret_ev) != 0 )
                    goto fail;
            case WS_BINARY:
                break;

            case WS_CLOSE:
                /* Handling the close event INITIALIZED by the peer side */
                return ws_close_finish(ws_conn,conn,&(s->ws_frame));
            default:
                goto fail;
            }

            /* checking the frame is OK or not */
            if( s->ws_frame.has_mask == 0 ) {
                /* a client sent message _MUST_ have mask , so this means we fail
                 * the protocol here. Just close the connection and return here */
                goto fail;
            } 
            state = s->ws_state;
            /* checking the fragmentation status */
            if( ws_do_frag(&(s->ws_frame),&state) != 0 ) {
                goto fail;
            }
            s->ws_state = state;

            /* moving the data into the pending buffer and clear the WS_FRAME object */
            s->pending_data = s->ws_frame.data;
            s->pending_data_sz = s->ws_frame.data_sz;
            /* reuse the ws_frame object */
            INITIALIZE_WS_FRAME(&(s->ws_frame));

            /* call user's callback function */
            ret_ev |= ws_conn_pending_event(
                s->cb( NET_EV_READ | ev , 0 , ws_conn ),ws_conn,conn);
        }
        len = cast(size_t,ret);
        net_buffer_consume(&(conn->in),&len);
        return ret_ev;
    }
fail:
    /* Destroy the frame if we need to */
    s->cb( NET_EV_ERR_READ | ev , -1 , ws_conn );
    return ws_abort(conn,ws_conn,WS_CLOSE_PROTO_ERROR);
}

static
int ws_ser_conn_callback( int ev , int ec , struct net_connection* conn ) {
    struct net_ws_conn* ws_conn = cast( struct net_ws_conn* , conn->user_data );
    struct net_ws_ser_conn* s = ws_conn->ptr.server;

    assert(ws_conn->type == WS_SERVER);
    if( ec != 0 ) {
        if( !ws_conn->detached )
            s->cb( ev , ec , ws_conn );
        net_ws_destroy(ws_conn);
        return NET_EV_CLOSE;
    } else {
        int rw_ev = 0;

        if( ev & NET_EV_EOF ) {
            return ws_conn_pending_event(s->cb( ev , ec , ws_conn ),ws_conn,conn);
        }

        /* write */
        if( ev & NET_EV_WRITE ) {
            /* handle write */
            switch(s->ws_state) {
            case WS_HANDSHAKE_SEND:
                s->ws_state = WS_OPEN;
                /* Finish the handshake and calling the user's callback function */
                return ws_conn_pending_event(
                    s->cb(NET_EV_CONNECT,0,ws_conn),ws_conn,conn);
            case WS_OPEN:
            case WS_WANT_FRAG:
                /* We don't call user's callback here, because we multiplex read/write
                 * into one single callback function, we delay this function call until
                 * we finish the read operation */
                rw_ev |= NET_EV_WRITE;
                if( !(ev & NET_EV_READ) ) {
                    return ws_conn_pending_event(
                        s->cb( NET_EV_WRITE , 0 , ws_conn ) , ws_conn ,conn );
                }
                break;
            case WS_ACTIVE_CLOSE_SEND:
                /* Now change the status to WS_ACTIVE_CLOSE_RECV */
                s->ws_state = WS_ACTIVE_CLOSE_RECV;
                conn->timeout =WS_FAIL_TIMEOUT_CLOSE;
                /* User is not aware of the callback function here */
                ws_conn->detached = 1;
                return NET_EV_READ | NET_EV_TIMEOUT;
            default:
                assert(0);
                return NET_EV_CLOSE;
            }

        }
        
        if( ev & NET_EV_READ ) {
                /* handle read */
                switch(s->ws_state) {
                case WS_HANDSHAKE_RECV:
                    return ws_ser_handle_handshake(ws_conn,conn);
                case WS_OPEN:
                case WS_WANT_FRAG:
                case WS_ACTIVE_CLOSE_RECV:
                    /* this function will call user's callback function and also
                     * append the previous write event (if we have any) to the 
                     * user's callback function which maintain consistent behavior */
                    return ws_ser_do_read(ws_conn,conn,rw_ev);
                default:
                    assert(0);
                    return NET_EV_CLOSE;
                }
        } 

        /* Handling timeout here, we will only have timeout when we detach users
         * callback function */

        if( ws_conn->detached && (ev & NET_EV_TIMEOUT) ) {
            net_ws_destroy(ws_conn);
            return NET_EV_CLOSE;
        }

        return ws_conn_pending_event( s->cb( ev , 0 , ws_conn ) , ws_conn ,conn );
    }
}

static int ws_cli_validate_handshake( const struct ws_ser_handshake* hs , char rand_key[16] ) {
    char buf[WS_CONCATE_KEY_LEN+1];
    SHA1_CTX shal_ctx;
    uint8_t digest[SHA1_DIGEST_SIZE];
    memcpy(buf,rand_key,16);
    strcpy(buf+16,WS_KEY_COOKIE);

    /* shal1 these key */
    SHA1_Init(&shal_ctx);
    SHA1_Update(&shal_ctx,cast(const uint8_t*,buf),WS_CONCATE_KEY_LEN);
    SHA1_Final(&shal_ctx,digest);
    return memcmp(hs->key,digest,SHA1_DIGEST_SIZE);
}

/* For a client, its initial handshake is sent once after user create it , so in the callback
 * function we only need to handle the handshake package sent from the server side */
static
int ws_cli_conn_finish_handshake( struct net_ws_conn* ws_conn , struct net_connection* conn ) {
    struct net_ws_cli_conn* c = ws_conn->ptr.client;
    void* data;
    size_t sz;
    int ret;

    assert( c->ws_state == WS_HANDSHAKE_RECV );

    sz = net_buffer_readable_size(&(conn->in));
    data = net_buffer_peek(&(conn->in),&sz);
    ret = ws_ser_handshake_parse(cast(const char*,data),sz,&(c->ws_hs));

    if( ret < 0 ) {
        /* failed , just close the connection */
        c->cb( NET_EV_CONNECT , -1 , ws_conn );
        net_ws_destroy(ws_conn);
        conn->timeout = WS_FAIL_TIMEOUT_CLOSE;
        return NET_EV_CLOSE | NET_EV_TIMEOUT;
    } else if( ret == 0 ) {
        /* verify the handshake key now */
        if( ws_cli_validate_handshake(&(c->ws_hs),c->rand_key) !=0 ) {
            c->cb( NET_EV_CONNECT , -1 , ws_conn );
            net_ws_destroy(ws_conn);
            conn->timeout = WS_FAIL_TIMEOUT_CLOSE;
            return NET_EV_CLOSE | NET_EV_TIMEOUT;
        }

        sz = net_buffer_readable_size(&(conn->in));
        net_buffer_consume(&(conn->in),&sz);

        c->ws_state = WS_OPEN;
        /* verified */
        return ws_conn_pending_event(
            c->cb( NET_EV_CONNECT , 0 , ws_conn ),ws_conn,conn);
    } else {
        sz = cast(size_t,ret);
        net_buffer_consume(&(conn->in),&sz);
        return NET_EV_READ;
    }
}

/* Sent the handshake directly as a client , call this function in net_websocket_create function when
 * user want a client web socket connection */
static
int ws_cli_send_handshake( const char* path , 
                           const char* host , 
                           struct net_ws_conn* ws_conn , 
                           struct net_connection* conn ) {
    char request[1024];
    struct net_ws_cli_conn* c = ws_conn->ptr.client;
    size_t sz;
    if( strlen(path) >= WS_MAX_DIR_NAME || strlen(host) >= WS_MAX_HOST_NAME )
        return NET_EV_NULL;
    sz = ws_handshake_cli_request(c->rand_key,path,host,request);
    net_buffer_produce(&(conn->out),request,sz);

    c->ws_state = WS_HANDSHAKE_SEND;
    return NET_EV_WRITE;
}

static
int ws_cli_do_read( struct net_ws_conn* ws_conn , struct net_connection* conn , int ev ) {
    struct net_ws_cli_conn* c = ws_conn->ptr.client;
    size_t len = net_buffer_readable_size(&(conn->in));
    void* data = net_buffer_peek(&(conn->in),&len);
    int ret = ws_frame_parse(data,len,&(c->ws_frame));
    int ret_ev = 0;
    int state;
    size_t pong_msg_sz = 0;
    int send_ping = c->ws_ping_send;

    if( ret < 0 ) {
        /* This means a frame error happened */
        goto fail;
    } else {
        if( c->ws_frame.state == WS_FP_DONE ) {

            switch(c->ws_frame.op) {
            case WS_PING:
            case WS_PONG:
                if( ws_do_pingpong(&(c->ws_frame),conn,&send_ping,&ret_ev) != 0 )
                    goto fail;
            case WS_BINARY:
            case WS_TEXT:
                break;
            case WS_CLOSE:
                return ws_close_finish(ws_conn,conn,&(c->ws_frame));
            default:
                goto fail;
            }

            /* client will not have any mask here */
            if( c->ws_frame.has_mask ) {
                goto fail;
            } 
            state = c->ws_state;
            /* checking the fragmentation status */
            if( ws_do_frag(&(c->ws_frame),&state) != 0 ) {
                goto fail;
            }
            c->ws_state = state;

            /* moving the data into the pending buffer and clear the WS_FRAME object */
            c->pending_data = c->ws_frame.data;
            c->pending_data_sz = c->ws_frame.data_sz;
            /* reuse the ws_frame object */
            INITIALIZE_WS_FRAME(&(c->ws_frame));

            /* call user's callback function */
            ret_ev |= ws_conn_pending_event(
                c->cb( NET_EV_READ | ev , 0 , ws_conn ),ws_conn,conn);
        }
        len = cast(size_t,ret);
        net_buffer_consume(&(conn->in),&len);
        return ret_ev;
    }
fail:
    DESTROY_WS_FRAME(&(c->ws_frame));
    c->cb( NET_EV_ERR_READ | ev , -1 , ws_conn );
    return ws_abort(conn,ws_conn,WS_CLOSE_PROTO_ERROR);
}

static
int ws_cli_conn_callback( int ev , int ec , struct net_connection* conn ) {
    struct net_ws_conn* ws_conn = cast(struct net_ws_conn*,conn->user_data);
    struct net_ws_cli_conn* c = ws_conn->ptr.client;

    if( ec != 0 ) {
        /* Network error */
        if( !ws_conn->detached )
            c->cb( ev , ec , ws_conn );
        net_ws_destroy(ws_conn);
        return NET_EV_CLOSE;
    } else {
        int rw_ev = 0; /* read write event */

        if( ev & NET_EV_EOF ) {
            return ws_conn_pending_event(c->cb(ev,ec,ws_conn),ws_conn ,conn);
        }

        if( ev & NET_EV_WRITE ) {
            switch(c->ws_state) {
            case WS_HANDSHAKE_SEND:
                c->ws_state = WS_HANDSHAKE_RECV;
                return NET_EV_READ;
            case WS_OPEN:
            case WS_WANT_FRAG:
                rw_ev |= NET_EV_WRITE;
                if( !(ev & NET_EV_READ) ) {
                    ws_conn_pending_event(
                        c->cb( NET_EV_WRITE , 0 , ws_conn ) , ws_conn ,conn);
                }
                break;
            case WS_ACTIVE_CLOSE_SEND:
                c->ws_state = WS_ACTIVE_CLOSE_RECV;
                conn->timeout = WS_FAIL_TIMEOUT_CLOSE;
                ws_conn->detached = 1;
                return NET_EV_READ | NET_EV_TIMEOUT;
            default:
                assert(0);
                return NET_EV_CLOSE;
            }
        } 
        
        if( ev & NET_EV_READ ) {
            switch(c->ws_state) {
            case WS_HANDSHAKE_RECV:
                /* We want handshake here */
                return ws_cli_conn_finish_handshake(ws_conn,conn);
            case WS_OPEN:
            case WS_WANT_FRAG:
            case WS_ACTIVE_CLOSE_RECV:
                return ws_cli_do_read(ws_conn,conn,rw_ev);
            default:
                assert(0);
                return NET_EV_CLOSE;
            }
        } 

        if( ws_conn->detached && (ev & NET_EV_TIMEOUT) ) {
            net_ws_destroy(ws_conn);
            return NET_EV_CLOSE;
        }

        return ws_conn_pending_event(
            c->cb( ev , 0 , ws_conn ) , ws_conn ,conn);
    }
}

void* net_ws_get_udata( struct net_ws_conn* ws ) {
    if( ws->type == WS_SERVER )
        return ws->ptr.server->user_data;
    else
        return ws->ptr.client->user_data;
}

void net_ws_set_udata( struct net_ws_conn* ws , void* data ) {
    if( ws->type == WS_SERVER )
        ws->ptr.server->user_data = data;
    else
        ws->ptr.client->user_data = data;
}

void* net_ws_recv( struct net_ws_conn* ws , size_t* len ) {
    void* ret;
    if( ws->type == WS_SERVER ) {
        if( ws->ptr.server->pending_data == NULL )
            return NULL;
        ret = ws->ptr.server->pending_data;
        *len = ws->ptr.server->pending_data_sz;

        ws->ptr.server->pending_data = NULL;
        ws->ptr.server->pending_data_sz = 0;

    } else {
        if( ws->ptr.client->pending_data == NULL )
            return NULL;
        ret = ws->ptr.client->pending_data;
        *len = ws->ptr.client->pending_data_sz;

        ws->ptr.client->pending_data = NULL;
        ws->ptr.client->pending_data_sz = 0;
    }
    return ret;
}

int net_ws_send( struct net_ws_conn* ws , void* data, size_t sz ) {
    void* framed_data;
    size_t framed_sz = sz;
    struct net_buffer* out;
    if( ws->type == WS_SERVER ) {
        assert( ws->ptr.server->ws_state != WS_CLOSED );
        framed_data = ws_frame_make( data , &framed_sz , 0 , WS_BINARY , WS_FR_NORMAL );
        out = &(ws->ptr.server->trans->out);
    } else {
        assert( ws->ptr.client->ws_state != WS_CLOSED );
        framed_data = ws_frame_make( data , &framed_sz , 1 , WS_BINARY , WS_FR_NORMAL );
        out = &(ws->ptr.client->trans->out);
    }
    net_buffer_produce(out,framed_data,framed_sz);
    free(framed_data);
    return NET_EV_WRITE;
}

const char* net_ws_get_path( struct net_ws_conn* ws ) {
    if( ws->type == WS_SERVER ) {
        return ws->ptr.server->ws_hs.host;
    } else {
        return NULL;
    }
}

const char* net_ws_get_host( struct net_ws_conn* ws ) {
    if( ws->type == WS_SERVER ) {
        return ws->ptr.server->ws_hs.dir;
    } else {
        return NULL;
    }
}

void net_ws_set_timeout( struct net_ws_conn* ws , int timeout ) {
    ws->timeout = timeout;
}

int net_ws_get_timeout( struct net_ws_conn* ws ) {
    return ws->timeout;
}

int net_ws_create_server( struct net_connection* conn , 
                                 net_ws_callback cb , 
                                 void* data ) {
    struct net_ws_conn* c = mem_alloc(sizeof(struct net_ws_conn)+sizeof(struct net_ws_ser_conn));
    c->type = WS_SERVER;
    c->timeout = 0;
    c->detached =0;
    c->ptr.server = cast(struct net_ws_ser_conn*,(cast(char*,c)+sizeof(struct net_ws_conn)));
    c->ptr.server->cb = cb;
    c->ptr.server->pending_data = NULL;
    c->ptr.server->pending_data_sz = 0;
    c->ptr.server->trans = conn;
    c->ptr.server->user_data = data;
    c->ptr.server->ws_in_frag =0;
    c->ptr.server->ws_ping_send = 0;
    c->ptr.server->ws_state = WS_HANDSHAKE_RECV;
    INITIALIZE_WS_FRAME( &(c->ptr.server->ws_frame) );
    INITIALIZE_WS_CLI_HANDSHAKE( &(c->ptr.server->ws_hs) );
    conn->user_data = c;
    conn->cb = ws_ser_conn_callback;
    return NET_EV_READ;
}

int net_ws_create_client( struct net_connection* conn ,
                                 net_ws_callback cb ,
                                 void* data , 
                                 const char* path ,
                                 const char* host) {
    struct net_ws_conn* c = mem_alloc(sizeof(struct net_ws_conn)+sizeof(struct net_ws_ser_conn));
    c->type = WS_CLIENT;
    c->timeout = 0;
    c->detached =0;
    c->ptr.client = cast(struct net_ws_cli_conn*,(cast(char*,c)+sizeof(struct net_ws_conn)));
    c->ptr.client->cb = cb;
    c->ptr.client->pending_data = NULL;
    c->ptr.client->pending_data_sz = 0;
    c->ptr.client->trans = conn;
    c->ptr.client->user_data = data;
    c->ptr.client->ws_in_frag =0;
    c->ptr.client->ws_ping_send = 0;
    c->ptr.client->ws_state = WS_HANDSHAKE_RECV;
    INITIALIZE_WS_FRAME( &(c->ptr.client->ws_frame) );
    INITIALIZE_WS_SER_HANDSHAKE( &(c->ptr.client->ws_hs) );
    conn->user_data = c; 
    conn->cb = ws_cli_conn_callback;
    return ws_cli_send_handshake(path,host,c,conn);
}

/* =============================================
 * Client side websocket API for blocking version
 * ============================================*/

int net_ws_fd_connect( struct ws_client* ws_cli , const char* addr , const char* path , const char* host , int timeout ) {
    char key[16];
    size_t buf_pos = 0;
    char hs[1024];
    size_t sz;
    struct ws_ser_handshake ws_hs;
    int ret;

    /* Initialize the ws_cli object */
    INITIALIZE_WS_SER_HANDSHAKE(&ws_hs);

    ws_cli->fd = invalid_socket_handler;
    ws_cli->buf.mem = NULL;

    ws_cli->fd = net_block_client_connect(addr,timeout);

    if( ws_cli->fd == invalid_socket_handler )
        goto fail;

    net_buffer_create(1024,&(ws_cli->buf));

    if( strlen(path) >= WS_MAX_DIR_NAME || 
        strlen(path) >= WS_MAX_HOST_NAME )
        goto fail;

    /* 1. Send out the websocket handshake frame */
    sz = ws_handshake_cli_request(key,path,host,hs);
    while( (ret =send(ws_cli->fd,hs,sz,0)) <0 )
        if( errno != EINTR )
            goto fail;

    /* 2. Wait for the peer side the send the handshake 
     * message feedback here */

    do {
        int recv_sz;
        void* hs_data;
        size_t hs_data_sz;

        recv_sz = recv( ws_cli->fd , hs , 1024 , 0 );

        if( recv_sz < 0 ) {
            if( errno == EINTR )
                continue;
            goto fail;
        } else if( recv_sz == 0 )
            goto fail; /* EOF */

        net_buffer_produce(&(ws_cli->buf),hs,recv_sz);

        hs_data_sz = net_buffer_readable_size(&(ws_cli->buf));
        hs_data = net_buffer_peek(&(ws_cli->buf),&hs_data_sz);
        ret = ws_ser_handshake_parse(hs_data,hs_data_sz,&ws_hs);

        if( ret == 0 ) {
            if( ws_hs.done ) {

                /* The handshake package is entirely received, just check
                 * its key is OK or not here */
                if( ws_cli_validate_handshake(&ws_hs,key) != 0 )
                    goto fail;
                sz = net_buffer_readable_size(&(ws_cli->buf));
                net_buffer_consume(&(ws_cli->buf),&sz);
                break;
            }
        } else {
            if( ret < 0 )
                goto fail;
            else {
                sz = cast(size_t,ret);
                net_buffer_consume(&(ws_cli->buf),&sz);
            }
        }
    } while(1);

    ws_cli->state = WS_OPEN;
    /* when we reach here, it means the connection is finished now */
    return 0;

fail:
    if( ws_cli->fd != invalid_socket_handler )
        closesocket(ws_cli->fd);
    if( ws_cli->buf.mem != NULL )
        net_buffer_clean(&(ws_cli->buf));
    return -1;
}

int net_ws_fd_send( struct ws_client* ws_cli , void* data , size_t sz ) {
    void* frame;
    int ret;
    assert( ws_cli->fd != invalid_socket_handler );
    
    if( ws_cli->state == WS_CLOSED ) {
        return 0;
    } else if( ws_cli->state != WS_OPEN && ws_cli->state != WS_WANT_FRAG ) {
        errno = EINVAL;
        return -1;
    }

    frame = ws_frame_make(data,&sz,1,WS_BINARY,WS_FR_NORMAL);
    while( (ret =send(ws_cli->fd,frame,sz,0)) <0 )
        if( errno != EINTR )
            goto fail;
    free(frame);
    return 0;
fail:
    return -1;
}

/* 
 * Recv function. This function needs to handle different situations
 * 1) Close
 * 2) Ping
 * 3) Data frame
 */

static
int net_ws_fd_handle_close_frame( struct ws_client* ws_cli , const struct ws_frame* fr ) {
    /*
     * When we receive a close frame, it means we are gonna perform
     * a passive close here. We need to send out a close fragment and
     * also, we need to report the current status to the user. If we
     * are in status WS_WANT_FRAG and then we get a close notification,
     * it means our peer side is not behaving properly, so we need to
     * notify user that we have a protocol error. */
    ws_cli->state = WS_CLOSED;

    if( ws_cli->state == WS_WANT_FRAG ) {
        /*
         * Based on RFC, we don't need to send the close message here,
         * just notifying user we are in a protocol error situations .
         */
        errno = EPROTO;
        return -1;
    } else {
        int close_code;
        int ret;
        if( fr->data_len != 0 ) 
            close_code = ntohs(*cast(uint16_t*,fr->data));
        else
            close_code = WS_CLOSE_NORMAL;

        if( close_code == WS_CLOSE_NORMAL ) {
            void* close_frag;
            size_t close_frag_sz;
            close_frag_sz = 0;
            close_frag = ws_frame_make(NULL,&close_frag_sz,0,WS_CLOSE,WS_FR_NORMAL);
            ret = net_timeout_write( ws_cli->fd , close_frag , close_frag_sz , 5000 ) > 0 ? 0 : -1;
            free( close_frag );
        } else {
            errno = EPROTO;
            ret = -1;
        }

        return ret;
    }
}

static
int net_ws_fd_handle_ctrl_frame( struct ws_client* ws_cli , const struct ws_frame* fr ) {
    void* pong_fr;
    size_t pong_fr_len;
    int ret;

    switch(fr->op) {
    case WS_CLOSE:
        /* Return zero to simulate the system socket behavior*/
        return net_ws_fd_handle_close_frame(ws_cli,fr);
    case WS_PING:
        /* The ping operations, we need to handle it with PONG 
         * frame here */
        pong_fr_len = 0;
        pong_fr = ws_frame_make(NULL,&pong_fr_len,0,WS_PONG,WS_FR_NORMAL);
        /* send this piece of data out of bound here */
        ret = send(ws_cli->fd,pong_fr,pong_fr_len,0);
        free(pong_fr);

        if( ret == 0 ) {
            return 0;
        } else {
            if( ret < 0 )
                return -1;
        }

        return 1;
    default:
        assert(0);
        return -1;
    }
}

void* net_ws_fd_recv( struct ws_client* ws_cli , size_t* buf_sz ) {
    void* data;
    size_t sz;
    int ret;
    struct ws_frame fr;
    char buf[1024];

    if( ws_cli->state != WS_OPEN && ws_cli->state != WS_WANT_FRAG ) {
        errno = EINVAL;
        if( ws_cli->state == WS_CLOSED )
            *buf_sz = 0; /* telling the user that this socket has been closed */
        return NULL;
    }

    INITIALIZE_WS_FRAME(&fr);

    /* feed it with ws_frame_parse function */
    do {
        sz = net_buffer_readable_size(&(ws_cli->buf));

        if( sz > 0 ) {
            data = net_buffer_peek(&(ws_cli->buf),&sz);
            ret = ws_frame_parse(data,sz,&fr);
        } else {
            ret = 0;
        }

        if( ret < 0 ) {
            /* The frame has an error internally */
            errno = EPROTO;
            DESTROY_WS_FRAME(&fr);
            return NULL;
        } else if( ret >= 0 ) {
            sz = cast(size_t,ret);
            net_buffer_consume(&(ws_cli->buf),&sz);
        }
        
        if( fr.state == WS_FP_DONE ) {
            /* Checking if it is the control package */
            switch(fr.op) {
            case WS_PING:
            case WS_CLOSE:
                ret = net_ws_fd_handle_ctrl_frame(ws_cli,&fr);
                if( ret < 0 ) {
                    /* We have encounter an error, so we are not sure
                     * the data current we have is OK or not, just notify
                     * the user that we have an error and drop everything*/
                    DESTROY_WS_FRAME(&fr);
                    return NULL;
                } else {
                    /* The control frame can carry data as well here */
                    if( fr.data_len != 0 )
                        goto done;  /* Even if this data is carried through close frame, we
                                     * don't notify user with this recv, but delay it when
                                     * user call recv again or send again */
                    else {
                        if( fr.op == WS_PING ) {
                            DESTROY_WS_FRAME(&fr);
                            break;
                        } else {
                            DESTROY_WS_FRAME(&fr);
                            *buf_sz = 0;
                            return NULL;
                        }
                    }
                }
            case WS_BINARY:
                /* Here we get a correct binary data package, however we need to 
                 * check its fragmentation validation here as well */
                if( ws_do_frag(&fr,&ws_cli->state) != 0 ) {
                    errno = EPROTO;
                    DESTROY_WS_FRAME(&fr);
                    return NULL;
                }
                goto done;
            default:
                /* Unknown message type, just ignore this frame and return
                 * error */
                DESTROY_WS_FRAME(&fr);
                return NULL;
            }
        }

        /* read data from the socket , very sloppy method */
        while( (ret = recv(ws_cli->fd,buf,1024,0)) < 0 )
            if( errno != EINTR )
                break;

        if( ret ==0 ) {
            DESTROY_WS_FRAME(&fr);
            /* the peer side shutdown the connection , we don't
             * send close fragment since it may be that the peer
             * side just close the underlying socket layer */
            ws_cli->state = WS_CLOSED;
            *buf_sz = 0;
            return NULL;
        } else if( ret < 0 ) {
            return NULL;
        } else {
            net_buffer_produce(&(ws_cli->buf),buf,ret);
        }

    } while(1);

done:
    /* When we reach here, we get a complete message packet. */
    assert( fr.data != NULL && fr.data_len != 0 );
    *buf_sz = cast(size_t,fr.data_len);
    return fr.data;
}

int net_ws_fd_close( struct ws_client* ws_cli ) {
    void* close_fr;
    size_t close_fr_sz = 0;
    int ret;

    /* This socket has been closed by PASSIVE close */
    if( ws_cli->state == WS_CLOSED ) {
        ret = 0;
        goto done;
    }

    close_fr = ws_close_frame_make(0,WS_CLOSE_NORMAL,&close_fr_sz);
    /* As this is the close segment, so we don't want to wait too long
     * time on sending out the close frame . It is highly possible that
     * the peer side turn/abort the protocol by just tearing down the 
     * tcp connection. Therefore, using a timeout to protect the long wait
     * here do make sense. */

    if( net_timeout_write( ws_cli->fd , close_fr , close_fr_sz , 2000 ) > 0 ) {
        /* Now we have sent out the frame correctly, then we just wait for the
         * peer side to return back the close segment. Since it is still a problem
         * to wait too long here, we just wait with timeout as well for the feedback.
         * If it fails, then we just notify our user that we have already closed
         * the web socket protocol. In order to try our best to close the connection
         * gracefully, we will loop until where we can and then close the connection*/
        struct net_buffer close_buf;
        struct ws_frame fr;

        net_buffer_create(256,&close_buf);
        INITIALIZE_WS_FRAME(&fr);

        do {
            char buf[256];
            ret = net_timeout_read( ws_cli->fd , buf , 256 , 10000 );
            if( ret <= 0 ) {
                ret = -1;
                net_buffer_clean(&close_buf);
                DESTROY_WS_FRAME(&fr);
                break;
            } else {
                void* data;
                size_t data_sz;
                net_buffer_produce(&close_buf,buf,ret);

                data_sz = net_buffer_readable_size(&close_buf);
                data = net_buffer_peek(&close_buf,&data_sz);

                ret = ws_frame_parse(data,data_sz,&fr);
                if( ret < 0 ) {
                    ret = -1;
                    net_buffer_clean(&close_buf);
                    DESTROY_WS_FRAME(&fr);
                    break;
                } else {
                    int close_code;

                    if( fr.state == WS_FP_DONE ) {
                        /* Checking this frame is a valid close frame or not */
                        if( fr.op != WS_CLOSE ) {
                            errno = EPROTO;
                            ret = -1;
                            net_buffer_clean(&close_buf);
                            DESTROY_WS_FRAME(&fr);
                            break;
                        }

                        /*  Checking the close frame close code */
                        if( fr.data_len > 0 ) {
                            close_code = ntohs(*cast(uint16_t*,fr.data));
                        } else {
                            close_code = WS_CLOSE_NORMAL;
                        }
                        
                        if( close_code != WS_CLOSE_NORMAL ) {
                            errno = EPROTO;
                            ret = -1;
                            break;
                        }

                        /* OK , we exit the web socket gracefully here */
                        ret = 0;
                        break;
                    }
                }
            }

        } while(1);
    } else {
        ret = -1;
    }

    free(close_fr);

done:
    closesocket(ws_cli->fd);
    ws_cli->fd = invalid_socket_handler;
    net_buffer_clean(&(ws_cli->buf));
    return ret;
}

int net_ws_fd_ping( struct ws_client* ws_cli ) {
    void* ping_fr;
    size_t ping_fr_sz = 0;
    int ret;

    ping_fr = ws_frame_make(NULL,&ping_fr_sz,0,WS_PING,WS_FR_NORMAL);

    while( (ret = send(ws_cli->fd,ping_fr,ping_fr_sz,0)) < 0 )
        if( errno != EINTR ) {
            ret = -1;
            break;
        }

    free(ping_fr);
    return ret >0 ? 0 : -1;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */

#ifdef TEST
#include "test.c"
#endif /* TEST */
