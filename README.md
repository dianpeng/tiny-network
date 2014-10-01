# Tiny Network Library

A tiny , cross platform and easy to use network library

## What is tiny network

You may have used many network libraries, like libevent , libev. Those libraries are greate, so why bother another one ? Because tiny network is a library design for small server that doesn't need to support C10K. It is extreamly tiny and easy to use. Since it only has 2 files, it is easy to integrate it into your project.

## Show me the code 
The only 2 functions you need to know is 1) accept callback and 2) connection callback. The concept is very simple. struct net_connection_t represent everthing that is not a server( not only a connection, also could be a timer) . struct net_server_t is a structure represents the server. Lastly a struct net_buffer_t is used to help you handle network read/write buffer. Then you are all set.

```
#include <network.h>

// This connection callback will be invoked after each connection registered 
// interested events _FINISHED_ .
int conn_cb( int ev , int ec , struct net_connection_t* conn ) {
    if( ec ) {
        fprintf(stderr,"%s\n",strerror(errno));
        return NET_EV_CLOSE;
    } else {
        if( ev & NET_EV_READ ) {
            // echo whatever we read from peer back
            size_t read_sz;
            void* read_buf = net_buffer_consume(&(conn->in),&read_sze);
            net_buffer_produce(&(conn->out),read_buf,read_sz);
            return NET_EV_LINGER_SILENT;
        } else {
            return NET_EV_CLOSE;
        }
    }
}

// This callback function will be invoked for every connection that has been accepted
int accept_cb( int ec , struct net_server_t* ser ,struct net_connection_t* conn ) {
    if( ec ) {
        fprintf(stderr,"%s\n",strerror(errno));
        return NET_EV_CLOSE;
    } else {
        conn->cb = conn_cb;
        return NET_EV_READ;
    }
}

int main() {
    struct net_server_t ser;
    net_init();
    if( net_server_create(&ser,"127.0.0.1:12345",accept_cb) != 0 ) {
        fprintf(stderr,"cannot create server");
        return -1;
    } 
    for(;;) {
        net_server_poll(&ser,-1,NULL);
    }
    return 0;
}
```

The above is a echo server that works well. 

Just notify the tiny network library what you want to do in next callback and then all the IO operations will be performed correctly.

##Build
1. Make
2. Visual Studio

##Platform
1. Windows
2. Linux

##Dependency
NO
