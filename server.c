#include "network.h"
#include <stdio.h>
#include <assert.h>
/* Setting up a web socket server */

static int ws_cb( int ev , int ec , struct net_ws_conn_t* ws_conn ) {
    if( ec != 0 ) {
        printf("Fail:%d",ec);
        return NET_EV_CLOSE;
    } else {
        if( ev & NET_EV_CONNECT ) {
            printf("Connected");
            return NET_EV_READ;
        } else if( ev & NET_EV_READ ) {
            size_t len ;
            void* data;
            data = net_ws_recv(ws_conn,&len);
            net_ws_send(ws_conn,data,len);
            free(data);
            printf("Data received!\n");
            return NET_EV_WRITE;
        } else if( ev & NET_EV_WRITE ) {
            printf("Data sent!\n");
            return NET_EV_CLOSE;
        }
    }
}

static int accept_cb( int ec , struct net_server_t* s , struct net_connection_t* conn ) {
    if( ec == 0 )
        return net_ws_create_server(conn,ws_cb,NULL);
    return NET_EV_CLOSE;
}

int main() {
    struct net_server_t s;
    net_init();
    assert( net_server_create(&s,"127.0.0.1:12345",accept_cb)==0 );
    for(;;) net_server_poll(&s,-1,NULL);
    return 0;
}
