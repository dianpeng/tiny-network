#define TEST
#include "network.c"

#if 0

#include <assert.h>
#include <Windows.h>
#include <stdio.h>

#define VERIFY(x) \
    do { \
        if(!(x)) { \
            fprintf(stderr,"%d:%d\n",WSAGetLastError(),errno); \
            assert(0); \
        } \
    }while(0)


int main() {
    struct ws_client cl;
    int ret;
    const char* hello_world="Hello World";
    char* recv_buf ;
    size_t recv_sz;

    net_init();

    VERIFY( net_ws_fd_connect(&cl,"127.0.0.1:12345","/","www.example.com") == 0 );
    VERIFY( net_ws_fd_send(&cl,hello_world,12) == 0 );
    recv_buf = net_ws_fd_recv(&cl,&recv_sz);
    VERIFY( recv_buf != NULL );
    VERIFY( net_ws_fd_close(&cl) == 0 );

    printf(recv_buf);
    printf("Done");

    return 0;
}


#else
int main() {
    run_test();
}
#endif










