
void test_http_readline() {
    {
        size_t len;
        const char* data = "GET / HTTP/1.1\r\n\r\n";
        int eof;

        len = http_readline(data,strlen(data),&eof);
        assert( data[len-1] == '\n' );
        assert( eof == 1 );
        assert( len == 16 );
    }

    {
        size_t len;
        const char* data = "GET / HTTP/1.1\n";
        int eof;

        len = http_readline(data,strlen(data),&eof);
        assert( len == -1 );
    }

    {
        size_t len;
        const char* data = "GET /SomeBOdyHerr/asdasda/asda HTTP/1.1 \r\nField:121231\r\nASDSAD\r\n\r\n";
        int eof;

        len = http_readline(data,strlen(data),&eof);
        assert( data[len-1] == '\n' );
        assert( eof == 0 );
        data += len;

        len = http_readline(data,strlen(data),&eof);
        assert( data[len-1] == '\n' );
        assert( eof == 0 );
        data +=len;

        len = http_readline(data,strlen(data),&eof);
        assert( data[len-1] == '\n' );
        assert( eof == 1 );
    }
}

void test_ws_cli_handshake_check_first_line() {
    {
        const char* data = \
            "GET / HTTP/1.1";
        char dir[256];
        assert( ws_cli_handshake_check_first_line(data,dir) == 0 );
        assert( strcmp(dir,"/")==0 );
    }

    {
        const char* data = \
            "GET /abdwdwd HTTP/1.1";
        char dir[256];
        assert( ws_cli_handshake_check_first_line(data,dir) == 0 );
        assert( strcmp(dir,"/abdwdwd")==0 );
    }


    {
        const char* data = \
            "GET / ";
        char dir[256];
        assert( ws_cli_handshake_check_first_line(data,dir) !=-1 );
    }

    {
        const char* data = \
            "GET / HT";
        char dir[256];
        assert( ws_cli_handshake_check_first_line(data,dir) !=-1 );
    }

    {
        const char* data = \
            "GET / HTTP/1.0";
        char dir[256];
        assert( ws_cli_handshake_check_first_line(data,dir) !=-1 );
    }

    {
        const char* data = \
            "GET / HTTP/.asda";
        char dir[256];
        assert( ws_cli_handshake_check_first_line(data,dir) !=-1 );
    }
}

void test_ws_http_misc() {
    assert(http_strcmp(" ABC","ABC") == 0);
    assert(http_strcmp("AbCDEfas","AbCDEfas") == 0);
    assert(http_strcmp("  ABCDEF","ABCDEF") == 0);

    {
        const char* data = \
            "   edf";
        assert( http_skip(data,' ') == 3 );
    }

    {
        const char* data = \
            "edf";
        assert( http_skip(data,' ') == 0 );
    }
}

void test_ws_cli_handshake_parse() {
    {
        /* Testing the parser with each call only have ONE byte */
        char data[] = \
            "GET /Dir HTTP/1.1\r\n" \
            "Upgrade:websocket\r\n" \
            "Connection:Upgrade\r\n" \
            "Sec-WebSocket-Version:13\r\n" \
            "Sec-WebSocket-Key:MTIzNDU2Nzg5QUJDREVGRw==\r\n" \
            "Host:www.example.com\r\n\r\n";

        int i = 0;
        int len = 1;
        struct ws_cli_handshake hs;
        int ret;

        INITIALIZE_WS_CLI_HANDSHAKE(&hs);

        while(1) {
            ret = ws_cli_handshake_parse(data+i,len,&hs);
            assert( ret >= 0 );
            if( ret > 0 ) {
                i+=ret;
                len = 1;
            } else {
                if( hs.done )
                    break;
                ++len;
            }
        }

        assert(strcmp(hs.dir,"/Dir")==0);
        assert(memcmp(hs.ws_key,"123456789ABCDEFG",16)==0);
        assert(strcmp(hs.host,"www.example.com")==0);
    }

    {
        /* Testing the parser with each call only have ONE byte */
        char data[] = \
            "GET /Dir HTTP/1.1\r\n" \
            "Upgrade:Websocket\r\n" \
            "connection:Upgrade\r\n" \
            "sec-webSocket-Version\r\n" \
            "Sec-WebSocket-Key\r\n" \
            "Host:www.example.com\r\n\r\n";

        int i = 0;
        int len = 1;
        struct ws_cli_handshake hs;
        int ret;
        int failed = 0;

        INITIALIZE_WS_CLI_HANDSHAKE(&hs);

        while(1) {
            ret = ws_cli_handshake_parse(data+i,len,&hs);
            if( ret < 0 ) {
                failed = 1;
                break;
            } else {
                ++len;
                i+=ret;
            }
        }

        assert(failed ==1);
    }

    {
        /* Testing the parser with each call only have ONE byte */
        char data[] = \
            "GET / HTTP/1.1\r\n" \
            "Upgrade:websocket\r\n" \
            "Connection:Upgrade\r\n" \
            "Sec-WebSocket-Version:13\r\n" \
            "Sec-WebSocket-Key:MTIzNDU2Nzg5QUJDREVGRw==\r\n" \
            "Host:www.ABC.com\r\n\r\n";

        int i = 0;
        int len = 1;
        struct ws_cli_handshake hs;
        int ret;

        INITIALIZE_WS_CLI_HANDSHAKE(&hs);

        while(1) {
            ret = ws_cli_handshake_parse(data+i,len,&hs);
            assert( ret >= 0 );
            if( ret > 0 ) {
                i+=ret;
                len = 1;
            } else {
                if( hs.done )
                    break;
                ++len;
            }
        }
        assert(strcmp(hs.dir,"/")==0);
        assert(memcmp(hs.ws_key,"123456789ABCDEFG",16)==0);
        assert(strcmp(hs.host,"www.ABC.com")==0);
    }

}

void test_b64() {
    {
        char * _1byte="a";
        char * _2byte="ab";
        char * _3byte="abc";
        char * _4byte="abcd";
        char buf[128];
        char dec[128];

        size_t j = b64_encode(_1byte,1,buf);
        assert( j == 4 );

        j = b64_decode(buf,j,dec,128);
        assert( j > 0 );
        dec[j] = 0;
        assert(strcmp(dec,_1byte) == 0);

        j = b64_encode(_2byte,2,buf);
        assert( j == 4 );

        j = b64_decode(buf,j,dec,128);
        assert( j > 0 );
        dec[j] = 0;
        assert(strcmp(dec,_2byte) == 0);

        j = b64_encode(_3byte,3,buf);
        assert( j == 4 );

        j = b64_decode(buf,j,dec,128);
        assert( j > 0 );
        dec[j] = 0;
        assert(strcmp(dec,_3byte) == 0);

        j = b64_encode(_4byte,4,buf);
        assert( j == 8 );

        j = b64_decode(buf,j,dec,128);
        assert( j > 0 );
        dec[j] = 0;
        assert(strcmp(dec,_4byte) == 0);
    }

    {

        const char* d = "ASDAFASDCASCXZXCZXCasdasdasdzcx12314r1eadsdas";
        const char* r = "QVNEQUZBU0RDQVNDWFpYQ1pYQ2FzZGFzZGFzZHpjeDEyMzE0cjFlYWRzZGFz";
        char buf[1024];
        char dec[1024];
        size_t j = b64_encode(d,strlen(d),buf);
        assert(j >0);
        buf[j] = 0;
        assert(strcmp(buf,r)==0);

        j = b64_decode(buf,j,dec,1024);
        assert(j >0);
        dec[j] = 0;
        assert(strcmp(dec,d)==0);
    }
}

void test_ws_handshake_ser_reply() {
    char buf[1024];
    size_t sz;
    char key[] ="123456789ABCDEFG";

    sz = ws_handshake_ser_reply(key,buf);
    buf[sz] =0;
    printf(buf);
}

static
void generate_ws_key( char key[16] , char b64key[28] ) {
    char buf[128];
    char b64_kbuf[25];
    SHA1_CTX shal_ctx;
    uint8_t digest[SHA1_DIGEST_SIZE];
    size_t len;

    ws_handshake_generate_key(b64_kbuf,key);

    len = cast(size_t, sprintf(buf,"%s%s",key,WS_KEY_COOKIE) );
    /* shal1 these key */
    SHA1_Init(&shal_ctx);
    SHA1_Update(&shal_ctx,cast(const uint8_t*,buf),len);
    SHA1_Final(&shal_ctx,digest);

    /* encode it into base64 */
    assert( b64_encode(cast(const char*,digest),SHA1_DIGEST_SIZE,b64key) == 28 );
}

void test_ws_ser_handshake_parse() {
    {
        struct ws_ser_handshake hs;
        char data[] = \
            "HTTP/1.1 101 Switching Protocols\r\n" \
            "Upgrade:websocket\r\n" \
            "CONNECTION:Upgrade\r\n" \
            "Sec-WebSocket-Accept:MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=\r\n\r\n";
        int i=0;
        int len = 1;

        INITIALIZE_WS_SER_HANDSHAKE(&hs);

        do {
            int ret = ws_ser_handshake_parse( data + i , len , &hs );
            if( ret == 0 ) {
                if(hs.done)
                    break;
                ++len;
            } else {
                assert(ret >0);
                i += ret;
                len = 1;
            }
        } while(1);

        assert( memcmp(hs.key,"12345678901234567890",20) == 0);
    }

    {
        struct ws_ser_handshake hs;
        char data[] = \
            "HTTP/1.1 101 Switching Protocols\r\n" \
            "Upgrade:webscket\r\n" \
            "Connection\r\n" \
            "Sec-WebSocket-Accept:MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=\r\n\r\n";
        int i=0;
        int len = 1;
        int fail = 0;

        INITIALIZE_WS_SER_HANDSHAKE(&hs);

        do {
            int ret = ws_ser_handshake_parse( data + i , len , &hs );
            if( ret == 0 ) {
                if(hs.done)
                    break;
                ++len;
            } else {
                if( ret < 0 ) {
                    fail = 1;
                    break;
                }
                i += ret;
                len = 1;
            }
        } while(1);
        assert(fail);
    }

    {
        struct ws_ser_handshake hs;
        char data[] = "HTTP/1.1 400 Bad request\r\n\r\n";
        int i=0;
        int len = 1;
        int fail = 0;

        INITIALIZE_WS_SER_HANDSHAKE(&hs);

        do {
            int ret = ws_ser_handshake_parse( data + i , len , &hs );
            if( ret == 0 ) {
                if(hs.done)
                    break;
                ++len;
            } else {
                if( ret < 0 ) {
                    fail = 1;
                    break;
                }
                i += ret;
                len = 1;
            }
        } while(1);
        assert(fail);
    }
}

/*
 * Testing frame 
 */

void test_ws_frame() {
    {
        char* data = "Hello World";
        size_t sz = 11;
        void* d = ws_frame_make(data,&sz,0,WS_BINARY,WS_FR_NORMAL);
        struct ws_frame fr;

        INITIALIZE_WS_FRAME(&fr);

        net_hex_dump(NULL,d,sz);

        /* parse this frame */
        assert( ws_frame_parse(d,sz,&fr) >=0 );
        assert( fr.state == WS_FP_DONE );
        assert( fr.data_len == 11 );
        assert( memcmp(fr.data,data,11) == 0 );
        assert( fr.op == WS_BINARY );
        assert( fr.has_mask == 0 );
        assert( fr.fin == 1  );
    }

    {
        char* data = "Random Data";
        size_t sz = 11;
        void* d = ws_frame_make(data,&sz,1,WS_PING,WS_FR_FRAG_INIT);
        struct ws_frame fr;

        INITIALIZE_WS_FRAME(&fr);

        net_hex_dump(NULL,d,sz);

        /* parse this frame */
        assert( ws_frame_parse(d,sz,&fr) >=0 );
        assert( fr.state == WS_FP_DONE );
        assert( fr.data_len == 11 );
        assert( memcmp(fr.data,data,11) == 0 );
        assert( fr.op == WS_PING );
        assert( fr.has_mask == 1 );
        assert( fr.fin == 0  );
    }
    // parse with only one byte length
    {
        char* data = "Random Data";
        size_t sz = 11;
        void* d = ws_frame_make(data,&sz,1,WS_CLOSE,WS_FR_FRAG_INIT);
        struct ws_frame fr;
        int i = 0;
        int len = 1;

        INITIALIZE_WS_FRAME(&fr);

        net_hex_dump(NULL,d,sz);

        do {
            int ret = ws_frame_parse(cast(char*,d)+i,len,&fr);
            assert( ret >= 0 );
            if( ret == 0 ) ++len;
            else {
                i += ret;
                len = 1;
            }
            if( fr.state == WS_FP_DONE )
                break;
        } while(1);

        assert( fr.data_len == 11 );
        assert( memcmp(fr.data,data,11) == 0 );
        assert( fr.op == WS_CLOSE );
        assert( fr.has_mask == 1 );
        assert( fr.fin == 0  );
    }
}

int run_test() {
    test_http_readline();
    test_ws_cli_handshake_check_first_line();
    test_ws_http_misc();
    test_ws_cli_handshake_parse();
    test_b64();
    // test_ws_handshake_ser_reply();
    test_ws_ser_handshake_parse();
    test_ws_frame();
    return 0;
}

