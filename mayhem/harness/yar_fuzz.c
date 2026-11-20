/*
 * libFuzzer harness: PHP embed SAPI with the (sanitized) yar extension linked in.
 *
 * The PHP engine starts once (LLVMFuzzerInitialize). Each input runs in its own PHP
 * request, so every object the input creates is destroyed by request shutdown and no
 * PHP state is carried between inputs. One source, four targets (-DYAR_TARGET=...):
 *
 *   SERVER      the input is the HTTP POST body handed to Yar_Server::handle()
 *               (yar_server.c php_yar_server_handle: header, packager, request).
 *   SOCKET      the input is what a peer answers to Yar_Client over unix:// (socket transport).
 *   HTTP        the input is the HTTP response body a peer answers to Yar_Client over http://
 *               (curl transport, php_yar_curl_exec).
 *   CONCURRENT  same responder, through Yar_Concurrent_Client::call()+loop()
 *               (curl multi transport, php_yar_curl_multi_parse_response).
 *
 * Client targets: a responder thread listens on loopback (a unix socket in $TMPDIR, or
 * 127.0.0.1:<ephemeral port>). For each connection it drains the client's request, writes
 * the current fuzz input (raw for unix://, as an HTTP/1.1 200 body for http://) and closes,
 * so the client always sees EOF and never waits. The listener itself is the only state kept
 * across inputs; it carries no input-derived data. The responder only touches the input
 * while LLVMFuzzerTestOneInput is running it: connections are served under a mutex
 * handshake, and the driver does not return until the connection it may have opened is
 * finished (after request shutdown it shuts that socket down and waits for the close), so
 * the input buffer is never read after libFuzzer frees or reuses it. PHP exceptions are caught in the driver;
 * PHP fatal errors unwind through the engine's own zend_try.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <sapi/embed/php_embed.h>
#include "SAPI.h"
#include "main/php_streams.h"

extern zend_module_entry yar_module_entry;

#define T_SERVER 1
#define T_SOCKET 2
#define T_HTTP 3
#define T_CONCURRENT 4

#ifndef YAR_TARGET
#error "define YAR_TARGET"
#endif

static const char SERVER_SRC[] =
    "class FuzzService {\n"
    "  /** echo the arguments back */\n"
    "  public function f(...$a) { return $a; }\n"
    "  public function g($x) { if ($x) throw new Exception('e'); return [1, 'a' => 2.5]; }\n"
    "}\n"
    "try { (new Yar_Server(new FuzzService()))->handle(); } catch (Throwable $t) {}\n";

static const char SOCKET_SRC[] =
    "try { $c = new Yar_Client($GLOBALS['yar_addr']); $c->f(1, 'a'); } catch (Throwable $t) {}\n";

static const char HTTP_SRC[] = /* same driver, http:// address */
    "try { $c = new Yar_Client($GLOBALS['yar_addr']); $c->f(1, 'a'); } catch (Throwable $t) {}\n";

static const char CONCURRENT_SRC[] =
    "try {\n"
    "  Yar_Concurrent_Client::call($GLOBALS['yar_addr'], 'f', [1, 'a'], function($r, $i) {});\n"
    "  Yar_Concurrent_Client::call($GLOBALS['yar_addr'], 'g', [2], function($r, $i) {}, function($t, $e) {});\n"
    "  Yar_Concurrent_Client::loop(function($r, $i) {}, function($t, $e) {});\n"
    "} catch (Throwable $t) {}\n"
    "try { Yar_Concurrent_Client::reset(); } catch (Throwable $t) {}\n";

/* ---- responder (client targets) ---- */
static const uint8_t *cur_data;
static size_t cur_size;
static int listen_fd = -1;
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t done_cv = PTHREAD_COND_INITIALIZER;
static int input_active; /* LLVMFuzzerTestOneInput is running cur_data */
static int conn_fd = -1; /* connection being served, -1 if none */
static char yar_addr[256];

static void write_all(int fd, const void *p, size_t n) {
    const char *c = p;
    while (n) {
        ssize_t w = send(fd, c, n, MSG_NOSIGNAL);
        if (w <= 0) return;
        c += w; n -= (size_t)w;
    }
}

/* Read the client's request: for yar-over-socket an 82-byte header + body_len bytes
 * (body_len is the big-endian u32 at offset 78); for HTTP, headers + Content-Length. */
static void drain_request(int fd, int http) {
    char buf[65536];
    size_t have = 0, need = (size_t)-1;
    while (have < sizeof(buf)) {
        ssize_t r = recv(fd, buf + have, sizeof(buf) - have, 0);
        if (r <= 0) return;
        have += (size_t)r;
        if (need == (size_t)-1) {
            if (!http && have >= 82) {
                uint32_t bl;
                memcpy(&bl, buf + 78, 4);
                need = 82 + ntohl(bl);
            } else if (http) {
                char *e = memmem(buf, have, "\r\n\r\n", 4);
                if (e) {
                    size_t cl = 0;
                    char *h = memmem(buf, (size_t)(e - buf), "Content-Length:", 15);
                    if (!h) h = memmem(buf, (size_t)(e - buf), "content-length:", 15);
                    if (h) cl = strtoul(h + 15, NULL, 10);
                    need = (size_t)(e - buf) + 4 + cl;
                }
            }
        }
        if (need != (size_t)-1 && have >= need) return;
    }
}

static void *responder(void *arg) {
    int http = (int)(intptr_t)arg;
    for (;;) {
        int fd = accept(listen_fd, NULL, NULL);
        if (fd < 0) continue;
        pthread_mutex_lock(&mu);
        if (!input_active) { /* stray connection between inputs: no input to serve */
            pthread_mutex_unlock(&mu);
            close(fd);
            continue;
        }
        conn_fd = fd;
        const uint8_t *data = cur_data;
        size_t size = cur_size;
        pthread_mutex_unlock(&mu);
        drain_request(fd, http);
        if (http) {
            char hdr[160];
            int n = snprintf(hdr, sizeof(hdr),
                             "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                             "Content-Length: %zu\r\nConnection: close\r\n\r\n", size);
            write_all(fd, hdr, (size_t)n);
        }
        write_all(fd, data, size);
        shutdown(fd, SHUT_WR);
        char sink[4096];
        while (recv(fd, sink, sizeof(sink), 0) > 0) {}
        pthread_mutex_lock(&mu);
        close(fd);
        conn_fd = -1;
        pthread_cond_broadcast(&done_cv);
        pthread_mutex_unlock(&mu);
    }
    return NULL;
}

static void start_responder(int http) {
    if (http) {
        struct sockaddr_in a = {0};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        listen_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd < 0 || bind(listen_fd, (struct sockaddr *)&a, sizeof(a)) || listen(listen_fd, 16)) abort();
        socklen_t l = sizeof(a);
        getsockname(listen_fd, (struct sockaddr *)&a, &l);
        snprintf(yar_addr, sizeof(yar_addr), "http://127.0.0.1:%d/", ntohs(a.sin_port));
    } else {
        const char *tmp = getenv("TMPDIR");
        if (!tmp || !*tmp) tmp = "/tmp";
        struct sockaddr_un a = {0};
        a.sun_family = AF_UNIX;
        snprintf(a.sun_path, sizeof(a.sun_path), "%s/yar-fuzz-%d.sock", tmp, (int)getpid());
        unlink(a.sun_path);
        listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (listen_fd < 0 || bind(listen_fd, (struct sockaddr *)&a, sizeof(a)) || listen(listen_fd, 16)) abort();
        snprintf(yar_addr, sizeof(yar_addr), "unix://%s", a.sun_path);
    }
    pthread_t th;
    if (pthread_create(&th, NULL, responder, (void *)(intptr_t)http)) abort();
    pthread_detach(th);
}

/* ---- PHP embed ---- */
static size_t quiet_ub_write(const char *str, size_t len) { (void)str; return len; }
static void quiet_log(const char *msg, int syslog_type) { (void)msg; (void)syslog_type; }
static void quiet_flush(void *ctx) { (void)ctx; }
static int quiet_send_headers(sapi_headers_struct *h) { (void)h; return SAPI_HEADER_SENT_SUCCESSFULLY; }

static int startup_with_yar(sapi_module_struct *sf) {
    return php_module_startup(sf, &yar_module_entry);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    /* Use the system allocator so ASan sees PHP heap objects individually. */
    setenv("USE_ZEND_ALLOC", "0", 1);
    php_embed_module.startup = startup_with_yar;
    php_embed_module.ub_write = quiet_ub_write;
    php_embed_module.log_message = quiet_log;
    php_embed_module.flush = quiet_flush;
    php_embed_module.send_headers = quiet_send_headers;
    php_embed_module.ini_entries =
        "display_errors=0\nlog_errors=0\nmemory_limit=256M\nmax_execution_time=0\n";
    static char *args[] = {"yar_fuzz", NULL};
    if (php_embed_init(1, args) == FAILURE) abort();
    php_request_shutdown(NULL);
#if YAR_TARGET == T_SOCKET
    start_responder(0);
#elif YAR_TARGET == T_HTTP || YAR_TARGET == T_CONCURRENT
    start_responder(1);
#endif
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    pthread_mutex_lock(&mu);
    cur_data = data;
    cur_size = size;
    input_active = 1;
    pthread_mutex_unlock(&mu);
    if (php_request_startup() == FAILURE) abort();
    zend_first_try {
#if YAR_TARGET == T_SERVER
        /* What a web SAPI does for a POST: the body is a rewindable temp stream. */
        SG(request_info).request_method = "POST";
        php_stream *body = php_stream_temp_create_ex(TEMP_STREAM_DEFAULT, SAPI_POST_BLOCK_SIZE, PG(upload_tmp_dir));
        if (size) php_stream_write(body, (const char *)data, size);
        SG(request_info).request_body = body;
        zend_eval_stringl((char *)SERVER_SRC, sizeof(SERVER_SRC) - 1, NULL, "fuzz_driver");
#else
        zval za;
        ZVAL_STRING(&za, yar_addr);
        zend_hash_str_update(&EG(symbol_table), "yar_addr", sizeof("yar_addr") - 1, &za);
#if YAR_TARGET == T_SOCKET
        zend_eval_stringl((char *)SOCKET_SRC, sizeof(SOCKET_SRC) - 1, NULL, "fuzz_driver");
#elif YAR_TARGET == T_HTTP
        zend_eval_stringl((char *)HTTP_SRC, sizeof(HTTP_SRC) - 1, NULL, "fuzz_driver");
#else
        zend_eval_stringl((char *)CONCURRENT_SRC, sizeof(CONCURRENT_SRC) - 1, NULL, "fuzz_driver");
#endif
#endif
    } zend_end_try();
#if YAR_TARGET == T_SERVER
    SG(request_info).request_body = NULL; /* the stream resource is freed by request shutdown */
    SG(request_info).request_method = NULL;
#endif
    php_request_shutdown(NULL);
    /* Request shutdown closed the client's sockets. Stop serving this input and wait
     * until the responder is done with any connection it accepted, so it never reads
     * `data` after we return (or writes it into the next input's connection). */
    pthread_mutex_lock(&mu);
    input_active = 0;
    if (conn_fd >= 0) shutdown(conn_fd, SHUT_RDWR);
    while (conn_fd >= 0) pthread_cond_wait(&done_cv, &mu);
    cur_data = NULL;
    cur_size = 0;
    pthread_mutex_unlock(&mu);
    return 0;
}
