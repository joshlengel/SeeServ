#include"SeeServ/SeeServ.h"
#include"SeeServLog.h"
#include"SeeServUtils.h"

#include<stdlib.h>
#include<string.h>
#include<stdio.h>
#include<assert.h>

// Linux
#include<sys/socket.h>
#include<netdb.h>
#include<unistd.h>
#include<errno.h>
#include<pthread.h>

typedef struct
{
    int no;
    SeeServError err;
} IntErrPair;

static const IntErrPair _ERRNO_ERRORS[] =
{
    { EACCES,       SEE_SERV_PERMISSION_DENIED },
    { EAFNOSUPPORT, SEE_SERV_UNSUPPORTED       },
    { ENOBUFS,      SEE_SERV_OUT_OF_MEMORY     },
    { ENOMEM,       SEE_SERV_OUT_OF_MEMORY     },
};
static const size_t _NUM_ERRNO_ERRORS = sizeof(_ERRNO_ERRORS) / sizeof(IntErrPair);

static const IntErrPair _GAI_ERRORS[] =
{
    { EAI_AGAIN,    SEE_SERV_TEMPORARY_FAILURE },
    { EAI_FAIL,     SEE_SERV_PERMANENT_FAILURE },
    { EAI_MEMORY,   SEE_SERV_OUT_OF_MEMORY     }
};
static const size_t _NUM_GAI_ERRORS = sizeof(_GAI_ERRORS) / sizeof(IntErrPair);

static SeeServError _see_serv_handle_errno(const char *function, int no)
{
    SeeServError ret = SEE_SERV_PLATFORM_ERROR;

    for (size_t i = 0; i < _NUM_ERRNO_ERRORS; ++i)
    {
        IntErrPair pair = _ERRNO_ERRORS[i];
        if (pair.no == no)
        {
            ret = pair.err;
            break;
        }
    }

    _see_serv_log_write(function, "%s", strerror(no));
    return ret;
}

static SeeServError _see_serv_handle_gai(const char *function, int no)
{
    SeeServError ret = SEE_SERV_PLATFORM_ERROR;

    for (size_t i = 0; i < _NUM_GAI_ERRORS; ++i)
    {
        IntErrPair pair = _GAI_ERRORS[i];
        if (pair.no == no)
        {
            ret = pair.err;
            break;
        }
    }

    _see_serv_log_write(function, "%s", gai_strerror(no));
    return ret;
}

struct _SeeServer
{
    char *hostname;
    uint16_t port;
    uint32_t num_workers;
    uint32_t max_connections;

    int fd;

    pthread_t main_thread;
    Vector worker_threads;

    int waiting;
    _Atomic(int) running;

    Vector accepted_clients;
    pthread_mutex_t acc_mut;
    pthread_cond_t acc_cond;

    Vector client_handlers;
    pthread_rwlock_t client_hdl_lock;
};

SeeServError see_server_create(const SeeServerConfig *config, SeeServer **server)
{
    assert(config != NULL);
    assert(server != NULL);

    *server = NULL;

    int fd;
    
    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        return _see_serv_handle_errno("see_server_create:open socket", errno);

    int reuse = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
        return _see_serv_handle_errno("see_server_create:set reuse address to true", errno);

    struct addrinfo hints, *addr;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;
    hints.ai_flags = AI_V4MAPPED | AI_NUMERICSERV;

    char port_str[6];
    sprintf(port_str, "%hu", config->port);

    int gai_error = getaddrinfo(config->hostname, port_str, &hints, &addr);
    if (gai_error < 0)
    {
        close(fd);
        return _see_serv_handle_gai("see_server_create:get address info", gai_error);
    }

    int bind_error = bind(fd, addr->ai_addr, addr->ai_addrlen);
    freeaddrinfo(addr);
    if (bind_error < 0)
    {
        close(fd);
        return _see_serv_handle_errno("see_server_create:bind socket address", errno);
    }

    SeeServer *s = malloc(sizeof(SeeServer));
    s->fd = fd;
    s->running = 0;
    
    s->hostname = strdup(config->hostname);
    s->port = config->port;
    s->num_workers = config->num_workers == 0? SEE_SERVER_DEFAULT_NUM_WORKERS : config->num_workers;
    s->max_connections = config->max_connections == 0? SEE_SERVER_DEFAULT_MAX_CONNECTIONS : config->max_connections;

    vector_create(&s->worker_threads, sizeof(pthread_t));
    vector_create(&s->accepted_clients, sizeof(int));
    pthread_mutex_init(&s->acc_mut, NULL);
    pthread_cond_init(&s->acc_cond, NULL);

    vector_create(&s->client_handlers, sizeof(SeeServClientHandler));
    pthread_rwlock_init(&s->client_hdl_lock, NULL);

    *server = s;

    return SEE_SERV_NONE;
}

SeeServError see_server_query_config(const SeeServer *server, SeeServerConfig *config)
{
    assert(server != NULL);
    assert(config != NULL);

    SeeServerConfig src =
    {
        .hostname=server->hostname,
        .port=server->port,
        .max_connections=server->max_connections
    };

    memcpy(config, &src, sizeof(SeeServerConfig));
    return SEE_SERV_NONE;
}

static void *_see_server_main_thread(void *arg)
{
    SeeServer *server = (SeeServer*)arg;

    while (server->running)
    {
        int client_fd;
        if ((client_fd = accept(server->fd, NULL, NULL)) < 0)
        {
            if (errno == EINTR && !server->running)
                return (void*)EXIT_SUCCESS;
            else
                _see_serv_log_write("see_server_listen:main thread:accept connection", "%s", strerror(errno));
        }

        _see_serv_log_write("see_server_listen:main thread", "Client %i received", client_fd);

        pthread_mutex_lock(&server->acc_mut);
        vector_push_back(&server->accepted_clients, &client_fd);
        pthread_cond_signal(&server->acc_cond);
        pthread_mutex_unlock(&server->acc_mut);
    }

    return (void*)EXIT_SUCCESS;
}

static void _see_server_handle_client(SeeServer *server, int fd);

static void *_see_server_worker_thread(void *arg)
{
    SeeServer *server = (SeeServer*)arg;

    while (server->running)
    {
        pthread_mutex_lock(&server->acc_mut);

        if (!server->running)
        {
            pthread_mutex_unlock(&server->acc_mut);
            return (void*)EXIT_SUCCESS;
        }

        while (server->accepted_clients.size == 0 && server->running)
            pthread_cond_wait(&server->acc_cond, &server->acc_mut);
        
        if (!server->running)
        {
            pthread_mutex_unlock(&server->acc_mut);
            return (void*)EXIT_SUCCESS;
        }
        
        int fd;
        vector_pop_front(&server->accepted_clients, &fd);
        pthread_mutex_unlock(&server->acc_mut);

        _see_server_handle_client(server, fd);
    }

    return (void*)EXIT_SUCCESS;
}

static void _see_server_handle_client(SeeServer *server, int fd)
{
    pthread_rwlock_rdlock(&server->client_hdl_lock);
    for (size_t i = 0; i < server->client_handlers.size; ++i)
    {
        SeeServClientHandler handler;
        vector_query(&server->client_handlers, i, &handler);
        int res = handler.handle_client(server, (SeeServClientID)fd, handler.userdata);
        switch (res)
        {
            case SEE_SERV_HANDLED:
                pthread_rwlock_unlock(&server->client_hdl_lock);
                close(fd);
                return;

            case SEE_SERV_FALLTHROUGH:
                break;
            
            default:
                _see_serv_log_write("see_server_listen:worker thread:client handler", "Client handlers must return SEE_SERV_HANDLED or SEE_SERV_FALLTHROUGH. Falling through by default");
                break;
        }
    }
    pthread_rwlock_unlock(&server->client_hdl_lock);
    _see_serv_log_write("see_server_listen:worker thread:close client connection", "Unhandled client. Must provide default handler");
    close(fd);
}

SeeServError see_server_listen(SeeServer *server)
{
    assert(server != NULL);

    if (listen(server->fd, (int)server->max_connections) < 0)
        return _see_serv_handle_errno("see_server_listen", errno);

    server->running = 1;
    for (size_t i = 0; i < server->num_workers; ++i)
    {
        pthread_t worker;
        pthread_create(&worker, NULL, &_see_server_worker_thread, server);
        vector_push_back(&server->worker_threads, &worker);
    }

    pthread_create(&server->main_thread, NULL, &_see_server_main_thread, server);

    server->waiting = 0;

    return SEE_SERV_NONE;
}

SeeServError see_server_add_client_handler(SeeServer *server, const SeeServClientHandler *handler)
{
    assert(server != NULL);
    assert(handler != NULL);

    pthread_rwlock_wrlock(&server->client_hdl_lock);
    vector_push_back(&server->client_handlers, handler);
    pthread_rwlock_unlock(&server->client_hdl_lock);

    return SEE_SERV_NONE;
}

SeeServError see_server_send_data(SeeServer *server, SeeServClientID id, size_t len, const void *data)
{
    assert(server != NULL);
    assert(data != NULL);

    ssize_t sent;
    const int8_t *buff = (const int8_t*)data;
    size_t remaining = len;
    while (remaining > 0 && (sent = write((int)id, buff, remaining)) > 0)
    {
        buff += sent;
        remaining -= (size_t)sent;
    }

    if (sent < 0)
    {
        if (errno == EINVAL || errno == EBADF)
        {
            _see_serv_log_write("see_server_send_data", "Invalid SeeServClientID given [%s]", strerror(errno));
            return SEE_SERV_API_USAGE;
        }

        return _see_serv_handle_errno("see_server_send_data", errno);
    }
    
    return SEE_SERV_NONE;
}

SeeServError see_server_read_data(SeeServer *server, SeeServClientID id, size_t *len, void *buff)
{
    assert(server != NULL);
    assert(len != NULL);
    assert(buff != NULL);

    ssize_t num_read = read((int)id, buff, *len);
    if (num_read < 0)
    {
        if (errno == EINVAL || errno == EBADF)
        {
            _see_serv_log_write("see_server_read_data", "Invalid SeeServClientID given [%s]", strerror(errno));
            return SEE_SERV_API_USAGE;
        }

        return _see_serv_handle_errno("see_server_read_data", errno);
    }

    *len = num_read;
    return SEE_SERV_NONE;
}

SeeServError see_server_wait(SeeServer *server)
{
    assert(server != NULL);

    server->waiting = 1;
    pthread_join(server->main_thread, NULL);

    return SEE_SERV_NONE;
}

SeeServError see_server_destroy(SeeServer *server)
{
    if (!server)
        return SEE_SERV_NONE;
    
    if (!server->waiting)
    {
        server->running = 0;
        pthread_cancel(server->main_thread);
        pthread_join(server->main_thread, NULL);

        pthread_mutex_lock(&server->acc_mut);
        pthread_cond_broadcast(&server->acc_cond);
        pthread_mutex_unlock(&server->acc_mut);

        for (size_t i = 0; i < server->num_workers; ++i)
        {
            pthread_t worker;
            vector_query(&server->worker_threads, i, &worker);
            pthread_join(worker, NULL);
        }
    }

    SeeServError err = SEE_SERV_NONE;

    if (shutdown(server->fd, SHUT_RDWR) < 0 || close(server->fd) < 0)
        err = _see_serv_handle_errno("see_server_destroy:shutdown server", errno);

    vector_destroy(&server->accepted_clients);
    pthread_mutex_destroy(&server->acc_mut);
    pthread_cond_destroy(&server->acc_cond);

    vector_destroy(&server->worker_threads);

    vector_destroy(&server->client_handlers);
    pthread_rwlock_destroy(&server->client_hdl_lock);

    free(server->hostname);
    free(server);

    return err;
}