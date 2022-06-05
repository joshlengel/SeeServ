#pragma once

#include<stdint.h>
#include<stddef.h>
#include<stdio.h>

// Errors
enum _SeeServError
{
    SEE_SERV_NONE = 0,
    SEE_SERV_PERMISSION_DENIED,
    SEE_SERV_UNSUPPORTED,
    SEE_SERV_CONNECTION_UNSUPPORTED,
    SEE_SERV_ADDRESS_IN_USE,
    SEE_SERV_PLATFORM_ERROR,
    SEE_SERV_OUT_OF_MEMORY,
    SEE_SERV_TEMPORARY_FAILURE,
    SEE_SERV_PERMANENT_FAILURE,
    SEE_SERV_API_USAGE

};
typedef enum _SeeServError SeeServError;

// Logging
void see_serv_set_log_file(FILE *file);

// Server
#define SEE_SERVER_DEFAULT_NUM_WORKERS 10
#define SEE_SERVER_DEFAULT_MAX_CONNECTIONS 4096

struct _SeeServer;
typedef struct _SeeServer SeeServer;

struct _SeeServerConfig
{
    const char *hostname;
    uint16_t port;
    uint32_t num_workers;
    uint32_t max_connections;
};
typedef struct _SeeServerConfig SeeServerConfig;

#define SEE_SERV_HANDLED 1
#define SEE_SERV_FALLTHROUGH 0

typedef int SeeServClientID;

struct _SeeServClientHandler
{
    void *userdata;
    int (*handle_client)(SeeServer *server, SeeServClientID id, void *userdata);
};
typedef struct _SeeServClientHandler SeeServClientHandler;

SeeServError see_server_create(const SeeServerConfig *config, SeeServer **server);
SeeServError see_server_query_config(const SeeServer *server, SeeServerConfig *config);
SeeServError see_server_add_client_handler(SeeServer *server, const SeeServClientHandler *handler);
SeeServError see_server_read_data(SeeServer *server, SeeServClientID id, size_t *len, void *buff);
SeeServError see_server_send_data(SeeServer *server, SeeServClientID id, size_t len, const void *data);
SeeServError see_server_listen(SeeServer *server);
SeeServError see_server_wait(SeeServer *server);
SeeServError see_server_destroy(SeeServer *server);