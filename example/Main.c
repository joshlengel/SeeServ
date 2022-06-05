#include"SeeServ/SeeServ.h"
#include"SeeServ/SeeServHTTP.h"

#include<stdio.h>
#include<stdlib.h>
#include<signal.h>
#include<string.h>

int handle_request(const SeeServHTTPRequest *req, SeeServHTTPResponse *res, void *userdata)
{
    printf("Request made to %s\n", req->uri);
    const char *directory = (const char*)userdata;
    const char *file = strcmp(req->uri, "/") == 0? "/index" : req->uri;
    const char *extension = strrchr(req->uri, '.');

    const char *content_type = NULL;

    res->status = SEE_SERV_HTTP_STATUS_BAD_REQUEST;

    if (strstr(file, ".."))
        return SEE_SERV_HANDLED;

    if (extension == NULL || strcmp(extension, ".html") == 0)
    {
        extension = ".html";
        content_type = "text/html";
    }
    else if (strcmp(extension, ".js") == 0)
    {
        content_type = "application/javascript";
        extension = "";
    }
    else if (strcmp(extension, ".css") == 0)
    {
        content_type = "text/css";
        extension = "";
    }
    else
    {
        return SEE_SERV_HANDLED;
    }

    char *path = malloc(strlen(directory) + strlen(file) + strlen(extension) + 1);
    memcpy(path, directory, strlen(directory));
    memcpy(path + strlen(directory), file, strlen(file));
    memcpy(path + strlen(directory) + strlen(file), extension, strlen(extension));
    path[strlen(directory) + strlen(file) + strlen(extension)] = '\0';

    FILE *f = fopen(path, "r");
    if (!f)
    {
        res->status = SEE_SERV_HTTP_STATUS_NOT_FOUND;
        return SEE_SERV_HANDLED;
    }

    fseek(f, 0, SEEK_END);
    size_t content_length = (size_t)ftell(f);
    fseek(f, 0, SEEK_SET);

    char *buff = malloc(content_length);
    fread(buff, 1, content_length, f);
    fclose(f);

    res->status = SEE_SERV_HTTP_STATUS_OK;

    see_serv_http_headers_set(res->headers, SEE_SERV_HTTP_HEADER_CONTENT_TYPE, content_type);
    see_serv_http_set_response_body(res, content_length, buff);
    free(buff);

    return SEE_SERV_HANDLED;
}

int main(int argc, char **argv)
{
    if (argc != 3)
    {
        printf("Usage: ./SeeServExample [log file] [page dir]\n");
        return EXIT_FAILURE;
    }

    FILE *log = fopen(argv[1], "w");
    if (!log)
    {
        perror("Error opening log file: ");
        raise(SIGABRT);
    }

    see_serv_set_log_file(log);

    // Server
    SeeServerConfig conf;
    memset(&conf, 0, sizeof(conf));
    conf.hostname = "0.0.0.0";
    conf.port = 9090;

    SeeServer *server;
    see_server_create(&conf, &server);

    // HTTP layer
    SeeServHTTPLayerConfig http_config;
    http_config.userdata = argv[2];
    http_config.handle_request = &handle_request;

    SeeServHTTPLayer *http_layer;
    see_serv_http_layer_create(&http_config, &http_layer);

    SeeServClientHandler handler;
    see_serv_http_layer_init_handler(http_layer, &handler);
    see_server_add_client_handler(server, &handler);

    // Listen
    see_server_listen(server);
    fgetc(stdin);

    // Clean up
    see_server_destroy(server);

    see_serv_http_layer_destroy(http_layer);

    fclose(log);
}