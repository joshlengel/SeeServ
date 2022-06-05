#include"SeeServ/SeeServHTTP.h"
#include"SeeServUtils.h"
#include"SeeServLog.h"

#include<string.h>
#include<stdlib.h>
#include<assert.h>

static const char *const _HTTP_VERSION_STRS[] =
{
    [SEE_SERV_HTTP_VERSION_1_0] = "HTTP/1.0",
    [SEE_SERV_HTTP_VERSION_1_1] = "HTTP/1.1",
    [SEE_SERV_HTTP_VERSION_2_0] = "HTTP/2.0"
};

static const char *const _HTTP_METHOD_STRS[] =
{
    [SEE_SERV_HTTP_METHOD_CONNECT] = "CONNECT",
    [SEE_SERV_HTTP_METHOD_DELETE]  = "DELETE",
    [SEE_SERV_HTTP_METHOD_GET]     = "GET",
    [SEE_SERV_HTTP_METHOD_HEAD]    = "HEAD",
    [SEE_SERV_HTTP_METHOD_OPTIONS] = "OPTIONS",
    [SEE_SERV_HTTP_METHOD_PATCH]   = "PATCH",
    [SEE_SERV_HTTP_METHOD_POST]    = "POST",
    [SEE_SERV_HTTP_METHOD_PUT]     = "PUT",
    [SEE_SERV_HTTP_METHOD_TRACE]   = "TRACE"
};

static const char *const _HTTP_STATUS_STRS[] =
{
    [SEE_SERV_HTTP_STATUS_CONTINUE]                        = "Continue",
    [SEE_SERV_HTTP_STATUS_SWITCHING_PROTOCOLS]             = "Switching Protocols",
    [SEE_SERV_HTTP_STATUS_EARLY_HINTS]                     = "Early Hints",
    [SEE_SERV_HTTP_STATUS_OK]                              = "Ok",
    [SEE_SERV_HTTP_STATUS_CREATED]                         = "Created",
    [SEE_SERV_HTTP_STATUS_ACCEPTED]                        = "Accepted",
    [SEE_SERV_HTTP_STATUS_NON_AUTHORITATIVE_INFORMATION]   = "Non Authoritative Information",
    [SEE_SERV_HTTP_STATUS_NO_CONTENT]                      = "No Content",
    [SEE_SERV_HTTP_STATUS_RESET_CONTENT]                   = "Reset Content",
    [SEE_SERV_HTTP_STATUS_PARTIAL_CONTENT]                 = "Partial Content",
    [SEE_SERV_HTTP_STATUS_MULTIPLE_CHOICES]                = "Multiple Choices",
    [SEE_SERV_HTTP_STATUS_MOVED_PERMANENTLY]               = "Moved Permanently",
    [SEE_SERV_HTTP_STATUS_FOUND]                           = "Found",
    [SEE_SERV_HTTP_STATUS_SEE_OTHER]                       = "See Other",
    [SEE_SERV_HTTP_STATUS_NOT_MODIFIED]                    = "Not Modified",
    [SEE_SERV_HTTP_STATUS_TEMPORARY_REDIRECT]              = "Temporary Redirect",
    [SEE_SERV_HTTP_STATUS_PERMANENT_REDIRECT]              = "Permanent Redirect",
    [SEE_SERV_HTTP_STATUS_BAD_REQUEST]                     = "Bad Request",
    [SEE_SERV_HTTP_STATUS_UNAUTHORIZED]                    = "Unauthorized",
    [SEE_SERV_HTTP_STATUS_PAYMENT_REQUIRED]                = "Payment Required",
    [SEE_SERV_HTTP_STATUS_FORBIDDEN]                       = "Forbidden",
    [SEE_SERV_HTTP_STATUS_NOT_FOUND]                       = "Not Found",
    [SEE_SERV_HTTP_STATUS_METHOD_NOT_ALLOWED]              = "Method Not Allowed",
    [SEE_SERV_HTTP_STATUS_NOT_ACCEPTABLE]                  = "Not Acceptable",
    [SEE_SERV_HTTP_STATUS_PROXY_AUTHENTICATION_REQUIRED]   = "Proxy Authentication Required",
    [SEE_SERV_HTTP_STATUS_REQUEST_TIMEOUT]                 = "Request Timeout",
    [SEE_SERV_HTTP_STATUS_CONFLICT]                        = "Conflict",
    [SEE_SERV_HTTP_STATUS_GONE]                            = "Gone",
    [SEE_SERV_HTTP_STATUS_LENGTH_REQUIRED]                 = "Length Required",
    [SEE_SERV_HTTP_STATUS_PRECONDITION_FAILED]             = "Precondition Failed",
    [SEE_SERV_HTTP_STATUS_PAYLOAD_TOO_LARGE]               = "Payload Too Large",
    [SEE_SERV_HTTP_STATUS_URI_TOO_LONG]                    = "Uri Too Long",
    [SEE_SERV_HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE]          = "Unsupported Media Type",
    [SEE_SERV_HTTP_STATUS_RANGE_NOT_SATISFIABLE]           = "Range Not Satisfiable",
    [SEE_SERV_HTTP_STATUS_EXPECTATION_FAILED]              = "Expectation Failed",
    [SEE_SERV_HTTP_STATUS_IM_A_TEAPOT]                     = "I'm A Teapot",
    [SEE_SERV_HTTP_STATUS_UNPROCESSABLE_ENTITY]            = "Unprocessable Entity",
    [SEE_SERV_HTTP_STATUS_TOO_EARLY]                       = "Too Early",
    [SEE_SERV_HTTP_STATUS_UPGRADE_REQUIRED]                = "Upgrade Required",
    [SEE_SERV_HTTP_STATUS_PRECONDITION_REQUIRED]           = "Precondition Required",
    [SEE_SERV_HTTP_STATUS_TOO_MANY_REQUESTS]               = "Too Many Requests",
    [SEE_SERV_HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE] = "Request Header Fields Too Large",
    [SEE_SERV_HTTP_STATUS_UNAVAILABLE_FOR_LEGAL_REASONS]   = "Unavailable For Legal Reasons",
    [SEE_SERV_HTTP_STATUS_INTERNAL_SERVER_ERROR]           = "Internal Server Error",
    [SEE_SERV_HTTP_STATUS_NOT_IMPLEMENTED]                 = "Not Implemented",
    [SEE_SERV_HTTP_STATUS_BAD_GATEWAY]                     = "Bad Gateway",
    [SEE_SERV_HTTP_STATUS_SERVICE_UNAVAILABLE]             = "Service Unavailable",
    [SEE_SERV_HTTP_STATUS_GATEWAY_TIMEOUT]                 = "Gateway Timeout",
    [SEE_SERV_HTTP_STATUS_HTTP_VERSION_NOT_SUPPORTED]      = "Http Version Not Supported",
    [SEE_SERV_HTTP_STATUS_VARIANT_ALSO_NEGOTIATES]         = "Variant Also Negotiates",
    [SEE_SERV_HTTP_STATUS_INSUFFICIENT_STORAGE]            = "Insufficient Storage",
    [SEE_SERV_HTTP_STATUS_LOOP_DETECTED]                   = "Loop Detected",
    [SEE_SERV_HTTP_STATUS_NOT_EXTENDED]                    = "Not Extended",
    [SEE_SERV_HTTP_STATUS_NETWORK_AUTHENTICATION_REQUIRED] = "Network Authentication Required"
};

const char *see_serv_http_version_str(SeeServHTTPVersion version)
{
    return _HTTP_VERSION_STRS[version];
}

const char *see_serv_http_method_str(SeeServHTTPMethod method)
{
    return _HTTP_METHOD_STRS[method];
}

const char *see_serv_http_status_str(SeeServHTTPStatus status)
{
    return _HTTP_STATUS_STRS[status];
}

struct _SeeServHTTPHeaders
{
    Vector arr;
};

static void _see_serv_http_headers_create(SeeServHTTPHeaders **headers)
{
    assert(headers != NULL);

    SeeServHTTPHeaders *h = malloc(sizeof(SeeServHTTPHeaders));
    vector_create(&h->arr, sizeof(SeeServHTTPHeader));
    *headers = h;
}

static void _see_serv_http_headers_destroy(SeeServHTTPHeaders *headers)
{
    assert(headers != NULL);

    vector_destroy(&headers->arr);
    free(headers);
}

size_t see_serv_http_headers_size(const SeeServHTTPHeaders *headers)
{
    assert(headers != NULL);

    return headers->arr.size;
}

const char *see_serv_http_headers_get(const SeeServHTTPHeaders *headers, const char *name)
{
    assert(headers != NULL);
    assert(name != NULL);

    for (size_t i = 0; i < headers->arr.size; ++i)
    {
        SeeServHTTPHeader header;
        vector_query(&headers->arr, i, &header);
        if (strcasecmp(header.name, name) == 0)
            return header.value;
    }

    return NULL;
}

void see_serv_http_headers_query(const SeeServHTTPHeaders *headers, size_t i, SeeServHTTPHeader *header)
{
    assert(headers != NULL);
    assert(header != NULL);

    vector_query(&headers->arr, i, header);
}

void see_serv_http_headers_set(SeeServHTTPHeaders *headers, const char *name, const char *value)
{
    assert(headers != NULL);
    assert(name != NULL);
    assert(value != NULL);

    for (size_t i = 0; i < headers->arr.size; ++i)
    {
        SeeServHTTPHeader *header = (SeeServHTTPHeader*)vector_get(&headers->arr, i);
        if (strcasecmp(header->name, name) == 0)
        {
            free((char*)header->value);
            free((char*)header->name);
            header->name = strdup(name);
            header->value = strdup(value);
            return;
        }
    }

    SeeServHTTPHeader header = { strdup(name), strdup(value) };
    vector_push_back(&headers->arr, &header);
}

void see_serv_http_headers_remove(SeeServHTTPHeaders *headers, const char *name)
{
    assert(headers != NULL);
    assert(name != NULL);

    for (size_t i = 0; i < headers->arr.size; ++i)
    {
        SeeServHTTPHeader header;
        vector_query(&headers->arr, i, &header);
        if (strcasecmp(header.name, name) == 0)
        {
            free((char*)header.name);
            free((char*)header.value);
            vector_remove(&headers->arr, i);
            return;
        }
    }
}

struct _SeeServHTTPResponseBody
{
    size_t length;
    const void *data;
};

void see_serv_http_set_response_body(SeeServHTTPResponse *response, size_t length, const void *body)
{
    assert(response != NULL);

    response->body->length = length;

    if (length > 0)
    {
        void *data = malloc(length);
        memcpy(data, body, length);
        response->body->data = data;
    }
}

static int _see_serv_http_handler(SeeServer *server, SeeServClientID id, void *userdata);

struct _SeeServHTTPLayer
{
    SeeServHTTPLayerConfig config;
};

void see_serv_http_layer_create(const SeeServHTTPLayerConfig *config, SeeServHTTPLayer **layer)
{
    assert(config != NULL);
    assert(layer != NULL);

    SeeServHTTPLayer *l = malloc(sizeof(SeeServHTTPLayer));
    l->config = *config;

    *layer = l;
}

void see_serv_http_layer_init_handler(SeeServHTTPLayer *layer, SeeServClientHandler *handler)
{
    assert(layer != NULL);
    assert(handler != NULL);

    handler->handle_client = &_see_serv_http_handler;
    handler->userdata = &layer->config;
}

void see_serv_http_layer_destroy(SeeServHTTPLayer *layer)
{
    free(layer);
}

#define HTTP_HANDLER_BUFSIZE 1024
#define HTTP_HANDLER_RECEIVE_TIMEOUT 10

// Linux
#include<unistd.h>
#include<errno.h>
#include<stdlib.h>

static void _see_serv_http_request_cleanup(SeeServHTTPRequest *req)
{
    assert(req != NULL);

    free((char*)req->uri);

    for (size_t i = 0; i < see_serv_http_headers_size(req->headers); ++i)
    {
        SeeServHTTPHeader header;
        see_serv_http_headers_query(req->headers, i, &header);
        free((char*)header.name);
        free((char*)header.value);
    }

    _see_serv_http_headers_destroy((SeeServHTTPHeaders*)req->headers);
}

static void _see_serv_http_response_cleanup(SeeServHTTPResponse *res)
{
    assert(res != NULL);
    
    for (size_t i = 0; i < see_serv_http_headers_size(res->headers); ++i)
    {
        SeeServHTTPHeader header;
        see_serv_http_headers_query(res->headers, i, &header);
        free((char*)header.name);
        free((char*)header.value);
    }

    _see_serv_http_headers_destroy((SeeServHTTPHeaders*)res->headers);
    free((void*)res->body->data);
    free(res->body);
}

#define _SEE_SERV_HTTP_SEND(fd, ...) if (dprintf(fd, __VA_ARGS__) < 0) { _see_serv_log_write("see_server_listen:worker thread:http handler:write", "%s", strerror(errno)); goto cleanup; }

static int _see_serv_http_handler(SeeServer *server, SeeServClientID id, void *userdata)
{
    (void)server;

    const SeeServHTTPLayerConfig *config = (const SeeServHTTPLayerConfig*)userdata;

    // Parse status line
    char *buff = malloc(HTTP_HANDLER_BUFSIZE);
    size_t offset = 0;
    size_t remaining = HTTP_HANDLER_BUFSIZE;

    int status_line_complete = 0;
    int headers_complete = 0;
    int body_complete = 0;

    int read_success = 1;
    SeeServHTTPRequest req;
    memset(&req, 0, sizeof(req));
    _see_serv_http_headers_create((SeeServHTTPHeaders**)&req.headers);

    while (!(status_line_complete && headers_complete && body_complete))
    {
        ssize_t bytes_read = read((int)id, buff + offset, remaining);
        if (bytes_read < 0)
        {
            _see_serv_log_write("see_server_listen:worker thread:http handler:read", "%s", strerror(errno));
            _see_serv_http_request_cleanup(&req);
            free(buff);
            return SEE_SERV_HANDLED;
        }

        offset += (size_t)bytes_read;
        remaining -= (size_t)bytes_read;

        if (!status_line_complete)
        {
            size_t status_line_len;
            size_t uri_offset = 0;
            size_t version_offset = 0;
            for (size_t i = 0; i < offset; ++i)
            {
                if (buff[i] == ' ')
                {
                    if (uri_offset && !version_offset)
                        version_offset = i + 1;
                    else if (!uri_offset)
                        uri_offset = i + 1;
                }

                size_t buf_len = offset - i;
                if (strncmp(buff + i, "\r\n", buf_len < 2? buf_len : 2) == 0)
                {
                    status_line_complete = 1;
                    status_line_len = i;
                    break;
                }
            }

            if (status_line_complete)
            {
                if (!(uri_offset && version_offset))
                {
                    _see_serv_log_write("see_server_listen:worker thread:http handler:read", "Malformed request. Sending BAD REQUEST (400) back");
                    read_success = 0;
                    break;
                }

                // Parse status line
                char *method = buff;
                size_t method_len = uri_offset - 1;
                
                char *uri = buff + uri_offset;
                size_t uri_len = version_offset - uri_offset - 1;

                char *version = buff + version_offset;
                size_t version_len = status_line_len - version_offset;

                req.uri = malloc(uri_len + 1);
                memcpy((char*)req.uri, uri, uri_len);
                ((char*)req.uri)[uri_len] = '\0';

                if (strncmp(method,      "CONNECT", method_len) == 0) req.method = SEE_SERV_HTTP_METHOD_CONNECT;
                else if (strncmp(method, "DELETE",  method_len) == 0) req.method = SEE_SERV_HTTP_METHOD_DELETE;
                else if (strncmp(method, "GET",     method_len) == 0) req.method = SEE_SERV_HTTP_METHOD_GET;
                else if (strncmp(method, "HEAD",    method_len) == 0) req.method = SEE_SERV_HTTP_METHOD_HEAD;
                else if (strncmp(method, "OPTIONS", method_len) == 0) req.method = SEE_SERV_HTTP_METHOD_OPTIONS;
                else if (strncmp(method, "PATCH",   method_len) == 0) req.method = SEE_SERV_HTTP_METHOD_PATCH;
                else if (strncmp(method, "POST",    method_len) == 0) req.method = SEE_SERV_HTTP_METHOD_POST;
                else if (strncmp(method, "PUT",     method_len) == 0) req.method = SEE_SERV_HTTP_METHOD_PUT;
                else if (strncmp(method, "TRACE",   method_len) == 0) req.method = SEE_SERV_HTTP_METHOD_TRACE;
                else
                {
                    _see_serv_log_write("see_server_listen:worker thread:http handler:read", "Invalid method. Sending BAD REQUEST (400) back");
                    read_success = 0;
                    break;
                }

                if (strncmp(version,      "HTTP/1.0", version_len) == 0) req.version = SEE_SERV_HTTP_VERSION_1_0;
                else if (strncmp(version, "HTTP/1.1", version_len) == 0) req.version = SEE_SERV_HTTP_VERSION_1_1;
                else if (strncmp(version, "HTTP/2.0", version_len) == 0) req.version = SEE_SERV_HTTP_VERSION_2_0;
                else
                {
                    _see_serv_log_write("see_server_listen:worker thread:http handler:read", "Invalid http version. Sending BAD REQUEST (400) back");
                    read_success = 0;
                    break;
                }

                size_t num_read = offset - (status_line_len + 2);
                memmove(buff, buff + offset - num_read, num_read);
                remaining = offset + remaining - num_read;
                offset = num_read;
            }
        }

        if (status_line_complete && !headers_complete)
        {
            size_t headers_len;

            for (size_t i = 0; i < offset; ++i)
            {
                size_t buf_len = offset - i;
                if (strncmp(buff + i, "\r\n\r\n", buf_len < 4? buf_len : 4) == 0)
                {
                    headers_len = i;
                    headers_complete = 1;
                    break;
                }
            }

            if (headers_complete)
            {
                size_t header_offset = 0;

                while (header_offset < headers_len)
                {
                    int header_complete = 0;

                    size_t name_offset = header_offset;
                    size_t value_offset = 0;

                    for (size_t i = header_offset; i < offset; ++i)
                    {
                        if (buff[i] == ':' && !value_offset)
                            value_offset = i + 2;

                        size_t buf_len = offset - i;
                        if (strncmp(buff + i, "\r\n", buf_len < 2? buf_len : 2) == 0)
                        {
                            header_complete = 1;
                            header_offset = i + 2;
                            break;
                        }
                    }

                    if (!header_complete || !value_offset)
                    {
                        _see_serv_log_write("see_server_listen:worker thread:http handler:read", "Malformed header. Sending BAD REQUEST (400) back");
                        read_success = 0;
                        break;
                    }

                    // Parse header line
                    char *name = buff + name_offset;
                    size_t name_len = value_offset - name_offset - 2;
                    name[name_len] = '\0';
                    
                    char *value = buff + value_offset;
                    size_t value_len = header_offset - value_offset - 2;
                    value[value_len] = '\0';

                    see_serv_http_headers_set((SeeServHTTPHeaders*)req.headers, name, value);

                    if (strcasecmp(name, SEE_SERV_HTTP_HEADER_CONTENT_LENGTH) == 0)
                    {
                        req.content_length = (size_t)strtoul(value, NULL, 10);
                    }
                }

                if (req.content_length == 0)
                    body_complete = 1;
                else
                {
                    size_t num_read = offset - (headers_len + 4);
                    memmove(buff, buff + offset - num_read, num_read);
                    remaining = offset + remaining - num_read;
                    offset = num_read;
                }
            }
        }

        if (headers_complete && !body_complete)
        {
            if (req.content_length <= offset)
            {
                body_complete = 1;
            }
        }
        
        if (remaining == 0 && !headers_complete)
        {
            char *tmp = buff;
            buff = realloc(buff, offset * 2);
            if (buff == NULL)
            {
                _see_serv_log_write("see_server_listen:worker thread:http handler", "No memory remaining");
                _see_serv_http_request_cleanup(&req);
                free(tmp);
                return SEE_SERV_HANDLED;
            }

            remaining = HTTP_HANDLER_BUFSIZE;
        }
    }

    req.content = buff;

    SeeServHTTPResponse res;
    _see_serv_http_headers_create(&res.headers);

    int ret = SEE_SERV_HANDLED;
    if (read_success)
    {
        res.status = SEE_SERV_HTTP_STATUS_NO_CONTENT;
        res.version = SEE_SERV_HTTP_VERSION_1_1;
        res.body = malloc(sizeof(SeeServHTTPResponseBody));
        res.body->length = 0;
        res.body->data = NULL;

        ret = config->handle_request(&req, &res, config->userdata);
    }
    else
    {
        res.status = SEE_SERV_HTTP_STATUS_BAD_REQUEST;
        res.version = SEE_SERV_HTTP_VERSION_1_1;
        res.body = malloc(sizeof(SeeServHTTPResponseBody));
        res.body->length = 0;
        res.body->data = NULL;
    }

    char content_length_str[10];
    snprintf(content_length_str, sizeof(content_length_str), "%lu", (unsigned long)res.body->length);
    see_serv_http_headers_set(res.headers, SEE_SERV_HTTP_HEADER_CONTENT_LENGTH, content_length_str);

    free(buff);
    _see_serv_http_request_cleanup(&req);

    // Write response
    _SEE_SERV_HTTP_SEND((int)id, "%s %i %s\r\n", see_serv_http_version_str(res.version), (int)res.status, see_serv_http_status_str(res.status))

    for (size_t i = 0; i < see_serv_http_headers_size(res.headers); ++i)
    {
        SeeServHTTPHeader header;
        see_serv_http_headers_query(res.headers, i, &header);
        _SEE_SERV_HTTP_SEND((int)id, "%s: %s\r\n", header.name, header.value);
    }

    _SEE_SERV_HTTP_SEND((int)id, "\r\n%.*s", (int)res.body->length, (const char*)res.body->data);

cleanup:
    _see_serv_http_response_cleanup(&res);

    return ret;
}