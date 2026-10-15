// HTTP parsing + response helpers (§5.8). The broker reads only the request
// line and headers (the body stays in the socket for the upstream forwarder)
// and speaks enough HTTP/1.1 to proxy a guest request.

#include "broker.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static char* trim(char* s) {
    while (*s && isspace((unsigned char)*s)) s++;
    if (*s == '\0') return s;
    char* end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

static int name_eq(const char* a, const char* b) {
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

int http_parse_headers(int fd, http_request_t* out) {
    if (fd < 0 || !out) {
        errno = EINVAL;
        return -1;
    }
    char buf[HTTP_MAX_HEADER_BYTES];
    size_t len = 0;
    int match = 0;  // progress through the \r\n\r\n terminator
    for (;;) {
        if (len + 1 >= sizeof(buf)) {
            errno = EMSGSIZE;
            return -1;
        }
        char ch;
        ssize_t r = recv(fd, &ch, 1, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return -1;  // EOF before the header block completed
        buf[len++] = ch;
        if ((match == 0 && ch == '\r') || (match == 1 && ch == '\n') ||
            (match == 2 && ch == '\r') || (match == 3 && ch == '\n')) {
            if (++match == 4) break;
        } else {
            match = (ch == '\r') ? 1 : 0;
        }
    }
    buf[len] = '\0';

    memset(out, 0, sizeof(*out));
    char* save = NULL;
    char* line = strtok_r(buf, "\r\n", &save);
    if (!line) return -1;
    if (sscanf(line, "%15s %2047s %15s", out->method, out->target, out->version) != 3)
        return -1;
    if (out->method[0] == '\0' || out->target[0] == '\0') return -1;

    while ((line = strtok_r(NULL, "\r\n", &save)) != NULL) {
        if (out->nheaders >= HTTP_MAX_HEADERS) {
            errno = EMSGSIZE;
            return -1;
        }
        char* colon = strchr(line, ':');
        if (!colon) continue;  // tolerate a stray line rather than 400
        *colon = '\0';
        char* name = trim(line);
        char* value = trim(colon + 1);
        snprintf(out->headers[out->nheaders].name, HTTP_MAX_NAME, "%s", name);
        snprintf(out->headers[out->nheaders].value, HTTP_MAX_VALUE, "%s", value);
        out->nheaders++;
    }
    return 0;
}

const char* http_get_header(const http_request_t* req, const char* name) {
    if (!req || !name) return NULL;
    for (size_t i = 0; i < req->nheaders; i++)
        if (name_eq(req->headers[i].name, name)) return req->headers[i].value;
    return NULL;
}

int http_set_header(http_request_t* req, const char* name, const char* value) {
    if (!req || !name || !value) {
        errno = EINVAL;
        return -1;
    }
    for (size_t i = 0; i < req->nheaders; i++) {
        if (name_eq(req->headers[i].name, name)) {
            snprintf(req->headers[i].value, HTTP_MAX_VALUE, "%s", value);
            return 0;
        }
    }
    if (req->nheaders >= HTTP_MAX_HEADERS) {
        errno = EMSGSIZE;
        return -1;
    }
    snprintf(req->headers[req->nheaders].name, HTTP_MAX_NAME, "%s", name);
    snprintf(req->headers[req->nheaders].value, HTTP_MAX_VALUE, "%s", value);
    req->nheaders++;
    return 0;
}

int http_remove_header(http_request_t* req, const char* name) {
    if (!req || !name) {
        errno = EINVAL;
        return -1;
    }
    for (size_t i = 0; i < req->nheaders; i++) {
        if (name_eq(req->headers[i].name, name)) {
            for (size_t j = i + 1; j < req->nheaders; j++)
                req->headers[j - 1] = req->headers[j];
            req->nheaders--;
            return 0;
        }
    }
    return 0;  // absent is success
}

static const char* reason_phrase(int code) {
    switch (code) {
        case 200: return "OK";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 500: return "Internal Server Error";
        case 502: return "Bad Gateway";
        case 504: return "Gateway Timeout";
        default: return "Error";
    }
}

int send_http_error(int fd, int code, const char* message) {
    if (fd < 0) {
        errno = EINVAL;
        return -1;
    }
    char body[512];
    int blen = snprintf(body, sizeof(body), "{\"error\":%d,\"message\":\"%s\"}\n",
                        code, message ? message : "");
    if (blen < 0) blen = 0;
    char head[512];
    int hlen = snprintf(head, sizeof(head),
                        "HTTP/1.1 %d %s\r\n"
                        "Content-Type: application/json\r\n"
                        "Content-Length: %d\r\n"
                        "Connection: close\r\n"
                        "\r\n",
                        code, reason_phrase(code), blen);
    if (hlen < 0) return -1;
    // One write of header+body keeps the response atomic on a blocking socket.
    char out[1024];
    if ((size_t)hlen + (size_t)blen > sizeof(out)) return -1;
    memcpy(out, head, (size_t)hlen);
    if (blen > 0) memcpy(out + hlen, body, (size_t)blen);
    size_t total = (size_t)hlen + (size_t)blen;
    size_t off = 0;
    while (off < total) {
        ssize_t w = send(fd, out + off, total - off, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)w;
    }
    return 0;
}
