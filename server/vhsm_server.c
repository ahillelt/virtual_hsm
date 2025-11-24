#include "../include/vhsm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <openssl/rand.h>

/* Simple HTTP server for REST API */

#define DEFAULT_PORT 8443
#define MAX_CONNECTIONS 10
#define BUFFER_SIZE 65536

static int server_running = 1;
static vhsm_ctx_t global_ctx = NULL;

/* Signal handler for graceful shutdown */
void signal_handler(int signum) {
    printf("\nReceived signal %d, shutting down...\n", signum);
    server_running = 0;
}

/* Parse JSON request (simple implementation) */
static char* get_json_value(const char* json, const char* key) {
    static char value[1024];
    char search[256];
    snprintf(search, sizeof(search), "\"%s\":", key);

    const char* pos = strstr(json, search);
    if (!pos) {
        return NULL;
    }

    pos += strlen(search);
    while (*pos == ' ' || *pos == '\t') pos++;

    if (*pos == '"') {
        pos++;
        const char* end = strchr(pos, '"');
        if (!end) {
            return NULL;
        }
        size_t len = end - pos;
        if (len >= sizeof(value)) {
            len = sizeof(value) - 1;
        }
        memcpy(value, pos, len);
        value[len] = '\0';
        return value;
    }

    return NULL;
}

/* Handle HTTP request */
void handle_request(int client_sock) {
    char buffer[BUFFER_SIZE];
    char response[BUFFER_SIZE];

    ssize_t received = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
    if (received < 0) {
        close(client_sock);
        return;
    }

    buffer[received] = '\0';

    /* Parse request line */
    char method[16], path[256];
    sscanf(buffer, "%15s %255s", method, path);

    /* Find JSON body */
    char* body = strstr(buffer, "\r\n\r\n");
    if (body) {
        body += 4;
    }

    /* Route request */
    int status_code = 200;
    char content[BUFFER_SIZE];
    content[0] = '\0';

    if (strcmp(path, "/api/version") == 0 && strcmp(method, "GET") == 0) {
        snprintf(content, sizeof(content),
                 "{\"version\":\"%s\",\"status\":\"ok\"}", vhsm_version());

    } else if (strcmp(path, "/api/user/create") == 0 && strcmp(method, "POST") == 0) {
        if (!body) {
            status_code = 400;
            snprintf(content, sizeof(content),
                     "{\"error\":\"Missing request body\"}");
        } else {
            char* username = get_json_value(body, "username");
            char* password = get_json_value(body, "password");
            char* role_str = get_json_value(body, "role");

            if (!username || !password) {
                status_code = 400;
                snprintf(content, sizeof(content),
                         "{\"error\":\"Missing required fields\"}");
            } else {
                vhsm_role_t role = VHSM_ROLE_USER;
                if (role_str) {
                    if (strcmp(role_str, "admin") == 0) role = VHSM_ROLE_ADMIN;
                    else if (strcmp(role_str, "operator") == 0) role = VHSM_ROLE_OPERATOR;
                    else if (strcmp(role_str, "auditor") == 0) role = VHSM_ROLE_AUDITOR;
                }

                vhsm_error_t err = vhsm_user_create(global_ctx, username, password, NULL, role);
                if (err == VHSM_SUCCESS) {
                    snprintf(content, sizeof(content),
                             "{\"success\":true,\"username\":\"%s\"}", username);
                } else {
                    /* SECURITY: Don't expose internal error details */
                    status_code = 500;
                    snprintf(content, sizeof(content),
                             "{\"error\":\"Internal server error\"}");
                }
            }
        }

    } else if (strcmp(path, "/api/session/login") == 0 && strcmp(method, "POST") == 0) {
        if (!body) {
            status_code = 400;
            snprintf(content, sizeof(content),
                     "{\"error\":\"Missing request body\"}");
        } else {
            char* username = get_json_value(body, "username");
            char* password = get_json_value(body, "password");

            if (!username || !password) {
                status_code = 400;
                snprintf(content, sizeof(content),
                         "{\"error\":\"Missing required fields\"}");
            } else {
                vhsm_session_t session;
                vhsm_error_t err = vhsm_session_login(global_ctx, &session,
                                                       username, password, NULL);
                if (err == VHSM_SUCCESS) {
                    /* SECURITY: Generate secure random session ID instead of pointer */
                    uint8_t session_id_bytes[16];
                    RAND_bytes(session_id_bytes, sizeof(session_id_bytes));
                    char session_id_hex[33];
                    for (int i = 0; i < 16; i++) {
                        snprintf(session_id_hex + i*2, 3, "%02x", session_id_bytes[i]);
                    }
                    snprintf(content, sizeof(content),
                             "{\"success\":true,\"session_id\":\"%s\"}", session_id_hex);
                } else {
                    /* SECURITY: Generic auth error message */
                    status_code = 401;
                    snprintf(content, sizeof(content),
                             "{\"error\":\"Authentication failed\"}");
                }
            }
        }

    } else if (strcmp(path, "/api/key/generate") == 0 && strcmp(method, "POST") == 0) {
        status_code = 501;
        snprintf(content, sizeof(content),
                 "{\"error\":\"Not implemented yet\"}");

    } else {
        status_code = 404;
        snprintf(content, sizeof(content),
                 "{\"error\":\"Endpoint not found\"}");
    }

    /* Build HTTP response */
    const char* status_text = "OK";
    if (status_code == 400) status_text = "Bad Request";
    else if (status_code == 401) status_text = "Unauthorized";
    else if (status_code == 404) status_text = "Not Found";
    else if (status_code == 500) status_text = "Internal Server Error";
    else if (status_code == 501) status_text = "Not Implemented";

    /* SECURITY: Restrict CORS - configure allowed origins via environment variable */
    const char* allowed_origin = getenv("VHSM_ALLOWED_ORIGIN");
    if (!allowed_origin) {
        allowed_origin = "http://localhost:3000";  /* Default for development */
    }

    snprintf(response, sizeof(response),
             "HTTP/1.1 %d %s\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: %zu\r\n"
             "Access-Control-Allow-Origin: %s\r\n"
             "X-Content-Type-Options: nosniff\r\n"
             "X-Frame-Options: DENY\r\n"
             "Content-Security-Policy: default-src 'none'\r\n"
             "Connection: close\r\n"
             "\r\n"
             "%s",
             status_code, status_text, strlen(content), allowed_origin, content);

    send(client_sock, response, strlen(response), 0);
    close(client_sock);
}

/* Client handler thread */
void* client_thread(void* arg) {
    int client_sock = *(int*)arg;
    free(arg);

    handle_request(client_sock);

    return NULL;
}

int main(int argc, char* argv[]) {
    int port = DEFAULT_PORT;
    const char* storage_path = "./vhsm_storage";

    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) {
            if (i + 1 < argc) {
                port = atoi(argv[++i]);
                /* SECURITY: Validate port range */
                if (port < 1 || port > 65535) {
                    fprintf(stderr, "Error: Port must be between 1 and 65535\n");
                    return 1;
                }
            }
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--storage") == 0) {
            if (i + 1 < argc) {
                storage_path = argv[++i];
            }
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Virtual HSM REST API Server\n");
            printf("Usage: %s [options]\n", argv[0]);
            printf("Options:\n");
            printf("  -p, --port PORT      Server port (default: %d)\n", DEFAULT_PORT);
            printf("  -s, --storage PATH   Storage path (default: ./vhsm_storage)\n");
            printf("  -h, --help           Show this help\n");
            return 0;
        }
    }

    /* Initialize library */
    if (vhsm_init() != VHSM_SUCCESS) {
        fprintf(stderr, "Failed to initialize HSM library\n");
        return 1;
    }

    /* Create context */
    if (vhsm_ctx_create(&global_ctx, storage_path) != VHSM_SUCCESS) {
        fprintf(stderr, "Failed to create HSM context\n");
        vhsm_cleanup();
        return 1;
    }

    /* Generate or load master key */
    uint8_t master_key[32];
    if (vhsm_ctx_generate_master_key(global_ctx, master_key) != VHSM_SUCCESS) {
        fprintf(stderr, "Failed to generate master key\n");
        vhsm_ctx_destroy(global_ctx);
        vhsm_cleanup();
        return 1;
    }

    printf("Virtual HSM REST API Server v%s\n", vhsm_version());
    printf("Listening on port %d\n", port);
    printf("Storage path: %s\n", storage_path);

    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Create socket */
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("socket");
        vhsm_ctx_destroy(global_ctx);
        vhsm_cleanup();
        return 1;
    }

    /* Allow address reuse */
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    /* Bind socket */
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_sock);
        vhsm_ctx_destroy(global_ctx);
        vhsm_cleanup();
        return 1;
    }

    /* Listen */
    if (listen(server_sock, MAX_CONNECTIONS) < 0) {
        perror("listen");
        close(server_sock);
        vhsm_ctx_destroy(global_ctx);
        vhsm_cleanup();
        return 1;
    }

    /* Accept connections */
    while (server_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int* client_sock = malloc(sizeof(int));
        if (!client_sock) {
            continue;
        }

        *client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_len);
        if (*client_sock < 0) {
            free(client_sock);
            if (server_running) {
                perror("accept");
            }
            continue;
        }

        /* Handle in thread */
        pthread_t thread;
        if (pthread_create(&thread, NULL, client_thread, client_sock) == 0) {
            pthread_detach(thread);
        } else {
            close(*client_sock);
            free(client_sock);
        }
    }

    /* Cleanup */
    close(server_sock);
    vhsm_ctx_destroy(global_ctx);
    vhsm_cleanup();

    printf("Server stopped\n");
    return 0;
}
