#include "../include/vhsm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>

/* TLS-enabled HTTP server for REST API */

#define DEFAULT_PORT 8443
#define MAX_CONNECTIONS 10
#define BUFFER_SIZE 65536

static int server_running = 1;
static vhsm_ctx_t global_ctx = NULL;
static SSL_CTX* ssl_ctx = NULL;

/* Signal handler */
void signal_handler(int signum) {
    printf("\nReceived signal %d, shutting down...\n", signum);
    server_running = 0;
}

/* Generate self-signed certificate */
static int generate_self_signed_cert(const char* cert_file, const char* key_file) {
    EVP_PKEY* pkey = NULL;
    X509* x509 = NULL;
    FILE* fp = NULL;

    /* Generate RSA key */
    EVP_PKEY_CTX* pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!pkey_ctx) return 0;

    if (EVP_PKEY_keygen_init(pkey_ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, 2048) <= 0 ||
        EVP_PKEY_keygen(pkey_ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pkey_ctx);
        return 0;
    }
    EVP_PKEY_CTX_free(pkey_ctx);

    /* Create certificate */
    x509 = X509_new();
    if (!x509) {
        EVP_PKEY_free(pkey);
        return 0;
    }

    /* Set version, serial, validity */
    X509_set_version(x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);  /* 1 year */

    /* Set public key */
    X509_set_pubkey(x509, pkey);

    /* Set subject and issuer */
    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"Virtual HSM", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"localhost", -1, -1, 0);
    X509_set_issuer_name(x509, name);

    /* Sign certificate */
    if (X509_sign(x509, pkey, EVP_sha256()) <= 0) {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return 0;
    }

    /* Write certificate */
    fp = fopen(cert_file, "wb");
    if (!fp || PEM_write_X509(fp, x509) != 1) {
        if (fp) fclose(fp);
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return 0;
    }
    fclose(fp);

    /* Write private key */
    fp = fopen(key_file, "wb");
    if (!fp || PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
        if (fp) fclose(fp);
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return 0;
    }
    fclose(fp);

    X509_free(x509);
    EVP_PKEY_free(pkey);

    chmod(key_file, 0600);
    printf("Generated self-signed certificate: %s\n", cert_file);
    printf("Generated private key: %s\n", key_file);

    return 1;
}

/* Initialize SSL context */
static SSL_CTX* init_ssl_context(const char* cert_file, const char* key_file) {
    SSL_CTX* ctx;

    /* Initialize OpenSSL */
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    /* Create SSL context */
    const SSL_METHOD* method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    /* Set options for security */
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    /* SECURITY: Set strong cipher suite */
    if (SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256") != 1) {
        fprintf(stderr, "Warning: Failed to set cipher list\n");
    }

    /* Load certificate */
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    /* Load private key */
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    /* Verify key matches certificate */
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match certificate\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}

/* Parse JSON (simple implementation) */
static char* get_json_value(const char* json, const char* key) {
    static char value[1024];
    char search[256];
    snprintf(search, sizeof(search), "\"%s\":", key);

    const char* pos = strstr(json, search);
    if (!pos) return NULL;

    pos += strlen(search);
    while (*pos == ' ' || *pos == '\t') pos++;

    if (*pos == '"') {
        pos++;
        const char* end = strchr(pos, '"');
        if (!end) return NULL;

        size_t len = end - pos;
        if (len >= sizeof(value)) len = sizeof(value) - 1;

        memcpy(value, pos, len);
        value[len] = '\0';
        return value;
    }

    return NULL;
}

/* Handle HTTPS request */
void handle_ssl_request(SSL* ssl) {
    char buffer[BUFFER_SIZE];
    char response[BUFFER_SIZE];

    int received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (received <= 0) {
        return;
    }

    buffer[received] = '\0';

    /* Parse request */
    char method[16], path[256];
    sscanf(buffer, "%15s %255s", method, path);

    char* body = strstr(buffer, "\r\n\r\n");
    if (body) body += 4;

    /* Route request */
    int status_code = 200;
    char content[BUFFER_SIZE];
    content[0] = '\0';

    if (strcmp(path, "/api/version") == 0 && strcmp(method, "GET") == 0) {
        snprintf(content, sizeof(content),
                 "{\"version\":\"%s\",\"status\":\"ok\",\"tls\":\"enabled\"}", vhsm_version());

    } else if (strcmp(path, "/api/health") == 0 && strcmp(method, "GET") == 0) {
        snprintf(content, sizeof(content),
                 "{\"status\":\"healthy\",\"secure\":true}");

    } else if (strcmp(path, "/api/user/create") == 0 && strcmp(method, "POST") == 0) {
        if (!body) {
            status_code = 400;
            snprintf(content, sizeof(content), "{\"error\":\"Missing request body\"}");
        } else {
            char* username = get_json_value(body, "username");
            char* password = get_json_value(body, "password");
            char* role_str = get_json_value(body, "role");

            if (!username || !password) {
                status_code = 400;
                snprintf(content, sizeof(content), "{\"error\":\"Missing required fields\"}");
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
            snprintf(content, sizeof(content), "{\"error\":\"Missing request body\"}");
        } else {
            char* username = get_json_value(body, "username");
            char* password = get_json_value(body, "password");

            if (!username || !password) {
                status_code = 400;
                snprintf(content, sizeof(content), "{\"error\":\"Missing required fields\"}");
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

    } else {
        status_code = 404;
        snprintf(content, sizeof(content), "{\"error\":\"Endpoint not found\"}");
    }

    /* Build HTTPS response */
    const char* status_text = "OK";
    if (status_code == 400) status_text = "Bad Request";
    else if (status_code == 401) status_text = "Unauthorized";
    else if (status_code == 404) status_text = "Not Found";
    else if (status_code == 500) status_text = "Internal Server Error";

    /* SECURITY: Enhanced security headers */
    const char* allowed_origin = getenv("VHSM_ALLOWED_ORIGIN");
    if (!allowed_origin) {
        allowed_origin = "https://localhost:3000";  /* Default for development */
    }

    snprintf(response, sizeof(response),
             "HTTP/1.1 %d %s\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: %zu\r\n"
             "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\n"
             "X-Content-Type-Options: nosniff\r\n"
             "X-Frame-Options: DENY\r\n"
             "Content-Security-Policy: default-src 'none'; frame-ancestors 'none'\r\n"
             "Access-Control-Allow-Origin: %s\r\n"
             "Connection: close\r\n"
             "\r\n"
             "%s",
             status_code, status_text, strlen(content), allowed_origin, content);

    SSL_write(ssl, response, strlen(response));
}

/* Client thread */
void* client_ssl_thread(void* arg) {
    int client_sock = *(int*)arg;
    free(arg);

    SSL* ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        close(client_sock);
        return NULL;
    }

    SSL_set_fd(ssl, client_sock);

    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        handle_ssl_request(ssl);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_sock);

    return NULL;
}

int main(int argc, char* argv[]) {
    int port = DEFAULT_PORT;
    const char* storage_path = "./vhsm_storage";
    const char* cert_file = "./server.crt";
    const char* key_file = "./server.key";
    int generate_cert = 0;

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
            if (i + 1 < argc) storage_path = argv[++i];
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--cert") == 0) {
            if (i + 1 < argc) cert_file = argv[++i];
        } else if (strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--key") == 0) {
            if (i + 1 < argc) key_file = argv[++i];
        } else if (strcmp(argv[i], "--generate-cert") == 0) {
            generate_cert = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Virtual HSM TLS REST API Server\n");
            printf("Usage: %s [options]\n", argv[0]);
            printf("Options:\n");
            printf("  -p, --port PORT       Server port (default: %d)\n", DEFAULT_PORT);
            printf("  -s, --storage PATH    Storage path\n");
            printf("  -c, --cert FILE       Certificate file\n");
            printf("  -k, --key FILE        Private key file\n");
            printf("  --generate-cert       Generate self-signed certificate\n");
            printf("  -h, --help            Show this help\n");
            return 0;
        }
    }

    /* Generate certificate if requested or missing */
    if (generate_cert || access(cert_file, F_OK) != 0 || access(key_file, F_OK) != 0) {
        printf("Generating self-signed certificate...\n");
        if (!generate_self_signed_cert(cert_file, key_file)) {
            fprintf(stderr, "Failed to generate certificate\n");
            return 1;
        }
    }

    /* Initialize SSL context */
    ssl_ctx = init_ssl_context(cert_file, key_file);
    if (!ssl_ctx) {
        fprintf(stderr, "Failed to initialize SSL context\n");
        return 1;
    }

    /* Initialize HSM */
    if (vhsm_init() != VHSM_SUCCESS) {
        fprintf(stderr, "Failed to initialize HSM library\n");
        SSL_CTX_free(ssl_ctx);
        return 1;
    }

    if (vhsm_ctx_create(&global_ctx, storage_path) != VHSM_SUCCESS) {
        fprintf(stderr, "Failed to create HSM context\n");
        SSL_CTX_free(ssl_ctx);
        vhsm_cleanup();
        return 1;
    }

    uint8_t master_key[32];
    if (vhsm_ctx_generate_master_key(global_ctx, master_key) != VHSM_SUCCESS) {
        fprintf(stderr, "Failed to generate master key\n");
        vhsm_ctx_destroy(global_ctx);
        SSL_CTX_free(ssl_ctx);
        vhsm_cleanup();
        return 1;
    }

    printf("Virtual HSM TLS REST API Server v%s\n", vhsm_version());
    printf("Listening on https://localhost:%d\n", port);
    printf("Storage path: %s\n", storage_path);
    printf("TLS: Enabled (TLS 1.2+)\n");

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Create socket */
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("socket");
        vhsm_ctx_destroy(global_ctx);
        SSL_CTX_free(ssl_ctx);
        vhsm_cleanup();
        return 1;
    }

    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_sock);
        vhsm_ctx_destroy(global_ctx);
        SSL_CTX_free(ssl_ctx);
        vhsm_cleanup();
        return 1;
    }

    if (listen(server_sock, MAX_CONNECTIONS) < 0) {
        perror("listen");
        close(server_sock);
        vhsm_ctx_destroy(global_ctx);
        SSL_CTX_free(ssl_ctx);
        vhsm_cleanup();
        return 1;
    }

    /* Accept connections */
    while (server_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int* client_sock = malloc(sizeof(int));
        if (!client_sock) continue;

        *client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_len);
        if (*client_sock < 0) {
            free(client_sock);
            if (server_running) perror("accept");
            continue;
        }

        pthread_t thread;
        if (pthread_create(&thread, NULL, client_ssl_thread, client_sock) == 0) {
            pthread_detach(thread);
        } else {
            close(*client_sock);
            free(client_sock);
        }
    }

    /* Cleanup */
    close(server_sock);
    vhsm_ctx_destroy(global_ctx);
    SSL_CTX_free(ssl_ctx);
    vhsm_cleanup();

    printf("Server stopped\n");
    return 0;
}
