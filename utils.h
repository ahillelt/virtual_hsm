#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Utility Functions
int hex_to_int(char c);
void hex_to_bytes(const char *hex, unsigned char *bytes, size_t length);
void handle_errors(void);
unsigned char* read_file(const char* filename, size_t* file_size);
int write_file(const char* filename, const unsigned char* data, size_t data_len);
size_t read_hex_string(const char* hex_string, unsigned char* buffer, size_t buffer_size);

int hex_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

void hex_to_bytes(const char *hex, unsigned char *bytes, size_t length) {
    DEBUG_PRINT("Converting hex string to bytes: %s", hex);
    for (size_t i = 0; i < length; i++) {
        bytes[i] = (hex_to_int(hex[i*2]) << 4) | hex_to_int(hex[i*2 + 1]);
    }
}

void handle_errors() {
    unsigned long err = ERR_get_error();
    char err_msg[CHAR_ERR_MSG_ARRAY];
    ERR_error_string_n(err, err_msg, sizeof(err_msg));
    fprintf(stderr, "Debug: OpenSSL Error: %s\n", err_msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

unsigned char* read_file(const char* filename, size_t* file_size) {
    FILE* fp = fopen(filename, "rb");
    if (!fp) {
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    long length = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    unsigned char* buffer = malloc((size_t)length);
    if (!buffer) {
        fclose(fp);
        return NULL;
    }

    *file_size = fread(buffer, 1, (size_t)length, fp);
    fclose(fp);
    return buffer;
}

int write_file(const char* filename, const unsigned char* data, size_t data_len) {
    FILE* fp = fopen(filename, "wb");
    if (!fp) {
        return 0;
    }

    size_t written = fwrite(data, 1, data_len, fp);
    fclose(fp);
    return written == data_len;
}

size_t read_hex_string(const char* hex_string, unsigned char* buffer, size_t buffer_size) {
    size_t len = strlen(hex_string);
    if (len > buffer_size * 2) {
        len = buffer_size * 2;
    }

    size_t j = 0;
    for (size_t i = 0; i < len; i += 2) {
        int high = hex_to_int(hex_string[i]);
        int low = hex_to_int(hex_string[i + 1]);
        if (high == -1 || low == -1) {
            return 0;
        }
        buffer[j++] = (high << 4) | low;
    }

    return j;
}

#endif // UTILS_H
