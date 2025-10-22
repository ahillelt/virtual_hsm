# Virtual HSM Makefile

CC = gcc
CFLAGS = -Wall -Wextra -O2 -fPIC -pthread -I./include
LDFLAGS = -lcrypto -lssl -lz -luuid -pthread

# Directories
SRC_DIR = src
BUILD_DIR = build
LIB_DIR = lib
BIN_DIR = bin

# Source files
CORE_SRCS = $(SRC_DIR)/core/vhsm_core.c
AUTH_SRCS = $(SRC_DIR)/auth/vhsm_auth.c
STORAGE_SRCS = $(SRC_DIR)/storage/vhsm_storage.c $(SRC_DIR)/storage/vhsm_storage_ops.c $(SRC_DIR)/storage/vhsm_file_storage.c
CRYPTO_SRCS = $(SRC_DIR)/crypto/vhsm_crypto_impl.c $(SRC_DIR)/crypto/vhsm_homomorphic.c
AUDIT_SRCS = $(SRC_DIR)/audit/vhsm_audit.c
UTILS_SRCS = $(SRC_DIR)/utils/secure_memory.c

LIB_SRCS = $(CORE_SRCS) $(AUTH_SRCS) $(STORAGE_SRCS) $(CRYPTO_SRCS) $(AUDIT_SRCS) $(UTILS_SRCS)

# Object files
LIB_OBJS = $(LIB_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

# Targets
STATIC_LIB = $(LIB_DIR)/libvhsm.a
SHARED_LIB = $(LIB_DIR)/libvhsm.so
CLI_BIN = $(BIN_DIR)/vhsm
SERVER_BIN = $(BIN_DIR)/vhsm-server
SERVER_TLS_BIN = $(BIN_DIR)/vhsm-server-tls
TEST_CRYPTO_BIN = $(BIN_DIR)/test_crypto
TEST_HE_BIN = $(BIN_DIR)/test_homomorphic
TEST_INTEGRATION_BIN = $(BIN_DIR)/test_integration

.PHONY: all clean lib cli server server-tls examples install test test-crypto test-he test-integration

all: lib cli server server-tls

lib: $(STATIC_LIB) $(SHARED_LIB)

cli: $(CLI_BIN)

server: $(SERVER_BIN)

# Create directories
$(BUILD_DIR) $(LIB_DIR) $(BIN_DIR):
	mkdir -p $@

$(BUILD_DIR)/core $(BUILD_DIR)/auth $(BUILD_DIR)/storage $(BUILD_DIR)/crypto $(BUILD_DIR)/audit $(BUILD_DIR)/utils:
	mkdir -p $@

# Build object files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)/core $(BUILD_DIR)/auth $(BUILD_DIR)/storage $(BUILD_DIR)/crypto $(BUILD_DIR)/audit $(BUILD_DIR)/utils
	$(CC) $(CFLAGS) -c $< -o $@

# Build static library
$(STATIC_LIB): $(LIB_OBJS) | $(LIB_DIR)
	ar rcs $@ $^
	@echo "Static library created: $@"

# Build shared library
$(SHARED_LIB): $(LIB_OBJS) | $(LIB_DIR)
	$(CC) -shared -o $@ $^ $(LDFLAGS)
	@echo "Shared library created: $@"

# Build CLI
$(CLI_BIN): cli/vhsm_cli.c $(STATIC_LIB) | $(BIN_DIR)
	$(CC) $(CFLAGS) $< -o $@ -L$(LIB_DIR) -lvhsm $(LDFLAGS)
	@echo "CLI built: $@"

# Build server
$(SERVER_BIN): server/vhsm_server.c $(STATIC_LIB) | $(BIN_DIR)
	$(CC) $(CFLAGS) $< -o $@ -L$(LIB_DIR) -lvhsm $(LDFLAGS)
	@echo "Server built: $@"

# Build TLS server
$(SERVER_TLS_BIN): server/vhsm_server_tls.c $(STATIC_LIB) | $(BIN_DIR)
	$(CC) $(CFLAGS) $< -o $@ -L$(LIB_DIR) -lvhsm $(LDFLAGS)
	@echo "TLS server built: $@"

server-tls: $(SERVER_TLS_BIN)

# Build examples
examples: $(STATIC_LIB)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) examples/basic_usage.c -o $(BIN_DIR)/example_basic -L$(LIB_DIR) -lvhsm $(LDFLAGS)
	@echo "Examples built"

# Build tests
$(TEST_CRYPTO_BIN): tests/test_crypto.c $(STATIC_LIB) | $(BIN_DIR)
	$(CC) $(CFLAGS) $< -o $@ -L$(LIB_DIR) -lvhsm $(LDFLAGS)
	@echo "Crypto tests built: $@"

$(TEST_HE_BIN): tests/test_homomorphic.c $(STATIC_LIB) | $(BIN_DIR)
	$(CC) $(CFLAGS) $< -o $@ -L$(LIB_DIR) -lvhsm $(LDFLAGS)
	@echo "Homomorphic tests built: $@"

$(TEST_INTEGRATION_BIN): tests/test_integration.c $(STATIC_LIB) | $(BIN_DIR)
	$(CC) $(CFLAGS) $< -o $@ -L$(LIB_DIR) -lvhsm $(LDFLAGS)
	@echo "Integration tests built: $@"

test-crypto: $(TEST_CRYPTO_BIN)
	@echo "Running crypto tests..."
	@./$(TEST_CRYPTO_BIN)

test-he: $(TEST_HE_BIN)
	@echo "Running homomorphic encryption tests..."
	@./$(TEST_HE_BIN)

test-integration: $(TEST_INTEGRATION_BIN)
	@echo "Running integration tests..."
	@./$(TEST_INTEGRATION_BIN)

test: $(TEST_CRYPTO_BIN) $(TEST_HE_BIN) $(TEST_INTEGRATION_BIN)
	@echo "Running all tests..."
	@./$(TEST_CRYPTO_BIN) && \
	./$(TEST_HE_BIN) && \
	./$(TEST_INTEGRATION_BIN) && \
	echo "All tests passed!" || echo "Some tests failed!"

# Install
install: all
	install -d $(DESTDIR)/usr/local/lib
	install -d $(DESTDIR)/usr/local/include
	install -d $(DESTDIR)/usr/local/bin
	install -m 644 $(STATIC_LIB) $(DESTDIR)/usr/local/lib/
	install -m 755 $(SHARED_LIB) $(DESTDIR)/usr/local/lib/
	install -m 644 include/*.h $(DESTDIR)/usr/local/include/
	install -m 755 $(CLI_BIN) $(DESTDIR)/usr/local/bin/
	install -m 755 $(SERVER_BIN) $(DESTDIR)/usr/local/bin/
	@echo "Installation complete"

# Clean
clean:
	rm -rf $(BUILD_DIR) $(LIB_DIR) $(BIN_DIR)
	@echo "Clean complete"

# Help
help:
	@echo "Virtual HSM Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all            - Build everything (default)"
	@echo "  lib            - Build library only"
	@echo "  cli            - Build CLI only"
	@echo "  server         - Build REST API server"
	@echo "  server-tls     - Build TLS REST API server"
	@echo "  examples       - Build example programs"
	@echo "  test           - Build and run all tests"
	@echo "  test-crypto    - Build and run crypto tests"
	@echo "  test-he        - Build and run homomorphic encryption tests"
	@echo "  test-integration - Build and run integration tests"
	@echo "  install        - Install to system"
	@echo "  clean          - Remove build artifacts"
	@echo "  help           - Show this help"
