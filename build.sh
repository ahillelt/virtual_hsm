#!/bin/bash
#
# Virtual HSM Build Script for Linux/Unix
# Builds the complete Virtual HSM library, tools, and servers
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Build configuration
BUILD_TYPE="${BUILD_TYPE:-Release}"
ENABLE_TESTS="${ENABLE_TESTS:-1}"
ENABLE_EXAMPLES="${ENABLE_EXAMPLES:-1}"
ENABLE_PYTHON="${ENABLE_PYTHON:-1}"
JOBS="${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"

echo -e "${BLUE}=== Virtual HSM Build Script ===${NC}"
echo "Build type: $BUILD_TYPE"
echo "Parallel jobs: $JOBS"
echo ""

# Detect platform
PLATFORM="$(uname -s)"
case "$PLATFORM" in
    Linux*)     OS=linux;;
    Darwin*)    OS=macos;;
    CYGWIN*)    OS=windows;;
    MINGW*)     OS=windows;;
    *)          OS=unknown;;
esac

echo -e "${BLUE}Platform: $OS${NC}"

# Function to check dependencies
check_dependencies() {
    echo -e "${BLUE}Checking dependencies...${NC}"

    local missing_deps=()

    # Check for compiler
    if ! command -v gcc &> /dev/null && ! command -v clang &> /dev/null; then
        missing_deps+=("gcc or clang")
    fi

    # Check for make
    if ! command -v make &> /dev/null; then
        missing_deps+=("make")
    fi

    # Check for OpenSSL
    if ! pkg-config --exists openssl 2>/dev/null && ! [ -f /usr/include/openssl/ssl.h ]; then
        missing_deps+=("openssl-dev")
    fi

    # Platform-specific checks
    if [ "$OS" = "linux" ]; then
        if ! pkg-config --exists uuid 2>/dev/null && ! [ -f /usr/include/uuid/uuid.h ]; then
            missing_deps+=("uuid-dev")
        fi
        if ! pkg-config --exists zlib 2>/dev/null && ! [ -f /usr/include/zlib.h ]; then
            missing_deps+=("zlib-dev")
        fi
    fi

    if [ ${#missing_deps[@]} -ne 0 ]; then
        echo -e "${RED}Missing dependencies:${NC}"
        for dep in "${missing_deps[@]}"; do
            echo "  - $dep"
        done
        echo ""
        echo "Install dependencies:"
        if [ "$OS" = "linux" ]; then
            echo "  Ubuntu/Debian: sudo apt-get install build-essential libssl-dev zlib1g-dev uuid-dev libsodium-dev"
            echo "  Fedora/RHEL:   sudo dnf install gcc make openssl-devel zlib-devel libuuid-devel libsodium-devel"
            echo "  Arch Linux:    sudo pacman -S base-devel openssl zlib util-linux-libs libsodium"
        elif [ "$OS" = "macos" ]; then
            echo "  macOS:         brew install openssl zlib ossp-uuid libsodium"
        fi
        exit 1
    fi

    echo -e "${GREEN}✓ All dependencies found${NC}"
}

# Function to clean build artifacts
clean_build() {
    echo -e "${BLUE}Cleaning build artifacts...${NC}"
    make clean
    rm -f virtual_hsm hsm_enhanced passkey_tool
    echo -e "${GREEN}✓ Clean complete${NC}"
}

# Function to build library
build_library() {
    echo -e "${BLUE}Building Virtual HSM library...${NC}"
    make lib -j${JOBS}

    if [ -f "lib/libvhsm.so" ] || [ -f "lib/libvhsm.dylib" ] || [ -f "lib/libvhsm.a" ]; then
        echo -e "${GREEN}✓ Library built successfully${NC}"
        ls -lh lib/
    else
        echo -e "${RED}✗ Library build failed${NC}"
        exit 1
    fi
}

# Function to build CLI
build_cli() {
    echo -e "${BLUE}Building CLI tools...${NC}"
    make cli -j${JOBS}

    if [ -f "bin/vhsm" ]; then
        echo -e "${GREEN}✓ CLI built successfully${NC}"
    else
        echo -e "${RED}✗ CLI build failed${NC}"
        exit 1
    fi
}

# Function to build servers
build_servers() {
    echo -e "${BLUE}Building REST API servers...${NC}"
    make server server-tls -j${JOBS}

    if [ -f "bin/vhsm-server" ] && [ -f "bin/vhsm-server-tls" ]; then
        echo -e "${GREEN}✓ Servers built successfully${NC}"
    else
        echo -e "${YELLOW}⚠ Server build incomplete (expected in some environments)${NC}"
    fi
}

# Function to build standalone tools
build_standalone() {
    echo -e "${BLUE}Building standalone tools...${NC}"

    # Build virtual_hsm
    gcc -o virtual_hsm virtual_hsm.c -lcrypto -lssl -Wall -Wextra || {
        echo -e "${RED}✗ virtual_hsm build failed${NC}"
        exit 1
    }

    # Build hsm_enhanced
    gcc -o hsm_enhanced hsm_enhanced.c -lcrypto -lssl -Wall -Wextra || {
        echo -e "${RED}✗ hsm_enhanced build failed${NC}"
        exit 1
    }

    # Build passkey_tool (may fail if libfido2 not available)
    if gcc -o passkey_tool passkey.c -lfido2 -ljson-c -lcrypto -Wall -Wextra 2>/dev/null; then
        echo -e "${GREEN}✓ passkey_tool built successfully${NC}"
    else
        echo -e "${YELLOW}⚠ passkey_tool build skipped (requires libfido2 and libjson-c)${NC}"
    fi

    echo -e "${GREEN}✓ Standalone tools built${NC}"
}

# Function to build examples
build_examples() {
    if [ "$ENABLE_EXAMPLES" = "1" ]; then
        echo -e "${BLUE}Building examples...${NC}"
        make examples -j${JOBS} || {
            echo -e "${YELLOW}⚠ Examples build incomplete${NC}"
        }
    fi
}

# Function to run tests
run_tests() {
    if [ "$ENABLE_TESTS" = "1" ]; then
        echo -e "${BLUE}Running tests...${NC}"

        # Build tests
        make test-crypto test-he test-integration -j${JOBS} || {
            echo -e "${RED}✗ Test build failed${NC}"
            exit 1
        }

        # Run tests
        ./bin/test_crypto && \
        ./bin/test_homomorphic && \
        ./bin/test_integration && \
        echo -e "${GREEN}✓ All tests passed${NC}" || {
            echo -e "${RED}✗ Tests failed${NC}"
            exit 1
        }
    fi
}

# Function to install Python library
install_python() {
    if [ "$ENABLE_PYTHON" = "1" ]; then
        echo -e "${BLUE}Setting up Python library...${NC}"

        if command -v python3 &> /dev/null; then
            cd python
            python3 -m pip install -e . --user || {
                echo -e "${YELLOW}⚠ Python library installation skipped${NC}"
            }
            cd ..
            echo -e "${GREEN}✓ Python library installed${NC}"
        else
            echo -e "${YELLOW}⚠ Python3 not found, skipping Python library${NC}"
        fi
    fi
}

# Function to create distribution package
create_package() {
    echo -e "${BLUE}Creating distribution package...${NC}"

    VERSION="2.0.0"
    PACKAGE_NAME="virtual_hsm-${VERSION}-${OS}-$(uname -m)"

    mkdir -p "dist/${PACKAGE_NAME}"/{bin,lib,include,examples,docs}

    # Copy binaries
    cp -r bin/* "dist/${PACKAGE_NAME}/bin/" 2>/dev/null || true
    cp virtual_hsm hsm_enhanced "dist/${PACKAGE_NAME}/bin/" 2>/dev/null || true

    # Copy libraries
    cp -r lib/* "dist/${PACKAGE_NAME}/lib/" 2>/dev/null || true

    # Copy headers
    cp -r include/* "dist/${PACKAGE_NAME}/include/" 2>/dev/null || true

    # Copy examples
    cp -r examples/* "dist/${PACKAGE_NAME}/examples/" 2>/dev/null || true

    # Copy documentation
    cp README.md LICENSE "dist/${PACKAGE_NAME}/docs/" 2>/dev/null || true

    # Create archive
    cd dist
    tar czf "${PACKAGE_NAME}.tar.gz" "${PACKAGE_NAME}"
    cd ..

    echo -e "${GREEN}✓ Package created: dist/${PACKAGE_NAME}.tar.gz${NC}"
}

# Main build process
main() {
    # Parse arguments
    case "${1:-}" in
        clean)
            clean_build
            exit 0
            ;;
        library|lib)
            check_dependencies
            build_library
            exit 0
            ;;
        cli)
            check_dependencies
            build_library
            build_cli
            exit 0
            ;;
        standalone)
            check_dependencies
            build_standalone
            exit 0
            ;;
        test)
            check_dependencies
            build_library
            run_tests
            exit 0
            ;;
        package)
            check_dependencies
            build_library
            build_cli
            build_servers
            build_standalone
            build_examples
            create_package
            exit 0
            ;;
        help|--help|-h)
            echo "Usage: $0 [command]"
            echo ""
            echo "Commands:"
            echo "  (none)       Build everything (default)"
            echo "  clean        Clean build artifacts"
            echo "  library|lib  Build library only"
            echo "  cli          Build CLI only"
            echo "  standalone   Build standalone tools only"
            echo "  test         Build and run tests"
            echo "  package      Create distribution package"
            echo "  help         Show this help"
            echo ""
            echo "Environment variables:"
            echo "  BUILD_TYPE       Release or Debug (default: Release)"
            echo "  ENABLE_TESTS     1 to enable tests (default: 1)"
            echo "  ENABLE_EXAMPLES  1 to build examples (default: 1)"
            echo "  ENABLE_PYTHON    1 to install Python library (default: 1)"
            echo "  JOBS             Number of parallel jobs (default: auto)"
            exit 0
            ;;
    esac

    # Default: build everything
    check_dependencies
    clean_build
    build_library
    build_cli
    build_servers
    build_standalone
    build_examples
    run_tests
    install_python

    echo ""
    echo -e "${GREEN}=== Build Complete ===${NC}"
    echo ""
    echo "Built artifacts:"
    echo "  Libraries:  lib/"
    echo "  Binaries:   bin/"
    echo "  Standalone: virtual_hsm, hsm_enhanced"
    echo ""
    echo "Next steps:"
    echo "  1. Run tests:        make test"
    echo "  2. Install:          sudo make install"
    echo "  3. Try example:      cd examples/python && python3 hsm_example.py"
}

main "$@"
