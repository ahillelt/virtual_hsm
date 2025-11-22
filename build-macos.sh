#!/bin/bash
#
# Virtual HSM Build Script for macOS
# Handles macOS-specific build requirements and Homebrew dependencies
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== Virtual HSM Build Script for macOS ===${NC}"
echo ""

# Check for Homebrew
if ! command -v brew &> /dev/null; then
    echo -e "${RED}Error: Homebrew not found${NC}"
    echo ""
    echo "Install Homebrew:"
    echo '  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
    exit 1
fi

echo -e "${GREEN}✓ Homebrew found${NC}"

# Check and install dependencies
check_install_deps() {
    echo -e "${BLUE}Checking dependencies...${NC}"

    local deps_needed=()

    # Check each dependency
    if ! brew list openssl@3 &>/dev/null && ! brew list openssl@1.1 &>/dev/null; then
        deps_needed+=("openssl@3")
    fi

    if ! brew list zlib &>/dev/null; then
        deps_needed+=("zlib")
    fi

    if ! brew list ossp-uuid &>/dev/null; then
        deps_needed+=("ossp-uuid")
    fi

    if ! brew list libsodium &>/dev/null; then
        deps_needed+=("libsodium")
    fi

    # Install missing dependencies
    if [ ${#deps_needed[@]} -ne 0 ]; then
        echo -e "${YELLOW}Installing missing dependencies: ${deps_needed[*]}${NC}"
        brew install "${deps_needed[@]}"
    fi

    echo -e "${GREEN}✓ All dependencies installed${NC}"
}

# Set up environment variables for OpenSSL
setup_openssl_env() {
    echo -e "${BLUE}Setting up OpenSSL environment...${NC}"

    # Try OpenSSL 3 first, then fall back to 1.1
    if brew list openssl@3 &>/dev/null; then
        OPENSSL_PREFIX=$(brew --prefix openssl@3)
    elif brew list openssl@1.1 &>/dev/null; then
        OPENSSL_PREFIX=$(brew --prefix openssl@1.1)
    else
        echo -e "${RED}Error: OpenSSL not found${NC}"
        exit 1
    fi

    export OPENSSL_ROOT_DIR="$OPENSSL_PREFIX"
    export OPENSSL_INCLUDE_DIR="$OPENSSL_PREFIX/include"
    export OPENSSL_LIB_DIR="$OPENSSL_PREFIX/lib"

    echo "  OPENSSL_PREFIX: $OPENSSL_PREFIX"
    echo -e "${GREEN}✓ OpenSSL configured${NC}"
}

# Update Makefile for macOS
update_makefile_macos() {
    echo -e "${BLUE}Configuring build for macOS...${NC}"

    # Create macOS-specific compiler flags
    export CFLAGS="-I$OPENSSL_INCLUDE_DIR -I$(brew --prefix)/include"
    export LDFLAGS="-L$OPENSSL_LIB_DIR -L$(brew --prefix)/lib"

    # macOS uses .dylib instead of .so
    if [ -f "Makefile" ]; then
        # Make temporary backup
        cp Makefile Makefile.bak

        # Update library extension for macOS
        sed -i.tmp 's/\.so/.dylib/g' Makefile || true
        rm -f Makefile.tmp
    fi

    echo -e "${GREEN}✓ Build configured for macOS${NC}"
}

# Restore Makefile
restore_makefile() {
    if [ -f "Makefile.bak" ]; then
        mv Makefile.bak Makefile
    fi
}

# Build library for macOS
build_library_macos() {
    echo -e "${BLUE}Building Virtual HSM library for macOS...${NC}"

    # Build with macOS-specific flags
    make lib \
        CFLAGS="-Wall -Wextra -O2 -fPIC -pthread -I./include -I$OPENSSL_INCLUDE_DIR -I$(brew --prefix)/include" \
        LDFLAGS="-L$OPENSSL_LIB_DIR -L$(brew --prefix)/lib -lcrypto -lssl -lz -pthread"

    # Fix library install names for macOS
    if [ -f "lib/libvhsm.dylib" ]; then
        install_name_tool -id "@rpath/libvhsm.dylib" lib/libvhsm.dylib
        echo -e "${GREEN}✓ Library built and install names fixed${NC}"
    else
        echo -e "${RED}✗ Library build failed${NC}"
        exit 1
    fi
}

# Build standalone tools for macOS
build_standalone_macos() {
    echo -e "${BLUE}Building standalone tools for macOS...${NC}"

    # Build virtual_hsm
    clang -o virtual_hsm virtual_hsm.c \
        -I$OPENSSL_INCLUDE_DIR \
        -L$OPENSSL_LIB_DIR \
        -lssl -lcrypto \
        -Wall -Wextra || {
        echo -e "${RED}✗ virtual_hsm build failed${NC}"
        exit 1
    }

    # Build hsm_enhanced
    clang -o hsm_enhanced hsm_enhanced.c \
        -I$OPENSSL_INCLUDE_DIR \
        -L$OPENSSL_LIB_DIR \
        -lssl -lcrypto \
        -Wall -Wextra || {
        echo -e "${RED}✗ hsm_enhanced build failed${NC}"
        exit 1
    }

    echo -e "${GREEN}✓ Standalone tools built${NC}"
}

# Build CLI for macOS
build_cli_macos() {
    echo -e "${BLUE}Building CLI for macOS...${NC}"

    make cli \
        CFLAGS="-Wall -Wextra -O2 -fPIC -pthread -I./include -I$OPENSSL_INCLUDE_DIR -I$(brew --prefix)/include" \
        LDFLAGS="-L$OPENSSL_LIB_DIR -L$(brew --prefix)/lib -lcrypto -lssl -lz -pthread"

    if [ -f "bin/vhsm" ]; then
        echo -e "${GREEN}✓ CLI built${NC}"
    else
        echo -e "${YELLOW}⚠ CLI build incomplete${NC}"
    fi
}

# Build servers for macOS
build_servers_macos() {
    echo -e "${BLUE}Building servers for macOS...${NC}"

    make server server-tls \
        CFLAGS="-Wall -Wextra -O2 -fPIC -pthread -I./include -I$OPENSSL_INCLUDE_DIR -I$(brew --prefix)/include" \
        LDFLAGS="-L$OPENSSL_LIB_DIR -L$(brew --prefix)/lib -lcrypto -lssl -lz -pthread" || {
        echo -e "${YELLOW}⚠ Server build incomplete${NC}"
    }
}

# Run tests
run_tests_macos() {
    echo -e "${BLUE}Running tests...${NC}"

    # Set DYLD_LIBRARY_PATH for dynamic library loading
    export DYLD_LIBRARY_PATH="$(pwd)/lib:$DYLD_LIBRARY_PATH"

    make test || {
        echo -e "${YELLOW}⚠ Some tests failed${NC}"
    }
}

# Create macOS app bundle (optional)
create_app_bundle() {
    echo -e "${BLUE}Creating macOS app bundle...${NC}"

    APP_NAME="VirtualHSM"
    BUNDLE_DIR="dist/${APP_NAME}.app/Contents"

    mkdir -p "$BUNDLE_DIR"/{MacOS,Resources,Frameworks}

    # Copy executables
    cp hsm_enhanced "$BUNDLE_DIR/MacOS/"
    cp lib/libvhsm.dylib "$BUNDLE_DIR/Frameworks/"

    # Create Info.plist
    cat > "$BUNDLE_DIR/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>hsm_enhanced</string>
    <key>CFBundleIdentifier</key>
    <string>com.virtualhsm.app</string>
    <key>CFBundleName</key>
    <string>Virtual HSM</string>
    <key>CFBundleVersion</key>
    <string>2.0.0</string>
    <key>CFBundleShortVersionString</key>
    <string>2.0.0</string>
</dict>
</plist>
EOF

    echo -e "${GREEN}✓ App bundle created: dist/${APP_NAME}.app${NC}"
}

# Main function
main() {
    case "${1:-all}" in
        clean)
            make clean
            rm -f virtual_hsm hsm_enhanced
            restore_makefile
            ;;
        deps)
            check_install_deps
            ;;
        standalone)
            check_install_deps
            setup_openssl_env
            build_standalone_macos
            ;;
        lib|library)
            check_install_deps
            setup_openssl_env
            update_makefile_macos
            build_library_macos
            restore_makefile
            ;;
        bundle)
            check_install_deps
            setup_openssl_env
            build_standalone_macos
            create_app_bundle
            ;;
        test)
            check_install_deps
            setup_openssl_env
            update_makefile_macos
            build_library_macos
            run_tests_macos
            restore_makefile
            ;;
        all)
            check_install_deps
            setup_openssl_env
            update_makefile_macos
            build_library_macos
            build_cli_macos
            build_servers_macos
            restore_makefile
            build_standalone_macos
            run_tests_macos

            echo ""
            echo -e "${GREEN}=== Build Complete ===${NC}"
            echo ""
            echo "To set up library path for runtime:"
            echo "  export DYLD_LIBRARY_PATH=$(pwd)/lib:\$DYLD_LIBRARY_PATH"
            ;;
        help|--help|-h)
            echo "Usage: $0 [command]"
            echo ""
            echo "Commands:"
            echo "  all          Build everything (default)"
            echo "  clean        Clean build artifacts"
            echo "  deps         Install dependencies via Homebrew"
            echo "  lib          Build library only"
            echo "  standalone   Build standalone tools only"
            echo "  bundle       Create macOS app bundle"
            echo "  test         Build and run tests"
            echo "  help         Show this help"
            ;;
        *)
            echo "Unknown command: $1"
            echo "Run '$0 help' for usage"
            exit 1
            ;;
    esac
}

# Run with trap to ensure cleanup
trap restore_makefile EXIT
main "$@"
