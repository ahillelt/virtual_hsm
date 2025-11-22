@echo off
REM Virtual HSM Build Script for Windows
REM Builds the Virtual HSM using MinGW or MSVC

setlocal enabledelayedexpansion

echo === Virtual HSM Build Script for Windows ===
echo.

REM Detect build environment
where gcc >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    set COMPILER=gcc
    set BUILD_ENV=MinGW
) else (
    where cl >nul 2>&1
    if %ERRORLEVEL% EQU 0 (
        set COMPILER=cl
        set BUILD_ENV=MSVC
    ) else (
        echo ERROR: No compiler found. Please install MinGW or Visual Studio.
        echo.
        echo Install MinGW: https://www.mingw-w64.org/
        echo Install Visual Studio: https://visualstudio.microsoft.com/
        exit /b 1
    )
)

echo Build environment: !BUILD_ENV!
echo Compiler: !COMPILER!
echo.

REM Check for OpenSSL
if not exist "C:\Program Files\OpenSSL-Win64\include\openssl\ssl.h" (
    if not exist "C:\OpenSSL-Win64\include\openssl\ssl.h" (
        echo ERROR: OpenSSL not found
        echo.
        echo Install OpenSSL for Windows:
        echo   https://slproweb.com/products/Win32OpenSSL.html
        echo.
        echo Or use vcpkg:
        echo   vcpkg install openssl:x64-windows
        exit /b 1
    )
)

echo OpenSSL found
echo.

REM Parse command line
set BUILD_TARGET=%1
if "%BUILD_TARGET%"=="" set BUILD_TARGET=all

if "%BUILD_TARGET%"=="clean" goto clean
if "%BUILD_TARGET%"=="standalone" goto standalone
if "%BUILD_TARGET%"=="help" goto help
if "%BUILD_TARGET%"=="all" goto all

:help
echo Usage: build.bat [command]
echo.
echo Commands:
echo   all          Build everything (default)
echo   clean        Clean build artifacts
echo   standalone   Build standalone tools only
echo   help         Show this help
echo.
goto :eof

:clean
echo Cleaning build artifacts...
if exist virtual_hsm.exe del virtual_hsm.exe
if exist hsm_enhanced.exe del hsm_enhanced.exe
if exist bin rmdir /s /q bin
if exist lib rmdir /s /q lib
if exist build rmdir /s /q build
echo Clean complete
goto :eof

:standalone
echo Building standalone tools...
call :build_virtual_hsm
call :build_hsm_enhanced
echo Standalone tools built successfully
goto :eof

:all
call :clean
call :standalone
echo.
echo === Build Complete ===
echo.
echo Built executables:
dir /b *.exe 2>nul
echo.
echo To test:
echo   virtual_hsm.exe -help
echo   hsm_enhanced.exe -help
goto :eof

REM Build functions
:build_virtual_hsm
echo Building virtual_hsm.exe...

if "!COMPILER!"=="gcc" (
    REM MinGW build
    set OPENSSL_DIR=C:\Program Files\OpenSSL-Win64
    if not exist "!OPENSSL_DIR!\include" set OPENSSL_DIR=C:\OpenSSL-Win64

    gcc -o virtual_hsm.exe virtual_hsm.c ^
        -I"!OPENSSL_DIR!\include" ^
        -L"!OPENSSL_DIR!\lib" ^
        -lssl -lcrypto ^
        -lws2_32 -lgdi32 -lcrypt32 -luser32 -ladvapi32 -lkernel32 -lbcrypt ^
        -DWIN32_LEAN_AND_MEAN -D_WIN32 ^
        -Wall -Wextra

    if !ERRORLEVEL! NEQ 0 (
        echo ERROR: virtual_hsm build failed
        exit /b 1
    )
) else (
    REM MSVC build
    cl /Fe:virtual_hsm.exe virtual_hsm.c ^
        /I"C:\Program Files\OpenSSL-Win64\include" ^
        /link /LIBPATH:"C:\Program Files\OpenSSL-Win64\lib" ^
        libssl.lib libcrypto.lib ^
        ws2_32.lib gdi32.lib crypt32.lib user32.lib advapi32.lib kernel32.lib bcrypt.lib ^
        /NOLOGO

    if !ERRORLEVEL! NEQ 0 (
        echo ERROR: virtual_hsm build failed
        exit /b 1
    )
)

echo virtual_hsm.exe built successfully
exit /b 0

:build_hsm_enhanced
echo Building hsm_enhanced.exe...

if "!COMPILER!"=="gcc" (
    REM MinGW build
    set OPENSSL_DIR=C:\Program Files\OpenSSL-Win64
    if not exist "!OPENSSL_DIR!\include" set OPENSSL_DIR=C:\OpenSSL-Win64

    gcc -o hsm_enhanced.exe hsm_enhanced.c ^
        -I"!OPENSSL_DIR!\include" ^
        -L"!OPENSSL_DIR!\lib" ^
        -lssl -lcrypto ^
        -lws2_32 -lgdi32 -lcrypt32 -luser32 -ladvapi32 -lkernel32 -lbcrypt ^
        -DWIN32_LEAN_AND_MEAN -D_WIN32 ^
        -Wall -Wextra

    if !ERRORLEVEL! NEQ 0 (
        echo ERROR: hsm_enhanced build failed
        exit /b 1
    )
) else (
    REM MSVC build
    cl /Fe:hsm_enhanced.exe hsm_enhanced.c ^
        /I"C:\Program Files\OpenSSL-Win64\include" ^
        /link /LIBPATH:"C:\Program Files\OpenSSL-Win64\lib" ^
        libssl.lib libcrypto.lib ^
        ws2_32.lib gdi32.lib crypt32.lib user32.lib advapi32.lib kernel32.lib bcrypt.lib ^
        /NOLOGO

    if !ERRORLEVEL! NEQ 0 (
        echo ERROR: hsm_enhanced build failed
        exit /b 1
    )
)

echo hsm_enhanced.exe built successfully
exit /b 0
