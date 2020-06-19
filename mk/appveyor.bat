echo on
SetLocal EnableDelayedExpansion

set VCVARSALL="C:\Program Files (x86)\Microsoft Visual Studio %TOOLCHAIN_VERSION%\VC\vcvarsall.bat"

if [%Platform%] NEQ [x64] goto win32
set TARGET_ARCH=x86_64
goto download

:win32
echo on
if [%Platform%] NEQ [Win32] exit 1
set TARGET_ARCH=i686
goto download

:download
REM vcvarsall turns echo off
echo on

mkdir windows_build_tools
mkdir windows_build_tools\

echo Downloading Nasm...
powershell -Command "(New-Object Net.WebClient).DownloadFile('https://www.nasm.us/pub/nasm/releasebuilds/2.13.03/win64/nasm-2.13.03-win64.zip', 'windows_build_tools\nasm.zip')"
powershell -Command "Expand-Archive -Path windows_build_tools\nasm.zip -DestinationPath windows_build_tools"
powershell -Command "mv windows_build_tools\nasm-2.13.03\nasm.exe windows_build_tools"

if %ERRORLEVEL% NEQ 0 (
  echo ...downloading Nasm failed.
  exit 1
)

mkdir build
set RUSTUP_URL=https://win.rustup.rs/%TARGET_ARCH%
set RUSTUP_EXE=build\rustup-init-%TARGET_ARCH%.exe
echo Downloading %RUSTUP_URL%...
powershell -Command "(New-Object Net.WebClient).DownloadFile('%RUSTUP_URL%', '%RUSTUP_EXE%')"
if %ERRORLEVEL% NEQ 0 (
  echo ...downloading rustup failed.
  exit 1
)

set TARGET=%TARGET_ARCH%-pc-windows-msvc
%RUSTUP_EXE% -y --default-host %TARGET% --default-toolchain %RUST%
if %ERRORLEVEL% NEQ 0 exit 1

set PATH=%USERPROFILE%\.cargo\bin;%cd%\windows_build_tools;%PATH%

if [%Configuration%] == [Release] set CARGO_MODE=--release

set

link /?
cl /?
rustc --version
cargo --version

cargo test -vv %CARGO_MODE%
if %ERRORLEVEL% NEQ 0 exit 1

REM Verify that `cargo build`, independent from `cargo test`, works; i.e.
REM verify that non-test builds aren't trying to use test-only features.
cargo build -vv %CARGO_MODE%
if %ERRORLEVEL% NEQ 0 exit 1
