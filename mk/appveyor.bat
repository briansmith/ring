echo on
SetLocal EnableDelayedExpansion

REM This is the recommended way to choose the toolchain version, according to
REM Appveyor's documentation.
SET PATH=C:\Program Files (x86)\MSBuild\%TOOLCHAIN_VERSION%\Bin;%PATH%

if [%RUST%] == [msbuild] goto msbuild

set VCVARSALL="C:\Program Files (x86)\Microsoft Visual Studio %TOOLCHAIN_VERSION%\VC\vcvarsall.bat"

if [%Platform%] NEQ [x64] goto win32
set RUST_TAR_GZ_BASE=rust-%RUST%-x86_64-pc-windows-msvc
call %VCVARSALL% amd64
if %ERRORLEVEL% NEQ 0 exit 1
goto download

:win32
echo on
if [%Platform%] NEQ [Win32] exit 1
set RUST_TAR_GZ_BASE=rust-%RUST%-i686-pc-windows-msvc
call %VCVARSALL% amd64_x86
if %ERRORLEVEL% NEQ 0 exit 1
goto download

:download
REM vcvarsall turns echo off
echo on
set RUST_URL=https://static.rust-lang.org/dist/%RUST_TAR_GZ_BASE%.tar.gz
echo Downloading %RUST_URL%...
mkdir build
powershell -Command "(New-Object Net.WebClient).DownloadFile('%RUST_URL%', 'build\%RUST_TAR_GZ_BASE%.tar.gz')"
if %ERRORLEVEL% NEQ 0 (
  echo ...downloading failed.
  exit 1
)

pushd build
7z x -y %RUST_TAR_GZ_BASE%.tar.gz > nul
if %ERRORLEVEL% NEQ 0 exit 1
7z x -y %RUST_TAR_GZ_BASE%.tar > nul
if %ERRORLEVEL% NEQ 0 exit 1
popd

set PATH=%cd%\build\%RUST_TAR_GZ_BASE%\rustc\bin;%cd%\build\%RUST_TAR_GZ_BASE%\cargo\bin;%PATH%

if [%Configuration%] == [Release] set CARGO_MODE=--release

set

rustc --version
cargo --version

cargo build --verbose %CARGO_MODE%
if %ERRORLEVEL% NEQ 0 exit 1

cargo test --verbose %CARGO_MODE%
if %ERRORLEVEL% NEQ 0 exit 1

cargo doc --verbose
if %ERRORLEVEL% NEQ 0 exit 1

cargo clean --verbose
if %ERRORLEVEL% NEQ 0 exit 1

goto done

:msbuild
msbuild "ring.sln" /m /verbosity:normal /logger:"C:\Program Files\AppVeyor\BuildAgent\Appveyor.MSBuildLogger.dll"
if %ERRORLEVEL% NEQ 0 exit 1

go run util/all_tests.go -build-dir=build/%Platform%-%Configuration%/test/ring
if %ERRORLEVEL% NEQ 0 exit 1
goto done

:done
