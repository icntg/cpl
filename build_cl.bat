@echo off
setlocal
set "VSROOT=C:\Program Files\Microsoft Visual Studio\18\Community"
call "%VSROOT%\VC\Auxiliary\Build\vcvarsall.bat" x86 >nul
set "CMAKE=%VSROOT%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
set "NINJA=%VSROOT%\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe"
set "CLDIR=%VSROOT%\VC\Tools\MSVC\14.51.36231\bin\Hostx86\x86"
set "CC=%CLDIR%\cl.exe"
set "CXX=%CLDIR%\cl.exe"
cd /d C:\home\src\icntg\cpl
if exist build_cl rmdir /s /q build_cl
"%CMAKE%" -S . -B build_cl -G Ninja -DCMAKE_MAKE_PROGRAM="%NINJA%" -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER="%CC%" -DCMAKE_CXX_COMPILER="%CXX%"
if errorlevel 1 exit /b 1
"%CMAKE%" --build build_cl
if errorlevel 1 exit /b 1
echo ===BUILD OK, RUNNING TESTS===
build_cl\cpl_test.exe
