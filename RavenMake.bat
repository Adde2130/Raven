@echo off

rem Run make in the current directory
echo Building Raven...
make

rem Check if compilation succeeded
if %errorlevel% neq 0 (
    echo Compilation failed.
    exit /b %errorlevel%
)

rem Get the current directory
set "curdir=%CD%"

rem Run RavenMake.exe with the argument of the relative path {curdir}/lib
cd RavenMake
RavenMake.exe "%curdir%\lib"
cd ..