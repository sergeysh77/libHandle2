@echo off
echo ------------------------------
echo Building test_dll.jar with JNA
echo ------------------------------
echo.

REM 1. Create build folder
echo [1/8] Creating build directory...
mkdir build 2>nul
if exist build (
    echo       OK - build folder created/available
) else (
    echo       ERROR - Failed to create build folder
    pause
    exit /b 1
)
echo.

REM 2. Copy source file to build
echo [2/8] Copying test_dll.java to build...
copy test_dll.java build\ >nul 2>&1
if exist build\test_dll.java (
    echo       OK - test_dll.java copied
) else (
    echo       ERROR - test_dll.java not found in current directory
    pause
    exit /b 1
)
echo.

REM 3. Copy JNA to build
echo [3/8] Copying jna-5.14.0.jar to build...
copy jna-5.14.0.jar build\ >nul 2>&1
if exist build\jna-5.14.0.jar (
    echo       OK - jna-5.14.0.jar copied
) else (
    echo       ERROR - jna-5.14.0.jar not found in current directory
    pause
    exit /b 1
)
echo.

REM 4. Extract JNA
echo [4/8] Extracting jna-5.14.0.jar...
cd build
jar xf jna-5.14.0.jar >nul 2>&1
if exist com\sun\jna\ (
    echo       OK - JNA extracted successfully
) else (
    echo       ERROR - Failed to extract JNA
    cd ..
    pause
    exit /b 1
)
echo.

REM 5. Compile Java source
echo [5/8] Compiling test_dll.java...
javac -encoding UTF-8 -cp ".;jna-5.14.0.jar" test_dll.java >nul 2>&1
if %errorlevel% equ 0 (
    echo       OK - Compilation successful
) else (
    echo       ERROR - Compilation failed
    cd ..
    pause
    exit /b 1
)
echo.

REM 6. Delete temporary files
echo [6/8] Cleaning up temporary files...
del test_dll.java >nul 2>&1
del jna-5.14.0.jar >nul 2>&1
echo       OK - Temporary files removed
echo.

REM 7. Create JAR file
echo [7/8] Creating test_dll.jar...
jar cfe ..\test_dll.jar test_dll *.class com/ >nul 2>&1
if exist ..\test_dll.jar (
    echo       OK - test_dll.jar created successfully
) else (
    echo       ERROR - Failed to create JAR
    cd ..
    pause
    exit /b 1
)
echo.

REM 8. Delete build folder
echo [8/8] Removing build directory...
cd ..
rmdir /s /q build >nul 2>&1
if not exist build (
    echo       OK - Build folder removed
) else (
    echo       WARNING - Could not remove build folder completely
)
echo.

echo -----------------------------
echo BUILD COMPLETED SUCCESSFULLY!
echo Output: test_dll.jar
echo -----------------------------
echo How to run: 
echo java -jar test_dll.jar --help
echo -----------------------------

pause