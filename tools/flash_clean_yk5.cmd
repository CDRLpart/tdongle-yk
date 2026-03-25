@echo off
setlocal

set "PORT=%~1"
if "%PORT%"=="" set "PORT=COM5"

for %%I in ("%~dp0..") do set "REPO_ROOT=%%~fI"
cd /d "%REPO_ROOT%"

set "PY=%IDF_PYTHON_ENV_PATH%\Scripts\python.exe"
if not exist "%PY%" set "PY=%USERPROFILE%\.espressif\python_env\idf5.5_py3.11_env\Scripts\python.exe"
if not exist "%PY%" set "PY=python"

echo [1/2] Full chip erase on %PORT% ...
"%PY%" -m esptool --chip esp32s3 -p %PORT% -b 115200 erase_flash
if errorlevel 1 goto :fail

echo [2/2] Flashing build-tdongle-yk5 ...
"%PY%" -m esptool --chip esp32s3 -p %PORT% -b 460800 --before default_reset --after hard_reset write_flash --flash_mode dio --flash_size 4MB --flash_freq 80m 0x0 build-tdongle-yk5\bootloader\bootloader.bin 0x8000 build-tdongle-yk5\partition_table\partition-table.bin 0x10000 build-tdongle-yk5\pico_fido2.bin
if errorlevel 1 goto :fail

echo.
echo Flash done.
echo Unplug/replug the dongle now.
exit /b 0

:fail
echo.
echo Flash failed. Keep BOOT button pressed while plugging in and run again.
exit /b 1
