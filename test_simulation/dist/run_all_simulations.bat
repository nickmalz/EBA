@echo off
echo Запуск всех симуляторов вредоносных процессов с интервалами...
echo.

echo Запуск SystemUpdater.exe (симуляция майнера)...
start "" "SystemUpdater.exe"
echo Ждем 10 секунд...
timeout /t 10 /nobreak >nul

echo.
echo Запуск CryptoLocker.exe (симуляция шифровальщика)...
start "" "CryptoLocker.exe"
echo Ждем 10 секунд...
timeout /t 10 /nobreak >nul

echo.
echo Запуск DataEncryptor.exe (симуляция комбинированного вредоносного поведения)...
start "" "DataEncryptor.exe"
echo Ждем 10 секунд...
timeout /t 10 /nobreak >nul

echo.
echo Все симуляторы запущены. Для завершения закройте окна вручную.
pause