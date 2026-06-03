Упаковка и запуск на Windows
Запуск из исходного кода
Создайте или активируйте виртуальное окружение:

venv\Scripts\activate

Установите зависимости:

python -m pip install -r requirements.txt

Запустите приложение:

python run.py

Сборка исполняемого файла для Windows
Активируйте виртуальное окружение:

venv\Scripts\activate

Установите зависимости:

python -m pip install -r requirements.txt

Запустите скрипт сборки:

powershell -ExecutionPolicy Bypass -File .\build_windows.ps1

Результат сборки

PyInstaller создаёт дистрибутив в формате одной папки:

исполняемый файл: dist\CryptoSafeManager\CryptoSafeManager.exe
зависимости: остальные файлы внутри папки dist\CryptoSafeManager\

Это соответствует используемой здесь модели распространения Windows-приложения: один основной исполняемый файл и все необходимые runtime-файлы в той же папке.

Запуск упакованного приложения
Откройте папку:

dist\CryptoSafeManager\

Запустите:

CryptoSafeManager.exe

Примечания
Упакованное приложение создаёт и использует файл config.json рядом с рабочей папкой исполняемого файла.
При первом запуске мастер настройки создаёт или выбирает SQLite-базу данных хранилища.
Если Windows SmartScreen предупреждает об исполняемом файле, для локальных тестовых сборок разрешите запуск приложения вручную.