# Техническая справка

## Обзор архитектуры

Приложение разделено на три основных слоя.

### GUI-слой

Расположен в `src/gui/`.

Отвечает за:

- главное окно приложения
- дочерние окна и диалоги
- системный трей
- обработку действий пользователя

Ключевая точка входа GUI:

- `src/gui/main_window.py`

### Core-слой

Расположен в `src/core/`.

Отвечает за:

- аутентификацию и состояние сессии
- работу хранилища
- криптографию и вывод ключей
- защищенный буфер обмена
- аудит и контроль целостности
- импорт/экспорт и обмен записями
- security hardening, panic mode и activity monitoring

Основные пакеты:

- `src/core/crypto/`
- `src/core/vault/`
- `src/core/clipboard/`
- `src/core/import_export/`
- `src/core/security/`
- `src/core/audit/`

### Слой данных

Расположен в `src/database/`.

Отвечает за:

- соединение с SQLite
- миграции схемы
- постоянные настройки и метаданные

Ключевые файлы:

- `src/database/db.py`
- `src/database/models.py`

## Поток запуска приложения

Основная инициализация идет через `src/__main__.py`.

Высокоуровневый порядок:

1. Загружается `config.json`.
2. Создается корневой Tk-контекст.
3. При первом запуске открывается мастер настройки.
4. Открывается база SQLite и применяются миграции.
5. Создаются `EventBus`, `KeyManager`, `StateManager` и `SettingsService`.
6. Загружаются и валидируются настройки security hardening.
7. Инициализируются `ActivityMonitor`, `MemoryGuard`, `PanicMode` и `AuthenticationService`.
8. Если vault уже инициализирован, выполняется вход через мастер-пароль.
9. Подключается аудит.
10. Запускается `MainWindow`.

## Криптографические алгоритмы

### AES-256-GCM

Шифрование записей реализовано в `src/core/vault/encryption_service.py`.

Параметры:

- реализация: `cryptography.hazmat.primitives.ciphers.aead.AESGCM`
- размер nonce: 12 байт
- режим: GCM
- формат данных: `nonce + ciphertext`

Используется для:

- шифрования payload записей vault
- части сценариев безопасного обмена

### Argon2id

Вывод хеша аутентификации реализован в `src/core/crypto/key_derivation.py`.

Параметры `Argon2Params` по умолчанию:

- `time_cost = 3`
- `memory_cost = 65536`
- `parallelism = 4`
- `hash_len = 32`
- `salt_len = 16`
- тип: Argon2id

Используется для:

- вычисления и проверки хеша мастер-пароля

### PBKDF2-HMAC-SHA256

Вывод ключа шифрования также реализован в `src/core/crypto/key_derivation.py`.

Параметры `PBKDF2Params` по умолчанию:

- `iterations = 100000`
- `dklen = 32`
- `hash_name = sha256`
- `salt_len = 16`

Используется для:

- получения ключа шифрования vault из мастер-пароля

### Алгоритмы обмена ключами и подписи

Реализованы в `src/core/import_export/key_exchange.py`.

Поддерживаются:

- X25519 для ECDH-обмена
- P-256 для ECDH и ECDSA
- RSA-2048 для обертки ключей и подписей

Сопутствующие примитивы:

- HKDF-SHA256 для вывода общего ключа
- RSA OAEP для шифрования ключевого материала
- ECDSA-SHA256 и RSA-PSS-SHA256 для подписей

## Security Hardening

Модули hardening находятся в `src/core/security/`.

Они покрывают:

- constant-time compare и нормализацию времени выполнения
- защиту памяти и очистку чувствительных буферов
- мониторинг активности пользователя
- panic mode
- платформенные проверки возможностей защиты
- профили безопасности и валидацию настроек

Интеграции уже есть в:

- `VaultEncryptionService`
- `key_derivation.py`
- логике аутентификации и автоблокировки

## Ключевые структуры данных

### Entry

Структура определена в `src/core/vault/entry_manager.py`.

```python
Entry(
    id,
    title,
    username,
    password,
    url,
    notes,
    category,
    version,
    created_at,
    updated_at,
    tags,
)
```

Поведение:

- GUI работает с расшифрованными объектами `Entry`
- в базе хранится зашифрованный payload
- `EntryManager` отвечает за CRUD, пагинацию и soft delete, если он поддерживается схемой

### Payload записи vault

Нормализуется и шифруется через `VaultEncryptionService`.

Поля payload:

- `title`
- `username`
- `password`
- `url`
- `notes`
- `category`
- `created_at`
- `version`

### ClipboardContent

Определена в `src/core/clipboard/clipboard_service.py`.

Поля:

- `data_type`
- `expected_hash`
- `created_at`
- `entry_id`

Эта структура хранит ожидаемое состояние буфера для безопасной очистки и проверки подозрительной активности.

## Схема базы данных

Миграции схемы описаны в `src/database/models.py`.

### Основные таблицы

`vault_entries`

- хранит зашифрованные записи хранилища
- содержит временные метки создания и обновления
- хранит теги отдельно от зашифрованного payload

Ключевые поля в текущем пути схемы:

- `id`
- `encrypted_data`
- `created_at`
- `updated_at`
- `tags`

`settings`

- хранит настройки приложения и безопасности
- поддерживает как зашифрованные, так и открытые значения

Поля:

- `id`
- `setting_key`
- `setting_value`
- `encrypted`

`key_store`

- хранит ключевой материал и связанные метаданные

Поля:

- `id`
- `key_type`
- `key_data`
- `version`
- `created_at`

### Таблицы аудита

`audit_log_new`

- основной журнал аудита с полями для контроля целостности

Ключевые поля:

- `sequence_number`
- `previous_hash`
- `entry_data`
- `entry_hash`
- `signature`
- `signature_algorithm`
- `timestamp`
- `event_type`
- `severity`
- `user_id`
- `source`
- `entry_id`

Связанные таблицы:

- `audit_write_control`
- `audit_public_keys`
- `audit_entry_keys`
- `audit_log_archive`
- `audit_security_log`

### Таблицы обмена и импорта/экспорта

`shared_entries`

- хранит метаданные расшаренных записей

Поля:

- `shared_id`
- `original_entry_id`
- `encryption_method`
- `recipient_info`
- `permissions`
- `shared_at`
- `expires_at`

`import_export_history`

- хранит историю импорта и экспорта

Поля:

- `id`
- `operation_type`
- `format`
- `encryption_used`
- `entry_count`
- `file_size`
- `checksum`
- `verification_status`
- `created_at`

## Тесты и покрытие

Для автоматических проверок используются `pytest` и `pytest-cov`.

Ключевые файлы:

- `pytest.ini`
- `.coveragerc`
- `tests/report/summary.md`
- `tests/report/junit.xml`
- `tests/report/coverage.xml`

Текущее требование по покрытию - не менее 80%.
