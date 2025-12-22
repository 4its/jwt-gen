# JWT Token Generator

Русская версия | [English](README.md)

Полнофункциональный генератор и валидатор JWT токенов с подписью RSA. Генерация, декодирование и проверка токенов в одной утилите.

## Возможности

- ✅ **Генерация JWT токенов** с произвольными claims
- ✅ **Декодирование токенов** без проверки подписи
- ✅ **Верификация токенов** с проверкой подписи RSA
- ✅ Поддержка RSA ключей в форматах PKCS1 и PKCS8
- ✅ Удобный интерфейс командной строки с подкомандами

## Установка

```bash
go mod download
go build -o jwt-gen jwt-generator.go
```

## Использование

```
jwt-gen <command> [options]

Commands:
  generate    Generate a new JWT token
  decode      Decode and display JWT token claims
  verify      Verify JWT token signature
  help        Show this help message
```

### 1. Генерация токена (generate)

Создание JWT токена с произвольными claims:

```bash
# Базовое использование
./jwt-gen generate -claim source=my-app

# Несколько claims через запятую
./jwt-gen generate -claim source=my-app,user_id=12345,role=admin

# Несколько claims отдельными флагами
./jwt-gen generate -claim source=my-app -claim user_id=12345 -claim role=admin

# Комбинированный подход
./jwt-gen generate -claim source=my-app,user_id=12345 -claim role=admin -claim email=user@example.com

# С пользовательским путём к ключу
./jwt-gen generate -claim source=my-app -key /path/to/private_key.pem

# Указание времени жизни токена (в секундах)
./jwt-gen generate -claim source=my-app -exp 7200
```

**Параметры generate:**
- `-claim key=value` (обязательный, может указываться многократно) - пара ключ=значение для добавления в JWT claims. Можно указывать несколько пар через запятую: `key1=val1,key2=val2`
- `-key` (опционально, по умолчанию: `private_key.pem`) - путь к приватному ключу RSA
- `-exp` (опционально, по умолчанию: `2592000`) - время жизни токена в секундах (по умолчанию 30 дней)

### 2. Декодирование токена (decode)

Декодирование и отображение содержимого токена без проверки подписи:

```bash
# Декодировать токен
./jwt-gen decode eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

# С переменной
TOKEN=$(./jwt-gen generate -claim source=app)
./jwt-gen decode "$TOKEN"
```

**Вывод:**
```
Token Claims:
=============
{
  "exp": "1766391303 (2025-12-22T11:15:03+03:00)",
  "iat": "1766387703 (2025-12-22T10:15:03+03:00)",
  "nbf": "1766387703 (2025-12-22T10:15:03+03:00)",
  "role": "admin",
  "source": "test-app",
  "user_id": "12345"
}
```

### 3. Верификация токена (verify)

Проверка подписи токена с использованием публичного ключа:

```bash
# Проверить токен
./jwt-gen verify eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9... -pubkey public_key.pem

# С переменной
TOKEN=$(./jwt-gen generate -claim source=app)
./jwt-gen verify "$TOKEN" -pubkey public_key.pem
```

**Параметры verify:**
- `<token>` (обязательный) - JWT токен для проверки
- `-pubkey` (опционально, по умолчанию: `public_key.pem`) - путь к публичному ключу RSA

**Вывод при успешной проверке:**
```
✓ Token signature is valid

Token Claims:
=============
{
  "exp": "1766391303 (2025-12-22T11:15:03+03:00)",
  "iat": "1766387703 (2025-12-22T10:15:03+03:00)",
  "nbf": "1766387703 (2025-12-22T10:15:03+03:00)",
  "role": "admin",
  "source": "test-app",
  "user_id": "12345"
}
```

**При ошибке:**
```
2025/12/22 10:15:40 Error verifying token: token signature is invalid
```

## Генерация тестовых ключей

Если у вас нет RSA ключей, создайте их:

```bash
# Генерация приватного ключа
openssl genrsa -out private_key.pem 2048

# Генерация публичного ключа (для проверки токена)
openssl rsa -in private_key.pem -pubout -out public_key.pem
```

## Полный пример использования

```bash
# 1. Сгенерировать ключи (если их нет)
openssl genrsa -out private_key.pem 2048
openssl rsa -in private_key.pem -pubout -out public_key.pem

# 2. Сгенерировать токен
TOKEN=$(./jwt-gen generate -claim source=my-app,user_id=12345,role=admin -exp 3600)
echo "Generated token: $TOKEN"

# 3. Декодировать токен
./jwt-gen decode "$TOKEN"

# 4. Проверить подпись токена
./jwt-gen verify "$TOKEN" -pubkey public_key.pem
```

## Особенности

- **Автоматические claims**: `exp`, `iat` и `nbf` добавляются автоматически
  - `exp` - время истечения токена (текущее время + значение флага `-exp`)
  - `iat` - время создания токена
  - `nbf` - время, с которого токен становится валидным
- **Гибкий формат claims**: можно указывать через запятую или отдельными флагами
- **Читаемые временные метки**: при декодировании timestamps отображаются в удобном формате
- **Проверка подписи**: полная валидация RSA подписи при использовании команды `verify`
- **Относительные пути**: ключи можно указывать относительно директории программы

## Проверка токена онлайн

Токены также можно проверить на [jwt.io](https://jwt.io), загрузив публичный ключ для верификации подписи.