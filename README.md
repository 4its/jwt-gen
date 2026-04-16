# JWT Token Generator

[Русская версия](README.ru.md) | English

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go&logoColor=white)](https://golang.org)
[![Release](https://github.com/4its/jwt-gen/actions/workflows/release.yml/badge.svg)](https://github.com/4its/jwt-gen/actions/workflows/release.yml)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A full-featured JWT token generator and validator with RSA signature. Generate, decode, and verify tokens in one utility.

## Features

- ✅ **Generate JWT tokens** with custom claims
- ✅ **Decode tokens** without signature verification
- ✅ **Verify tokens** with RSA signature validation
- ✅ Support for RSA keys in PKCS1 and PKCS8 formats
- ✅ User-friendly command-line interface with subcommands

## Installation

```bash
go mod download
go build -o jwt-gen jwt-generator.go
```

## Usage

```
jwt-gen <command> [options]

Commands:
  generate    Generate a new JWT token
  decode      Decode and display JWT token claims
  verify      Verify JWT token signature
  help        Show this help message
```

### 1. Generate Token

Create a JWT token with custom claims:

```bash
# Basic usage
./jwt-gen generate -claim source=my-app

# Multiple claims via comma
./jwt-gen generate -claim source=my-app,user_id=12345,role=admin

# Multiple claims with separate flags
./jwt-gen generate -claim source=my-app -claim user_id=12345 -claim role=admin

# Combined approach
./jwt-gen generate -claim source=my-app,user_id=12345 -claim role=admin -claim email=user@example.com

# With custom key path
./jwt-gen generate -claim source=my-app -key /path/to/private_key.pem

# Set token expiration time (in seconds)
./jwt-gen generate -claim source=my-app -exp 7200
```

**Generate Parameters:**
- `-claim key=value` (required, can be specified multiple times) - key=value pair to add to JWT claims. Multiple pairs can be specified via comma: `key1=val1,key2=val2`
- `-key` (optional, default: `private_key.pem`) - path to RSA private key
- `-exp` (optional, default: `2592000`) - token lifetime in seconds (default 30 days)

### 2. Decode Token

Decode and display token contents without signature verification:

```bash
# Decode token
./jwt-gen decode eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

# With variable
TOKEN=$(./jwt-gen generate -claim source=app)
./jwt-gen decode "$TOKEN"
```

**Output:**
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

### 3. Verify Token

Verify token signature using public key:

```bash
# Verify token
./jwt-gen verify -pubkey public_key.pem eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

# With variable
TOKEN=$(./jwt-gen generate -claim source=app)
./jwt-gen verify -pubkey public_key.pem "$TOKEN"
```

**Verify Parameters:**
- `<token>` (required) - JWT token to verify
- `-pubkey` (optional, default: `public_key.pem`) - path to RSA public key

**Output on successful verification:**
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

**On error:**
```
2025/12/22 10:15:40 Error verifying token: token signature is invalid
```

## Generating Test Keys

If you don't have RSA keys, create them:

```bash
# Generate private key
openssl genrsa -out private_key.pem 2048

# Generate public key (for token verification)
openssl rsa -in private_key.pem -pubout -out public_key.pem
```

## Complete Usage Example

```bash
# 1. Generate keys (if you don't have them)
openssl genrsa -out private_key.pem 2048
openssl rsa -in private_key.pem -pubout -out public_key.pem

# 2. Generate token
TOKEN=$(./jwt-gen generate -claim source=my-app,user_id=12345,role=admin -exp 3600)
echo "Generated token: $TOKEN"

# 3. Decode token
./jwt-gen decode "$TOKEN"

# 4. Verify token signature
./jwt-gen verify -pubkey public_key.pem "$TOKEN"
```

## Features

- **Automatic claims**: `exp`, `iat`, and `nbf` are added automatically
  - `exp` - token expiration time (current time + `-exp` flag value)
  - `iat` - token issued at time
  - `nbf` - token not valid before time
- **Flexible claims format**: can be specified via comma or separate flags
- **Readable timestamps**: timestamps are displayed in human-readable format when decoding
- **Signature verification**: full RSA signature validation with `verify` command

## Verify Token Online

Tokens can also be verified at [jwt.io](https://jwt.io) by uploading the public key for signature verification.

## License

This project is open source and available under the [MIT License](LICENSE).