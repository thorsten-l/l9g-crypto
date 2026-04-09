# L9G Crypto Libraries

## Project Overview

This project is a multi-module Maven project providing AES-256 encryption and decryption capabilities along with integration for Spring Framework encrypted properties, JPA attribute conversion, and a WebAuthn-backed "Vault" mechanism. It consists of five modules: `l9g-crypto-core`, `l9g-crypto-spring`, `l9g-crypto-jpa`, `l9g-crypto-tool`, and `l9g-crypto-vault-sample-app`.

## Modules

### 1. `l9g-crypto-core`

#### Project Overview
This module, `l9g-crypto-core`, is a Java library designed to provide AES-256 encryption and decryption capabilities. It implements AES-256 in GCM (Galois/Counter Mode) for robust encryption, handling secure random Initialization Vector (IV) generation and authentication tags. 

#### Key Features
*   **Singleton Pattern:** `CryptoHandler` acts as a centralized entry point.
*   **Key Management:** `AppSecretKey` manages the master secret, supporting environment overrides and secure memory wiping.
*   **Password Generator:** Includes a cryptographically secure random password generator that avoids ambiguous characters.

#### Building
```bash
mvn clean install -pl l9g-crypto-core
```

#### Running/Integrating
```xml
<dependency>
  <groupId>de.l9g</groupId>
  <artifactId>crypto-core</artifactId>
  <version>1.0.4</version>
</dependency>
```

---

### 2. `l9g-crypto-spring`

#### Project Overview
Provides seamless integration with the Spring Framework to automatically decrypt properties. It uses `EncryptedPropertiesEnvironmentPostProcessor` to intercept and decrypt string properties prefixed with `{AES256}` during the Spring environment setup.

#### Building
```bash
mvn clean install -pl l9g-crypto-spring
```

#### Running/Integrating
```xml
<dependency>
  <groupId>de.l9g</groupId>
  <artifactId>crypto-spring</artifactId>
  <version>1.0.4</version>
</dependency>
```

---

### 3. `l9g-crypto-jpa`

#### Project Overview
Provides transparent encryption and decryption of JPA entity attributes. It leverages the core library to encrypt String attributes before database persistence and decrypt them upon loading.

#### Example Usage
Annotate your entity fields:
```java
@Convert(converter = EncryptedAttributeConverter.class)
private String sensitiveData;
```

#### Running/Integrating
```xml
<dependency>
  <groupId>de.l9g</groupId>
  <artifactId>crypto-jpa</artifactId>
  <version>1.0.4</version>
</dependency>
```

---

### 4. `l9g-crypto-tool`

#### Project Overview
A CLI application built with Spring Shell for standalone cryptographic operations. It supports interactive and batch modes.

#### Available Commands
*   `version`: Show version info.
*   `encrypt --text <plain_text>`: Encrypt text.
*   `decrypt --encrypted <cipher_text>`: Decrypt text.
*   `pwgen --length <n>`: Generate and encrypt a random password.

#### Native Compilation
Supports GraalVM native image for improved performance and security:
```bash
./NATIVE_COMPILE.sh
```

---

### 5. `l9g-crypto-vault-sample-app`

#### Project Overview
A comprehensive Spring Boot sample application demonstrating a high-security "Vault" architecture.

#### Key Features
*   **WebAuthn PRF Integration:** Uses hardware security keys (like YubiKey) to derive encryption keys.
*   **Sealed/Unsealed State:** The master key exists only in volatile memory with a configurable TTL.
*   **OIDC/OAuth2:** Full integration with identity providers for administrator authentication.
*   **Transparent Decryption:** Demonstrates the use of the `crypto-spring` module for configuration properties.

#### Running
```bash
mvn spring-boot:run -pl l9g-crypto-vault-sample-app
```

## Building the Entire Project

To build all modules from the root directory:
```bash
mvn clean install
```

## Development Conventions

*   **Language:** Java 17
*   **Encryption:** AES-256 GCM (Authenticated Encryption)
*   **Hygiene:** Explicit memory wiping of sensitive key material.
*   **Frameworks:** Spring Boot 3.5+, Jakarta Persistence 3.2+
