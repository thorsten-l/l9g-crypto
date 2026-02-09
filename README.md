# L9G Crypto Libraries

## Project Overview

This project is a multi-module Maven project providing AES-256 encryption and decryption capabilities along with integration for Spring Framework encrypted properties and JPA attribute conversion. It consists of three modules: `l9g-crypto-core`, `l9g-crypto-spring`, and `l9g-crypto-jpa`.

## Modules

### 1. `l9g-crypto-core`

#### Project Overview
This module, `l9g-crypto-core`, is a Java library designed to provide AES-256 encryption and decryption capabilities. It is built with Maven and utilizes Project Lombok.

The library implements AES-256 in GCM (Galois/Counter Mode) for robust encryption, handling secure random Initialization Vector (IV) generation and authentication tags. `CryptoHandler` acts as a singleton for managing encryption and decryption operations, using `AppSecretKey` to manage the application's secret key from `data/secret.bin`. Encrypted strings are prefixed with "{AES256}".

#### Building
To build only this module, navigate to its directory (`l9g-crypto-core`) and execute:
```bash
mvn clean install
```

#### Running/Integrating
To use this library in another Maven project, add the following dependency to your project's `pom.xml`:

```xml
<dependency>
  <groupId>de.l9g</groupId>
  <artifactId>l9g-crypto-core</artifactId>
  <version>1.0.1</version> <!-- Use the appropriate version -->
</dependency>
```

Example usage:
```java
import de.l9g.crypto.core.CryptoHandler;

public class MyService {
    private final CryptoHandler cryptoHandler = CryptoHandler.getInstance();

    public String encryptData(String data) {
        return cryptoHandler.encrypt(data);
    }

    public String decryptData(String encryptedData) {
        return cryptoHandler.decrypt(encryptedData);
    }
}
```

#### Development Conventions
*   **Language:** Java 17
*   **Build Tool:** Maven
*   **Libraries:** Project Lombok
*   **Encryption Standard:** AES-256 GCM
*   **Secret Key Management:** `AppSecretKey` from `data/secret.bin`.

### 2. `l9g-crypto-spring`

#### Project Overview
This module, `l9g-crypto-spring`, provides integration with the Spring Framework to automatically decrypt properties that are encrypted using the `l9g-crypto-core` library. It uses `EncryptedPropertiesEnvironmentPostProcessor` to intercept and decrypt properties prefixed with "{AES256}" during the Spring environment setup.

#### Building
To build only this module, navigate to its directory (`l9g-crypto-spring`) and execute:
```bash
mvn clean install
```

#### Running/Integrating
To use this library in a Spring Boot Maven project, add the following dependency to your project's `pom.xml`:

```xml
<dependency>
  <groupId>de.l9g</groupId>
  <artifactId>l9g-crypto-spring</artifactId>
  <version>1.0.1</version> <!-- Use the appropriate version -->
</dependency>
```
The `EncryptedPropertiesEnvironmentPostProcessor` is automatically registered via `META-INF/spring.factories` and will process encrypted properties during application startup.

#### Development Conventions
*   **Language:** Java 17
*   **Build Tool:** Maven
*   **Libraries:** Project Lombok, Spring Framework, Spring Boot
*   **Dependencies:** `l9g-crypto-core`

### 3. `l9g-crypto-jpa`

#### Project Overview
This module, `l9g-crypto-jpa`, provides seamless integration with Jakarta Persistence API (JPA) for transparent encryption and decryption of entity attributes. It leverages the `l9g-crypto-core` library to automatically encrypt String attributes before they are persisted to the database and decrypt them when loaded. This is achieved through an `AttributeConverter`.

#### Building
To build only this module, navigate to its directory (`l9g-crypto-jpa`) and execute:
```bash
mvn clean install
```

#### Running/Integrating
To use this library in another Maven project that uses JPA, add the following dependency to your project's `pom.xml`:

```xml
<dependency>
  <groupId>de.l9g</groupId>
  <artifactId>l9g-crypto-jpa</artifactId>
  <version>1.0.1</version> <!-- Use the appropriate version -->
</dependency>
```

Then, annotate the String attributes in your JPA entities that you wish to encrypt with `@Convert(converter = EncryptedAttributeConverter.class)`.

Example:
```java
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import de.l9g.crypto.jpa.EncryptedAttributeConverter;

@Entity
public class User {
    @Id
    private Long id;

    private String username;

    @Convert(converter = EncryptedAttributeConverter.class)
    private String sensitiveData;

    // Getters and Setters
}
```

#### Development Conventions
*   **Language:** Java 17
*   **Build Tool:** Maven
*   **Libraries:** Project Lombok (inherited), Jakarta Persistence API
*   **Dependencies:** `l9g-crypto-core`

### 4. `l9g-crypto-tool`

#### Project Overview
This module, `l9g-crypto-tool`, is a command-line interface (CLI) application built with Spring Shell. It provides utilities for encrypting and decrypting strings using the `l9g-crypto-core` library, and for generating random passwords. It acts as a convenient standalone tool for interacting with the core crypto functionalities.

#### Building
To build only this module, navigate to its directory (`l9g-crypto-tool`) and execute:
```bash
mvn clean install
```

#### Running/Integrating
The `l9g-crypto-tool` can be run directly as an executable JAR or compiled into a native image using GraalVM.

**Running as JAR:**
```bash
java -jar l9g-crypto-tool.jar [commands]
```
For interactive mode:
```bash
java -jar l9g-crypto-tool.jar -i
```

**Running native image:**
First, compile the native image (requires GraalVM and `native-image` tool installed):
```bash
./NATIVE_COMPILE.sh
```
Then run the executable:
```bash
./l9g-crypto-tool [commands]
```
For interactive mode:
```bash
./l9g-crypto-tool -i
```

**Available Commands (e.g., in interactive mode or directly):**
*   `version`: Displays the application version.
*   `encrypt --text <your_text>`: Encrypts the provided clear text.
*   `decrypt --encrypted <encrypted_text>`: Decrypts the provided encrypted text.
*   `pwgen --length <number>`: Generates a random password of specified length (default length = 16 characters) and encrypts it.

#### Development Conventions
*   **Language:** Java 17
*   **Build Tool:** Maven
*   **Libraries:** Project Lombok, Spring Boot, Spring Shell
*   **Dependencies:** `l9g-crypto-core`
*   **Native Compilation:** GraalVM `native-image`

## Building the Entire Project

To build all modules from the root directory of the `l9g-crypto` project, execute the following Maven command:

```bash
mvn clean install
```

This command will compile all modules, run their respective tests, and package them into JAR files.

## Development Conventions (Overall)

*   **Language:** Java 17
*   **Build Tool:** Maven
*   **Libraries:** Project Lombok for reducing boilerplate code.
*   **Encryption Standard:** AES-256 GCM
*   **Secret Key Management:** Application secret keys are managed by `AppSecretKey` and stored in `data/secret.bin` within the `l9g-crypto-core` context.
