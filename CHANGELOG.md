# Changelog

All notable changes to l9g-crypto. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versioning follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The version number is shared by all modules
(`crypto-core`, `crypto-spring`, `crypto-jpa`, `crypto-tool`,
`crypto-vault-sample-app`).

## [Unreleased] – 1.0.7

### Added

- `AppSecretKey` can read the key from a **classpath resource**.
  `SECRET_PATH=classpath:assets/secret.bin` looks the resource up via the
  context class loader first and then via its own. This lets the key travel
  inside a jar or a GraalVM native image instead of sitting next to it as a
  file.
- System property **`secret.path`** as a fallback when the `SECRET_PATH`
  environment variable is not set. Intended for programs that ship their own
  key and have no opportunity to set an environment variable, such as a desktop
  application started by double-click. The environment variable deliberately
  keeps precedence so that operations can redirect the key from the outside
  without touching the application.
- `AppSecretKey.resolveClasspathResource()` and `AppSecretKey.CLASSPATH_PREFIX`
  as public companions to `resolveSecretPath()`.
- Five additional tests in `AppSecretKeyTest` (loading from the classpath,
  missing resource, wrong key length, prefix and leading-slash resolution,
  environment variable taking precedence over the system property) plus two
  test resources (`test-secret.bin`, `test-secret-short.bin`).

### Changed

- `resolveSecretPath()` no longer returns a bogus file path when a classpath
  resource is configured; `classpath:...` would otherwise have been treated as
  a relative file name.

### Important for callers

A **missing classpath resource does not generate a new key**; it throws
`CryptoException`. Nothing can be written into a jar or a native image, and a
freshly generated key would only surface later as a `Tag mismatch` during the
first decryption, an error that no longer reveals its real cause. Automatic key
generation remains reserved for file system paths and is unchanged there.

## [1.0.6] – 2026-09-09

### Added

- `CryptoFailureAnalyzer`: Spring Boot now reports key and decryption failures
  as a readable "APPLICATION FAILED TO START" diagnosis instead of a stack
  trace, including a hint about `SECRET_PATH` and the expected key length.
  Registered via `META-INF/spring.factories`.
- `CryptoException` (extends `IllegalStateException`) as the single exception
  type of the core library, carrying the complete cause chain.
- `EncryptedPropertiesEnvironmentPostProcessor` logs through Spring Boot's
  `DeferredLogFactory`, touches the secret key only when at least one
  `{AES256}` value is present, and names the failing property key and property
  source (never the value) on decryption errors.
- Tests for the post-processor and the failure analyzer.
- `CRYPTO_SOURCECODE_STATISTIK.md`.

### Changed

- `AppSecretKey` reworked: a failed singleton initialization is no longer
  cached, so a repeated call throws the real `CryptoException` instead of a
  `NoClassDefFoundError`. On fatal errors one additional line goes to
  `System.err`, because the failure frequently occurs before logging is
  initialized. Key material is never printed.
- The core library no longer logs at error level before throwing. Such
  log-and-throw messages were silently discarded during Spring Boot's
  `EnvironmentPostProcessor` phase, where Logback (and bridged
  `java.util.logging`) is suppressed.
- `AES256` and `CryptoHandler` hardened, Javadoc revised.
- `crypto-tool` prints the complete cause chain of any failure to `stderr` and
  exits with status 1; the logging level for `de.l9g.crypto.core` is now
  actually applied (the previous logger name `l9g` matched nothing).
- Dependency updates: Spring Boot 3.5.16, Spring Framework 6.2.19, SLF4J
  2.0.18, Spring Shell 3.4.3, JUnit 6.1.3 (now managed centrally in the parent
  POM), central-publishing-maven-plugin 0.11.0. The tool imports the Spring
  Boot BOM ahead of the Spring Shell BOM so that all Boot artifacts resolve to
  the same version.

## [1.0.5] – 2026-05-04

### Added

- JUnit tests for `crypto-core`.

### Changed

- More precise exception information.

## [1.0.4] – 2026-04-09

### Changed

- Security hardening in core and sample application, revised Javadoc.

## [1.0.3] – 2026-04-08

### Added

- `crypto-vault-sample-app`: management of admin keys via a web interface,
  enrollment workflow, handling of particularly sensitive data, TTL for
  unsealing including a remaining-time display.
- New password generator code.

## [1.0.2] – 2026-02-20

### Added

- `crypto-tool` command line utility.
- Default length for the password generator, `HELP` constant, more
  documentation.

### Fixed

- Overriding of values from multiple profiles.
- Debug output via `System.out` removed.

## [1.0.1] – 2026-02-05

First published version.
