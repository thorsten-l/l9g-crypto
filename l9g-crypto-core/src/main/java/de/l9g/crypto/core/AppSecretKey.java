/*
 * Copyright 2025 Thorsten Ludewig (t.ludewig@gmail.com).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.l9g.crypto.core;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Set;
import javax.security.auth.Destroyable;
import lombok.extern.slf4j.Slf4j;

/**
 * Manages the application's secret key, loading it from or generating it into a file.
 * This class ensures a single instance of the secret key is available throughout the application
 * for cryptographic operations, primarily for AES-256 encryption.
 * <p>
 * The secret key is stored in a binary file. The path to this file can be configured via the
 * {@code SECRET_PATH} environment variable or, if that is unset, the {@code secret.path}
 * system property. If neither is provided, it defaults to {@code data/secret.bin}.
 * On systems supporting POSIX file attributes, strict file permissions (read-only for the owner)
 * are applied to the secret file.
 * </p>
 * <p>
 * {@code SECRET_PATH} may instead reference a classpath resource by using the
 * {@code classpath:} prefix, e.g. {@code classpath:assets/secret.bin}. This allows the key
 * to ship inside a jar or a GraalVM native image. A classpath resource is read-only: if it
 * cannot be found, a {@link CryptoException} is thrown rather than generating a new key,
 * because there is nowhere to write it. Automatic generation therefore remains reserved for
 * file system paths.
 * </p>
 * <p>
 * If the key cannot be loaded or created, a {@link CryptoException} is thrown from
 * {@link #getInstance()}. Because this is a fatal condition that frequently occurs
 * before the application's logging is initialized (e.g. during Spring Boot's
 * environment post-processing), a single diagnostic line is additionally written
 * to {@link System#err}. No key material is ever written there.
 * </p>
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
@Slf4j
public class AppSecretKey implements Destroyable, AutoCloseable
{
  /**
   * Environment variable name for overriding the default secret key file path.
   */
  public static final String SECRET_PATH_ENV_NAME = "SECRET_PATH";

  /**
   * System property consulted when {@link #SECRET_PATH_ENV_NAME} is not set.
   * <p>
   * Intended for applications that ship their own key and have no opportunity to
   * set an environment variable - a desktop program started by double click, for
   * instance. Such an application sets this property before the first key access;
   * the environment variable keeps precedence so that an operator can still
   * redirect the key without touching the application.
   * </p>
   */
  public static final String SECRET_PATH_PROPERTY_NAME = "secret.path";

  /**
   * Prefix marking a {@code SECRET_PATH} value as a classpath resource instead of a file.
   */
  public static final String CLASSPATH_PREFIX = "classpath:";

  /**
   * The default path to the file where the secret key is stored.
   */
  public static final Path DEFAULT_SECRET_PATH = Path.of("data/secret.bin");

  /**
   * Prefix of the single fallback line written to {@link System#err} on fatal errors.
   */
  static final String FATAL_PREFIX = "[l9g-crypto] FATAL: ";

  /**
   * The expected length of the secret key in bytes (32 bytes for AES-256).
   */
  private static final int KEY_LEN = AES256.KEY_LEN_BYTES; // 32

  /**
   * Lazily initialized singleton instance. Unlike the initialization-on-demand
   * holder idiom, a failed initialization is not cached: every subsequent call
   * to {@link #getInstance()} retries and rethrows the real {@link CryptoException}
   * instead of a {@code NoClassDefFoundError}.
   */
  private static volatile AppSecretKey instance;

  /**
   * Private constructor to initialize AppSecretKey with a given secret key.
   * Ensures that the secret key is always set when an instance is created.
   *
   * @param secretKey The byte array representing the secret key.
   */
  private AppSecretKey(byte[] secretKey)
  {
    this.secretKey = secretKey;
  }

  /**
   * Returns the singleton instance of {@code AppSecretKey}.
   * The secret key is loaded or generated on first access.
   *
   * @return The singleton instance of {@code AppSecretKey}.
   *
   * @throws CryptoException If the secret file cannot be read, created or has an invalid length.
   */
  public static AppSecretKey getInstance()
  {
    AppSecretKey result = instance;
    if(result == null)
    {
      synchronized(AppSecretKey.class)
      {
        result = instance;
        if(result == null)
        {
          String classpathResource = resolveClasspathResource();
          result = classpathResource != null
            ? loadFromClasspath(classpathResource)
            : loadOrCreate(resolveSecretPath());
          instance = result;
        }
      }
    }
    return result;
  }

  /**
   * Returns the configured secret location: the {@code SECRET_PATH} environment
   * variable if set, otherwise the {@code secret.path} system property, otherwise
   * {@code null}.
   * <p>
   * The environment variable deliberately wins: an application may set the system
   * property to point at its own bundled key, and an operator must still be able to
   * override that from outside.
   * </p>
   *
   * @return The configured location, or {@code null} if neither is set.
   */
  static String configuredLocation()
  {
    String value = System.getenv(SECRET_PATH_ENV_NAME);
    if(value == null || value.isBlank())
    {
      value = System.getProperty(SECRET_PATH_PROPERTY_NAME);
    }
    return (value == null || value.isBlank()) ? null : value.trim();
  }

  /**
   * Determines the secret file path from {@link #configuredLocation()},
   * falling back to {@link #DEFAULT_SECRET_PATH}.
   * <p>
   * Only meaningful for file system locations. When the configured value names a
   * classpath resource, use {@link #resolveClasspathResource()} instead - the value
   * would otherwise be mistaken for a relative file name.
   * </p>
   *
   * @return The path of the secret key file.
   */
  public static Path resolveSecretPath()
  {
    String location = configuredLocation();
    if(location != null &&  ! location.startsWith(CLASSPATH_PREFIX))
    {
      return Path.of(location);
    }
    return DEFAULT_SECRET_PATH;
  }

  /**
   * Returns the classpath resource named by {@link #configuredLocation()}, or
   * {@code null} if nothing is configured or it points at the file system.
   *
   * @return The resource name without the {@code classpath:} prefix and without a
   *         leading slash, or {@code null}.
   */
  public static String resolveClasspathResource()
  {
    String location = configuredLocation();
    if(location == null || ! location.startsWith(CLASSPATH_PREFIX))
    {
      return null;
    }

    String resource = location.substring(CLASSPATH_PREFIX.length()).trim();
    while(resource.startsWith("/"))
    {
      resource = resource.substring(1);
    }
    return resource.isEmpty() ? null : resource;
  }

  /**
   * Loads the secret key from a classpath resource.
   * <p>
   * Unlike {@link #loadOrCreate(Path)} this never generates a key: a classpath
   * resource lives inside a jar or native image and cannot be written to. A missing
   * resource is a configuration error and is reported as such, instead of silently
   * producing a key that cannot decrypt any existing value.
   * </p>
   *
   * @param resource The resource name, e.g. {@code assets/secret.bin}.
   *
   * @return An instance holding the key from the classpath.
   *
   * @throws CryptoException If the resource is missing, unreadable or has an invalid length.
   */
  static AppSecretKey loadFromClasspath(String resource)
  {
    log.debug("Loading secret from classpath resource: {}", resource);

    // Context class loader first (Spring, servlet containers, tests), then our own.
    ClassLoader contextLoader = Thread.currentThread().getContextClassLoader();
    byte[] secretKey = null;

    for(ClassLoader loader : new ClassLoader[]
    {
      contextLoader, AppSecretKey.class.getClassLoader()
    })
    {
      if(loader == null)
      {
        continue;
      }
      try(var in = loader.getResourceAsStream(resource))
      {
        if(in != null)
        {
          secretKey = in.readAllBytes();
          break;
        }
      }
      catch(IOException e)
      {
        throw fatal("Could not read secret key resource '"
          + CLASSPATH_PREFIX + resource + "'", e);
      }
    }

    if(secretKey == null)
    {
      throw fatal("Secret key resource not found on classpath: '"
        + CLASSPATH_PREFIX + resource + "'", null);
    }

    if(secretKey.length != KEY_LEN)
    {
      AES256.wipe(secretKey);
      throw fatal("Invalid secret key length in '" + CLASSPATH_PREFIX + resource
        + "': " + secretKey.length + " bytes, expected " + KEY_LEN, null);
    }

    return new AppSecretKey(secretKey);
  }

  /**
   * Loads the secret key from the given file or generates a new one if it doesn't exist.
   * <p>
   * If a new key is generated, it is written to the given path with restricted
   * file permissions to ensure security.
   * </p>
   *
   * @param secretPath The path of the secret key file.
   *
   * @return An instance of {@code AppSecretKey} with the loaded or newly generated key.
   *
   * @throws CryptoException If the secret file cannot be read, created or has an invalid length.
   */
  static AppSecretKey loadOrCreate(Path secretPath)
  {
    byte[] secretKey;

    if(Files.exists(secretPath))
    {
      log.debug("Loading secret file: {}", secretPath);
      try
      {
        secretKey = Files.readAllBytes(secretPath);
      }
      catch(IOException e)
      {
        throw fatal("Could not read secret key file '" + secretPath + "'", e);
      }

      if(secretKey.length != KEY_LEN)
      {
        AES256.wipe(secretKey);
        throw fatal("Invalid secret key length in '" + secretPath + "': "
          + secretKey.length + " bytes, expected " + KEY_LEN, null);
      }
    }
    else
    {
      log.info("Generating and writing new secret file: {}", secretPath);
      secretKey = new byte[KEY_LEN];
      new SecureRandom().nextBytes(secretKey);

      try
      {
        writeSecretFile(secretPath, secretKey);
      }
      catch(IOException e)
      {
        AES256.wipe(secretKey);
        throw fatal("Could not create secret key file '" + secretPath + "'", e);
      }
    }

    return new AppSecretKey(secretKey);
  }

  /**
   * Writes a freshly generated key to disk, creating parent directories as
   * needed and restricting permissions to the owner.
   *
   * @param secretPath The target file.
   * @param secretKey The key bytes to write.
   *
   * @throws IOException If any file system operation fails.
   */
  private static void writeSecretFile(Path secretPath, byte[] secretKey)
    throws IOException
  {
    if(secretPath.getParent() != null)
    {
      Files.createDirectories(secretPath.getParent());
    }

    // Set POSIX permissions atomically if supported
    if(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"))
    {
      Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-------");
      FileAttribute<Set<PosixFilePermission>> attr = PosixFilePermissions.asFileAttribute(perms);
      Files.createFile(secretPath, attr);
      Files.write(secretPath, secretKey, StandardOpenOption.WRITE);
      Files.setPosixFilePermissions(secretPath, PosixFilePermissions.fromString("r--------"));
    }
    else
    {
      // Fallback for non-POSIX (Windows): Write first, then restrict
      Files.write(secretPath, secretKey, StandardOpenOption.CREATE_NEW);
      File secretFile = secretPath.toFile();
      secretFile.setExecutable(false, false);
      secretFile.setWritable(false, false);
      secretFile.setReadable(false, false);
      secretFile.setReadable(true, true);
    }
  }

  /**
   * Builds the {@link CryptoException} for a fatal key initialization failure
   * and writes a single fallback line to {@link System#err}.
   * <p>
   * This is the only place in the library that bypasses SLF4J. It exists because
   * key initialization typically happens at application startup, possibly before
   * any logging backend is configured, and the failure must never go unnoticed.
   *
   * @param message Human readable description including the file path.
   * @param cause Underlying cause, may be {@code null}.
   *
   * @return The exception to be thrown by the caller.
   */
  private static CryptoException fatal(String message, Throwable cause)
  {
    System.err.println(FATAL_PREFIX + message + (cause != null ? " (" + cause + ")" : ""));
    return cause != null ? new CryptoException(message, cause) : new CryptoException(message);
  }

  /**
   * Returns a copy of the raw AES-256 secret key bytes (32 bytes).
   * <p>
   * This method returns a new array to prevent external modification of the internal
   * secret key state.
   * </p>
   *
   * @return A byte array containing a copy of the secret key.
   *
   * @throws IllegalStateException If the secret key has been destroyed.
   */
  public byte[] getSecretKey() // mutable copy 
  {
    if(isDestroyed())
    {
      throw new IllegalStateException("Secret key has been destroyed");
    }

    return Arrays.copyOf(secretKey, secretKey.length);
  }

  /**
   * Checks if the secret key has been destroyed.
   *
   * @return true if the key is destroyed, false otherwise.
   */
  @Override
  public boolean isDestroyed()
  {
    return destroyed;
  }

  /**
   * Securely destroys the secret key by wiping its contents with zeros.
   * Once destroyed, the key can no longer be retrieved.
   */
  @Override
  public void destroy()
  {
    if( ! destroyed)
    {
      Arrays.fill(secretKey, (byte)0);
      destroyed = true;
      log.info("AppSecretKey has been securely wiped from memory.");
    }
  }

  /**
   * Closes the resource by calling {@link #destroy()}.
   */
  @Override
  public void close()
  {
    destroy();
  }

  /**
   * The raw byte array of the secret key.
   */
  private final byte[] secretKey;

  /**
   * Flag indicating if the secret key has been destroyed.
   */
  private volatile boolean destroyed = false;

}
