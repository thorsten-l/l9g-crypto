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
 * {@code SECRET_PATH} environment variable. If not provided, it defaults to {@code data/secret.bin}.
 * On systems supporting POSIX file attributes, strict file permissions (read-only for the owner)
 * are applied to the secret file.
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
  private static final String SECRET_PATH_ENV_NAME = "SECRET_PATH";

  /**
   * The default path to the file where the secret key is stored.
   */
  private static final Path DEFAULT_SECRET_PATH = Path.of("data/secret.bin");

  /**
   * The expected length of the secret key in bytes (32 bytes for AES-256).
   */
  private static final int KEY_LEN = AES256.KEY_LEN_BYTES; // 32

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
   * This method ensures that the secret key is loaded or generated only once
   * using the initialization-on-demand holder idiom.
   *
   * @return The singleton instance of {@code AppSecretKey}.
   */
  public static AppSecretKey getInstance()
  {
    return Holder.INSTANCE;
  }

  /**
   * Inner static class to implement the initialization-on-demand holder idiom
   * for the {@code AppSecretKey} singleton.
   */
  private static final class Holder
  {
    /**
     * The singleton instance of {@code AppSecretKey}, initialized upon first access.
     */
    private static final AppSecretKey INSTANCE = loadOrCreate();

  }

  /**
   * Loads the secret key from a file or generates a new one if it doesn't exist.
   * <p>
   * If a new key is generated, it is written to the configured path with restricted
   * file permissions to ensure security.
   * </p>
   *
   * @return An instance of {@code AppSecretKey} with the loaded or newly generated key.
   *
   * @throws RuntimeException If the secret file cannot be read, created, or written.
   */
  private static AppSecretKey loadOrCreate()
  {
    Path secretPath = DEFAULT_SECRET_PATH;

    String secretPathEnv = System.getenv(SECRET_PATH_ENV_NAME);
    if(secretPathEnv != null &&  ! secretPathEnv.isBlank())
    {
      secretPath = Path.of(secretPathEnv);
    }

    try
    {
      if(secretPath.getParent() != null)
      {
        Files.createDirectories(secretPath.getParent());
      }

      byte[] secretKey;

      if(Files.exists(secretPath))
      {
        secretKey = Files.readAllBytes(secretPath);
        log.debug("Loading secret file: {}", secretPath);

        if(secretKey.length != KEY_LEN)
        {
          throw new RuntimeException("Invalid secret key length: "
            + secretKey.length);
        }
      }
      else
      {
        secretKey = new byte[KEY_LEN];
        new SecureRandom().nextBytes(secretKey);
        log.info("Generating and writing new secret file: {}", secretPath);

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

      return new AppSecretKey(secretKey);
    }
    catch(IOException e)
    {
      log.error("CRITICAL ERROR: Could not manage secret file at {}", secretPath, e);
      throw new RuntimeException("Application cannot start without secret key: " + secretPath, e);
    }
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
