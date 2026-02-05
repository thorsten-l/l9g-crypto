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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.util.Arrays;
import lombok.extern.slf4j.Slf4j;

/**
 * Manages the application's secret key, loading it from or generating it into a file.
 * This class ensures a single instance of the secret key is available throughout the application
 * for cryptographic operations, primarily for AES-256 encryption.
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
@Slf4j
public class AppSecretKey
{
  /**
   * The path to the file where the secret key is stored.
   */
  private static final Path SECRET_PATH = Path.of("data/secret.bin");

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
   * This method ensures that the secret key is loaded or generated only once.
   *
   * @return The singleton instance of {@code AppSecretKey}.
   */
  public static AppSecretKey getInstance()
  {
    return Holder.INSTANCE;
  }

  /**
   * Inner static class to implement the singleton pattern for {@code AppSecretKey}.
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
   * Sets appropriate file permissions for security.
   *
   * @return An instance of {@code AppSecretKey} with the loaded or newly generated key.
   */
  private static AppSecretKey loadOrCreate()
  {
    try
    {
      Files.createDirectories(SECRET_PATH.getParent());

      if(Files.exists(SECRET_PATH))
      {
        byte[] secretKey = Files.readAllBytes(SECRET_PATH);
        log.debug("Loading secret file");
        return new AppSecretKey(secretKey);
      }

      byte[] secretKey = new byte[KEY_LEN];
      new SecureRandom().nextBytes(secretKey);
      log.info("Writing secret file");
      Files.write(SECRET_PATH, secretKey, StandardOpenOption.CREATE_NEW);

      File secretFile = SECRET_PATH.toFile();

      // file permissions - r-- --- ---
      secretFile.setExecutable(false, false);
      secretFile.setWritable(false, false);
      secretFile.setReadable(false, false);
      secretFile.setReadable(true, true);

      return new AppSecretKey(secretKey);
    }
    catch(IOException e)
    {
      log.error("ERROR: secret file ", e);
      System.exit(-1);
    }

    return null;
  }

  /**
   * Returns a mutable copy of the raw AES-256 secret key bytes (32 bytes).
   * It returns a copy to prevent external modification of the internal key.
   *
   * @return A byte array containing the secret key.
   */
  public byte[] getSecretKey() // mutable copy 
  {
    return Arrays.copyOf(secretKey, secretKey.length);
  }

  /**
   * The raw byte array of the secret key.
   */
  private final byte[] secretKey;

}
