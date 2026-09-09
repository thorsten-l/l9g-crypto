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

import lombok.extern.slf4j.Slf4j;

/**
 * A thread-safe singleton handler for performing high-level cryptographic operations.
 * <p>
 * This class provides a centralized way to encrypt and decrypt strings and byte arrays
 * using AES-256 GCM. It manages a single instance of the {@link AES256} cipher,
 * which is automatically initialized with the application's master secret key 
 * retrieved from {@link AppSecretKey}.
 * <p>
 * For convenience, encrypted string values are prefixed with {@code {AES256}}. 
 * This allows the {@link #decrypt(String)} method to differentiate between 
 * plain text and encrypted content, enabling transparent decryption (e.g., for 
 * configuration properties).
 * <p>
 * All failures are reported as {@link CryptoException}; nothing is logged at
 * error level before throwing (see {@link CryptoException} for the rationale).
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
@Slf4j
public class CryptoHandler
{
  /**
   * The prefix used to identify and version AES-256 encrypted strings.
   */
  public final static String AES256_PREFIX = "{AES256}";

  /**
   * Lazily initialized singleton instance. A failed initialization is not
   * cached, so every call to {@link #getInstance()} rethrows the real
   * {@link CryptoException} instead of a {@code NoClassDefFoundError}.
   */
  private static volatile CryptoHandler instance;

  /**
   * The underlying AES-256 cipher instance.
   */
  private final AES256 aes256;

  /**
   * Private constructor to initialize the {@code CryptoHandler}.
   * It retrieves the master secret key from {@link AppSecretKey} and
   * initializes the internal {@link AES256} cipher.
   * <p>
   * To ensure maximum security, the temporary key copy is wiped immediately 
   * after initialization.
   */
  private CryptoHandler()
  {
    log.debug("Initializing CryptoHandler");
    byte[] key = AppSecretKey.getInstance().getSecretKey();
    try
    {
      aes256 = new AES256(key);
    }
    finally
    {
      AES256.wipe(key);
    }
  }

  /**
   * Returns the thread-safe singleton instance of {@code CryptoHandler}.
   * The instance is created on first access.
   *
   * @return The singleton instance.
   *
   * @throws CryptoException If the application secret key cannot be loaded or created.
   */
  public static CryptoHandler getInstance()
  {
    CryptoHandler result = instance;
    if(result == null)
    {
      synchronized(CryptoHandler.class)
      {
        result = instance;
        if(result == null)
        {
          result = new CryptoHandler();
          instance = result;
        }
      }
    }
    return result;
  }

  /**
   * Encrypts a plain text string and prepends the {@code {AES256}} prefix.
   *
   * @param text The plain text to encrypt.
   *
   * @return The encrypted string, encoded in Base64 and prefixed with {@code {AES256}}.
   *
   * @throws CryptoException If encryption fails.
   */
  public String encrypt(String text)
  {
    return AES256_PREFIX + aes256.encrypt(text);
  }

  /**
   * Decrypts a string, provided it starts with the {@code {AES256}} prefix.
   * <p>
   * If the input string is {@code null} or does not start with the prefix,
   * it is returned as-is (transparent decryption).
   *
   * @param encryptedText The string to decrypt, potentially with the {@code {AES256}} prefix.
   *
   * @return The decrypted plain text, or the original string if no prefix was found.
   *
   * @throws CryptoException If decryption of a prefixed string fails (invalid Base64,
   *                         wrong key, tampered payload, ...).
   */
  public String decrypt(String encryptedText)
  {
    String text;

    if(encryptedText != null && encryptedText.startsWith(AES256_PREFIX))
    {
      try
      {
        text = aes256.decrypt(encryptedText.substring(AES256_PREFIX.length()));
      }
      catch(IllegalArgumentException ex)
      {
        // Base64.getDecoder().decode(...) rejects malformed input
        throw new CryptoException("Decryption failed: invalid Base64 payload", ex);
      }
    }
    else
    {
      text = encryptedText;
    }

    return text;
  }

  /**
   * Encrypts a raw byte array.
   *
   * @param bytes The plain byte array to encrypt.
   *
   * @return The encrypted byte array (containing IV, ciphertext, and tag).
   *
   * @throws CryptoException If encryption fails.
   */
  public byte[] encrypt(byte[] bytes)
  {
    return aes256.encrypt(bytes);
  }

  /**
   * Decrypts a raw encrypted byte array.
   *
   * @param bytes The encrypted byte array (IV + ciphertext + tag).
   *
   * @return The decrypted plain byte array.
   *
   * @throws CryptoException If decryption fails.
   */
  public byte[] decrypt(byte[] bytes)
  {
    return aes256.decrypt(bytes);
  }

}
