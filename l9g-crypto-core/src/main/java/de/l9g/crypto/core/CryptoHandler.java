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
   * Uses the initialization-on-demand holder idiom.
   *
   * @return The singleton instance.
   */
  public static CryptoHandler getInstance()
  {
    return Holder.INSTANCE;
  }

  /**
   * Inner static class to implement the initialization-on-demand holder idiom.
   */
  private static final class Holder
  {
    /**
     * The singleton instance of {@code CryptoHandler}.
     */
    private static final CryptoHandler INSTANCE = new CryptoHandler();
  }

  /**
   * Encrypts a plain text string and prepends the {@code {AES256}} prefix.
   *
   * @param text The plain text to encrypt.
   *
   * @return The encrypted string, encoded in Base64 and prefixed with {@code {AES256}}.
   *
   * @throws IllegalStateException If encryption fails.
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
   * @throws IllegalStateException If decryption of a prefixed string fails.
   */
  public String decrypt(String encryptedText)
  {
    String text;

    if(encryptedText != null && encryptedText.startsWith(AES256_PREFIX))
    {
      text = aes256.decrypt(encryptedText.substring(AES256_PREFIX.length()));
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
   * @throws IllegalStateException If encryption fails.
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
   * @throws IllegalStateException If decryption fails.
   */
  public byte[] decrypt(byte[] bytes)
  {
    return aes256.decrypt(bytes);
  }

}
