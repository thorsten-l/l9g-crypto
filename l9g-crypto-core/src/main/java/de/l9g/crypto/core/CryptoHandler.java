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
 * A singleton handler for performing cryptographic operations.
 * <p>
 * This class provides a centralized way to encrypt and decrypt strings using
 * AES-256. It manages a single instance of the {@link AES256} cipher,
 * initialized with a secret key from {@link AppSecretKey}.
 * <p>
 * Encrypted values are prefixed with "{AES256}" to identify them as such.
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
@Slf4j
public class CryptoHandler
{
  /**
   * The prefix used for AES-256 encrypted strings.
   */
  public final static String AES256_PREFIX = "{AES256}";

  /**
   * The AES-256 cipher instance used for encryption and decryption.
   */
  private final AES256 aes256;

  /**
   * Private constructor to initialize the {@code CryptoHandler} with an AES256 instance
   * using the application's secret key.
   */
  private CryptoHandler()
  {
    log.debug("CryptoHandler()");
    aes256 = new AES256(AppSecretKey.getInstance().getSecretKey());
  }

  /**
   * Returns the singleton instance of {@code CryptoHandler}.
   *
   * @return The singleton instance.
   */
  public static CryptoHandler getInstance()
  {
    return Holder.INSTANCE;
  }

  /**
   * Inner static class to implement the singleton pattern for {@code CryptoHandler}.
   */
  private static final class Holder
  {
    /**
     * The singleton instance of {@code CryptoHandler}.
     */
    private static final CryptoHandler INSTANCE = new CryptoHandler();

  }

  /**
   * Encrypts a plain text string.
   * <p>
   * The resulting encrypted string is prefixed with {@code {AES256}}.
   *
   * @param text The plain text to encrypt.
   *
   * @return The AES-256 encrypted and prefixed string.
   */
  public String encrypt(String text)
  {
    return AES256_PREFIX + aes256.encrypt(text);
  }

  /**
   * Decrypts an encrypted string.
   * <p>
   * This method checks for the {@code {AES256}} prefix. If present, it
   * attempts to decrypt the subsequent value. If the prefix is not found, the
   * original string is returned unmodified.
   *
   * @param encryptedText The encrypted string, potentially with a prefix.
   *
   * @return The decrypted plain text, or the original string if not encrypted.
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
   * Encrypts a byte array.
   *
   * @param bytes The byte array to encrypt.
   *
   * @return The encrypted byte array.
   */
  public byte[] encrypt(byte[] bytes)
  {
    return aes256.encrypt(bytes);
  }

  /**
   * Decrypts a byte array.
   *
   * @param bytes The byte array to decrypt.
   *
   * @return The decrypted byte array.
   */
  public byte[] decrypt(byte[] bytes)
  {
    return aes256.decrypt(bytes);
  }

}
