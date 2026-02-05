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

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import lombok.extern.slf4j.Slf4j;

/**
 * Provides AES-256 encryption and decryption functionality using GCM (Galois/Counter Mode).
 * This class handles key generation, encryption of strings and byte arrays, and decryption,
 * with secure random IV generation and authentication tags.
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
@Slf4j
public class AES256
{
  /**
   * The algorithm used for key generation and cipher operations (AES).
   */
  private final static String KEY_ALGORITHM = "AES";

  /**
   * The full cipher algorithm string (AES/GCM/NoPadding) used for encryption/decryption.
   */
  private static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";

  /**
   * The length of the AES key in bytes (256 bits).
   */
  public static final int KEY_LEN_BYTES = 32;  // 256 bit

  /**
   * The length of the Initialization Vector (IV) in bytes (GCM recommended).
   */
  private static final int IV_LEN_BYTES = 12;  // GCM recommended

  /**
   * The length of the authentication tag in bits (16 bytes).
   */
  private static final int TAG_LEN_BITS = 128; // 16 bytes auth tag

  /**
   * The secret key used for AES encryption/decryption.
   */
  private final SecretKey key;

  /**
   * Secure random number generator for creating IVs.
   */
  private final SecureRandom secureRandom = new SecureRandom();

  /**
   * Constructs an AES256 instance by generating a new 256-bit AES key.
   *
   * @throws NoSuchAlgorithmException If the AES algorithm is not available.
   */
  public AES256()
    throws NoSuchAlgorithmException
  {
    KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM);
    keyGenerator.init(256);
    this.key = keyGenerator.generateKey();
  }

  /**
   * Constructs an AES256 instance with a predefined AES key.
   *
   * @param encodedSecretBytes The AES-256 key as a byte array (must be 32 bytes long).
   *
   * @throws IllegalArgumentException If the provided key is not 32 bytes long.
   */
  public AES256(byte[] encodedSecretBytes)
  {
    if(encodedSecretBytes == null || encodedSecretBytes.length != KEY_LEN_BYTES)
    {
      throw new IllegalArgumentException("Secret must be " + KEY_LEN_BYTES + " bytes (AES-256 key)");
    }
    this.key = new SecretKeySpec(encodedSecretBytes, KEY_ALGORITHM);
  }

  /**
   * Constructs an AES256 instance with a predefined AES key provided as a Base64 encoded string.
   *
   * @param encodedSecret The Base64 encoded AES-256 key string.
   *
   * @throws IllegalArgumentException If the decoded key is not 32 bytes long.
   */
  public AES256(String encodedSecret)
  {
    this(Base64.getDecoder().decode(encodedSecret));
  }

  /**
   * Encrypts a plain text string using AES/GCM/NoPadding.
   * The output is a Base64 encoded string containing the IV, ciphertext, and GCM tag.
   *
   * @param plainText The string to encrypt.
   *
   * @return The Base64 encoded encrypted string.
   *
   * @throws IllegalStateException If encryption fails.
   */
  public String encrypt(String plainText)
  {
    try
    {
      byte[] iv = new byte[IV_LEN_BYTES];
      secureRandom.nextBytes(iv);

      Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
      cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LEN_BITS, iv));

      byte[] ctWithTag = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

      // output = IV || (ciphertext||tag)
      byte[] out = new byte[IV_LEN_BYTES + ctWithTag.length];
      System.arraycopy(iv, 0, out, 0, IV_LEN_BYTES);
      System.arraycopy(ctWithTag, 0, out, IV_LEN_BYTES, ctWithTag.length);

      return Base64.getEncoder().encodeToString(out);
    }
    catch(Exception ex)
    {
      log.error("Encryption failed", ex);
      throw new IllegalStateException("Encryption failed", ex);
    }
  }

  /**
   * Decrypts a Base64 encoded encrypted string using AES/GCM/NoPadding.
   *
   * @param encryptedText The Base64 encoded encrypted string.
   *
   * @return The decrypted plain text string.
   *
   * @throws IllegalArgumentException If the encrypted payload is too short or malformed.
   * @throws IllegalStateException If decryption fails.
   */
  public String decrypt(String encryptedText)
  {
    try
    {
      byte[] in = Base64.getDecoder().decode(encryptedText);

      if(in.length < IV_LEN_BYTES + 16)
      {
        throw new IllegalArgumentException("Encrypted payload too short");
      }

      byte[] iv = java.util.Arrays.copyOfRange(in, 0, IV_LEN_BYTES);
      byte[] ctWithTag = java.util.Arrays.copyOfRange(in, IV_LEN_BYTES, in.length);

      Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
      cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LEN_BITS, iv));

      byte[] pt = cipher.doFinal(ctWithTag);
      return new String(pt, StandardCharsets.UTF_8);
    }
    catch(Exception ex)
    {
      log.error("Decryption failed", ex);
      throw new IllegalStateException("Decryption failed", ex);
    }
  }

  /**
   * Encrypts plain byte data using AES/GCM/NoPadding.
   * The output byte array contains the IV, ciphertext, and GCM tag.
   *
   * @param plainData The byte array to encrypt.
   *
   * @return The encrypted byte array.
   *
   * @throws IllegalStateException If encryption fails.
   */
  public byte[] encrypt(byte[] plainData)
  {
    try
    {
      byte[] iv = new byte[IV_LEN_BYTES];
      secureRandom.nextBytes(iv);

      Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
      cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LEN_BITS, iv));

      byte[] ctWithTag = cipher.doFinal(plainData);

      byte[] out = new byte[IV_LEN_BYTES + ctWithTag.length];
      System.arraycopy(iv, 0, out, 0, IV_LEN_BYTES);
      System.arraycopy(ctWithTag, 0, out, IV_LEN_BYTES, ctWithTag.length);

      return out;
    }
    catch(Exception ex)
    {
      log.error("Encryption failed", ex);
      throw new IllegalStateException("Encryption failed", ex);
    }
  }

  /**
   * Decrypts an encrypted byte array using AES/GCM/NoPadding.
   *
   * @param encryptedData The encrypted byte array.
   *
   * @return The decrypted plain byte array.
   *
   * @throws IllegalArgumentException If the encrypted payload is too short.
   * @throws IllegalStateException If decryption fails.
   */
  public byte[] decrypt(byte[] encryptedData)
  {
    try
    {
      if(encryptedData.length < IV_LEN_BYTES + 16)
      {
        throw new IllegalArgumentException("Encrypted payload too short");
      }

      byte[] iv = java.util.Arrays.copyOfRange(encryptedData, 0, IV_LEN_BYTES);
      byte[] ctWithTag = java.util.Arrays.copyOfRange(encryptedData, IV_LEN_BYTES, encryptedData.length);

      Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
      cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LEN_BITS, iv));

      return cipher.doFinal(ctWithTag);
    }
    catch(Exception ex)
    {
      log.error("Decryption failed", ex);
      throw new IllegalStateException("Decryption failed", ex);
    }
  }

  /**
   * Returns only the raw AES-256 key bytes (32 bytes).
   */
  public byte[] getSecret()
  {
    byte[] keyBytes = key.getEncoded();
    if(keyBytes.length != KEY_LEN_BYTES)
    {
      // sollte bei AES-256 nicht passieren, aber besser explizit
      throw new IllegalStateException("Unexpected key length: " + keyBytes.length);
    }
    return keyBytes;
  }

  /**
   * Returns the AES-256 key encoded as a Base64 string.
   *
   * @return The Base64 encoded secret key.
   */
  public String getEncodedSecret()
  {
    return Base64.getEncoder().encodeToString(getSecret());
  }

}
