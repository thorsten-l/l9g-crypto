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
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import lombok.extern.slf4j.Slf4j;

/**
 * Provides AES-256 encryption and decryption functionality using GCM (Galois/Counter Mode).
 * This class handles key generation, encryption of strings and byte arrays, and decryption,
 * with secure random IV generation and authentication tags.
 * <p>
 * AES-256 GCM is used for robust encryption, providing both confidentiality and integrity.
 * The output of encryption includes the Initialization Vector (IV) followed by the ciphertext
 * and the authentication tag.
 * </p>
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
@Slf4j

public class AES256 implements Destroyable, AutoCloseable
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
   * The length of the authentication tag in bits (128 bits / 16 bytes).
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
   * Flag indicating if the instance has been destroyed.
   */
  private volatile boolean destroyed = false;

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
   * @throws IllegalArgumentException If the provided key is null or not 32 bytes long.
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
   * Helper method to check if the instance is destroyed.
   *
   * @throws IllegalStateException If the instance has been destroyed.
   */
  private void checkDestroyed()
  {
    if(isDestroyed())
    {
      throw new IllegalStateException("AES256 instance has been destroyed");
    }
  }

  /**
   * Helper method to securely wipe a byte array by filling it with zeros.
   *
   * @param array The array to wipe.
   */
  public static void wipe(byte[] array)
  {
    if(array != null)
    {
      Arrays.fill(array, (byte)0);
    }
  }

  /**
   * Encrypts plain byte data using AES/GCM/NoPadding.
   * The output byte array contains the IV (12 bytes), followed by the ciphertext 
   * and the GCM authentication tag.
   *
   * @param plainData The byte array to encrypt.
   *
   * @return The encrypted byte array containing IV + ciphertext + tag.
   *
   * @throws IllegalStateException If encryption fails or the instance is destroyed.
   */
  public byte[] encrypt(byte[] plainData)
  {
    checkDestroyed();
    byte[] iv = new byte[IV_LEN_BYTES];
    byte[] ctWithTag = null;

    try
    {
      secureRandom.nextBytes(iv);

      Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
      cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LEN_BITS, iv));

      ctWithTag = cipher.doFinal(plainData);

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
    finally
    {
      wipe(iv);
      wipe(ctWithTag);
    }
  }

  /**
   * Decrypts an encrypted byte array using AES/GCM/NoPadding.
   * The input byte array must contain the IV (12 bytes) followed by the ciphertext and tag.
   *
   * @param encryptedData The encrypted byte array (IV + ciphertext + tag).
   *
   * @return The decrypted plain byte array.
   *
   * @throws IllegalArgumentException If the encrypted payload is too short.
   * @throws IllegalStateException If decryption fails or the instance is destroyed.
   */
  public byte[] decrypt(byte[] encryptedData)
  {
    checkDestroyed();
    byte[] iv = null;
    byte[] ctWithTag = null;

    try
    {
      if(encryptedData.length < IV_LEN_BYTES + 16)
      {
        throw new IllegalArgumentException("Encrypted payload too short");
      }

      iv = java.util.Arrays.copyOfRange(encryptedData, 0, IV_LEN_BYTES);
      ctWithTag = java.util.Arrays.copyOfRange(encryptedData, IV_LEN_BYTES, encryptedData.length);

      Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
      cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LEN_BITS, iv));

      return cipher.doFinal(ctWithTag);
    }
    catch(Exception ex)
    {
      log.error("Decryption failed", ex);
      throw new IllegalStateException("Decryption failed", ex);
    }
    finally
    {
      wipe(iv);
      wipe(ctWithTag);
    }
  }

  /**
   * Encrypts a plain text string using AES/GCM/NoPadding.
   * The output is a Base64 encoded string containing the IV, ciphertext, and GCM tag.
   *
   * @param plainText The string to encrypt.
   *
   * @return The Base64 encoded encrypted string.
   * 
   * @throws IllegalStateException If encryption fails or the instance is destroyed.
   */
  public String encrypt(String plainText)
  {
    byte[] plainBytes = null;

    try
    {
      plainBytes = plainText.getBytes(StandardCharsets.UTF_8);
      return Base64.getEncoder().encodeToString(encrypt(plainBytes));
    }
    finally
    {
      wipe(plainBytes);
    }
  }

  /**
   * Decrypts a Base64 encoded encrypted string using AES/GCM/NoPadding.
   *
   * @param encryptedText The Base64 encoded encrypted string.
   *
   * @return The decrypted plain text string.
   *
   * @throws IllegalStateException If decryption fails or the instance is destroyed.
   */
  public String decrypt(String encryptedText)
  {
    checkDestroyed();
    byte[] encryptedTextBytes = null;
    byte[] plainTextBytes = null;

    try
    {
      encryptedTextBytes = Base64.getDecoder().decode(encryptedText);
      plainTextBytes = decrypt(encryptedTextBytes);
      return new String(plainTextBytes, StandardCharsets.UTF_8);
    }
    finally
    {
      wipe(encryptedTextBytes);
      wipe(plainTextBytes);
    }
  }

  /**
   * Returns the raw AES-256 key bytes (32 bytes).
   * 
   * @return The secret key as a byte array.
   * 
   * @throws IllegalStateException If the key length is unexpected.
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

  /**
   * Securely destroys the secret key and wipes sensitive data.
   * Once destroyed, the instance can no longer be used for encryption or decryption.
   */
  @Override
  public void destroy()
  {
    if( ! destroyed)
    {
      try
      {
        if(key != null &&  ! key.isDestroyed())
        {
          key.destroy();
        }
      }
      catch(DestroyFailedException e)
      {
        log.warn("Failed to destroy SecretKey", e);
      }
      finally
      {
        destroyed = true;
        log.debug("AES256 instance destroyed.");
      }
    }
  }

  /**
   * Checks if the instance has been destroyed.
   *
   * @return true if destroyed, false otherwise.
   */
  @Override
  public boolean isDestroyed()
  {
    return destroyed;
  }

  /**
   * Closes the instance by calling {@link #destroy()}.
   */
  @Override
  public void close()
  {
    destroy();
  }

}
