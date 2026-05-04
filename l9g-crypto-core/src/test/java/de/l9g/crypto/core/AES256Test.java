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

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Unit tests for {@link AES256}.
 */
@DisplayName("AES256 Core Tests")
class AES256Test {

  @Test
  @DisplayName("Should encrypt and decrypt byte array correctly")
  void testByteArrayEncryption() throws NoSuchAlgorithmException {
    try (AES256 aes = new AES256()) {
      byte[] original = "Hello World".getBytes();
      byte[] encrypted = aes.encrypt(original);
      
      assertNotNull(encrypted);
      assertNotEquals(original, encrypted);
      assertTrue(encrypted.length > original.length); // IV + Tag

      byte[] decrypted = aes.decrypt(encrypted);
      assertArrayEquals(original, decrypted);
    }
  }

  @Test
  @DisplayName("Should encrypt and decrypt string correctly")
  void testStringEncryption() throws NoSuchAlgorithmException {
    try (AES256 aes = new AES256()) {
      String original = "This is a secret message.";
      String encrypted = aes.encrypt(original);
      
      assertNotNull(encrypted);
      assertNotEquals(original, encrypted);

      String decrypted = aes.decrypt(encrypted);
      assertEquals(original, decrypted);
    }
  }

  @Test
  @DisplayName("Should work with a predefined key")
  void testPredefinedKey() {
    byte[] keyBytes = new byte[32];
    for (int i = 0; i < 32; i++) keyBytes[i] = (byte) i;
    
    AES256 aes = new AES256(keyBytes);
    String original = "Fixed key test";
    String encrypted = aes.encrypt(original);
    
    // Create new instance with same key
    AES256 aes2 = new AES256(keyBytes);
    assertEquals(original, aes2.decrypt(encrypted));
    
    aes.close();
    aes2.close();
  }

  @Test
  @DisplayName("Should work with Base64 encoded key")
  void testBase64Key() {
    byte[] keyBytes = new byte[32];
    java.util.Arrays.fill(keyBytes, (byte) 0x42);
    String encodedKey = Base64.getEncoder().encodeToString(keyBytes);
    
    try (AES256 aes = new AES256(encodedKey)) {
      assertArrayEquals(keyBytes, aes.getSecret());
      assertEquals(encodedKey, aes.getEncodedSecret());
    }
  }

  @Test
  @DisplayName("Should throw exception for invalid key length")
  void testInvalidKeyLength() {
    byte[] shortKey = new byte[16];
    assertThrows(IllegalArgumentException.class, () -> new AES256(shortKey));
    assertThrows(IllegalArgumentException.class, () -> new AES256((byte[])null));
  }

  @Test
  @DisplayName("Should throw exception if payload is too short")
  void testPayloadTooShort() throws NoSuchAlgorithmException {
    try (AES256 aes = new AES256()) {
      byte[] shortPayload = new byte[10]; // Minimum is 12 (IV) + 16 (Tag/Min)
      IllegalStateException ex = assertThrows(IllegalStateException.class, () -> aes.decrypt(shortPayload));
      assertTrue(ex.getCause() instanceof IllegalArgumentException);
      assertEquals("Encrypted payload too short", ex.getCause().getMessage());
    }
  }

  @Test
  @DisplayName("Should throw exception if instance is destroyed")
  void testDestroyedInstance() throws NoSuchAlgorithmException {
    AES256 aes = new AES256();
    aes.destroy();
    assertTrue(aes.isDestroyed());
    
    assertThrows(IllegalStateException.class, () -> aes.encrypt("test"));
    assertThrows(IllegalStateException.class, () -> aes.decrypt("test"));
    assertThrows(IllegalStateException.class, () -> aes.encrypt(new byte[0]));
    assertThrows(IllegalStateException.class, () -> aes.decrypt(new byte[0]));
  }

  @Test
  @DisplayName("Should wipe byte array")
  void testWipe() {
    byte[] data = {1, 2, 3, 4, 5};
    AES256.wipe(data);
    for (byte b : data) {
      assertEquals(0, b);
    }
    // Should handle null
    assertDoesNotThrow(() -> AES256.wipe(null));
  }
}
