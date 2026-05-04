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

/**
 * Unit tests for {@link CryptoHandler}.
 */
@DisplayName("CryptoHandler Tests")
class CryptoHandlerTest {

  @Test
  @DisplayName("Should return singleton instance")
  void testSingleton() {
    CryptoHandler instance1 = CryptoHandler.getInstance();
    CryptoHandler instance2 = CryptoHandler.getInstance();
    assertSame(instance1, instance2);
  }

  @Test
  @DisplayName("Should encrypt with prefix")
  void testEncryptWithPrefix() {
    CryptoHandler crypto = CryptoHandler.getInstance();
    String plainText = "My Secret Password";
    String encrypted = crypto.encrypt(plainText);
    
    assertTrue(encrypted.startsWith("{AES256}"));
    assertNotEquals(plainText, encrypted);
  }

  @Test
  @DisplayName("Should decrypt prefixed string")
  void testDecryptWithPrefix() {
    CryptoHandler crypto = CryptoHandler.getInstance();
    String plainText = "Another secret";
    String encrypted = crypto.encrypt(plainText);
    
    String decrypted = crypto.decrypt(encrypted);
    assertEquals(plainText, decrypted);
  }

  @Test
  @DisplayName("Should handle transparent decryption (no prefix)")
  void testTransparentDecryption() {
    CryptoHandler crypto = CryptoHandler.getInstance();
    String plainText = "Just a normal string";
    
    assertEquals(plainText, crypto.decrypt(plainText));
    assertNull(crypto.decrypt((String)null));
  }

  @Test
  @DisplayName("Should encrypt and decrypt byte arrays")
  void testByteArrayEncryption() {
    CryptoHandler crypto = CryptoHandler.getInstance();
    byte[] original = {1, 2, 3, 4, 5};
    byte[] encrypted = crypto.encrypt(original);
    
    assertNotNull(encrypted);
    assertArrayEquals(original, crypto.decrypt(encrypted));
  }
}
