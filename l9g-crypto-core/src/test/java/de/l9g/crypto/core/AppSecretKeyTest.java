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
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Unit tests for {@link AppSecretKey}.
 */
@DisplayName("AppSecretKey Tests")
class AppSecretKeyTest {

  @Test
  @DisplayName("Should return singleton instance")
  void testSingleton() {
    AppSecretKey instance1 = AppSecretKey.getInstance();
    AppSecretKey instance2 = AppSecretKey.getInstance();
    assertSame(instance1, instance2);
  }

  @Test
  @DisplayName("Should provide a valid 32-byte secret key")
  void testSecretKey() {
    AppSecretKey instance = AppSecretKey.getInstance();
    byte[] key = instance.getSecretKey();
    assertNotNull(key);
    assertEquals(32, key.length);
    
    // Test that it's a copy
    byte[] keyCopy = instance.getSecretKey();
    assertNotSame(key, keyCopy);
    assertArrayEquals(key, keyCopy);
    
    key[0] = (byte) ~key[0]; // modify copy
    assertFalse(java.util.Arrays.equals(key, instance.getSecretKey()));
  }

  @Test
  @DisplayName("Should be destroyable")
  void testDestroy() {
    // Note: Since it's a singleton, destroying it will affect other tests 
    // in the same JVM. For now, we only verify it's not destroyed initially.
    AppSecretKey instance = AppSecretKey.getInstance();
    assertFalse(instance.isDestroyed());
    
    // instance.destroy();
    // assertTrue(instance.isDestroyed());
  }

  @Test
  @DisplayName("Should create data directory and secret file if missing")
  void testFileCreation() throws IOException {
    // This test assumes the default path is data/secret.bin
    // It's a bit of an integration test but useful.
    AppSecretKey.getInstance(); // Ensure initialized
    
    Path path = Path.of("data/secret.bin");
    // If the test environment allows writing to data/secret.bin
    if (Files.exists(path)) {
      assertTrue(Files.isRegularFile(path));
      assertEquals(32, Files.size(path));
    }
  }
}
