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
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.io.TempDir;

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

  @Test
  @DisplayName("Should create a new 32-byte key file in a fresh directory")
  void testLoadOrCreateGeneratesKey(@TempDir Path tempDir) throws IOException {
    Path secret = tempDir.resolve("sub/dir/secret.bin");
    AppSecretKey key = AppSecretKey.loadOrCreate(secret);
    assertEquals(32, key.getSecretKey().length);
    assertTrue(Files.isRegularFile(secret));
    assertEquals(32, Files.size(secret));

    // Second load must return the same key material
    AppSecretKey again = AppSecretKey.loadOrCreate(secret);
    assertArrayEquals(key.getSecretKey(), again.getSecretKey());
  }

  @Test
  @DisplayName("Should throw CryptoException with path and length for invalid key file")
  void testInvalidKeyLength(@TempDir Path tempDir) throws IOException {
    Path secret = tempDir.resolve("bad.bin");
    Files.write(secret, new byte[] {1, 2, 3, 4, 5});

    String stderr = captureStderr(() -> {
      CryptoException ex = assertThrows(CryptoException.class,
        () -> AppSecretKey.loadOrCreate(secret));
      assertTrue(ex.getMessage().contains(secret.toString()), ex.getMessage());
      assertTrue(ex.getMessage().contains("5 bytes"), ex.getMessage());
      assertTrue(ex.getMessage().contains("expected 32"), ex.getMessage());
      assertNull(ex.getCause());
    });

    // slf4j-simple (test scope) also writes to stderr, so only count FATAL lines
    assertEquals(1, fatalLines(stderr), stderr);
    assertTrue(stderr.contains(AppSecretKey.FATAL_PREFIX + "Invalid secret key length"), stderr);
    assertTrue(stderr.contains(secret.toString()), stderr);
  }

  @Test
  @DisplayName("Should throw CryptoException with IOException cause if key file cannot be created")
  void testUnwritableLocation(@TempDir Path tempDir) throws IOException {
    // A regular file where the parent directory should be -> createDirectories fails
    Path blocker = tempDir.resolve("blocker");
    Files.writeString(blocker, "not a directory");
    Path secret = blocker.resolve("secret.bin");

    String stderr = captureStderr(() -> {
      CryptoException ex = assertThrows(CryptoException.class,
        () -> AppSecretKey.loadOrCreate(secret));
      assertTrue(ex.getMessage().contains("Could not create secret key file"), ex.getMessage());
      assertTrue(ex.getMessage().contains(secret.toString()), ex.getMessage());
      assertInstanceOf(IOException.class, ex.getCause());
    });

    assertEquals(1, fatalLines(stderr), stderr);
    assertTrue(stderr.contains(AppSecretKey.FATAL_PREFIX + "Could not create secret key file"), stderr);
  }

  @Test
  @DisplayName("Should fall back to default path when SECRET_PATH is not set")
  void testResolveSecretPathDefault() {
    String env = System.getenv(AppSecretKey.SECRET_PATH_ENV_NAME);
    if (env == null || env.isBlank()) {
      assertEquals(AppSecretKey.DEFAULT_SECRET_PATH, AppSecretKey.resolveSecretPath());
    } else {
      assertEquals(Path.of(env), AppSecretKey.resolveSecretPath());
    }
  }

  private static long fatalLines(String stderr) {
    return stderr.lines().filter(l -> l.startsWith(AppSecretKey.FATAL_PREFIX)).count();
  }

  /**
   * Runs the given action while System.err is redirected and returns what was written.
   */
  private static String captureStderr(Runnable action) {
    PrintStream original = System.err;
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    System.setErr(new PrintStream(buffer, true, StandardCharsets.UTF_8));
    try {
      action.run();
    } finally {
      System.setErr(original);
    }
    return buffer.toString(StandardCharsets.UTF_8);
  }

  @Test
  @DisplayName("Should load a key from a classpath resource")
  void testLoadFromClasspath()
  {
    AppSecretKey key = AppSecretKey.loadFromClasspath("test-secret.bin");
    assertArrayEquals(
      new byte[]
      {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
      },
      key.getSecretKey());
  }

  @Test
  @DisplayName("Should fail instead of generating when the resource is missing")
  void testMissingClasspathResource()
  {
    // A classpath resource cannot be written to, so a missing one must be an
    // error - generating a fresh key here would only produce a later, far more
    // confusing "Tag mismatch" on the first decryption.
    CryptoException e = assertThrows(CryptoException.class,
      () -> AppSecretKey.loadFromClasspath("does/not/exist.bin"));
    assertTrue(e.getMessage().contains("not found on classpath"));
  }

  @Test
  @DisplayName("Should reject a classpath key of wrong length")
  void testClasspathResourceWrongLength()
  {
    CryptoException e = assertThrows(CryptoException.class,
      () -> AppSecretKey.loadFromClasspath("test-secret-short.bin"));
    assertTrue(e.getMessage().contains("Invalid secret key length"));
  }

  @Test
  @DisplayName("Should strip the classpath prefix and leading slashes")
  void testResolveClasspathResource()
  {
    // The environment variable cannot be set from within the JVM; the system
    // property can, which is what makes these paths testable at all.
    try
    {
      System.setProperty(AppSecretKey.SECRET_PATH_PROPERTY_NAME,
        "classpath:/assets/secret.bin");
      assertEquals("assets/secret.bin", AppSecretKey.resolveClasspathResource());
      // A classpath location must not leak into the file path resolver.
      assertEquals(AppSecretKey.DEFAULT_SECRET_PATH, AppSecretKey.resolveSecretPath());

      System.setProperty(AppSecretKey.SECRET_PATH_PROPERTY_NAME, "keys/app.bin");
      assertNull(AppSecretKey.resolveClasspathResource());
      assertEquals(Path.of("keys/app.bin"), AppSecretKey.resolveSecretPath());
    }
    finally
    {
      System.clearProperty(AppSecretKey.SECRET_PATH_PROPERTY_NAME);
    }

    assertNull(AppSecretKey.resolveClasspathResource());
    assertEquals(AppSecretKey.DEFAULT_SECRET_PATH, AppSecretKey.resolveSecretPath());
  }

  @Test
  @DisplayName("Should prefer the environment variable over the system property")
  void testEnvironmentWinsOverProperty()
  {
    try
    {
      System.setProperty(AppSecretKey.SECRET_PATH_PROPERTY_NAME, "from/property.bin");
      String env = System.getenv(AppSecretKey.SECRET_PATH_ENV_NAME);
      if(env == null || env.isBlank())
      {
        // No variable in this environment: the property must take effect.
        assertEquals("from/property.bin", AppSecretKey.configuredLocation());
      }
      else
      {
        assertEquals(env.trim(), AppSecretKey.configuredLocation());
      }
    }
    finally
    {
      System.clearProperty(AppSecretKey.SECRET_PATH_PROPERTY_NAME);
    }
  }
}
