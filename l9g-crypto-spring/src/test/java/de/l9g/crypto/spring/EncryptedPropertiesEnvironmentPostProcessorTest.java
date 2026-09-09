/*
 * Copyright 2026 Thorsten Ludewig (t.ludewig@gmail.com).
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
package de.l9g.crypto.spring;

import static org.junit.jupiter.api.Assertions.*;

import de.l9g.crypto.core.CryptoException;
import de.l9g.crypto.core.CryptoHandler;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.logging.DeferredLogs;
import org.springframework.core.env.MapPropertySource;
import org.springframework.mock.env.MockEnvironment;

@DisplayName("EncryptedPropertiesEnvironmentPostProcessor Tests")
class EncryptedPropertiesEnvironmentPostProcessorTest
{

  private EncryptedPropertiesEnvironmentPostProcessor newProcessor()
  {
    return new EncryptedPropertiesEnvironmentPostProcessor(new DeferredLogs());
  }

  @Test
  @DisplayName("Should decrypt prefixed properties into a high priority property source")
  void testDecryptsProperties()
  {
    String encrypted = CryptoHandler.getInstance().encrypt("top secret");
    MockEnvironment env = new MockEnvironment();
    env.getPropertySources().addLast(new MapPropertySource("test-source",
      Map.of("app.password", encrypted, "app.plain", "visible")));

    newProcessor().postProcessEnvironment(env, null);

    assertEquals("top secret", env.getProperty("app.password"));
    assertEquals("visible", env.getProperty("app.plain"));
    assertNotNull(env.getPropertySources().get(
      EncryptedPropertiesEnvironmentPostProcessor.DECRYPTED_PROPERTY_SOURCE_NAME));
    assertEquals(EncryptedPropertiesEnvironmentPostProcessor.DECRYPTED_PROPERTY_SOURCE_NAME,
      env.getPropertySources().iterator().next().getName());
  }

  @Test
  @DisplayName("Should not add a property source when nothing is encrypted")
  void testNoEncryptedValues()
  {
    MockEnvironment env = new MockEnvironment();
    env.setProperty("app.plain", "visible");

    newProcessor().postProcessEnvironment(env, null);

    assertNull(env.getPropertySources().get(
      EncryptedPropertiesEnvironmentPostProcessor.DECRYPTED_PROPERTY_SOURCE_NAME));
    assertEquals("visible", env.getProperty("app.plain"));
  }

  @Test
  @DisplayName("Should name property key and source, but not the value, when decryption fails")
  void testFailureNamesPropertyNotValue()
  {
    String brokenValue = CryptoHandler.AES256_PREFIX + "AAAA";
    MockEnvironment env = new MockEnvironment();
    env.getPropertySources().addLast(new MapPropertySource("broken-source",
      Map.of("app.secret", brokenValue)));

    CryptoException ex = assertThrows(CryptoException.class,
      () -> newProcessor().postProcessEnvironment(env, null));

    assertTrue(ex.getMessage().contains("'app.secret'"), ex.getMessage());
    assertTrue(ex.getMessage().contains("'broken-source'"), ex.getMessage());
    assertFalse(ex.getMessage().contains("AAAA"), ex.getMessage());
    assertInstanceOf(CryptoException.class, ex.getCause());
    assertTrue(ex.getCause().getMessage().contains("Encrypted payload too short"),
      ex.getCause().getMessage());
  }

}
