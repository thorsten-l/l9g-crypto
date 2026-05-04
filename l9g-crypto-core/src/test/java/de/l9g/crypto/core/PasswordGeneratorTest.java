/*
 * Copyright 2025-2026 Thorsten Ludewig (t.ludewig@gmail.com).
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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Unit tests for {@link PasswordGenerator}.
 */
@DisplayName("PasswordGenerator Tests")
class PasswordGeneratorTest {

  @Test
  @DisplayName("Should throw exception if length is less than 4")
  void testMinLengthRequirement() {
    assertThrows(IllegalArgumentException.class, () -> PasswordGenerator.generate(3));
  }

  @ParameterizedTest
  @ValueSource(ints = {4, 8, 16, 32, 64})
  @DisplayName("Should generate password of requested length")
  void testPasswordLength(int length) {
    String password = PasswordGenerator.generate(length);
    assertEquals(length, password.length());
  }

  @Test
  @DisplayName("Should contain characters from all groups")
  void testCharacterGroups() {
    // Run multiple times to reduce chance of false positive due to randomness
    for (int i = 0; i < 100; i++) {
      String password = PasswordGenerator.generate(16);
      
      assertTrue(password.chars().anyMatch(c -> "abcdefghijkmnopqrstuvwxyz".indexOf(c) >= 0), 
          "Should contain lowercase: " + password);
      assertTrue(password.chars().anyMatch(c -> "ABCDEFGHJKLMNPQRSTUVWXYZ".indexOf(c) >= 0), 
          "Should contain uppercase: " + password);
      assertTrue(password.chars().anyMatch(c -> "0123456789".indexOf(c) >= 0), 
          "Should contain digits: " + password);
      assertTrue(password.chars().anyMatch(c -> "-.~_^(){}[]<>*".indexOf(c) >= 0), 
          "Should contain special chars: " + password);
    }
  }

  @Test
  @DisplayName("Should not contain ambiguous characters")
  void testNoAmbiguousChars() {
    String ambiguous = "lIO";
    for (int i = 0; i < 100; i++) {
      String password = PasswordGenerator.generate(64);
      for (char c : ambiguous.toCharArray()) {
        assertFalse(password.indexOf(c) >= 0, "Should not contain '" + c + "': " + password);
      }
    }
  }
}
