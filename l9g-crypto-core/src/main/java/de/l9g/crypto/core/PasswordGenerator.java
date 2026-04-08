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

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

/**
 * Utility class for generating random passwords or tokens.
 * It uses a predefined set of characters to generate random strings of a
 * specified length.
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
@Slf4j
@UtilityClass
public class PasswordGenerator
{
  /**
   * Lowercase letters excluding ambiguous character 'l'.
   */
  private static final String LOWERCASE = "abcdefghijkmnopqrstuvwxyz";

  /**
   * Uppercase letters excluding ambiguous characters 'O' and 'I'.
   */
  private static final String UPPERCASE = "ABCDEFGHJKLMNPQRSTUVWXYZ";

  /**
   * Digits 0-9.
   */
  private static final String DIGITS = "0123456789";

  /**
   * URL-safe special characters from the 7-bit ASCII charset.
   * Excluded: : + ? & / % # = @ $ ! and other URL-sensitive characters.
   * Also excluded: space, quotes, backslash, backtick (shell-unsafe).
   */
  private static final String SPECIAL = "-.~_^(){}[]<>*";

  /**
   * Combined pool of all allowed characters.
   */
  private static final String ALL_CHARS = LOWERCASE + UPPERCASE + DIGITS + SPECIAL;

  private static final SecureRandom RANDOM = new SecureRandom();

  /**
   * Minimum password length to satisfy all character group requirements.
   */
  private static final int MIN_LENGTH = 4;

  /**
   * Generates a cryptographically secure random password of the given length.
   *
   * <p>
   * The password is guaranteed to contain at least one character from each
   * of the four character groups: lowercase, uppercase, digits, and special characters.
   *
   * @param length the desired password length (must be at least {@value MIN_LENGTH})
   *
   * @return a randomly generated password as a {@code String}
   *
   * @throws IllegalArgumentException if {@code length} is less than {@value MIN_LENGTH}
   */
  public static String generate(int length)
  {

    if(length < MIN_LENGTH)
    {
      throw new IllegalArgumentException(
        "Password length must be at least %d characters.".formatted(MIN_LENGTH));
    }

    log.debug("Generating random password with length {}", length);

    List<Character> passwordChars = new ArrayList<>(length);

    // Guarantee at least one character from each required group
    passwordChars.add(randomChar(LOWERCASE));
    passwordChars.add(randomChar(UPPERCASE));
    passwordChars.add(randomChar(DIGITS));
    passwordChars.add(randomChar(SPECIAL));

    // Fill remaining positions from the full character pool
    for(int i = MIN_LENGTH; i < length; i ++)
    {
      passwordChars.add(randomChar(ALL_CHARS));
    }

    // Shuffle to avoid predictable positions for mandatory characters
    Collections.shuffle(passwordChars, RANDOM);

    StringBuilder password = new StringBuilder(length);
    passwordChars.forEach(password :: append);

    return password.toString();
  }

  /**
   * Returns a random character from the given character pool.
   *
   * @param pool the string of characters to choose from
   *
   * @return a randomly selected character
   */
  private static char randomChar(String pool)
  {
    return pool.charAt(RANDOM.nextInt(pool.length()));
  }

}
