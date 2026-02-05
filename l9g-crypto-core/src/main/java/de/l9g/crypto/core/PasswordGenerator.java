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

import java.util.Random;

/**
 * Utility class for generating random passwords or tokens.
 * It uses a predefined set of characters to generate random strings of a 
 * specified length.
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
public class PasswordGenerator
{
  /**
   * Array of characters used for generating passwords.
   */
  private final static char[] PWCHARS =
  {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '.', '!', '#', '%',
    '/', '?', '+', '*', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
    'm', 'n', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B',
    'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'R', 'S', 'T',
    'U', 'V', 'W', 'X', 'Y', 'Z', '$', '&', '<', '>'
  };

  /**
   * Singleton instance of the PasswordGenerator.
   */
  private final static PasswordGenerator SINGLETON = new PasswordGenerator();

  /**
   * Random number generator used for selecting characters.
   */
  private final Random random;

  /**
   * Private constructor to initialize the random number generator.
   */
  private PasswordGenerator()
  {
    random = new Random(System.currentTimeMillis());
  }

  /**
   * Generates a random string of a specified length using the predefined 
   * character set.
   *
   * @param length The desired length of the generated string.
   *
   * @return A randomly generated string.
   */
  public static String generate(int length)
  {
    char[] pwd = new char[length];

    for(int i = 0; i < length; i ++)
    {
      pwd[i] = PWCHARS[SINGLETON.random.nextInt(PWCHARS.length)];
    }

    return String.valueOf(pwd);
  }

}
