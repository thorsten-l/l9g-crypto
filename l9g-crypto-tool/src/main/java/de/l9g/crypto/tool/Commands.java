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
package de.l9g.crypto.tool;

import de.l9g.crypto.core.CryptoHandler;
import de.l9g.crypto.core.PasswordGenerator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.info.BuildProperties;
import org.springframework.shell.command.annotation.Command;
import org.springframework.shell.command.annotation.Option;

/**
 * This class defines the available commands for the L9G Crypto Tool.
 * It provides functionalities for showing the application version,
 * encrypting and decrypting text, and generating random passwords.
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
@Command
@RequiredArgsConstructor
@Slf4j
public class Commands
{
  private final CryptoHandler cryptoHandler = CryptoHandler.getInstance();

  private final BuildProperties buildProperties;

  /**
   * Displays the application version.
   *
   * @return A string containing the artifact ID and version of the application.
   */
  @Command(description = "Show application version")
  public String version()
  {
    return buildProperties.getArtifact() + "/" +  buildProperties.getVersion();
  }

  /**
   * Encrypts the provided clear text. The encrypted text is prefixed with "{AES256}".
   *
   * @param text The clear text to be encrypted.
   * @throws Throwable if an error occurs during encryption.
   */
  @Command(description = "encrypt clear text for passwords")
  public void encrypt(
    @Option(description = "clear text", required = true) String text)
    throws Throwable
  {
    System.out.println("text = \"" + text + "\"");
    System.out.println("encrypted text = \"" + cryptoHandler.encrypt(text) + "\"");
  }

  /**
   * Decrypts the provided encrypted text. The encrypted text is expected to be prefixed with "{AES256}".
   *
   * @param encrypted The encrypted text to be decrypted.
   * @throws Throwable if an error occurs during decryption.
   */
  @Command(description = "decrypt encrypted text")
  public void decrypt(
    @Option(description = "encrypted text", required = true) String encrypted)
    throws Throwable
  {
    System.out.println("encrypted text = \"" + encrypted + "\"");
    System.out.println("text = \""
      + cryptoHandler.decrypt(encrypted) + "\"");
  }

  /**
   * Generates a random password of a specified length and then encrypts it.
   *
   * @param length The number of characters for the generated password.
   * @throws Throwable if an error occurs during password generation or encryption.
   */
  @Command(alias = "pwgen", description = "create random passwords")
  public void passwordGenerator(
    @Option(description = "number of chars", required = true, defaultValue = "16") int length)
    throws Throwable
  {
    System.out.println("random password");
    encrypt(PasswordGenerator.generate(length));
  }

}
