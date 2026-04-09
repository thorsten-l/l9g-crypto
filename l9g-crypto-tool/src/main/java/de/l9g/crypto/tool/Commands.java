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
 * Defines the available shell commands for the L9G Crypto Tool.
 * <p>
 * This class implements various cryptographic utilities including:
 * <ul>
 *   <li>Encryption of clear text using AES-256 GCM.</li>
 *   <li>Decryption of prefixed encrypted strings.</li>
 *   <li>Generation of secure random passwords and tokens.</li>
 *   <li>Application version information.</li>
 * </ul>
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
@Command
@RequiredArgsConstructor
@Slf4j
public class Commands
{
  /**
   * The crypto handler used for all encryption and decryption operations.
   */
  private final CryptoHandler cryptoHandler = CryptoHandler.getInstance();

  /**
   * Spring Boot build properties for versioning.
   */
  private final BuildProperties buildProperties;

  /**
   * Displays the current application version.
   *
   * @return A string containing the artifact name and version.
   */
  @Command(description = "Show application version")
  public String version()
  {
    return buildProperties.getArtifact() + "/" +  buildProperties.getVersion();
  }

  /**
   * Encrypts the provided clear text.
   * <p>
   * The resulting encrypted text is encoded in Base64 and prefixed 
   * with {@code {AES256}}.
   *
   * @param text The clear text to be encrypted.
   * @throws Throwable If an error occurs during the encryption process.
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
   * Decrypts the provided encrypted text.
   * <p>
   * The input text must start with the {@code {AES256}} prefix.
   *
   * @param encrypted The encrypted text to be decrypted.
   * @throws Throwable If an error occurs during the decryption process.
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
   * Generates a random password and immediately encrypts it.
   * <p>
   * This command combines password generation and encryption in a single step 
   * for improved usability.
   *
   * @param length The desired length of the password (default: 16).
   * @throws Throwable If an error occurs during generation or encryption.
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
