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
package de.l9g.crypto.vault.sample;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.info.BuildProperties;
import org.springframework.context.annotation.Bean;

/**
 * Main application class for the L9G Crypto Vault Sample Web Application.
 * <p>
 * This application demonstrates the integration of AES-256 GCM encryption 
 * with a "Vault" mechanism, utilizing WebAuthn PRF (Pseudo-Random Function) 
 * for hardware-backed key derivation.
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
@SpringBootApplication
@Slf4j
public class Application
{

  /**
   * Application entry point.
   *
   * @param args Command-line arguments.
   */
  public static void main(String[] args)
  {
    SpringApplication.run(Application.class, args);
  }

  /**
   * Logs application build information on startup.
   *
   * @param buildProperties The build-time properties.
   * @return A {@link CommandLineRunner} that prints the info.
   */
  @Bean
  public CommandLineRunner commandLineRunner(BuildProperties buildProperties)
  {
    return args ->
    {
      log.info("");
      log.info("");
      log.info("--- Application Info ----------------------------");
      log.info("Name: {}", buildProperties.getName());
      log.info("Version: {}", buildProperties.getVersion());
      log.info("Build: {}", buildProperties.getTime());
      log.info("-------------------------------------------------");
    };
  }

}
