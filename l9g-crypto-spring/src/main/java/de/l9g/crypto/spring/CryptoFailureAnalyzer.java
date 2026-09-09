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

import de.l9g.crypto.core.AppSecretKey;
import de.l9g.crypto.core.CryptoException;
import org.springframework.boot.diagnostics.AbstractFailureAnalyzer;
import org.springframework.boot.diagnostics.FailureAnalysis;

/**
 * Spring Boot {@link org.springframework.boot.diagnostics.FailureAnalyzer} that
 * turns a {@link CryptoException} raised during startup into a readable
 * "APPLICATION FAILED TO START" report.
 * <p>
 * Spring Boot removes its logging suppression before running failure analyzers,
 * so this report is visible even when the failure happened in the environment
 * post-processing phase where regular log statements are discarded.
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
public class CryptoFailureAnalyzer extends AbstractFailureAnalyzer<CryptoException>
{

  @Override
  protected FailureAnalysis analyze(Throwable rootFailure, CryptoException cause)
  {
    StringBuilder description = new StringBuilder(cause.getMessage());
    Throwable t = cause.getCause();
    while(t != null)
    {
      description.append(System.lineSeparator()).append("  caused by: ")
        .append(t.getClass().getSimpleName());
      if(t.getMessage() != null)
      {
        description.append(": ").append(t.getMessage());
      }
      t = t.getCause();
    }

    String action = "Check the AES-256 secret key file '" + AppSecretKey.resolveSecretPath()
      + "' (override the location with the " + AppSecretKey.SECRET_PATH_ENV_NAME
      + " environment variable). The file must be readable and exactly 32 bytes long, "
      + "and every {AES256} value must have been encrypted with this key "
      + "(e.g. using 'crypto-tool encrypt --text ...').";

    return new FailureAnalysis(description.toString(), action, cause);
  }

}
