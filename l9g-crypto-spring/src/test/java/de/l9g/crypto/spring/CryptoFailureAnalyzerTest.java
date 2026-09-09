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
import java.io.IOException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.diagnostics.FailureAnalysis;

@DisplayName("CryptoFailureAnalyzer Tests")
class CryptoFailureAnalyzerTest
{

  @Test
  @DisplayName("Should render message chain and an action for a nested CryptoException")
  void testAnalyzeNested()
  {
    CryptoException cause = new CryptoException("Could not read secret key file 'x/secret.bin'",
      new IOException("Permission denied"));
    RuntimeException wrapper = new IllegalArgumentException("Unable to instantiate factory", cause);

    FailureAnalysis analysis = new CryptoFailureAnalyzer().analyze(wrapper);

    assertNotNull(analysis);
    assertSame(cause, analysis.getCause());
    assertTrue(analysis.getDescription().contains("x/secret.bin"), analysis.getDescription());
    assertTrue(analysis.getDescription().contains("IOException: Permission denied"), analysis.getDescription());
    assertTrue(analysis.getAction().contains("32 bytes"), analysis.getAction());
    assertTrue(analysis.getAction().contains("SECRET_PATH"), analysis.getAction());
  }

  @Test
  @DisplayName("Should ignore unrelated exceptions")
  void testIgnoresOtherExceptions()
  {
    assertNull(new CryptoFailureAnalyzer().analyze(new IllegalStateException("unrelated")));
  }

}
