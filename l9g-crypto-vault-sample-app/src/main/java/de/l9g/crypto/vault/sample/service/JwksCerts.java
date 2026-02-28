/*
 * Copyright 2024 Thorsten Ludewig (t.ludewig@gmail.com).
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
package de.l9g.crypto.vault.sample.service;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * Represents a collection of JSON Web Key Set (JWKS) certificates.
 */
public record JwksCerts(
  List<JwksKey> keys)
  {
  /**
   * Represents a JSON Web Key (JWK) used in the JWKS response.
   */
  public record JwksKey(
    @JsonProperty("kid")
    String keyId,
    @JsonProperty("kty")
    String keyType,
    @JsonProperty("alg")
    String algorithm,
    @JsonProperty("use")
    String keyUsage,
    @JsonProperty("n")
    String modulus,
    @JsonProperty("e")
    String exponent,
    @JsonProperty("x5c")
    List<String> x509CertificateChain,
    @JsonProperty("x5t")
    String x509CertificateThumbprint,
    @JsonProperty("x5t#S256")
    String x509CertificateSha256Thumbprint)
    {
  }

}
