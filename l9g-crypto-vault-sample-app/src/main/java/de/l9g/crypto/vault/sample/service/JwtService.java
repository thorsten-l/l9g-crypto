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

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Service class for handling JWT (JSON Web Token) operations such as decoding 
 * and validating signatures.
 * <p>
 * This class provides methods to split, decode, and validate JWT tokens using 
 * various algorithms.
 * <p>
 * It supports RS256 and HS512 algorithms for signature validation.
 * <p>
 * Methods:
 * <ul>
 *   <li>{@link #splitJwt(String)} - Splits a JWT token into its constituent parts.</li>
 *   <li>{@link #decodeJwtPayload(String)} - Decodes the payload of a JWT token.</li>
 *   <li>{@link #validateJwtSignature(String)} - Validates the signature of a JWT token.</li>
 *   <li>{@link #getPublicKeyFromJwks(JwksCerts, String)} - Retrieves the public key from JWKS.</li>
 *   <li>{@link #validateRs256Signature(String, String)} - Validates the RS256 signature.</li>
 *   <li>{@link #validateHs512Signature(String)} - Validates the HS512 signature.</li>
 * </ul>
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
@Service
@Slf4j
@Getter
public class JwtService
{
  /**
   * JSON Web Key Set (JWKS) certificates for OAuth2.
   * This is typically populated from the OIDC discovery endpoint and contains
   * the public keys used by the authorization server to sign JWTs.
   */
  @Setter
  private JwksCerts oauth2JwksCerts;

  /**
   * OAuth2 client secret used as the HMAC key for HS512 signature validation.
   */
  @Value("${spring.security.oauth2.client.registration.app.client-secret}")
  private String clientSecret;

  /**
   * Splits a JWT token string into its three constituent parts: header, payload, 
   * and signature.
   *
   * @param jwt The JWT string to split.
   *
   * @return A string array containing the header, payload, and signature.
   *
   * @throws IllegalArgumentException If the JWT format is invalid.
   */
  public String[] splitJwt(String jwt)
  {
    String[] parts = jwt.split("\\.");
    if(parts.length != 3)
    {
      throw new IllegalArgumentException("Ungültiges JWT-Format");
    }
    return parts;
  }

  /**
   * Decodes the payload section of a JWT token and returns it as a sorted map.
   *
   * @param jwt The full JWT string.
   *
   * @return A {@link Map} containing the decoded payload claims.
   *
   * @throws RuntimeException If an error occurs during decoding or JSON parsing.
   */
  public Map<String, String> decodeJwtPayload(String jwt)
  {
    try
    {
      String[] parts = splitJwt(jwt);

      String payload = parts[1];

      byte[] decodedBytes = Base64.getUrlDecoder().decode(payload);
      String decodedPayload = new String(decodedBytes);

      ObjectMapper objectMapper = new ObjectMapper();
      Map<String, String> sorted = new TreeMap<>(Comparator.naturalOrder());
      sorted.putAll(objectMapper.readValue(decodedPayload, HashMap.class));

      return sorted;
    }
    catch(Exception e)
    {
      throw new RuntimeException("Fehler beim Decodieren des JWT-Tokens", e);
    }
  }

  /**
   * Validates the signature of a JWT token based on its algorithm.
   * Supports RS256 and HS512 algorithms.
   *
   * @param jwt The JWT string to validate.
   *
   * @return {@code true} if the JWT signature is valid, {@code false} otherwise.
   */
  public boolean validateJwtSignature(String jwt)
  {
    String[] parts = splitJwt(jwt);
    try
    {
      ObjectMapper mapper = new ObjectMapper();
      JwtHeader jwtHeader = mapper.readValue(
        new String(Base64.getUrlDecoder().decode(parts[0])), JwtHeader.class);

      log.debug("jwt header = {}", jwtHeader);

      if(null == jwtHeader.algorithm())
      {
        log.error("Unsupported algorithm: {}", jwtHeader.algorithm());
        return false;
      }
      else
      {
        switch(jwtHeader.algorithm())
        {
          case "RS256":
            return validateRs256Signature(jwt, jwtHeader.kid());
          case "HS512":
            return validateHs512Signature(jwt);
          default:
            log.error("Unsupported algorithm: {}", jwtHeader.algorithm());
            return false;
        }
      }
    }
    catch(Throwable t)
    {
      log.error("ERROR: {}", t.getMessage(), t);
      return false;
    }
  }

  /**
   * Retrieves an RSA public key from a JSON Web Key Set (JWKS).
   *
   * @param jwksCerts The {@link JwksCerts} object containing the JWKS.
   * @param kid The key ID of the public key to retrieve.
   * @return The {@link RSAPublicKey} corresponding to the provided kid.
   * @throws Exception If the public key cannot be found or processed.
   */
  private RSAPublicKey getPublicKeyFromJwks(JwksCerts jwksCerts, String kid)
    throws Exception
  {
    for(JwksCerts.JwksKey key : jwksCerts.keys())
    {
      log.debug("key={}", key);
      if(key.algorithm().equals("RS256"))
      {
        String x509Cert = key.x509CertificateChain().get(0);
        byte[] decodedCert = Base64.getDecoder().decode(x509Cert);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate =
          (X509Certificate)factory.generateCertificate(
            new java.io.ByteArrayInputStream(decodedCert));
        return (RSAPublicKey)certificate.getPublicKey();
      }
    }
    throw new IllegalArgumentException(
      "Public key with kid=" + kid + " not found");
  }

  /**
   * Validates the RS256 signature of a JWT token.
   *
   * @param jwt The JWT string to validate.
   * @param keyId The key ID (kid) of the public key.
   *
   * @return {@code true} if the signature is valid, {@code false} otherwise.
   */
  private boolean validateRs256Signature(String jwt, String keyId)
  {
    try
    {
      String[] parts = splitJwt(jwt);
      String data = parts[0] + "." + parts[1];
      byte[] signatureBytes = Base64.getUrlDecoder().decode(parts[2]);

      // Öffentlichen Schlüssel abrufen
      RSAPublicKey publicKey = getPublicKeyFromJwks(oauth2JwksCerts, keyId);
      if(publicKey == null)
      {
        log.error("Public key with kid={} not found", keyId);
        return false;
      }

      // Signatur validieren
      Signature signature = Signature.getInstance("SHA256withRSA");
      signature.initVerify(publicKey);
      signature.update(data.getBytes(StandardCharsets.UTF_8));
      return signature.verify(signatureBytes);
    }
    catch(Throwable t)
    {
      log.error("ERROR in RS256 validation: {}", t.getMessage(), t);
      return false;
    }
  }

  /**
   * Validates the HS512 (HMAC-SHA512) signature of a JWT token.
   *
   * @param jwt The JWT string to validate.
   *
   * @return {@code true} if the signature is valid, {@code false} otherwise.
   */
  private boolean validateHs512Signature(String jwt)
  {
    try
    {
      String[] parts = splitJwt(jwt);
      String signingInput = parts[0] + "." + parts[1];
      byte[] signatureBytes = Base64.getUrlDecoder().decode(parts[2]);

      Mac mac = Mac.getInstance("HmacSHA512");
      mac.init(new SecretKeySpec(
        clientSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA512"));
      byte[] expectedSignature = mac.doFinal(
        signingInput.getBytes(StandardCharsets.UTF_8));

      return MessageDigest.isEqual(expectedSignature, signatureBytes);
    }
    catch(Throwable t)
    {
      log.error("ERROR in HS512 validation: {}", t.getMessage(), t);
      return false;
    }
  }

}
