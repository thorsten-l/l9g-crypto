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
package de.l9g.crypto.vault.sample.vault.api;

import de.l9g.crypto.vault.sample.vault.VaultAdminKey;
import de.l9g.crypto.vault.sample.vault.VaultService;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
@Slf4j
@RestController
@RequestMapping(path = "/api/v1/admin/vault", produces = MediaType.APPLICATION_JSON_VALUE)
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class VaultApiController
{
  // Allows standard Base64 (+/=) and Base64url (_-) characters as used by WebAuthn
  private static final Pattern CREDENTIAL_ID_PATTERN =
    Pattern.compile("^[A-Za-z0-9+/_=\\-]+$");

  private final VaultService vaultService;

  @PostMapping(path = "/adminkey", produces = MediaType.TEXT_PLAIN_VALUE)
  ResponseEntity<String> addAdminkey(
    @AuthenticationPrincipal DefaultOidcUser principal,
    @RequestBody VaultAdminKey vaultAdminKey)
  {
    log.debug("principal = {}", principal);

    boolean isUnsealed = (vaultService.getUnlockedKey() != null);
    boolean adminKeysIsEmpty = vaultService.adminKeysIsEmpty();

    if( ! isUnsealed &&  ! adminKeysIsEmpty)
    {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN,
        "Enrollment not allowed when vault is sealed and keys already exist.");
    }

    log.trace("vaultAdminKey = {}", vaultAdminKey);
    vaultService.addVaultAdminKey(vaultAdminKey);
    return ResponseEntity.ok("OK");
  }

  @DeleteMapping(path = "/adminkey", produces = MediaType.TEXT_PLAIN_VALUE)
  ResponseEntity<String> deleteAdminkey(
    @RequestParam(name = "id", required = true) String credentialId,
    @AuthenticationPrincipal DefaultOidcUser principal)
  {
    log.debug("principal = {}", principal);

    if(credentialId.isBlank() || credentialId.length() > 2048
      || !CREDENTIAL_ID_PATTERN.matcher(credentialId).matches())
    {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
        "Invalid credentialId format.");
    }

    if(vaultService.getUnlockedKey() == null)
    {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN,
        "Remove admin key not allowed when vault is sealed.");
    }

    boolean isOwner = vaultService
      .findVaultAdminKeysByAdminId(principal.getPreferredUsername())
      .stream()
      .anyMatch(k -> k.credentialId().equals(credentialId));

    if(!isOwner)
    {
      log.warn("Admin '{}' attempted to delete credential '{}' which does not belong to them",
        principal.getPreferredUsername(), credentialId);
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Access denied.");
    }

    log.debug("credentialId = {}", credentialId);
    vaultService.removeVaultAdminKeyByCredentialId(credentialId);
    return ResponseEntity.ok("OK");
  }

  @GetMapping("/challenge-data")
  public List<VaultAdminKey> getChallengeData(
    @AuthenticationPrincipal OidcUser oidcUser)
    throws Exception
  {
    List<VaultAdminKey> adminKeys = vaultService.findVaultAdminKeysByAdminId(
      oidcUser.getPreferredUsername());

    if(adminKeys.isEmpty())
    {
      log.warn("No YubiKeys registered for admin '{}'", oidcUser.getPreferredUsername());
      throw new ResponseStatusException(HttpStatus.NOT_FOUND, "No keys found.");
    }
    return adminKeys;
  }

  @GetMapping("/unlocktimeleft")
  public long unlockTimeLeft(@AuthenticationPrincipal OidcUser principal)
  {
    // log.trace("principal={}", principal);
    return vaultService.getUnlockTimeLeft();
  }

  @PostMapping("/unseal")
  public void unsealServer(@RequestBody VaultUnsealRequest request,
    @AuthenticationPrincipal OidcUser oidcUser)
    throws Exception
  {
    VaultAdminKey vaultAdminKey = vaultService.findVaultAdminKeysByAdminId(
      oidcUser.getPreferredUsername()).stream()
      .filter(c -> c.credentialId().equals(request.usedCredentialId()))
      .findFirst()
      .orElseThrow(() ->
      {
        log.warn("Unseal attempt by '{}' with unknown credentialId '{}'",
          oidcUser.getPreferredUsername(), request.usedCredentialId());
        return new ResponseStatusException(HttpStatus.FORBIDDEN, "Authentication failed.");
      });

    byte[] prfOutputKek = Base64.getDecoder().decode(request.prfOutput());
    byte[] encryptedPayload = Base64.getDecoder().decode(
      vaultAdminKey.encryptedMasterKey());
    byte[] iv = Arrays.copyOfRange(encryptedPayload, 0, 12);
    byte[] cipherTextAndTag = Arrays.copyOfRange(
      encryptedPayload, 12, encryptedPayload.length);

    SecretKey kek = new SecretKeySpec(prfOutputKek, "AES");
    GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.DECRYPT_MODE, kek, gcmSpec);

    try
    {
      byte[] decryptedMasterKeyBytes = cipher.doFinal(cipherTextAndTag);

      SecretKey masterKey = new SecretKeySpec(decryptedMasterKeyBytes, "AES");
      vaultService.setUnlockedKey(masterKey);

      log.info("Server unsealed by {} using {}",
        oidcUser.getPreferredUsername(), vaultAdminKey.description());
      log.debug("  - vault admin key = {}", vaultAdminKey);
      log.trace("decrypted masterkey base64 = {}",
        Base64.getEncoder().encodeToString(decryptedMasterKeyBytes));
    }
    catch(Exception e)
    {
      log.warn("Unseal decryption failed for admin '{}': {}",
        oidcUser.getPreferredUsername(), e.getMessage());
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Authentication failed.");
    }
    finally
    {
      Arrays.fill(prfOutputKek, (byte)0);
    }
  }

}
