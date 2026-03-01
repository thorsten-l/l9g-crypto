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
  private final VaultService vaultService;

  @PostMapping(path = "/addadminkey", produces = MediaType.TEXT_PLAIN_VALUE)
  ResponseEntity<String> addAdminkey(
    @AuthenticationPrincipal DefaultOidcUser principal,
    @RequestBody VaultAdminKey vaultAdminKey)
  {
    log.debug("principal = {}", principal);

    boolean isUnsealed = (vaultService.getUnlockedKey() != null);
    boolean adminKeysIsEmpty = vaultService.adminKeysIsEmpty();

    if (!isUnsealed && !adminKeysIsEmpty)
    {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Enrollment not allowed when vault is sealed and keys already exist.");
    }

    log.trace("vaultAdminKey = {}", vaultAdminKey);
    vaultService.addVaultAdminKey(vaultAdminKey);
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
      throw new RuntimeException("Keine YubiKeys für diesen Admin hinterlegt!");
    }
    return adminKeys;
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
      .orElseThrow(() -> new RuntimeException(
      "Unbekannter oder nicht berechtigter YubiKey!"));

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
      throw new RuntimeException(
        "Entschlüsselung fehlgeschlagen. Falscher YubiKey?", e);
    }
    finally
    {
      Arrays.fill(prfOutputKek, (byte)0);
    }
  }

}
