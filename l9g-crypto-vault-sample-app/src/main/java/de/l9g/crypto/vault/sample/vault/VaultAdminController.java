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
package de.l9g.crypto.vault.sample.vault;

import java.util.Locale;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

/**
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
@Controller
@Slf4j
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class VaultAdminController
{
  private final VaultService vaultService;

  @GetMapping("/admin/vault/enrollment")
  public String enrollment(
    Model model,
    @AuthenticationPrincipal DefaultOidcUser principal)
  {
    log.debug("enrollment principal={}", principal);

    if(vaultService.getUnlockedKey() == null
      &&  ! vaultService.adminKeysIsEmpty())
    {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN,
        "Enrollment not allowed when vault is sealed and keys already exist.");
    }

    Locale locale = LocaleContextHolder.getLocale();
    log.debug("locale={}", locale);
    model.addAttribute("principal", principal);
    model.addAttribute("locale", locale.toString());
    return "admin/enrollment";
  }

  @GetMapping("/admin/vault/managekeys")
  public String managekeys(
    Model model,
    @AuthenticationPrincipal DefaultOidcUser principal)
  {
    log.debug("enrollment principal={}", principal);

    if(vaultService.getUnlockedKey() == null)
    {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN,
        "Manage keys not allowed when vault is sealed.");
    }

    Locale locale = LocaleContextHolder.getLocale();
    log.debug("locale={}", locale);
    model.addAttribute("principal", principal);
    model.addAttribute("locale", locale.toString());
    model.addAttribute("adminkeys", vaultService.findAllVaultAdminKeys());
    return "admin/managekeys";
  }

  @GetMapping("/admin/vault/unseal")
  public String unseal(
    Model model,
    @AuthenticationPrincipal DefaultOidcUser principal)
  {
    log.debug("enrollment principal={}", principal);
    Locale locale = LocaleContextHolder.getLocale();
    log.debug("locale={}", locale);
    model.addAttribute("isUnsealed", (vaultService.getUnlockedKey() != null));
    model.addAttribute("principal", principal);
    model.addAttribute("locale", locale.toString());
    return "admin/unseal";
  }

}
