/*
 * Copyright 2025 Thorsten Ludewig (t.ludewig@gmail.com).
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
package de.l9g.crypto.vault.sample.controller;

import java.util.Locale;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * Controller responsible for signature pad administration functionality.
 * Provides endpoints for registering, connecting, validating signature pads
 * and managing their lifecycle within the system.
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
@Controller
@Slf4j
@RequestMapping(path = "/admin")
@RequiredArgsConstructor
public class AdminController
{

  /**
   * Displays the main home page with an overview of active signature pad sessions.
   * Sets up localization and provides a list of currently connected signature pads.
   *
   * @param model Spring MVC model for passing data to the view
   *
   * @return the name of the home template to render
   */
  @GetMapping(
  {
    "", "/"
  })
  public String home(@AuthenticationPrincipal DefaultOidcUser principal, Model model)
  {
    log.debug("admin home principal = {}", principal);
    Locale locale = LocaleContextHolder.getLocale();
    log.debug("locale={}", locale);
    model.addAttribute("locale", locale.toString());
    model.addAttribute("principal", principal);
    return "admin/home";
  }
}
