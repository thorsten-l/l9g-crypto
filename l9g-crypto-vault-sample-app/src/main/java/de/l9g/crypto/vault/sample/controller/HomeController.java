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
import org.springframework.boot.info.BuildProperties;

/**
 * Handles the main home page requests for the application.
 */
@Controller
@Slf4j
@RequiredArgsConstructor
public class HomeController
{
  /**
   * Provides access to application build-time properties.
   */
  private final BuildProperties buildProperties;

  /**
   * Displays the application home page. If a user is already authenticated,
   * they will be redirected to the main application page ("/app").
   * Otherwise, it displays a neutral home page, handling locale information.
   *
   * @param model The Spring MVC model for passing data to the view.
   * @param principal The authenticated OIDC user, or null if not authenticated.
   *
   * @return A redirect to "/app" if authenticated, otherwise the "home" view.
   */
  @GetMapping("/")
  public String home(
    Model model,
    @AuthenticationPrincipal DefaultOidcUser principal)
  {
    log.debug("home", principal);

    if(principal != null)
    {
      return "redirect:/app";
    }

    Locale locale = LocaleContextHolder.getLocale();
    log.debug("locale={}", locale);
    model.addAttribute("buildProperties", buildProperties);
    model.addAttribute("principal", principal);
    model.addAttribute("locale", locale.toString());
    return "home";
  }

}
