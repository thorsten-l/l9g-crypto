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


import de.l9g.crypto.vault.sample.service.JwtService;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.info.BuildProperties;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;

/**
 * Handles application-specific requests, primarily displaying user and application information.
 * This controller provides the main application view after successful authentication,
 * presenting JWT details, build properties, and system properties.
 */
@Controller
@Slf4j
@RequiredArgsConstructor
public class AppController
{
  /**
   * Service for handling JWT (JSON Web Token) related operations.
   */
  private final JwtService jwtService;

  /**
   * Provides access to application build-time properties.
   */
  private final BuildProperties buildProperties;

  /**
   * Displays the main application page with user and application details.
   * This endpoint is secured and requires either 'PUBLISHER' or 'ADMIN' role.
   * It extracts and displays information from the ID token, access token, and refresh token (if available),
   * along with build properties and filtered system properties.
   *
   * @param model The Spring MVC model to pass data to the view.
   * @param principal The authenticated OIDC user.
   * @param authorizedClient The OAuth2 authorized client containing token details.
   *
   * @return The name of the view ("app") to render.
   */
  @GetMapping("/app")
  @PreAuthorize("hasRole('PUBLISHER') or hasRole('ADMIN')")
  public String app(
    Model model,
    @AuthenticationPrincipal DefaultOidcUser principal,
    @RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient)
  {
    log.debug("home principal={}", principal);

    if(principal == null)
    {
      return "redirect:/";
    }

    String idToken = principal.getIdToken().getTokenValue();
    String accessToken = authorizedClient.getAccessToken().getTokenValue();
    String refreshToken = authorizedClient.getRefreshToken() != null
      ? authorizedClient.getRefreshToken().getTokenValue() : null;

    //log.debug("idToken = {}", idToken);
    //log.debug("accessToken = {}", accessToken);
    //log.debug("refreshToken= {}", refreshToken);
    Locale locale = LocaleContextHolder.getLocale();
    log.debug("locale={}", locale);

    model.addAttribute("principal", principal);
    model.addAttribute("locale", locale.toString());

    ClientRegistration client = authorizedClient.getClientRegistration();
    String clientId = client.getClientId();

    Map<String, Object> providerMetadata =
      client.getProviderDetails().getConfigurationMetadata();
    String endSessionEndpoint = providerMetadata != null
      ? (String)providerMetadata.getOrDefault("end_session_endpoint", null)
      : null;

    ArrayList<String> keys = new ArrayList<>();
    buildProperties.forEach(p -> keys.add(p.getKey()));
    Collections.sort(keys);
    LinkedHashMap<String, String> properties = new LinkedHashMap<>();
    for(String key : keys)
    {
      properties.put(key, buildProperties.get(key));
    }

    model.addAttribute("buildProperties", properties);
    model.addAttribute("systemProperties", systemPropertiesMap());

    model.addAttribute("oauth2ClientId", clientId);
    model.addAttribute("oauth2EndSessionEndpoint", endSessionEndpoint);
    model.addAttribute("oauth2PostLogoutRedirectUri", null);

    model.addAttribute("oauth2IdToken", idToken);
    model.addAttribute("idTokenMap", jwtService.decodeJwtPayload(idToken));
    model.addAttribute("accessTokenMap", jwtService.decodeJwtPayload(accessToken));
    model.addAttribute("refreshTokenMap", refreshToken != null
      ? jwtService.decodeJwtPayload(refreshToken) : null);

    return "app";
  }

  /**
   * Retrieves a filtered map of system properties.
   * Only properties starting with "java.", "os.", "sun.", "file.", "native",
   * "user.lang", "user.time", or "user.coun" are included,
   * excluding those ending with "path" or ".tmpdir".
   *
   * @return A sorted map of filtered system properties.
   */
  private Map<String, String> systemPropertiesMap()
  {
    LinkedHashMap<String, String> properties = new LinkedHashMap<>();
    String[] keys = System.getProperties().keySet().toArray(String[] :: new);
    Arrays.sort(keys);
    for(String key : keys)
    {
      if(key.startsWith("java.")
        || key.startsWith("os.")
        || key.startsWith("sun.")
        || key.startsWith("file.")
        || key.startsWith("native")
        || key.startsWith("user.lang")
        || key.startsWith("user.time")
        || key.startsWith("user.coun"))
      {
        if( ! key.endsWith("path")
          &&  ! key.endsWith(".tmpdir"))
        {
          properties.put(key, System.getProperty(key));
        }
      }
    }
    return properties;
  }

}
