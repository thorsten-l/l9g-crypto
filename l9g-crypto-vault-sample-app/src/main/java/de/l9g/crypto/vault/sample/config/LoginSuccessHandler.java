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
package de.l9g.crypto.vault.sample.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

/**
 * Handles successful authentication events, storing session information.
 * This class implements {@link AuthenticationSuccessHandler} to perform
 * actions after a user successfully logs in, such as storing the session ID
 * and redirecting the user to the application's main page.
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class LoginSuccessHandler implements AuthenticationSuccessHandler
{
  /**
   * Service for storing and retrieving user sessions.
   */
  // private final SessionStoreService sessionStore;

  /**
   * Called when a user has been successfully authenticated.
   * Stores the session ID (sid) from the OIDC user in the {@link SessionStoreService}
   * and redirects the user to the "/app" endpoint.
   *
   * @param request The HttpServletRequest.
   * @param response The HttpServletResponse.
   * @param authentication The Authentication object representing the authenticated user.
   *
   * @throws IOException If an I/O error occurs during redirection.
   * @throws ServletException If a servlet-specific error occurs.
   */
  @Override
  public void onAuthenticationSuccess(HttpServletRequest request,
    HttpServletResponse response, Authentication authentication)
    throws IOException,
           ServletException
  {
    log.debug("onAuthenticationSuccess");
    HttpSession session = request.getSession();
    OidcUser user = (OidcUser)authentication.getPrincipal();
    String sid = user.getIdToken().getClaimAsString("sid");
    log.debug("sid={}, session id={}", sid, session.getId());
    // sessionStore.put(sid, session);
    log.info("LOGIN: {}, {}", session.getId(), user.getName());
    
    /*
    log.debug("--- Request Headers ---");
    java.util.Enumeration<String> headerNames = request.getHeaderNames();
    if (headerNames != null)
    {
      while (headerNames.hasMoreElements())
      {
        String name = headerNames.nextElement();
        log.debug("{}: {}", name, request.getHeader(name));
      }
    }
    log.debug("-----------------------");
    */
    
    response.sendRedirect("/app");
  }

}
