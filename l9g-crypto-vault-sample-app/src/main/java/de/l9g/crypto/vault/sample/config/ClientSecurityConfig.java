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
package de.l9g.crypto.vault.sample.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Collection;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import static org.springframework.security.config.Customizer.withDefaults;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;

import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

/**
 * Security configuration for the client-side of the application.
 * This class configures Spring Security for OAuth2/OIDC, including authorization,
 * logout handling, and authorities conversion. It also sets up Content Security Policy.
 *
 * @author Thorsten Ludewig <t.ludewig@gmail.com>
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@Slf4j
public class ClientSecurityConfig
{
  private final AppAuthoritiesConverter appAuthoritiesConverter;

  private final LoginSuccessHandler loginSuccessHandler;

  /**
   * Content Security Policy directives for enhanced security.
   * This policy defines allowed content sources for various types of resources.
   */
  // private final String CSP_POLICY;

  /**
   * Constructs a {@code ClientSecurityConfig} instance.
   *
   * @param appAuthoritiesConverter The converter for application authorities.
   * @param loginSuccessHandler The handler for successful logins.
   */
  public ClientSecurityConfig(
    AppAuthoritiesConverter appAuthoritiesConverter,
    LoginSuccessHandler loginSuccessHandler )
  {
    this.appAuthoritiesConverter = appAuthoritiesConverter;
    this.loginSuccessHandler = loginSuccessHandler;
  }

  /**
   * Configures the security filter chain for HTTP requests.
   * Defines authorization rules, OAuth2 login, OAuth2 client, and logout behavior.
   * Includes CSRF configuration and Content Security Policy headers.
   *
   * @param http The HttpSecurity object to configure.
   * @param clientRegistrationRepository The repository for client registrations.
   *
   * @return A SecurityFilterChain instance.
   *
   * @throws Exception If an error occurs during configuration.
   */
  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http,
    ClientRegistrationRepository clientRegistrationRepository)
    throws Exception
  {
    log.debug("filterChain clientRegistrationRepository={}",
      clientRegistrationRepository);

    DefaultOAuth2AuthorizationRequestResolver resolver =
      new DefaultOAuth2AuthorizationRequestResolver(
        clientRegistrationRepository,
        OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);

    resolver.setAuthorizationRequestCustomizer(
      OAuth2AuthorizationRequestCustomizers.withPkce());

    http.authorizeHttpRequests(
      authorize -> authorize
        // test deny all
        .requestMatchers("/system/test/error403").denyAll()
        // allow all
        .requestMatchers("/", "/manifest.json",
          "/manifest.webmanifest",
          "/system/test/**","/error/**", "/api/v1/buildinfo",
          "/webjars/**", "/icons/**", "/css/**", "/js/**", "/images/**",
          "/actuator/**", "/flags/**", "/logout", "/oidc-backchannel-logout",
          "/android**",
          "/apple**",
          "/favicon**"
        )
        .permitAll()
        .requestMatchers("/admin**", "/api/v1/admin**", "/v3/api-docs")
        .hasRole("ADMIN")
        .anyRequest()
        .authenticated()
    )
      .headers(
        headers -> headers
          .frameOptions(frameOptions -> frameOptions.disable())
          // .contentSecurityPolicy(csp -> csp.policyDirectives(CSP_POLICY))
      )
      .oauth2Login(
        login -> login
          .authorizationEndpoint(
            authorizationEndpointCustomizer -> authorizationEndpointCustomizer
              .authorizationRequestResolver(resolver))
          .userInfoEndpoint(userInfo -> userInfo
          .oidcUserService(this.oidcUserService())
          )
          .successHandler(loginSuccessHandler))
      .oauth2Client(withDefaults())
      .logout(
        logout -> logout
          .deleteCookies("JSESSIONID") // Session info from embedded Tomcat
          .addLogoutHandler(invalidateCacheLogoutHandler())
          .logoutSuccessHandler(
            oidcLogoutSuccessHandler(clientRegistrationRepository))
      )
      // permit even POST, PUT and DELETE requests
      .csrf(csrf -> csrf.ignoringRequestMatchers(
      "/oidc-backchannel-logout"));

    return http.build();
  }

  /**
   * Creates a {@link LogoutHandler} that invalidates the security context and session.
   *
   * @return A {@link LogoutHandler} instance.
   */
  private LogoutHandler invalidateCacheLogoutHandler()
  {
    return (HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) ->
    {
      String sessionId = "no-session";
      if (request.getSession(false) != null)
      {
        sessionId = request.getSession().getId();
      }

      String username = "anonymous";
      if (authentication != null
        && authentication.getPrincipal() instanceof OidcUser oidcUser)
      {
        username = oidcUser.getName();
      }

      log.info("LOGOUT: {}, {}", sessionId, username);
      new SecurityContextLogoutHandler().logout(request, response, authentication);
    };
  }

  /**
   * Configures the OIDC client-initiated logout success handler.
   * This handler redirects to the post-logout URI after a successful logout.
   *
   * @param clientRegistrationRepository The repository for client registrations.
   *
   * @return An {@link OidcClientInitiatedLogoutSuccessHandler} instance.
   */
  private LogoutSuccessHandler oidcLogoutSuccessHandler(
    ClientRegistrationRepository clientRegistrationRepository)
  {
    log.debug("oidcLogoutSuccessHandler");
    OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler =
      new OidcClientInitiatedLogoutSuccessHandler(
        clientRegistrationRepository);
    oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}");
    return oidcLogoutSuccessHandler;
  }

  /**
   * Configures the OIDC user service to load user information and convert authorities.
   * This service retrieves the OidcUser and then converts JWT roles into Spring Security GrantedAuthorities.
   *
   * @return An {@link OidcUserService} instance.
   */
  private OidcUserService oidcUserService()
  {
    log.debug("oidcUserService");
    OidcUserService delegate = new OidcUserService();

    return new OidcUserService()
    {
      @Override
      public OidcUser loadUser(OidcUserRequest userRequest)
      {
        OidcUser oidcUser = delegate.loadUser(userRequest);

        Jwt accessToken = decodeAccessToken(
          userRequest.getAccessToken().getTokenValue(),
          userRequest.getClientRegistration().getProviderDetails().getIssuerUri()
        );

        Collection<GrantedAuthority> authorities =
          appAuthoritiesConverter.convert(oidcUser, accessToken);

        if(log.isDebugEnabled())
        {
          authorities.stream()
            .map(GrantedAuthority :: getAuthority)
            .forEach(System.out :: println);
        }

        return new DefaultOidcUser(
          authorities, oidcUser.getIdToken(), oidcUser.getUserInfo());
      }

    };
  }

  /**
   * Decodes an access token using a JwtDecoder.
   *
   * @param token The access token string.
   * @param issuerUri The issuer URI for the JWT.
   *
   * @return A decoded {@link Jwt} object.
   */
  private Jwt decodeAccessToken(String token, String issuerUri)
  {
    JwtDecoder jwtDecoder = JwtDecoders.fromIssuerLocation(issuerUri);
    return jwtDecoder.decode(token);
  }

}
