/*
 * Copyright 2024 Thorsten Ludewig <t.ludewig@gmail.com>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
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

import java.util.Locale;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.i18n.CookieLocaleResolver;
import org.springframework.web.servlet.i18n.LocaleChangeInterceptor;

/**
 * Configuration for locale and internationalization (i18n) settings in the web application.
 * This class sets up a LocaleResolver and a LocaleChangeInterceptor to handle
 * locale changes based on a request parameter or a cookie.
 *
 * @author Thorsten Ludewig <t.ludewig@gmail.com>
 */
@Configuration
@Slf4j
public class LocaleWebConfig implements WebMvcConfigurer
{
  /**
   * The default locale for the application, loaded from application properties.
   */
  @Value("${app.default.locale}")
  private String defaultLocale;

  /**
   * Configures and provides a {@link LocaleResolver} bean that uses cookies to store
   * and retrieve the user's preferred locale.
   *
   * @return A {@link CookieLocaleResolver} instance.
   */
  @Bean
  public LocaleResolver localeResolver()
  {
    Locale locale = Locale.of(defaultLocale);
    log.debug("set default locale to {}", locale);
    CookieLocaleResolver resolver = new CookieLocaleResolver();
    resolver.setDefaultLocale(locale);
    return resolver;
  }

  /**
   * Configures and provides a {@link LocaleChangeInterceptor} bean.
   * This interceptor allows changing the current locale based on a request parameter (defaulting to "lang").
   *
   * @return A {@link LocaleChangeInterceptor} instance.
   */
  @Bean
  public LocaleChangeInterceptor localeChangeInterceptor()
  {
    log.debug("localeChangeInterceptor");
    LocaleChangeInterceptor interceptor = new LocaleChangeInterceptor();
    interceptor.setParamName("lang");
    return interceptor;
  }

  /**
   * Registers the {@link LocaleChangeInterceptor} with the application's interceptor registry.
   *
   * @param registry The {@link InterceptorRegistry} to add the interceptor to.
   */
  @Override
  public void addInterceptors(InterceptorRegistry registry)
  {
    log.debug("addInterceptors");
    registry.addInterceptor(localeChangeInterceptor());
  }

}
