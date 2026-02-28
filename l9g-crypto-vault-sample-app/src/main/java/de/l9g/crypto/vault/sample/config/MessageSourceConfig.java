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

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.ReloadableResourceBundleMessageSource;

/**
 * Configuration for the application's message sources, enabling internationalization (i18n).
 * This class defines a {@link MessageSource} bean to resolve messages from
 * resource bundles (e.g., `messages.properties`).
 *
 * @author Thorsten Ludewig <t.ludewig@gmail.com>
 */
@Configuration
@Slf4j
public class MessageSourceConfig
{
  /**
   * Configures and provides a {@link MessageSource} bean for resolving messages.
   * Messages are loaded from "classpath:messages" with UTF-8 encoding.
   *
   * @return A {@link ReloadableResourceBundleMessageSource} instance.
   */
  @Bean
  public MessageSource messageSource()
  {
    log.debug("messageSource");
    ReloadableResourceBundleMessageSource messageSource =
      new ReloadableResourceBundleMessageSource();
    messageSource.setBasename("classpath:messages");
    messageSource.setDefaultEncoding("UTF-8");
    return messageSource;
  }

}
