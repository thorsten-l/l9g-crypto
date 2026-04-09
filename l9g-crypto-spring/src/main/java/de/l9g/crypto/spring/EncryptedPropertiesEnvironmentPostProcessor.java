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
package de.l9g.crypto.spring;

import de.l9g.crypto.core.CryptoHandler;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.PropertySource;

/**
 * Spring Boot {@link EnvironmentPostProcessor} that automatically decrypts 
 * encrypted properties in the application environment.
 * <p>
 * This processor scans all {@link EnumerablePropertySource}s for string 
 * properties starting with the {@code {AES256}} prefix. When an encrypted 
 * property is found, it is decrypted using the {@link CryptoHandler}.
 * <p>
 * The decrypted properties are then collected into a new {@link MapPropertySource} 
 * which is added to the beginning of the environment's property sources. 
 * This ensures that decrypted values take precedence over their encrypted 
 * counterparts, making the decryption transparent to the application.
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
public class EncryptedPropertiesEnvironmentPostProcessor implements
  EnvironmentPostProcessor
{

  /**
   * The crypto handler used for decrypting property values.
   */
  private final CryptoHandler cryptoHandler = CryptoHandler.getInstance();

  /**
   * Post-processes the Spring environment to decrypt properties.
   * <p>
   * Iterates through all available property sources, identifies encrypted 
   * strings, and registers their decrypted versions in a high-priority 
   * property source.
   *
   * @param environment The configurable environment to process.
   * @param application The Spring application instance.
   */
  @Override
  public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application)
  {
    Map<String, Object> decryptedProperties = new HashMap<>();
    Set<String> keys = new HashSet<>();

    for(PropertySource<?> propertySource : environment.getPropertySources())
    {
      if(propertySource instanceof EnumerablePropertySource)
      {
        for(String key : ((EnumerablePropertySource<?>)propertySource).getPropertyNames())
        {
          if( ! keys.contains(key))
          {
            keys.add(key);
            Object value = propertySource.getProperty(key);
            if(value instanceof String)
            {
              String stringValue = (String)value;
              if(stringValue.startsWith(CryptoHandler.AES256_PREFIX))
              {
                String decryptedValue = cryptoHandler.decrypt(stringValue);
                decryptedProperties.put(key, decryptedValue);
              }
            }
          }
        }
      }
    }

    if( ! decryptedProperties.isEmpty())
    {
      environment.getPropertySources().addFirst(
        new MapPropertySource("decryptedProperties", decryptedProperties)
      );
    }
  }

}
