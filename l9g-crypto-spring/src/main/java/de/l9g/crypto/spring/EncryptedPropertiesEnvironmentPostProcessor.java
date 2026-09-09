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

import de.l9g.crypto.core.CryptoException;
import de.l9g.crypto.core.CryptoHandler;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.apache.commons.logging.Log;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.boot.logging.DeferredLogFactory;
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
 * <p>
 * Environment post-processors run before Spring Boot's logging system is
 * initialized, so this class logs through a {@link DeferredLogFactory}; the
 * messages are replayed once logging is available. The {@link CryptoHandler}
 * (and therefore the secret key file) is only touched when at least one
 * encrypted value is present. Failures are reported as {@link CryptoException}
 * naming the affected property key and property source (never the value) and
 * are rendered by {@link CryptoFailureAnalyzer}.
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
public class EncryptedPropertiesEnvironmentPostProcessor implements
  EnvironmentPostProcessor
{
  /**
   * Name of the property source holding the decrypted values.
   */
  static final String DECRYPTED_PROPERTY_SOURCE_NAME = "decryptedProperties";

  /**
   * Deferred logger, replayed after the logging system has been initialized.
   */
  private final Log log;

  /**
   * Creates the post-processor. Spring Boot injects the {@link DeferredLogFactory}.
   *
   * @param logFactory Factory for deferred logs.
   */
  public EncryptedPropertiesEnvironmentPostProcessor(DeferredLogFactory logFactory)
  {
    this.log = logFactory.getLog(getClass());
  }

  /**
   * Post-processes the Spring environment to decrypt properties.
   * <p>
   * Iterates through all available property sources, identifies encrypted 
   * strings, and registers their decrypted versions in a high-priority 
   * property source.
   *
   * @param environment The configurable environment to process.
   * @param application The Spring application instance.
   *
   * @throws CryptoException If the secret key is unavailable or a property cannot be decrypted.
   */
  @Override
  public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application)
  {
    Map<String, Object> decryptedProperties = new HashMap<>();
    Set<String> keys = new HashSet<>();
    CryptoHandler cryptoHandler = null;

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
                if(cryptoHandler == null)
                {
                  cryptoHandler = CryptoHandler.getInstance();
                }
                decryptedProperties.put(key,
                  decrypt(cryptoHandler, key, propertySource.getName(), stringValue));
              }
            }
          }
        }
      }
    }

    if( ! decryptedProperties.isEmpty())
    {
      log.debug("Decrypted " + decryptedProperties.size() + " encrypted propertie(s): "
        + decryptedProperties.keySet());
      environment.getPropertySources().addFirst(
        new MapPropertySource(DECRYPTED_PROPERTY_SOURCE_NAME, decryptedProperties)
      );
    }
  }

  /**
   * Decrypts a single property value, translating failures into a
   * {@link CryptoException} that names the property but never its value.
   */
  private static String decrypt(CryptoHandler cryptoHandler, String key,
    String propertySourceName, String encryptedValue)
  {
    try
    {
      return cryptoHandler.decrypt(encryptedValue);
    }
    catch(RuntimeException ex)
    {
      throw new CryptoException("Could not decrypt property '" + key
        + "' from property source '" + propertySourceName + "'", ex);
    }
  }

}
