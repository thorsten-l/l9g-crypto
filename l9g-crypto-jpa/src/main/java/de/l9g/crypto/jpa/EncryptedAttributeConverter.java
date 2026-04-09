/*
 * Copyright 2025 Thorsten Ludewig <t.ludewig@gmail.com>.
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
package de.l9g.crypto.jpa;

import de.l9g.crypto.core.CryptoHandler;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

/**
 * JPA Attribute Converter for transparent encryption and decryption of String
 * attributes in the database.
 * <p>
 * This converter leverages the {@link CryptoHandler} to encrypt sensitive 
 * entity fields before they are persisted to the database and decrypt them 
 * automatically when they are loaded back into memory.
 * <p>
 * By using this converter, sensitive information is stored in an encrypted 
 * format (AES-256 GCM) in the database column, while the application can 
 * work with the plain text values in the entity objects.
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
@Converter
public class EncryptedAttributeConverter implements
  AttributeConverter<String, String>
{

  /**
   * Converts an entity attribute value to its encrypted form for storage in 
   * the database column.
   * <p>
   * The resulting string will be prefixed with {@code {AES256}} as defined 
   * by {@link CryptoHandler}.
   *
   * @param attribute The plain text value to be encrypted.
   *
   * @return The encrypted and prefixed string, or {@code null} if the input 
   *         attribute is {@code null}.
   */
  @Override
  public String convertToDatabaseColumn(String attribute)
  {
    return attribute == null ? null : CryptoHandler.getInstance().encrypt(attribute);
  }

  /**
   * Converts a database column value to its decrypted form for use as an 
   * entity attribute.
   * <p>
   * This method performs transparent decryption if the prefix is present.
   *
   * @param dbData The encrypted value retrieved from the database column.
   *
   * @return The decrypted plain text value, or {@code null} if the database 
   *         value is {@code null}.
   */
  @Override
  public String convertToEntityAttribute(String dbData)
  {
    return dbData == null ? null : CryptoHandler.getInstance().decrypt(dbData);
  }

}
