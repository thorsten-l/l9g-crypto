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
 * This converter uses {@link CryptoHandler} to encrypt values before persisting
 * them and decrypt them when loading from the database.
 *
 * @author Thorsten Ludewig t.ludewig@gmail.com
 */
@Converter
public class EncryptedAttributeConverter implements
  AttributeConverter<String, String>
{

  /**
   * Converts an entity attribute value to its encrypted form for storage in the
   * database column.
   *
   * @param attribute The value to be converted (encrypted).
   *
   * @return The encrypted value, or null if the input attribute is null.
   */
  @Override
  public String convertToDatabaseColumn(String attribute)
  {
    return attribute == null ? null : CryptoHandler.getInstance().encrypt(attribute);
  }

  /**
   * Converts a database column value to its decrypted form for use as an entity
   * attribute.
   *
   * @param dbData The value retrieved from the database column (encrypted).
   *
   * @return The decrypted value, or null if the database value is null.
   */
  @Override
  public String convertToEntityAttribute(String dbData)
  {
    return dbData == null ? null : CryptoHandler.getInstance().decrypt(dbData);
  }

}
