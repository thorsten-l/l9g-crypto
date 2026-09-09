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
package de.l9g.crypto.core;

/**
 * Unchecked exception thrown by the L9G crypto library for all failures
 * during key management, encryption and decryption.
 * <p>
 * The message and the cause chain of this exception carry all information
 * needed to diagnose the failure (file path, expected key length, underlying
 * JCE exception, ...). The library deliberately does <em>not</em> log an error
 * before throwing: in some environments (e.g. Spring Boot's
 * {@code EnvironmentPostProcessor} phase) logging is not yet initialized and
 * such log statements would be silently discarded. Callers are expected to
 * report this exception themselves.
 * <p>
 * This class extends {@link IllegalStateException} for backward compatibility
 * with code that catches the exception types thrown by earlier versions.
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
public class CryptoException extends IllegalStateException
{
  private static final long serialVersionUID = 1L;

  /**
   * Creates a new exception with the given message.
   *
   * @param message The detail message.
   */
  public CryptoException(String message)
  {
    super(message);
  }

  /**
   * Creates a new exception with the given message and cause.
   *
   * @param message The detail message.
   * @param cause The underlying cause.
   */
  public CryptoException(String message, Throwable cause)
  {
    super(message, cause);
  }

}
