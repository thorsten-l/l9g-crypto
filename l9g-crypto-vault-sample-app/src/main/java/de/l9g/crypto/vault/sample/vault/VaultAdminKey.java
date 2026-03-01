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
package de.l9g.crypto.vault.sample.vault;

/**
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
public record VaultAdminKey(
  String adminId, // z.B. die E-Mail aus dem Keycloak OIDC Token
  String fullName, // z.B. die E-Mail aus dem Keycloak OIDC Token
  String description,
  String credentialId, // Base64
  String prfSalt, // Base64 (wird ans Frontend für den WebAuthn Aufruf geschickt)
  String encryptedMasterKey // Base64 (wird im Backend nach dem WebAuthn Aufruf entschlüsselt)
  )
  {

  public VaultAdminKey(
    String adminId,
    String fullName,
    String description,
    String credentialId)
  {
    this(adminId, fullName, description, credentialId, null, null);
  }

}
