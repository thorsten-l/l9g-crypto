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

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;

/**
 * Service for managing the application's Vault and its associated administrator keys.
 * <p>
 * This service handles the persistence of administrator keys (WebAuthn credentials) 
 * and manages the lifecycle of the volatile master key. The master key is stored 
 * only in memory and is subject to a Time-To-Live (TTL).
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
@Slf4j
@Service
public class VaultService
{
  /**
   * Filename for persisting administrator keys.
   */
  private static final String ADMINKEYS_FILENAME = "data/vault-adminkeys.json";

  /**
   * In-memory list of registered administrator keys.
   */
  private final List<VaultAdminKey> adminKeys = new ArrayList<>();

  /**
   * Time-To-Live for the master key in milliseconds.
   */
  private final long masterkeyTTL;

  /**
   * The volatile master key, stored only in RAM.
   */
  private SecretKey masterKey;

  /**
   * Timestamp when the master key was last set/unlocked.
   */
  private long masterKeyTimestamp;

  /**
   * Constructs the VaultService and loads existing administrator keys from disk.
   *
   * @param masterkeyTTL The TTL for the master key in milliseconds.
   */
  public VaultService(@Value("${app.vault.masterkey-ttl}") long masterkeyTTL)
  {
    this.masterkeyTTL = masterkeyTTL;
    log.debug("masterKeyTTL={}", masterkeyTTL);
    ObjectMapper mapper = new ObjectMapper();

    try
    {
      File adminKeysFile = new File(ADMINKEYS_FILENAME);
      if(adminKeysFile.exists())
      {
        List<VaultAdminKey> loadedKeys = mapper.readValue(adminKeysFile,
          mapper.getTypeFactory().constructCollectionType(List.class, VaultAdminKey.class));
        this.adminKeys.addAll(loadedKeys);
        log.info("{} admin keys loaded from {}", adminKeys.size(), ADMINKEYS_FILENAME);
      }
    }
    catch(IOException e)
    {
      log.error("Failed to initialize VaultService", e);
      throw new RuntimeException("Could not read or create masterkey file or admin keys file", e);
    }
  }

  /**
   * Adds a new administrator key and persists it to disk.
   *
   * @param key The administrator key to add.
   */
  public synchronized void addVaultAdminKey(VaultAdminKey key)
  {
    adminKeys.add(key);
    saveAdminKeys();
  }

  /**
   * Finds administrator keys associated with a specific admin ID.
   *
   * @param adminId The admin ID (e.g., username or email).
   * @return A list of matching administrator keys.
   */
  public synchronized List<VaultAdminKey> findVaultAdminKeysByAdminId(String adminId)
  {
    final List<VaultAdminKey> resultList = new ArrayList<>();
    adminKeys.forEach(key ->
    {
      if(key.adminId().equalsIgnoreCase(adminId))
      {
        resultList.add(key);
      }
    });
    return resultList;
  }

  /**
   * Returns a list of all registered administrator keys (without sensitive payload).
   *
   * @return A list of all administrator keys.
   */
  public synchronized List<VaultAdminKey> findAllVaultAdminKeys()
  {
    final List<VaultAdminKey> resultList = new ArrayList<>();
    adminKeys.forEach(key ->
    {
      resultList.add(new VaultAdminKey(
        key.adminId(),
        key.fullName(),
        key.description(),
        key.credentialId()
      ));
    });
    return resultList;
  }

  /**
   * Checks if any administrator keys are registered.
   *
   * @return {@code true} if no keys exist, {@code false} otherwise.
   */
  public synchronized boolean adminKeysIsEmpty()
  {
    return adminKeys.isEmpty();
  }

  /**
   * Calculates the remaining time until the master key expires.
   *
   * @return Remaining time in seconds.
   */
  public long getUnlockTimeLeft()
  {
    long timeLeft = (masterkeyTTL + masterKeyTimestamp 
      - System.currentTimeMillis()) / 1000;
    return (timeLeft > 0 ) ? timeLeft : 0;
  }
  
  /**
   * Retrieves the master key if it is currently unlocked and not expired.
   *
   * @return The {@link SecretKey}, or {@code null} if sealed or expired.
   */
  public synchronized SecretKey getUnlockedKey()
  {
    if(masterkeyTTL > 0
      && (System.currentTimeMillis() - masterKeyTimestamp) > masterkeyTTL)
    {
      masterKey = null;
    }
    return masterKey;
  }

  /**
   * Sets the master key and resets the expiration timer.
   *
   * @param masterKey The master key to unlock.
   */
  public synchronized void setUnlockedKey(SecretKey masterKey)
  {
    this.masterKey = masterKey;
    this.masterKeyTimestamp = System.currentTimeMillis();
  }

  /**
   * Removes an administrator key by its WebAuthn credential ID.
   *
   * @param credentialId The credential ID to remove.
   */
  public synchronized void removeVaultAdminKeyByCredentialId(String credentialId)
  {
    if(adminKeys.removeIf(key -> key.credentialId().equals(credentialId)))
    {
      log.info("VaultAdminKey with credentialId {} removed.", credentialId);
      saveAdminKeys();
    }
    else
    {
      log.warn("VaultAdminKey with credentialId {} not found for removal.", credentialId);
    }
  }

  /**
   * Persists the current list of administrator keys to the JSON file.
   */
  private synchronized void saveAdminKeys()
  {
    ObjectMapper mapper = new ObjectMapper();
    try
    {
      mapper.writerWithDefaultPrettyPrinter().writeValue(new File(ADMINKEYS_FILENAME), adminKeys);
      log.info("VaultAdminKey added and saved to {}", ADMINKEYS_FILENAME);
    }
    catch(IOException e)
    {
      log.error("Failed to save admin keys", e);
    }
  }

}
