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
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
@Slf4j
@Service
public class VaultService
{
  private static final String ADMINKEYS_FILENAME = "data/vault-adminkeys.json";

  private final List<VaultAdminKey> adminKeys = new ArrayList<>();

  private final long masterkeyTTL;

  private SecretKey masterKey;

  private long masterKeyTimestamp;

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

  public synchronized void addVaultAdminKey(VaultAdminKey key)
  {
    adminKeys.add(key);
    saveAdminKeys();
  }

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

  public synchronized boolean adminKeysIsEmpty()
  {
    return adminKeys.isEmpty();
  }

  public long getUnlockTimeLeft()
  {
    long timeLeft = (masterkeyTTL + masterKeyTimestamp 
      - System.currentTimeMillis()) / 1000;
    return (timeLeft > 0 ) ? timeLeft : 0;
  }
  
  public synchronized SecretKey getUnlockedKey()
  {
    if(masterkeyTTL > 0
      && (System.currentTimeMillis() - masterKeyTimestamp) > masterkeyTTL)
    {
      masterKey = null;
    }
    return masterKey;
  }

  public synchronized void setUnlockedKey(SecretKey masterKey)
  {
    this.masterKey = masterKey;
    this.masterKeyTimestamp = System.currentTimeMillis();
  }

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
