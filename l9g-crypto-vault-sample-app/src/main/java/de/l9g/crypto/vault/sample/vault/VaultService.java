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
import com.fasterxml.jackson.databind.node.ObjectNode;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;

/**
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
@Slf4j
@Service
public class VaultService
{
  // In a production environment THIS MAKES NO SENSE!!!
  // It is for this development sample only.
  // the masterkey should not be stored in plain text on the server
  private static final String MASTERKEY_FILENAME = "data/vault-masterkey.json";

  //
  private static final String ADMINKEYS_FILENAME = "data/vault-adminkeys.json";

  private final List<VaultAdminKey> adminKeys = new ArrayList<>();

  @Getter
  private String secret;

  public VaultService()
  {
    ObjectMapper mapper = new ObjectMapper();
    File file = new File(MASTERKEY_FILENAME);
    Path path = file.toPath();

    try
    {
      if(file.exists())
      {
        this.secret = mapper.readTree(file).get("secret").asText();
        log.info("Masterkey successfully loaded from {}", MASTERKEY_FILENAME);
      }
      else
      {
        SecureRandom random = new SecureRandom();
        byte[] keyBytes = new byte[32];
        random.nextBytes(keyBytes);
        this.secret = Base64.getEncoder().encodeToString(keyBytes);

        File parentDir = file.getParentFile();
        if(parentDir != null &&  ! parentDir.exists())
        {
          parentDir.mkdirs();
        }

        ObjectNode root = mapper.createObjectNode();
        root.put("secret", this.secret);
        mapper.writerWithDefaultPrettyPrinter().writeValue(file, root);
        log.info("New masterkey generated and saved to {}", MASTERKEY_FILENAME);
      }

      // Unix Dateirechte auf '--r --- ---' (owner read-only) setzen
      try
      {
        Set<PosixFilePermission> perms = PosixFilePermissions.fromString("r--------");
        Files.setPosixFilePermissions(path, perms);
      }
      catch(UnsupportedOperationException e)
      {
        // Fallback, falls das Betriebssystem keine POSIX-Rechte unterstützt (z. B. Windows)
        file.setReadable(false, false);
        file.setWritable(false, false);
        file.setExecutable(false, false);
        file.setReadable(true, true);
      }

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

}
