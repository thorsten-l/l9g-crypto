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
package de.l9g.crypto.tool;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.shell.command.annotation.CommandScan;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * This class is the main entry point for the L9G Crypto Tool application.
 * It is a Spring Boot application that provides command-line utilities
 * for encryption, decryption, and password generation.
 * It supports both interactive and non-interactive modes.
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
@SpringBootApplication
@CommandScan
public class Application
{
  private final static String PARAMETER_I = "-i";

  private final static String PARAMETER_INTERACTIVE = "--interactive";

  public static void main(String[] args)
  {
    List<String> argsList = new ArrayList<>(Arrays.asList(args));
    boolean interactiveModeRequested = false;

    if(argsList.contains(PARAMETER_I))
    {
      interactiveModeRequested = true;
      argsList.remove(PARAMETER_I);
    }
    if(argsList.contains(PARAMETER_INTERACTIVE))
    {
      interactiveModeRequested = true;
      argsList.remove(PARAMETER_INTERACTIVE);
    }

    SpringApplicationBuilder builder = new SpringApplicationBuilder(Application.class);

    if(interactiveModeRequested)
    {
      builder.run(new String[0]);
    }
    else if(argsList.isEmpty())
    {
      builder.run("help");
    }
    else
    {
      try
      {
        builder.run(argsList.toArray(new String[0]));
      }
      catch(Throwable t)
      {
        System.out.println(t.getMessage());
      }
    }
  }

}
