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
 * Main entry point for the L9G Crypto Tool.
 * <p>
 * This application is built on Spring Boot and Spring Shell to provide a 
 * convenient CLI interface for cryptographic operations. It supports two 
 * distinct operating modes:
 * <p>
 * 1. Interactive Mode: Activated by the {@code -i} or {@code --interactive} 
 *    parameters, providing a persistent shell environment.
 * <p>
 * 2. Non-Interactive Mode: Directly executes a single command passed via 
 *    command-line arguments.
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
@SpringBootApplication
@CommandScan
public class Application
{
  /**
   * Short parameter for interactive mode.
   */
  private final static String PARAMETER_I = "-i";

  /**
   * Long parameter for interactive mode.
   */
  private final static String PARAMETER_INTERACTIVE = "--interactive";

  /**
   * Default command to show help if no arguments are provided.
   */
  private final static String HELP = "help";

  /**
   * Main method to launch the Spring Boot application.
   * <p>
   * This method parses the initial arguments to determine the execution mode 
   * and configures the {@link SpringApplicationBuilder} accordingly.
   *
   * @param args Command-line arguments.
   */
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
      builder.run(HELP);
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
