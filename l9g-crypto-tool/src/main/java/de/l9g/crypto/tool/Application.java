/*
 * Copyright 2025 Thorsten Ludewig (t.ludewig@gmail.com).
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
 * Entry point of the L9G crypto command line tool.
 * <p>
 * Root logging is switched off in {@code application.yaml} to keep the CLI
 * output clean. Consequently Spring Boot's own failure report is invisible,
 * so any startup or command failure is reported here by printing the complete
 * cause chain to {@link System#err} and exiting with status 1.
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

    try
    {
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
        builder.run(argsList.toArray(new String[0]));
      }
    }
    catch(Throwable t)
    {
      printCauseChain(t);
      System.exit(1);
    }
  }

  /**
   * Prints the given throwable and all of its causes to {@link System#err},
   * root cause first, so that the actual reason (e.g. a missing or invalid
   * secret key file) is the first thing the user reads.
   *
   * @param t The throwable to report.
   */
  static void printCauseChain(Throwable t)
  {
    List<Throwable> chain = new ArrayList<>();
    for(Throwable c = t; c != null && ! chain.contains(c); c = c.getCause())
    {
      chain.add(c);
    }

    Throwable root = chain.get(chain.size() - 1);
    System.err.println("Error: " + describe(root));

    if(chain.size() > 1)
    {
      System.err.println("Context:");
      for(int i = chain.size() - 2; i >= 0; i--)
      {
        System.err.println("  " + describe(chain.get(i)));
      }
    }
  }

  private static String describe(Throwable t)
  {
    String message = t.getMessage();
    return t.getClass().getSimpleName() + (message != null ? ": " + message : "");
  }

}
