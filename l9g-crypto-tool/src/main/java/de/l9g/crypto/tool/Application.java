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
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
@SpringBootApplication
@CommandScan
public class Application
{
  public static void main(String[] args)
  {
    List<String> argsList = new ArrayList<>(Arrays.asList(args));
    boolean interactiveModeRequested = false;

    if(argsList.contains("-i"))
    {
      interactiveModeRequested = true;
      argsList.remove("-i");
    }
    if(argsList.contains("--interactive"))
    {
      interactiveModeRequested = true;
      argsList.remove("--interactive");
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
