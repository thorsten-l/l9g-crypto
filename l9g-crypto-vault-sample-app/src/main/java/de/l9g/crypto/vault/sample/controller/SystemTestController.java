/*
 * Copyright 2024 Thorsten Ludewig (t.ludewig@gmail.com).
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
package de.l9g.crypto.vault.sample.controller;


import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Controller for system testing endpoints.
 */
@Controller
@Slf4j
public class SystemTestController
{
  /**
   * Triggers an HTTP 403 Forbidden error for testing purposes.
   * This method throws an {@link AccessDeniedException} to simulate an access denied scenario.
   *
   * @return This method never returns normally due to the exception.
   *
   * @throws AccessDeniedException Always thrown to simulate a 403 error.
   */
  @GetMapping("/system/test/403")
  public String systemError403()
  {
    log.debug("systemError403");
    throw new AccessDeniedException("Access denied for testing purposes");
  }

  /**
   * Triggers an HTTP 500 Internal Server Error for testing purposes.
   * This method deliberately causes a division-by-zero error to simulate an unhandled exception.
   *
   * @return This method never returns normally due to the exception.
   */
  @GetMapping("/system/test/500")
  public String systemError500()
  {
    log.debug("systemError500");
    int i = 1 / 0; // division by zero
    System.out.println(i);
    return "home";
  }

  /**
   * Triggers an HTTP 400 Bad Request error by expecting a missing request parameter.
   * This method will throw a {@link org.springframework.web.bind.MissingServletRequestParameterException}
   * if the "no_params" parameter is not provided, simulating a bad request.
   *
   * @param p A placeholder parameter that is expected to be missing to trigger the error.
   *
   * @return This method never returns normally due to the exception.
   */
  @GetMapping("/system/test/400")
  public String badRequest400(@RequestParam("no_params") String p)
  {
    log.debug("badRequest400");
    return "home";
  }

  /**
   * Triggers an HTTP 400 Bad Request error.
   * This method simulates a bad request scenario.
   *
   * @return The "home" view.
   */
  @GetMapping("/system/test/400-2")
  public String badRequest400()
  {
    log.debug("badRequest400-2");
    return "home";
  }

}
