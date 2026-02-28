/*
 * Copyright 2024 Thorsten Ludewig <t.ludewig@gmail.com>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
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
package de.l9g.crypto.vault.sample;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.servlet.ModelAndView;

/**
 * Global exception handler for the application.
 * This class provides centralized exception handling across all controllers,
 * rendering appropriate error pages based on the type of exception.
 * It uses Spring's @ControllerAdvice to intercept exceptions.
 *
 * @author Thorsten Ludewig <t.ludewig@gmail.com>
 */
@ControllerAdvice
@Slf4j
public class GlobalExceptionHandler
{

  /**
   * Handles bad request exceptions (HTTP 400).
   * This includes `HttpClientErrorException.BadRequest` and `MissingServletRequestParameterException`.
   * It logs the exception and returns a ModelAndView for the 400 error page.
   *
   * @param request The current HttpServletRequest.
   * @param ex The caught Exception.
   *
   * @return A ModelAndView for the 400 error page.
   */
  @ExceptionHandler(
    {
      org.springframework.web.client.HttpClientErrorException.BadRequest.class,
      org.springframework.web.bind.MissingServletRequestParameterException.class
    })
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ModelAndView handleBadRequestException(HttpServletRequest request,
    Exception ex)
  {
    log.debug("handleBadRequestException : {}", ex.getMessage());
    ModelAndView modelAndView = new ModelAndView("error/400");
    modelAndView.addObject("pageErrorRequestUri", request.getRequestURI());
    modelAndView.addObject("pageErrorException", ex.getMessage());
    return modelAndView;
  }

  /**
   * Handles "no resource found" exceptions (HTTP 404).
   * Specifically handles `NoResourceFoundException`.
   * It returns a ModelAndView for the 404 error page.
   *
   * @param request The current HttpServletRequest.
   * @param ex The caught Exception.
   *
   * @return A ModelAndView for the 404 error page.
   */
  @ExceptionHandler(
    org.springframework.web.servlet.resource.NoResourceFoundException.class)
  @ResponseStatus(HttpStatus.NOT_FOUND)
  public ModelAndView handleNotFoundException(HttpServletRequest request,
    Exception ex)
  {
    ModelAndView modelAndView = new ModelAndView("error/404");
    modelAndView.addObject("pageErrorRequestUri", request.getRequestURI());
    return modelAndView;
  }

  /**
   * Handles generic exceptions (HTTP 500).
   * This catches `Exception.class` and `TemplateInputException`.
   * It attempts to log out the user, logs the exception details, and returns a ModelAndView for the 500 error page.
   *
   * @param request The current HttpServletRequest.
   * @param ex The caught Exception.
   *
   * @return A ModelAndView for the 500 error page.
   */
  @ExceptionHandler(
    {
      Exception.class, org.thymeleaf.exceptions.TemplateInputException.class
    })
  @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
  public ModelAndView handleException(HttpServletRequest request, Exception ex)
  {
    log.debug("request={} exception={}", request, ex);

    try
    {
      log.debug("SESSION: logout!");
      request.logout();
    }
    catch(ServletException ex1)
    {
      log.warn("LOGOUT failed : {}", ex1.getMessage());
    }

    ModelAndView modelAndView = new ModelAndView("error/500");
    modelAndView.addObject("pageErrorRequestUri", request.getRequestURI());
    modelAndView.addObject("pageErrorException", ex.getMessage());
    modelAndView.addObject("pageErrorExceptionClassname", ex.getClass().
      getCanonicalName());

    StringBuilder stackTrace = new StringBuilder();
    for(StackTraceElement element : ex.getStackTrace())
    {
      stackTrace.append(element.toString());
      stackTrace.append('\n');
    }

    modelAndView.addObject("pageErrorStacktrace", stackTrace.toString());
    return modelAndView;
  }

  /**
   * Handles access denied exceptions (HTTP 403).
   * Specifically handles `AccessDeniedException`.
   * It logs the access denied event, invalidates the session, and returns a ModelAndView for the 403 error page.
   *
   * @param ex The caught AccessDeniedException.
   * @param request The current HttpServletRequest.
   *
   * @return A ModelAndView for the 403 error page.
   */
  @ExceptionHandler(AccessDeniedException.class)
  @ResponseStatus(HttpStatus.FORBIDDEN)
  public ModelAndView handleAccessDeniedException(AccessDeniedException ex, HttpServletRequest request)
  {
    log.error("Access denied: " + ex.getMessage());
    ModelAndView modelAndView = new ModelAndView("error/403");
    modelAndView.addObject("pageErrorRequestUri", request.getRequestURI());
    modelAndView.addObject("pageErrorException", ex.getMessage());
    request.getSession().invalidate();
    return modelAndView;
  }

}
