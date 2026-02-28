package de.l9g.crypto.vault.sample;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.info.BuildProperties;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
@Slf4j
public class Application
{

  public static void main(String[] args)
  {
    SpringApplication.run(Application.class, args);
  }

  @Bean
  public CommandLineRunner commandLineRunner(BuildProperties buildProperties)
  {
    return args ->
    {
      log.info("");
      log.info("");
      log.info("--- Application Info ----------------------------");
      log.info("Name: {}", buildProperties.getName());
      log.info("Version: {}", buildProperties.getVersion());
      log.info("Build: {}", buildProperties.getTime());
      log.info("-------------------------------------------------");
    };
  }

}
