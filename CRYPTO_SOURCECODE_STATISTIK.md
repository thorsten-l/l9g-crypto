# Quellcode-Statistik — l9g-crypto

Stand: 2026-09-19 · Version 1.0.7 (unveröffentlicht) · HEAD `fa20cda` (Release 1.0.6, 2026-09-09) · 34 Commits (seit 2026-02-05)

Erhoben mit [cloc](https://github.com/AlDanial/cloc) v2.10 über die
`src`-Verzeichnisse der fünf Module (git-getrackte und neue, nicht ignorierte
Dateien, ohne `target/`); die Tests unter `src/test/` sind separat ausgewiesen.
„Code" = Zeilen ohne Leerzeilen und Kommentare. Der Arbeitsbaum enthält die noch
nicht committeten Änderungen für 1.0.7 (Classpath-Schlüssel, `secret.path`,
zusätzliche Tests); sie sind in den Zahlen enthalten.

Zwei Besonderheiten vorweg:

- `l9g-crypto` ist ein **Aggregator mit fünf Modulen**. Das Top-Level-`src/`
  enthält **keine getrackten Dateien** und trägt nichts bei.
- Vier der fünf Module sind Bibliothek, das fünfte
  (`l9g-crypto-vault-sample-app`) ist eine **Beispielanwendung**. Sie stellt
  73 % des Codes. Wer die Größe der Bibliothek beurteilen will, muss sie
  herausrechnen.

## Überblick (cloc, `src` aller Module)

| Sprache | Dateien | Leerzeilen | Kommentare | Code |
|---|---:|---:|---:|---:|
| Java | 40 | 440 | 1.945 | 2.615 |
| HTML (Thymeleaf) | 13 | 152 | 158 | 1.127 |
| SVG (Flaggen-Icons) | 9 | 0 | 2 | 640 |
| Properties (i18n) | 3 | 0 | 39 | 456 |
| YAML | 2 | 9 | 0 | 70 |
| CSS | 2 | 12 | 16 | 31 |
| XML | 1 | 3 | 4 | 7 |
| **Summe** | **70** | **616** | **2.164** | **4.946** |

Nicht mitgezählt, weil binär oder ohne cloc-Sprache: zwei Test-Schlüsseldateien
(`test-secret.bin`, `test-secret-short.bin`), `META-INF/spring.factories` und
statische Assets ohne Quelltextcharakter.

## Bibliothek gegen Beispielanwendung

| Modul | Dateien | Leerzeilen | Kommentare | Code | Rolle |
|---|---:|---:|---:|---:|---|
| `l9g-crypto-core` | 10 | 179 | 702 | 957 | AES-256, Schlüsselverwaltung, Passwortgenerator (inkl. 4 Testklassen) |
| `l9g-crypto-spring` | 5 | 38 | 140 | 205 | `EnvironmentPostProcessor`, `FailureAnalyzer` (inkl. 2 Testklassen) |
| `l9g-crypto-tool` | 3 | 26 | 114 | 155 | Spring-Shell-Kommandozeilenwerkzeug (+ `application.yaml`) |
| `l9g-crypto-jpa` | 2 | 6 | 71 | 20 | JPA-`AttributeConverter` für Feldverschlüsselung |
| **Bibliothek gesamt** | **20** | **249** | **1.027** | **1.337** | |
| `l9g-crypto-vault-sample-app` | 50 | 367 | 1.137 | 3.609 | Beispiel-Webanwendung (Vault) |
| **Summe** | **70** | **616** | **2.164** | **4.946** | |

Die eigentliche Bibliothek umfasst **1.337 Codezeilen in 20 Dateien** — davon
790 Zeilen Java-Produktivcode in 13 Dateien und 512 Zeilen Testcode in 6
Dateien. Die Beispielanwendung ist mit 3.609 Zeilen unverändert und knapp
dreimal so groß wie die Bibliothek. In der aggregierten Statistik erscheint
`l9g-crypto` mit 4.946 Zeilen; als Bibliotheksgröße wäre diese Zahl um den
Faktor drei bis vier zu hoch gegriffen.

Gegenüber der Erhebung vom 2026-08-28 (Version 1.0.5) ist die Bibliothek um
478 Codezeilen gewachsen, die Beispielanwendung gar nicht. Der Zuwachs verteilt
sich auf `core` (+302, davon 180 Test), `spring` (+152, davon 94 Test) und
`tool` (+24).

### Die Bibliothek im Einzelnen

| Modul | Klassen |
|---|---|
| `l9g-crypto-core` | `AES256`, `AppSecretKey`, `CryptoException`, `CryptoHandler`, `PasswordGenerator` (+ `package-info`) |
| `l9g-crypto-spring` | `EncryptedPropertiesEnvironmentPostProcessor`, `CryptoFailureAnalyzer` (+ `package-info`) |
| `l9g-crypto-jpa` | `EncryptedAttributeConverter` (+ `package-info`) |
| `l9g-crypto-tool` | `Application`, `Commands` |

Dreizehn Java-Produktivdateien, davon drei `package-info.java`. `l9g-crypto-jpa`
ist mit 20 Codezeilen gegen 71 Kommentarzeilen weiterhin das extremste
Verhältnis der Erhebung — eine einzige `AttributeConverter`-Implementierung,
die die Kernbibliothek in JPA einhängt. `l9g-crypto-spring` ist von 53 auf 111
Produktivzeilen gewachsen: der Post-Processor loggt jetzt über Spring Boots
`DeferredLogFactory`, benennt bei Fehlern Property und Property-Source, und der
neue `CryptoFailureAnalyzer` rendert `CryptoException` im
„APPLICATION FAILED TO START"-Report. Beide Module bleiben reine
Integrationsschichten; die Substanz liegt in `core`.

## Java im Detail

Von 4.269 Java-Gesamtzeilen in `src/main` sind 2.103 Code (49 %), 1.818
Kommentare (43 %) und 348 Leerzeilen (8 %). Alle 34 Dateien tragen den
15-zeiligen Apache-2.0-Header (510 Zeilen), 26 tragen ein `@author`-Tag, das
Projekt zählt 181 Javadoc-Blöcke.

### Typen und Endpoints

| Merkmal | Anzahl |
|---|---:|
| Java-Dateien `src/main` (davon 3 `package-info.java`) | 34 |
| Klassen (27 oberste Ebene, 0 innere) | 27 |
| Records (4 oberste Ebene, 1 innerer) | 5 |
| Enums / Interfaces | 0 / 0 |
| HTTP-Endpoints `@GetMapping` / `@PostMapping` / übrige | 14 / 2 / 5 |
| Controller-Klassen | 9 |
| Dateien mit Lombok-Annotationen | 22 |
| Maven-Dependencies (6 POMs, direkte Einträge) | 33 |

Die beiden inneren `Holder`-Klassen der Vorerhebung sind verschwunden:
`AppSecretKey` und `CryptoHandler` initialisieren ihr Singleton seit 1.0.6 mit
explizitem Double-Checked-Locking, damit ein fehlgeschlagener Start die echte
`CryptoException` wirft statt eines `NoClassDefFoundError`.

**Sämtliche 21 Endpoints und alle 9 Controller liegen in der
Beispielanwendung.** Die vier Bibliotheksmodule enthalten keinen einzigen
HTTP-Endpunkt — was für eine Verschlüsselungsbibliothek auch so sein soll, in
der aggregierten Statistik aber leicht den falschen Eindruck erweckt.

### Zeilen pro Package (`src/main`, ohne Unterpackages)

| Package | Dateien | Code | Kommentare |
|---|---:|---:|---:|
| `de.l9g.crypto.core` | 6 | 539 | 605 |
| `de.l9g.crypto.vault.sample.config` | 5 | 319 | 241 |
| `de.l9g.crypto.vault.sample.controller` | 6 | 315 | 231 |
| `de.l9g.crypto.vault.sample.vault` | 3 | 216 | 126 |
| `de.l9g.crypto.vault.sample.service` | 3 | 196 | 135 |
| `de.l9g.crypto.vault.sample.vault.api` | 2 | 155 | 87 |
| `de.l9g.crypto.tool` | 2 | 120 | 114 |
| `de.l9g.crypto.vault.sample` (Root) | 2 | 112 | 98 |
| `de.l9g.crypto.spring` | 3 | 111 | 110 |
| `de.l9g.crypto.jpa` | 2 | 20 | 71 |
| **Summe** | **34** | **2.103** | **1.818** |

### Die größten Dateien (nach Code-Zeilen)

| Datei | Sprache | Code | Kommentare |
|---|---|---:|---:|
| `…vault-sample-app/…/static/flags/4x3/es.svg` | SVG | 544 | 0 |
| `…vault-sample-app/…/templates/app.html` | HTML | 266 | 2 |
| `…vault-sample-app/…/templates/admin/enrollment.html` | HTML | 235 | 13 |
| `l9g-crypto-core/…/core/AppSecretKey.java` | Java | 221 | 201 |
| `l9g-crypto-core/…/core/AppSecretKeyTest.java` (Test) | Java | 190 | 39 |
| `l9g-crypto-core/…/core/AES256.java` | Java | 188 | 154 |
| `…vault-sample-app/…/config/ClientSecurityConfig.java` | Java | 181 | 66 |
| `…vault-sample-app/…/templates/admin/unseal.html` | HTML | 167 | 16 |
| `…vault-sample-app/…/service/JwtService.java` | Java | 155 | 96 |
| `…vault-sample-app/…/vault/api/VaultApiController.java` | Java | 153 | 68 |
| `…vault-sample-app/src/main/resources/messages*.properties` (3×) | Properties | je 152 | je 13 |
| `…vault-sample-app/…/vault/VaultService.java` | Java | 122 | 88 |

Die größte Datei des Projekts ist eine **Flagge**: `es.svg` mit 544 Zeilen. Die
neun Flaggen-SVGs der Sprachumschaltung stellen zusammen 640 Codezeilen — 13 %
des Gesamtprojekts und knapp die Hälfte der Bibliothek. Sie sind grafische
Assets, keine Programmlogik, und bei jeder Aufwandsbetrachtung abzuziehen.

Die größte Java-Datei der Bibliothek ist jetzt `AppSecretKey.java` mit 221
Codezeilen (vorher 120): Auflösung der Schlüsselquelle über Umgebungsvariable,
System-Property und `classpath:`-Präfix, Laden aus Datei oder Classpath,
Erzeugen mit POSIX-Rechten, `System.err`-Fallback. Sie und `AES256.java` (188)
machen zusammen drei Viertel des `core`-Produktivcodes aus.

## Frontend (nur Beispielanwendung)

| Bereich | Umfang |
|---|---|
| Thymeleaf-Templates | 13 Dateien, 1.127 Codezeilen |
| CSS | 2 Dateien, 31 Zeilen |
| SVG (Flaggen) | 9 Dateien, 640 Zeilen |
| i18n | `messages.properties`, `messages_de.properties`, `messages_en.properties` (je 152 Zeilen) |
| Fremdbibliotheken | Bootstrap 5.3.8, Font Awesome 7.3.0 über WebJars — nicht mitgezählt |

Kein eigenes JavaScript: die Beispielanwendung rendert serverseitig und kommt
mit Bootstrap aus. Am Frontend hat sich seit der Vorerhebung nichts geändert.

## Tests

43 automatisierte Tests in 6 Klassen (512 Java-Code-Zeilen), alle grün
(Surefire-Lauf vom 2026-09-19, JUnit 6.1.3):

| Testklasse | Modul | Tests | Prüft |
|---|---|---:|---|
| `AppSecretKeyTest` | core | 13 | Laden/Erzeugen aus Datei, Classpath-Ressource, Vorrang Env vor Property, Fehlerfälle samt `System.err`-Zeile |
| `AES256Test` | core | 10 | Ver-/Entschlüsselung, Schlüssellängen, manipulierter Tag, falscher Schlüssel |
| `PasswordGeneratorTest` | core | 8 | Zeichenvorrat, Länge, Zufallsverteilung (parametrisiert) |
| `CryptoHandlerTest` | core | 7 | Handler-Fassade, Präfix, ungültiges Base64, zu kurze Payload |
| `EncryptedPropertiesEnvironmentPostProcessorTest` | spring | 3 | Entschlüsselung in Property-Source, Lazy-Zugriff auf den Schlüssel, Fehlermeldung ohne Wert |
| `CryptoFailureAnalyzerTest` | spring | 2 | Ursachenkette und Handlungsempfehlung im Report |

Die Verteilung hat sich gegenüber der Vorerhebung (25 Tests, nur `core`)
verschoben: **`l9g-crypto-spring` ist jetzt getestet**, und zwar genau an der
Stelle, die vorher als Schwachpunkt benannt war — ob der Post-Processor
verschlüsselte Properties findet, entschlüsselt und bei Fehlern die richtige
Diagnose liefert. Testzeilen gegen Produktivzeilen: `core` 418 zu 539
(**78 %**, vorher 57 %), `spring` 94 zu 111 (**85 %**).

Ungetestet bleiben `l9g-crypto-jpa` und `l9g-crypto-tool` sowie die
Beispielanwendung. Für `jpa` wiegt das am schwersten: `EncryptedAttributeConverter`
entscheidet darüber, **ob** ein Feld verschlüsselt in die Datenbank geschrieben
wird. Ein stillschweigend nicht greifender Converter schreibt Klartext, ohne
dass ein `AES256Test` das je bemerken würde. Der Converter hat 20 Codezeilen;
ein Test dafür wäre der günstigste Sicherheitsgewinn im Projekt.

Über das gesamte Projekt gerechnet liegt der Testanteil bei 12 % (512 Testzeilen
gegen 4.434 Zeilen `src/main`, vorher 5 %) — die große, ungetestete
Beispielanwendung drückt ihn weiterhin.

## Abhängigkeiten (6 POMs, 33 direkte Einträge)

Java 17 (`maven.compiler.release`), eigener Parent (`crypto-parent`), Spring
Boot 3.5.16, Spring Framework 6.2.19, SLF4J 2.0.18, JUnit 6.1.3, Spring Shell
3.4.3. JUnit wird seit 1.0.6 zentral im `dependencyManagement` des Parents
verwaltet.

**`l9g-crypto-core` (4):** `lombok`, `slf4j-api`, dazu `junit-jupiter` und
`slf4j-simple` (test). Die Kernbibliothek kommt ohne Krypto-Fremdbibliothek
aus — sie nutzt die JCE des JDK.

**`l9g-crypto-spring` (9):** `crypto-core`, `spring-context`, `spring-boot`,
`spring-boot-autoconfigure`, `lombok`, `slf4j-api`, dazu `junit-jupiter`,
`spring-test` und `slf4j-simple` (test).

**`l9g-crypto-jpa` (2):** `crypto-core`, `jakarta.persistence-api`.

**`l9g-crypto-tool` (7):** `crypto-core`, `spring-context`, `spring-boot`,
`spring-boot-autoconfigure`, `lombok`, `slf4j-api`, `spring-shell-starter`.
Importiert die Spring-Boot-BOM vor der Spring-Shell-BOM, damit alle
Boot-Artefakte dieselbe Version tragen.

**`l9g-crypto-vault-sample-app` (11):** Spring-Boot-Starter `web`, `security`,
`oauth2-client`, `thymeleaf`, dazu `thymeleaf-extras-springsecurity6`,
`lombok`, die WebJars `bootstrap`, `font-awesome`, `webjars-locator-core` sowie
`crypto-core` und `crypto-spring`.

Der Schnitt ist sauber: `core` hängt an nichts außer Lombok und SLF4J, die
Integrationsmodule ziehen jeweils nur ihr Zielframework nach.

## Verwendung im Projektumfeld

`l9g-crypto` ist die einzige der sieben in der August-Erhebung vermessenen
Codebasen, die von anderen Projekten als **Abhängigkeit** eingebunden wird:

| Projekt | eingebundene Module |
|---|---|
| `l9g-accountinfo` | `crypto-core`, `crypto-spring`, `crypto-jpa` |
| `sonia-webapp-janus` | `crypto-core`, `crypto-spring` |

Die 790 Zeilen Bibliotheks-Produktivcode wirken damit über ihr eigenes
Repository hinaus. Nach vier Monaten Stillstand (Mai bis September) hat das
Projekt mit 1.0.6 und dem laufenden 1.0.7 wieder Bewegung: Fehlerdiagnose,
Tests für das Spring-Modul, Schlüssel aus dem Classpath.

## Hinweise zur Interpretation

- Die Typen- und Endpoint-Zahlen sind `grep`-Heuristiken über `src/main`, kein
  Parser: innere Typen zählen mit, auskommentierter Code ebenfalls. Die
  Testzahlen stammen aus Surefire und liegen über der Zahl der
  `@Test`-Annotationen (38), weil parametrisierte Tests mehrfach ausgeführt
  werden.
- Bibliothek und Beispielanwendung sind bei jeder Aussage zu trennen; die
  aggregierte Statistik weist nur die Summe aus.
- Die 640 SVG- und 456 Properties-Zeilen sind Assets bzw. Übersetzungen, keine
  Programmlogik. Zieht man sie und die Beispielanwendung ab, bleiben 790 Zeilen
  Java-Produktivcode — das ist die reale Größe von `l9g-crypto`.

---

*Erhebung: `git ls-files -co --exclude-standard | grep -E '(^|/)src/' | cloc --list-file=-`,
Modulzahlen über dieselbe Liste je Modulpräfix, Paketzahlen über `cloc` je
Verzeichnis (nicht rekursiv), größte Dateien über `cloc --by-file`, Typen und
Endpoints per `grep`, Testzahlen aus `*/target/surefire-reports/` nach
`mvn clean install`.*
