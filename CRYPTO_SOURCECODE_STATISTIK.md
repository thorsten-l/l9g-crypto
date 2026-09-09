# Quellcode-Statistik — l9g-crypto

Stand: 2026-08-28 · Version 1.0.5 · `fb08edb` (2026-05-04) · 33 Commits (seit 2026-02-05)

Erhoben mit [cloc](https://github.com/AlDanial/cloc) v2.10 über die
`src`-Verzeichnisse der fünf Module (git-getrackte Dateien, ohne `target/`);
die Tests unter `src/test/` sind separat ausgewiesen. „Code" = Zeilen ohne
Leerzeilen und Kommentare. Arbeitsbaum sauber.

Zwei Besonderheiten vorweg:

- `l9g-crypto` ist ein **Aggregator mit fünf Modulen**. Das Top-Level-`src/`
  enthält **keine getrackten Dateien** und trägt nichts bei.
- Vier der fünf Module sind Bibliothek, das fünfte
  (`l9g-crypto-vault-sample-app`) ist eine **Beispielanwendung**. Sie stellt
  81 % des Codes. Wer die Größe der Bibliothek beurteilen will, muss sie
  herausrechnen.

## Überblick (cloc, `src` aller Module)

| Sprache | Dateien | Leerzeilen | Kommentare | Code |
|---|---:|---:|---:|---:|
| Java | 36 | 367 | 1.693 | 2.137 |
| HTML (Thymeleaf) | 13 | 152 | 158 | 1.127 |
| SVG (Flaggen-Icons) | 9 | 0 | 2 | 640 |
| Properties (i18n) | 3 | 0 | 39 | 456 |
| YAML | 2 | 9 | 0 | 70 |
| CSS | 2 | 12 | 16 | 31 |
| XML | 1 | 3 | 4 | 7 |
| **Summe** | **66** | **543** | **1.912** | **4.468** |

## Bibliothek gegen Beispielanwendung

| Modul | Dateien | Leerzeilen | Kommentare | Code | Rolle |
|---|---:|---:|---:|---:|---|
| `l9g-crypto-core` | 9 | 140 | 530 | 655 | AES-256, Schlüsselableitung, Passwortgenerator |
| `l9g-crypto-tool` | 3 | 22 | 112 | 131 | Spring-Shell-Kommandozeilenwerkzeug |
| `l9g-crypto-spring` | 2 | 8 | 62 | 53 | `EnvironmentPostProcessor` für verschlüsselte Properties |
| `l9g-crypto-jpa` | 2 | 6 | 71 | 20 | JPA-`AttributeConverter` für Feldverschlüsselung |
| **Bibliothek gesamt** | **16** | **176** | **775** | **859** | |
| `l9g-crypto-vault-sample-app` | 50 | 367 | 1.137 | 3.609 | Beispiel-Webanwendung (Vault) |
| **Summe** | **66** | **543** | **1.912** | **4.468** | |

Die eigentliche Bibliothek umfasst **859 Codezeilen in 16 Dateien** — davon 586
Zeilen Java-Produktivcode in 11 Dateien. Die Beispielanwendung ist mit 3.609
Zeilen mehr als viermal so groß. In der aggregierten Statistik erscheint
`l9g-crypto` deshalb mit 4.468 Zeilen; als Bibliotheksgröße wäre diese Zahl um
den Faktor fünf zu hoch gegriffen.

### Die Bibliothek im Einzelnen

| Modul | Klassen |
|---|---|
| `l9g-crypto-core` | `AES256`, `AppSecretKey`, `CryptoHandler`, `PasswordGenerator` (+ `package-info`) |
| `l9g-crypto-spring` | `EncryptedPropertiesEnvironmentPostProcessor` (+ `package-info`) |
| `l9g-crypto-jpa` | `EncryptedAttributeConverter` (+ `package-info`) |
| `l9g-crypto-tool` | `Application`, `Commands` |

Elf Java-Dateien, davon drei `package-info.java`. `l9g-crypto-jpa` ist mit 20
Codezeilen gegen 71 Kommentarzeilen das extremste Verhältnis der gesamten
Erhebung — eine einzige `AttributeConverter`-Implementierung, die die
Kernbibliothek in JPA einhängt. `l9g-crypto-spring` (53 Zeilen) tut dasselbe für
Spring-Properties. Beide sind reine Integrationsschichten; die Substanz liegt in
`core`.

## Java im Detail

Von 3.829 Java-Gesamtzeilen in `src/main` sind 1.899 Code (50 %), 1.610
Kommentare (42 %) und 320 Leerzeilen (8 %). Alle 32 Dateien tragen den
15-zeiligen Apache-2.0-Header (480 Zeilen), 24 tragen ein `@author`-Tag, das
Projekt zählt 166 Javadoc-Blöcke.

### Typen und Endpoints

| Merkmal | Anzahl |
|---|---:|
| Java-Dateien `src/main` (davon 3 `package-info.java`) | 32 |
| Klassen (25 oberste Ebene, 2 innere) | 27 |
| Records (4 oberste Ebene, 1 innerer) | 5 |
| Enums / Interfaces | 0 / 0 |
| HTTP-Endpoints `@GetMapping` / `@PostMapping` / übrige | 14 / 2 / 5 |
| Controller-Klassen | 9 |
| Dateien mit Lombok-Annotationen | 22 |
| Maven-Dependencies (6 POMs) | 30 |

**Sämtliche 21 Endpoints und alle 9 Controller liegen in der
Beispielanwendung.** Die vier Bibliotheksmodule enthalten keinen einzigen
HTTP-Endpunkt — was für eine Verschlüsselungsbibliothek auch so sein soll, in
der aggregierten Statistik aber leicht den falschen Eindruck erweckt.

### Zeilen pro Package (`src/main`, ohne Unterpackages)

| Package | Dateien | Code | Kommentare |
|---|---:|---:|---:|
| `de.l9g.crypto.core` | 5 | 417 | 447 |
| `de.l9g.crypto.vault.sample.config` | 5 | 319 | 241 |
| `de.l9g.crypto.vault.sample.controller` | 6 | 315 | 231 |
| `de.l9g.crypto.vault.sample.vault` | 3 | 216 | 126 |
| `de.l9g.crypto.vault.sample.service` | 3 | 196 | 135 |
| `de.l9g.crypto.vault.sample.vault.api` | 2 | 155 | 87 |
| `de.l9g.crypto.vault.sample` (Root) | 2 | 112 | 98 |
| `de.l9g.crypto.tool` | 2 | 96 | 112 |
| `de.l9g.crypto.spring` | 2 | 53 | 62 |
| `de.l9g.crypto.jpa` | 2 | 20 | 71 |
| **Summe** | **32** | **1.899** | **1.610** |

### Die größten Dateien (nach Code-Zeilen)

| Datei | Sprache | Code | Kommentare |
|---|---|---:|---:|
| `…vault-sample-app/…/static/flags/4x3/es.svg` | SVG | 544 | 0 |
| `…vault-sample-app/…/templates/app.html` | HTML | 266 | 2 |
| `…vault-sample-app/…/templates/admin/enrollment.html` | HTML | 235 | 13 |
| `l9g-crypto-core/…/core/AES256.java` | Java | 197 | 147 |
| `…vault-sample-app/…/config/ClientSecurityConfig.java` | Java | 181 | 66 |
| `…vault-sample-app/…/templates/admin/unseal.html` | HTML | 167 | 16 |
| `…vault-sample-app/…/service/JwtService.java` | Java | 155 | 96 |
| `…vault-sample-app/…/vault/api/VaultApiController.java` | Java | 153 | 68 |
| `…vault-sample-app/src/main/resources/messages*.properties` (3×) | Properties | je 152 | je 13 |
| `…vault-sample-app/…/vault/VaultService.java` | Java | 122 | 88 |
| `l9g-crypto-core/…/core/AppSecretKey.java` | Java | 120 | 99 |

Die größte Datei des Projekts ist eine **Flagge**: `es.svg` mit 544 Zeilen. Die
neun Flaggen-SVGs der Sprachumschaltung stellen zusammen 640 Codezeilen — 14 %
des Gesamtprojekts und mehr als die halbe Bibliothek. Sie sind grafische
Assets, keine Programmlogik, und bei jeder Aufwandsbetrachtung abzuziehen.

Die größte Java-Datei der Bibliothek ist `AES256.java` mit 197 Codezeilen; sie
und `AppSecretKey.java` (120) machen zusammen mehr als die Hälfte des
`core`-Moduls aus.

## Frontend (nur Beispielanwendung)

| Bereich | Umfang |
|---|---|
| Thymeleaf-Templates | 13 Dateien, 1.127 Codezeilen |
| CSS | 2 Dateien, 31 Zeilen |
| SVG (Flaggen) | 9 Dateien, 640 Zeilen |
| i18n | `messages.properties`, `messages_de.properties`, `messages_en.properties` (je 152 Zeilen) |
| Fremdbibliotheken | Bootstrap, Font-Awesome über WebJars — nicht mitgezählt |

Kein eigenes JavaScript: die Beispielanwendung rendert serverseitig und kommt
mit Bootstrap aus.

## Tests

25 automatisierte Tests in 4 Klassen (238 Java-Code-Zeilen), alle grün
(Surefire-Lauf vom 2026-05-04):

| Testklasse | Tests | Prüft |
|---|---:|---|
| `AES256Test` | 8 | Ver-/Entschlüsselung, Schlüssellängen, Fehlerfälle |
| `PasswordGeneratorTest` | 8 | Zeichenvorrat, Länge, Zufallsverteilung |
| `CryptoHandlerTest` | 5 | Handler-Fassade über `AES256` |
| `AppSecretKeyTest` | 4 | Ableitung und Handhabung des Anwendungsschlüssels |

Die Verteilung ist bemerkenswert: **alle vier Testklassen liegen in
`l9g-crypto-core`**. Die Module `spring`, `jpa` und `tool` sowie die
Beispielanwendung haben keinen einzigen Test.

Das ist verteidigbar und zugleich der Schwachpunkt des Projekts. Verteidigbar,
weil in `core` die Kryptographie steckt und die 238 Testzeilen dort auf 417
Codezeilen kommen — ein Verhältnis von **57 %**, mit Abstand das beste der
sieben vermessenen Projekte. Schwachpunkt, weil die beiden
Integrationsmodule ungetestet sind, obwohl gerade sie den Fehlertyp bergen, der
teuer wird: `EncryptedAttributeConverter` und
`EncryptedPropertiesEnvironmentPostProcessor` entscheiden darüber, **ob**
verschlüsselt wird. Ein stillschweigend nicht greifender Converter schreibt
Klartext in die Datenbank, ohne dass ein `AES256Test` das je bemerken würde.

Über das gesamte Projekt gerechnet liegt der Testanteil bei 5 % (238 Testzeilen
gegen 4.230 Zeilen `src/main`) — die große, ungetestete Beispielanwendung drückt ihn.

## Abhängigkeiten (6 POMs, 30 Einträge)

Java 17 (`maven.compiler.release`), eigener Parent (`crypto-parent`), Spring
Boot 3.5.14, Spring Framework 6.2.18.

**`l9g-crypto-core` (4):** `lombok`, `slf4j-api`, dazu `junit-jupiter` und
`slf4j-simple` (test). Die Kernbibliothek kommt ohne Krypto-Fremdbibliothek
aus — sie nutzt die JCE des JDK.

**`l9g-crypto-spring` (6):** `crypto-core`, `spring-context`, `spring-boot`,
`spring-boot-autoconfigure`, `lombok`, `slf4j-api`.

**`l9g-crypto-jpa` (2):** `crypto-core`, `jakarta.persistence-api`.

**`l9g-crypto-tool` (7):** wie `spring`, zusätzlich `spring-shell-starter`.

**`l9g-crypto-vault-sample-app` (11):** Spring-Boot-Starter `web`, `security`,
`oauth2-client`, `thymeleaf`, dazu `thymeleaf-extras-springsecurity6`,
`lombok`, die WebJars `bootstrap`, `font-awesome`, `webjars-locator-core` sowie
`crypto-core` und `crypto-spring`.

Der Schnitt ist sauber: `core` hängt an nichts außer Lombok und SLF4J, die
Integrationsmodule ziehen jeweils nur ihr Zielframework nach.

## Verwendung im Projektumfeld

`l9g-crypto` ist die einzige der sieben Codebasen, die von anderen vermessenen
Projekten als **Abhängigkeit** eingebunden wird:

| Projekt | eingebundene Module |
|---|---|
| `l9g-accountinfo` | `crypto-core`, `crypto-spring`, `crypto-jpa` |
| `sonia-webapp-janus` | `crypto-core`, `crypto-spring` |

Die 859 Bibliothekszeilen wirken damit über ihr eigenes Repository hinaus. Der
Stand ist seit dem 04.05.2026 unverändert — `l9g-crypto` ist das einzige der
sieben Projekte, das seit über drei Monaten stillsteht.

## Hinweise zur Interpretation

- Die Typen- und Endpoint-Zahlen sind `grep`-Heuristiken über `src/main`, kein
  Parser: innere Typen zählen mit, auskommentierter Code ebenfalls. Die
  Testzahlen stammen aus Surefire und liegen über der Zahl der
  `@Test`-Annotationen (21), weil parametrisierte Tests mehrfach ausgeführt
  werden.
- Bibliothek und Beispielanwendung sind bei jeder Aussage zu trennen; die
  aggregierte Statistik weist nur die Summe aus.
- Die 640 SVG- und 456 Properties-Zeilen sind Assets bzw. Übersetzungen, keine
  Programmlogik. Zieht man sie und die Beispielanwendung ab, bleiben 586 Zeilen
  Java-Produktivcode — das ist die reale Größe von `l9g-crypto`.

---

*Erhebung: `git ls-files | grep -E '(^|/)src/' | cloc --list-file=-`, Modulzahlen
über dieselbe Liste je Modulpräfix, Paketzahlen über `cloc` je Verzeichnis
(nicht rekursiv), größte Dateien über `cloc --by-file`, Typen und Endpoints per
`grep`, Testzahlen aus `l9g-crypto-core/target/surefire-reports/`.*
