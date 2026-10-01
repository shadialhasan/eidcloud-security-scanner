[🇸🇦 العربية](README.ar.md) | [🇬🇧 English](README.md)

# 🛡️ eidcloud-security-scanner

> High-precision Static Application Security Testing (SAST) scanner detecting SQL Injection, Cross-Site Scripting (XSS), Remote Code Execution (RCE), Path Traversal, Insecure Deserialization, and Server-Side Request Forgery (SSRF) in pure PHP 8.2+.

[![Release](https://img.shields.io/badge/version-1.0.0-blue.svg?style=flat-square)](https://github.com/eidcloud/eidcloud-security-scanner/releases)
[![PHP Version](https://img.shields.io/badge/PHP-8.2%2B-777BB4.svg?style=flat-square&logo=php&logoColor=white)](https://www.php.net/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](LICENSE)
[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/eidcloud/eidcloud-security-scanner/blob/main/notebooks/quickstart.ipynb)
[![CI Status](https://img.shields.io/badge/CI-Passing-brightgreen.svg?style=flat-square&logo=github-actions)](.github/workflows/ci.yml)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero-success.svg?style=flat-square)](composer.json)

---

## 🏷️ Topics
`eidcloud` • `sast-scanner` • `security-scanner` • `owasp-top-10` • `vulnerability-detection` • `code-security` • `php8` • `taint-analysis` • `devsecops`

---

## 🏗️ Architecture & Scanning Pipeline

The scanner uses PHP's native tokenizer engine (`PhpToken`) coupled with an inter-procedural taint propagation analyzer that tracks untrusted input sources across variable assignments into critical sinks.

```mermaid
flowchart TD
    A[Target PHP Codebase / Files] --> B[PHP 8 Native Tokenizer Engine]
    B --> C[Taint Analysis & Variable Propagation Tracker]
    
    subgraph SOURCETRACK ["Source Identification"]
        C1["Superglobals: $_GET, $_POST, $_COOKIE, $_SERVER, $_FILES, php://input"]
        C2["Data Flow: Variable Assignments & String Concatenations"]
        C3["Sanitizers: intval, htmlspecialchars, escapeshellarg, basename"]
    end
    C --- SOURCETRACK

    C --> D[Security Rule Inspection Engine]
    
    subgraph RULES ["OWASP Top 10 Rules"]
        R1["SEC-SQLI-001: SQL Injection (PDO, mysql_query, raw concat)"]
        R2["SEC-XSS-002: Cross-Site Scripting (echo, print, printf)"]
        R3["SEC-RCE-003: Remote Code Execution (eval, system, exec, backticks)"]
        R4["SEC-PATH-004: Path Traversal (include, file_get_contents, fopen)"]
        R5["SEC-DESER-005: Insecure Deserialization (unserialize)"]
        R6["SEC-SSRF-006: Server-Side Request Forgery (cURL, remote fopen)"]
    end
    D --> RULES

    RULES --> E[Remediation & Patch Generator]
    E --> F[Unified Diff & Taint Trace Assembly]
    F --> G{Reporter & CI Gate}
    
    G -->|Terminal| H[ANSI Colored Terminal Report with Scorecard]
    G -->|JSON| I[Structured Security Audit JSON Output]
    G -->|CI Pipeline| J[Exit Code 1 / 0 Gate (--fail-on=level)]
```

---

## ⚡ Key Capabilities

- **Zero External Dependencies**: Operates completely on native PHP 8.2+ without requiring Composer packages, external libraries, or runtime extensions.
- **Deep Taint Propagation Analysis**: Follows variable hops (`$a = $_GET['id']; $b = $a; $c = $b;`) and respects sanitization functions (`(int)`, `intval()`, `htmlspecialchars()`, `escapeshellarg()`, `basename()`) to prevent false positives.
- **Automated Code Remediation**: Generates inline unified diffs (`--- a/file.php` / `+++ b/file.php`) showing developers precisely how to fix vulnerabilities.
- **Actionable Taint Trace**: Displays step-by-step breadcrumbs detailing how untrusted data originated from sources and traveled through code into sensitive sinks.
- **CI/CD Integration Ready**: Configurable failure thresholds (`--fail-on=high`, `--fail-on=critical`) to block pipeline merges on insecure code.
- **Multiple Output Formats**: Human-friendly ANSI terminal reports and machine-readable JSON output for DevSecOps workflows.

---

## 🛡️ OWASP Top 10 Vulnerability Matrix

| Rule ID | Vulnerability Class | Default Severity | Sinks Inspected | Automated Remediation |
| :--- | :--- | :---: | :--- | :--- |
| `SEC-SQLI-001` | SQL Injection | **CRITICAL** | `mysql_query`, `mysqli_query`, `$pdo->query()`, `$pdo->exec()` | PDO Prepared Statements (`:param`) |
| `SEC-XSS-002` | Cross-Site Scripting (XSS) | **HIGH** | `echo`, `print`, `printf`, `<?= ` | `htmlspecialchars($var, ENT_QUOTES, 'UTF-8')` |
| `SEC-RCE-003` | Remote Code Execution | **CRITICAL** | `eval()`, `system()`, `exec()`, `shell_exec()`, backticks (``` `` ```) | Safe command dispatch, `escapeshellarg()` |
| `SEC-PATH-004` | Path Traversal / LFI | **HIGH** | `include`, `require`, `file_get_contents()`, `readfile()`, `fopen()` | `basename()`, static whitelist routing |
| `SEC-DESER-005` | Insecure Deserialization | **CRITICAL** | `unserialize()` without safe options | `json_decode()` or `['allowed_classes' => false]` |
| `SEC-SSRF-006` | Server-Side Request Forgery | **HIGH** | `curl_init()`, `curl_setopt(CURLOPT_URL)`, `file_get_contents(http://)` | IP private range validation, domain whitelist |

---

## 🚀 Installation & Quick Start

### 1. Standalone / Global Installation
Clone the repository and run immediately (no Composer install required):

```bash
git clone https://github.com/eidcloud/eidcloud-security-scanner.git
cd eidcloud-security-scanner
php bin/eidcloud-sec --help
```

### 2. Composer Dependency
```bash
composer require eidcloud/security-scanner
```

---

## 💻 CLI Usage & Commands

```
USAGE:
  php bin/eidcloud-sec scan <path> [options]
  php bin/eidcloud-sec [options]

COMMANDS:
  scan <path>              Scan target file or directory for security vulnerabilities.

OPTIONS:
  --fail-on=<level>        CI failure threshold: critical, high, medium, low (exits with code 1).
  --json                   Output scan results in structured JSON format.
  --output=<file>          Save scan report to a specified file path.
  --no-ansi                Disable ANSI color escape sequences in terminal output.
  --verbose                Display verbose analysis and taint traces.
  -h, --help               Display help guide and command list.
  -v, --version            Display version information.
```

### Examples

#### Scan a project directory:
```bash
php bin/eidcloud-sec scan ./src
```

#### Enforce a CI Security Gate (fails build if HIGH or CRITICAL issues exist):
```bash
php bin/eidcloud-sec scan ./src --fail-on=high
```

#### Output Machine-Readable JSON:
```bash
php bin/eidcloud-sec scan ./src --json > security-report.json
```

#### Scan a single file and save clean report:
```bash
php bin/eidcloud-sec scan ./legacy-handler.php --output=audit.txt
```

---

## 📊 Example Terminal Output

```
  ███████╗██╗██████╗  ██████╗██╗      ██████╗ ██╗   ██╗██████╗ 
  ██╔════╝██║██╔══██╗██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗
  █████╗  ██║██║  ██║██║     ██║     ██║   ██║██║   ██║██║  ██║
  ██╔══╝  ██║██║  ██║██║     ██║     ██║   ██║██║   ██║██║  ██║
  ███████╗██║██████╔╝╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝
  ╚══════╝╚═╝╚═════╝  ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝ 
               EIDCLOUD STATIC SECURITY SCANNER v1.0.0

 Found 1 security finding(s):

────────────────────────────────────────────────────────────────────────────────
#1  CRITICAL  SEC-SQLI-001: SQL Injection (OWASP A03:2021 - Injection)
  Location: tests/fixtures/vulnerable_sqli.php:8
  Description: Untrusted or concatenated user input supplied directly into SQL query execution functions or PDO query methods without parameter binding.

  Vulnerable Code Snippet:
          7 | // Raw mysql_query sink
     >    8 | mysql_query($rawQuery);
          9 | 

  Taint Propagation Trace:
 └── [SOURCE] Source tainted input assigned to $userId at line 4 [ $_GET['id']]
      └── ──> Source tainted input assigned to $rawQuery at line 5 [ "SELECT * FROM users WHERE id = " . $userId]
      └── ──> Tainted variable '$rawQuery' forwarded to sink at line 8
      └── ──> Sink: mysql_query() called with unparameterized query at line 8

  Remediation: Replace direct string queries with PDO prepared statements and bound parameters (:param).

  Suggested Code Patch:
    --- a/tests/fixtures/vulnerable_sqli.php (line 8)
    +++ b/tests/fixtures/vulnerable_sqli.php
    @@ -8,1 +8,3 @@
    - mysql_query($rawQuery);
    + // SECURE: Use PDO Prepared Statements
    + $stmt = $pdo->prepare('SELECT ... WHERE id = :id');
    + $stmt->execute(['id' => $safeId]);
```

---

## 🧪 Automated Testing

The repository includes a zero-dependency test runner that scans positive and negative vulnerability fixtures and verifies 100% test pass:

```bash
php tests/run_tests.php
```

Sample test output:
```
====================================================================
   EIDCLOUD SECURITY SCANNER - AUTOMATED ZERO-DEPENDENCY TEST SUITE 
====================================================================
PHP Version: 8.2.12 | Total Tests: 13

  [PASS] testSqlInjectionDetection                  (4.09 ms)
  [PASS] testXssDetection                           (1.40 ms)
  [PASS] testRceDetection                           (1.30 ms)
  [PASS] testPathTraversalDetection                 (1.49 ms)
  [PASS] testInsecureDeserializationDetection       (1.04 ms)
  [PASS] testSsrfDetection                          (1.13 ms)
  [PASS] testSafePatternsAvoidFalsePositives        (1.74 ms)
  [PASS] testMultiHopTaintPropagation               (0.30 ms)
  [PASS] testNumericCastClearsTaint                 (0.33 ms)
  [PASS] testHtmlSpecialCharsClearsXss              (0.23 ms)
  [PASS] testSeverityThresholds                     (0.04 ms)
  [PASS] testJsonReporterContract                   (2.18 ms)
  [PASS] testCliExecution                           (764.44 ms)

--------------------------------------------------------------------
   TEST SUITE RESULT: 100% PASSED (13/13 tests in 785.22 ms)
====================================================================
```

---

## 📓 Interactive Google Colab Notebook

Run the scanner directly in your browser with no installation:
[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/eidcloud/eidcloud-security-scanner/blob/main/notebooks/quickstart.ipynb)

Located at [`notebooks/quickstart.ipynb`](notebooks/quickstart.ipynb), this interactive notebook demonstrates generating vulnerable code snippets, running static analysis scans, and parsing security findings programmatically.

---

## 👤 Author & Maintainer

**Eng. MHD. Shadi AL-Hasan**  
- **Role:** Executive CTO & Enterprise Solutions Architect  
- **Email:** [mhd.shadi.alhasan@gmail.com](mailto:mhd.shadi.alhasan@gmail.com)  
- **Phone / WhatsApp:** [+963934005922](tel:+963934005922)  
- **Location:** Damascus, Syria  
- **GitHub:** [shadialhasan](https://github.com/shadialhasan)  

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.  
Copyright (c) 2026 **MHD. Shadi AL-Hasan**. All rights reserved.
