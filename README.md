# Harvard University: CS50 Cybersecurity

![Build Status](https://github.com/Sais-gallego/harvard-cs50-cybersecurity/actions/workflows/ci.yml/badge.svg)
![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Course](https://img.shields.io/badge/Harvard-CS50%20Cybersecurity-crimson.svg)

Implementaciones completas de laboratorios, algoritmos de defensa criptográfica, análisis forense de sistemas y seguridad de redes del programa oficial de **Harvard University: CS50's Introduction to Cybersecurity**, impartido por el profesor **David J. Malan**.

**Autor:** Sergio Andrés Ipuz Saavedra  
**GitHub:** [@Sais-gallego](https://github.com/Sais-gallego)  
**Institución:** Harvard University (CS50)

---

## 🛡️ Estructura del Programa y Módulos Técnicos

```
harvard-cs50-cybersecurity/
├── .github/workflows/
│   └── ci.yml                     # Pipeline CI multi-versión (Python 3.10 - 3.13)
├── src/
│   ├── __init__.py
│   ├── account_security.py       # Semana 0 & 1: Entropía, Hashing PBKDF2, MFA/TOTP RFC 6238
│   ├── systems_security.py       # Semana 2: Stack Canaries, Buffer Overflows, Auditoría POSIX
│   ├── network_security.py       # Semana 3: Handshake TCP, Checksum IPv4, Detección ARP Poisoning
│   ├── web_security.py           # Semana 4: Inyecciones SQL, Sanitización XSS, Tokens CSRF
│   └── forensics_ir.py           # Semana 5: Manifiestos de Integridad SHA-256, Análisis de Logs
├── tests/
│   ├── __init__.py
│   └── test_cybersecurity.py     # Suite de 13 pruebas unitarias exhaustivas (100% Passing)
├── README.md
└── SOLUTIONS.md
```

---

## 🚀 Módulos Implementados

### 1. Seguridad de Cuentas y Criptografía (`src/account_security.py`)
- **Cálculo de Entropía de Contraseñas:** Entropía de Shannon e información teórica combinatoria $E = L \log_2(R)$ con estimación del tiempo de ruptura ante clusters GPU y funciones KDF lentas.
- **Derivación de Claves con PBKDF2:** Hashing criptográfico con sal única de 16 bytes y HMAC-SHA256 con 100,000 iteraciones. Comparación en tiempo constante (`hmac.compare_digest`) para mitigar ataques de temporización (*timing attacks*).
- **Autenticación en Dos Pasos (TOTP - RFC 6238):** Generador y validador de códigos de 6 dígitos con truncamiento dinámico sobre HMAC-SHA1 y ventana de tolerancia ante desfases de reloj.

### 2. Seguridad de Sistemas y Memoria (`src/systems_security.py`)
- **Simulador de Stack Frame Virtual x86-64:** Demostración de desbordamiento de búfer (*buffer overflow*), sobreescritura de dirección de retorno (`$rip`), detección de corrupción de *Stack Canary* (`0xDEADBEEF`) y prevención de ejecución de datos (NX/DEP).
- **Auditoría de Permisos POSIX:** Análisis de máscaras de bits octales para detección de escalamiento de privilegios por bits SUID (`0o4000`), SGID (`0o2000`) y archivos con permisos universales de escritura (*world-writable*).

### 3. Seguridad de Redes y Tráfico (`src/network_security.py`)
- **Protocolo IPv4 & TCP Handshake (RFC 791 / RFC 793):** Cálculo de suma de verificación en complemento a uno y máquina de estados del saludo de 3 vías (SYN $\to$ SYN-ACK $\to$ ACK) con sincronización de números de secuencia (`ISN`).
- **Detección de Ataques ARP Spoofing / Man-in-the-Middle:** Motor que rastrea la tabla de vecinos y dispara alertas inmediatas al detectar discrepancias en la correspondencia IP-MAC o anuncios ARP gratuitos maliciosos.

### 4. Seguridad Web y Defensas OWASP (`src/web_security.py`)
- **Prevención de Inyecciones SQL:** Análisis heurístico de patrones de escape (`OR 1=1`, `UNION SELECT`, comentarios `--`) y forzado estricto de consultas parametrizadas separando la estructura AST de los datos de entrada.
- **Sanitización de Cross-Site Scripting (XSS):** Detección de vectores de ataque reflejados/almacenados y escape contextual estricto de entidades HTML.
- **Protección contra CSRF:** Generación de tokens de doble envío (*Double-Submit*) vinculados criptográficamente al identificador de sesión mediante HMAC-SHA256.

### 5. Informática Forense y Respuesta a Incidentes (`src/forensics_ir.py`)
- **Auditor de Integridad de Archivos:** Comparación de hashes SHA-256 contra línea base para detectar alteraciones, puertas traseras añadidas o borrado de archivos críticos del sistema.
- **Analizador de Logs y Detección de Ataques de Fuerza Bruta:** Correlación temporal de eventos de autenticación en ventanas deslizantes para identificar vectores de ataque e intrusiones posteriores a ataques de diccionario.

---

## 🧪 Ejecución de Pruebas Unitarias

Para ejecutar la suite completa de pruebas:

```bash
python -m unittest tests/test_cybersecurity.py -v
```

### Salida de las Pruebas
```text
test_arp_cache_poison_detector ... ok
test_cryptographic_pbkdf2_hasher ... ok
test_csrf_token_lifecycle ... ok
test_file_integrity_baseline_auditor ... ok
test_incident_log_analyzer_brute_force ... ok
test_network_ipv4_checksum ... ok
test_password_entropy_and_tier ... ok
test_sql_injection_defense ... ok
test_stack_buffer_overflow_and_canary_protection ... ok
test_tcp_three_way_handshake ... ok
test_totp_2fa_generation_and_verification ... ok
test_unix_permission_auditor ... ok
test_xss_sanitizer ... ok

----------------------------------------------------------------------
Ran 13 tests in 0.017s

OK
```
