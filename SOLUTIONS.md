# Harvard CS50 Cybersecurity - Memoria Técnica de Soluciones

**Estudiante:** Sergio Andrés Ipuz Saavedra  
**Programa:** CS50's Introduction to Cybersecurity - Harvard University  
**Instructor:** Prof. David J. Malan  

---

## 📋 Resumen de Desafíos y Arquitectura de Solución

| Semana / Tema | Desafío Técnico | Mecanismo de Defensa Implementado |
|---|---|---|
| **Semana 0 & 1**<br>Seguridad de Cuentas | Ruptura de contraseñas por ataques de diccionario y temporización. | PBKDF2 con sal criptográfica de 16B, HMAC-SHA256 (100k iteraciones) y verificación en tiempo constante. |
| **Semana 1**<br>Autenticación MFA | Vulnerabilidad de contraseñas estáticas ante filtraciones. | TOTP bajo RFC 6238 con ventana de sincronización estricta. |
| **Semana 2**<br>Seguridad de Sistemas | Sobreescritura de direcciones de retorno en la pila (Buffer Overflow). | Stack Canaries de valor pseudoaleatorio y verificación previa al retorno (`$rip`). |
| **Semana 2**<br>Permisos POSIX | Escalamiento de privilegios a través de binarios vulnerables. | Detección de máscaras `0o4000` (SUID) y archivos modificables por cualquier usuario (`world-writable`). |
| **Semana 3**<br>Seguridad de Redes | Interceptación de tráfico en redes locales mediante envenenamiento ARP. | Detección de inconsistencias IP-MAC y alertas ante ARP Spoofing. |
| **Semana 4**<br>Seguridad Web | Inyecciones SQL y ataques Cross-Site Scripting (XSS). | Consultas preparadas parametrizadas y codificación estricta de entidades HTML. |
| **Semana 5**<br>Forense y Logs | Detección tardía de intrusiones y manipulación de archivos del sistema. | Hash manifests SHA-256 y analizador de ventanas temporales para ataques de fuerza bruta. |

---

## 🔒 Estándar de Integridad Académica
Todas las soluciones han sido diseñadas, implementadas y probadas cumpliendo los estándares de excelencia técnica de la Universidad de Harvard.
