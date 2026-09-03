# 🛡️ Auditor de Entropía y Seguridad de Contraseñas

Herramienta de análisis de robustez de contraseñas basada en teoría de la información de Shannon/NIST, cálculo de entropía en bits y detección de patrones de vulnerabilidad.

---

## 🚀 Características

* **Cálculo de Entropía de Shannon:** Medición precisa del espacio de búsqueda ($E = L \times \log_2(R)$).
* **Análisis de Vulnerabilidades:** Detección de patrones secuenciales, repeticiones consecutivas y diccionario de contraseñas filtradas.
* **Estimación de Crackeo por Fuerza Bruta:** Simulación de tiempo de ruptura contra clústeres de GPUs a 100 GH/s.
* **Generador Criptográfico Seguro:** Generador aleatorio mediante el módulo `secrets`.

---

## 💻 Uso

* **Modo interactivo:**
  ```bash
  python password_auditor.py
