# Cómo publicar SentinelAI en GitHub

Estos pasos **no publican nada automáticamente**. Debes hacerlos desde tu cuenta.

## A. Preparar el repositorio

1. Descomprime el `.zip` y abre la carpeta `SentinelAI` en VS Code.
2. Prueba primero `index.html` con doble clic.
3. Si tienes Python, ejecuta los tests: `python -m pip install -r requirements-dev.txt` y `python -m pytest`.
4. En GitHub, pulsa **New repository** y elige el nombre **SentinelAI** y visibilidad **Public**. No marques la opción de generar README (ya existe uno).
5. Abre una terminal integrada de VS Code en la carpeta y ejecuta:

```bash
git init
git branch -M main
git add .
git commit -m "feat: release SentinelAI SOC analytics v1.0"
git remote add origin https://github.com/TU-USUARIO/SentinelAI.git
git push -u origin main
```

Sustituye `TU-USUARIO` por tu usuario de GitHub. GitHub puede pedirte que te autentiques en el navegador; no escribas contraseñas en archivos del proyecto.

Si tienes GitHub Desktop, también puedes hacer el commit y publicar el repositorio desde su interfaz gráfica.

## B. Publicar una demo web gratuita con GitHub Pages

La demo se genera a partir del **motor real de detección**, pero contiene únicamente eventos sintéticos y resultados precalculados. No acepta logs nuevos.

1. Abre tu repositorio en GitHub.
2. Ve a **Settings → Pages**.
3. En **Build and deployment → Source**, selecciona **Deploy from a branch**.
4. Selecciona rama **main**, carpeta **/(root)** y **Save**.
5. GitHub Pages podrá publicar una URL parecida a `https://TU-USUARIO.github.io/SentinelAI/`.
6. Añade esa URL como **Website** en la sección "About" del repositorio para facilitar la revisión.

`index.html` es la propia demo (sin redirecciones), así que la URL raíz de Pages la muestra directamente. Para que LinkedIn y otras redes muestren una vista previa, añade en su `<head>` (plantilla `assets/preview_template.html`) `<meta property="og:image" content="https://TU-USUARIO.github.io/SentinelAI/assets/dashboard.png">` y `og:url` con tu URL real, y vuelve a ejecutar `python scripts/build_demo_preview.py`. La demo funciona completamente en el navegador y no envía el dataset a otros servicios.

> La dirección y el despliegue se confirmarán en GitHub Pages; no asumas que la URL está operativa hasta comprobarla.

## C. Hacerlo atractivo para empresas

- Usa como descripción: `Explainable SOC analytics: Python, threat detection, MITRE ATT&CK, Isolation Forest, Streamlit and automated tests.`
- Etiquetas (topics) sugeridas: `cybersecurity`, `soc`, `python`, `mitre-attack`, `threat-detection`, `streamlit`, `machine-learning`, `portfolio`.
- Deja `README.md` en la raíz para que se vea la captura al entrar.
- Fija (pin) el repositorio en tu perfil de GitHub.
- Añade el enlace del repositorio al apartado **Proyectos** de LinkedIn y al CV.
- Personaliza el README con tu autoría y explica las decisiones técnicas cuando te sientas capaz de defenderlas en una entrevista.

## D. Antes de compartir

- No subas API keys ni logs reales de clientes.
- Mantén archivos `.env` y `.streamlit/secrets.toml` fuera de Git, como ya indica `.gitignore`.
- Confirma que GitHub Actions se ejecuta en verde (Python 3.11, 3.12 y 3.13; el CI ejecuta ruff, los tests y comprueba que `index.html` está actualizado).
- Captura una imagen de la UI Streamlit en tu propio ordenador cuando la pruebes y, si quieres, diferencia en el README esa captura de la vista offline.
