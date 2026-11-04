# Gran Fortuna Casino

## Acceso y saldo compartido

Los tres juegos usan la misma cuenta y el saldo que mantiene el servidor en la base de datos. El navegador solo conserva el token de sesión en `sessionStorage`; no decide los premios ni acredita créditos. Fortuna China también calcula en el servidor las combinaciones, los giros gratis y sus multiplicadores.

Las cuentas públicas requieren una contraseña de al menos 12 caracteres, verificación de correo y se bloquean temporalmente tras varios intentos fallidos. Configura un proveedor SMTP antes de habilitar el registro. Las contraseñas se guardan con bcrypt. Para publicar el sitio, usa HTTPS y limita `FRONTEND_ORIGINS` a los orígenes reales del sitio.

## Configuración local

1. Activa el entorno virtual e instala dependencias con `pip install -r requirements.txt`.
2. Copia `.env.example` a `.env`.
3. Genera un valor secreto nuevo para `SECRET_KEY` (por ejemplo, con `python -c "import secrets; print(secrets.token_urlsafe(48))"`) y guárdalo solo en `.env`.
4. Para local, SQLite se configura por defecto. Para MySQL, establece `DATABASE_URL` con una URL `mysql+pymysql://...` en `.env`. No publiques contraseñas ni secretos.
5. Configura `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, `FRONTEND_URL` y `FRONTEND_ORIGINS`. Sin SMTP, el registro público devuelve un error y no crea cuentas.
6. Crea la cuenta privada del propietario desde una terminal local:

   ```powershell
   python main.py create-owner
   ```

   El comando pide un usuario y una contraseña fuerte. No existe una ruta web para solicitar el rol de propietario. Esta cuenta no descuenta saldo al jugar y el servidor muestra créditos infinitos.
7. Inicia el API con `uvicorn main:app --reload`.
8. Sirve los archivos HTML desde el origen configurado (por ejemplo, Live Server en `http://127.0.0.1:5500`) y abre `auth.html`.

El servidor crea las tablas que faltan y añade las columnas nuevas a las tablas existentes. Mantén copias de seguridad de la base de datos antes de desplegar cambios en producción.

## Límites del proyecto

La integración de depósitos/retiros bancarios no está implementada. Los créditos iniciales son de demostración y no representan dinero real. No uses datos bancarios en esta aplicación.
