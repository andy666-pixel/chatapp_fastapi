CRONOGRAMA
4 de agosto
Duración sugerida: 4 horas

Setup del entorno

Crear estructura base de carpetas

Definir endpoints básicos de la ChatApp

Instalar dependencias necesarias

 5 de agosto
Duración sugerida: 4 horas

Implementar lógica básica de conexión WebSocket (connect, disconnect, broadcast)

Crear backend funcional sin frontend aún

 6 de agosto
Duración sugerida: 3 horas

Pruebas locales del WebSocket con websocat o JavaScript simple

Mejorar diseño de eventos (mensajes, alertas de conexión, etc.)

 7 de agosto
Duración sugerida: 4 horas

Implementar modelos Pydantic para usuarios y mensajes

Añadir seguridad simple: autenticación por token dummy

8 de agosto
Duración sugerida: 4 horas

Añadir registro e inicio de sesión

Crear pruebas unitarias simples (pytest o httpx)

Documentación OpenAPI funcional

 9 de agosto
Duración sugerida: 3 horas

Añadir cifrado de contraseñas (hashlib + salt)

Middleware para autorización

10 de agosto
Duración sugerida: 4 horas

Dockerizar la aplicación (Dockerfile, docker-compose)

Pruebas locales de la imagen y contenedor

 11 de agosto
Duración sugerida: 4 horas

Comenzar a diseñar la CI/CD (GitHub Actions)

Linting, pruebas y build automatizado

 12 de agosto
Duración sugerida: 3 horas

Añadir escaneo de vulnerabilidades (ej. Trivy, Bandit)

Integrar un pipeline básico DevSecOps

 13 de agosto
Duración sugerida: 3 horas

Añadir despliegue automatizado con docker-compose o railway/vercel

Documentar el flujo de la pipeline

 14 de agosto
Duración sugerida: 4 horas

Hacer pruebas completas E2E

Pulir errores y revisar seguridad

Añadir monitoreo simple (logs o consola)

 15 de agosto
Duración sugerida: 3 horas

Documentación completa del proyecto

Subir a GitHub como repositorio final

Crear video corto o demo como presentación final (opcional)



ESTRUCTURA
chatapp/
├── app/
│   ├── __init__.py
│   ├── main.py               # Punto de entrada FastAPI
│   ├── config.py             # Configuración del entorno
│   ├── models/
│   │   ├── __init__.py
│   │   ├── user.py           # Modelos Pydantic y ORM para usuarios
│   │   └── message.py        # Modelos para mensajes
│   ├── db/
│   │   ├── __init__.py
│   │   ├── session.py        # Configuración DB (SQLAlchemy o Tortoise)
│   │   └── init_db.py        # Inicialización y creación de tablas
│   ├── routers/
│   │   ├── __init__.py
│   │   ├── auth.py           # Endpoints de login/registro
│   │   ├── websocket_routes.py # Endpoints de websockets
│   │   └── user.py           # Endpoints REST de usuario
│   ├── services/
│   │   ├── __init__.py
│   │   ├── auth.py           # Lógica de autenticación, hashing
│   │   └── chat.py           # Broadcast de mensajes, Lógica de WebSockets
│   └── middleware/
│       ├── __init__.py
│       └── auth.py           # Middleware para verificar tokens
│
├── tests/
│   ├── __init__.py
│   ├── test_auth.py
│   ├── test_chat.py
│   └── test_user.py
│
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── .env
├── .gitignore
├── README.md
├── .github/
│   └── workflows/
│       └── ci-cd.yml         # GitHub Actions CI/CD


app/: Lógica principal de la aplicación.

models/: Define los modelos de usuario y mensaje con Pydantic o SQLModel.

routers/: Agrupa los endpoints en archivos organizados por funcionalidad.

services/: Lógica que no pertenece directamente a los endpoints, como hashing, WS.

middleware/: Middleware personalizado para autorización.

db/: Manejo de la base de datos y conexión.

tests/: Contiene pruebas unitarias.

Dockerfile y docker-compose.yml: Para contenerización y despliegue local.

.github/workflows/: Automatización CI/CD con GitHub Actions.



REQUERIMIENTOS:
Tecnologías Base
Backend: FastAPI

WebSockets: para chat en tiempo real

Base de datos: PostgreSQL (por integridad, relaciones y escalabilidad)

ORM: Tortoise ORM

Pruebas: Pytest

CI/CD: GitHub Actions

Contenerización: Docker y Docker Compose

Seguridad: JWT, hashing (bcrypt/passlib), validación Pydantic

DevSecOps: Análisis de código estático, testing automático, control de dependencias

Control de versiones: Git + GitHub



 Estructura del Proyecto (Resumen)
/app → Lógica de aplicación

/app/routers → Rutas REST y WebSockets

/app/models → Modelos Pydantic + ORM

/app/services → Lógica separada (chat, auth)

/app/middleware → Middleware para validación de token

/app/db → Configuración e inicialización de la DB

/tests → Pruebas automáticas

.github/workflows/ci-cd.yml → Pipeline CI/CD

Dockerfile, docker-compose.yml, .env



Gestión de Usuarios
Registro de usuarios

Login con JWT

Middleware que valide JWT en cada petición

Hash de contraseñas con passlib o bcrypt

Endpoint para obtener perfil de usuario

Endpoint para listar otros usuarios (para chatear)



 Sistema de Chat en Tiempo Real
Conexión WebSocket por usuario autenticado

Manejador de conexión/desconexión

Broadcast de mensajes a destinatario específico

Guardado de mensajes en la base de datos

Recuperación del historial entre dos usuarios



 Seguridad y DevSecOps
Middleware de autenticación JWT

Escaneo de dependencias con pip-audit o safety

Uso de dependabot para mantener dependencias

Análisis estático con bandit o pylint

Tests unitarios automatizados (pytest)

GitHub Actions para correr:

Tests

Linter

Auditoría de seguridad

Variables de entorno gestionadas por .env

Evitar exposición de tokens/secretos



 Contenerización y Despliegue
Dockerfile para la app

docker-compose.yml para levantar PostgreSQL y app

Variables .env montadas como secrets

Volúmenes persistentes para PostgreSQL

Configuración de puertos (FastAPI y WebSocket)

Opción futura: despliegue en VPS o Render/Heroku

 CI/CD Pipeline (GitHub Actions)
Trigger: push/pull_request en main



Jobs:

Instalar dependencias

Lint con ruff o flake8

Tests con pytest

Seguridad con pip-audit

(opcional) Build de contenedor

(opcional) Deploy si pasa todo



 Pruebas
/tests/test_auth.py → Registro y login

/tests/test_user.py → Endpoints protegidos

/tests/test_chat.py → Simulación de envío/recepción

Uso de TestClient y DB de testing con SQLite

Mock de WebSockets para pruebas sin servidor activo



 Validaciones & Manejo de Errores
Validación de entrada con Pydantic

Manejo de errores personalizados (HTTPException)

Fallback para errores 500

Chequeo de integridad antes de insertar mensajes

Manejo de desconexiones WebSocket



 Extras opcionales (si hay tiempo)
Chat en grupo (multicast WS)
Timestamps en mensajes
Cifrado E2E local (básico, por ejemplo con Fernet)


