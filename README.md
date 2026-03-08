# Guarderia API (SQL Server + Node.js/Express)

Proyecto demo **funcional** para probar:
- Login con bcrypt
- Bloqueo por intentos fallidos (3) por 15 minutos
- Timeout por inactividad (1 minuto) en servidor con `UltimaActividad`
- Cifrado en capa app AES-256-GCM para teléfono/dirección de tutores
- Endpoints con **RBAC** (Admin/Maestro/Padre) + **scope** básico:
  - Padre: solo puede ver/crear recursos de sus hijos
  - Maestro: puede registrar bitácora para cualquier niño (demo) y ver asistencia (demo)
  - Admin: puede crear/gestionar

## 1) Crear base de datos
Ejecuta en SSMS:
- `sql/01_create_guarderiadb.sql`
- `sql/02_seed_roles.sql`

## 2) Configurar .env
Copia `.env.example` a `.env` y actualiza credenciales de SQL Server.

Genera `AES_KEY_B64` (32 bytes base64):
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

## 3) Instalar y seed
```bash
npm install
npm run seed
npm start
```

La API queda en: http://localhost:3000

## 4) Usuarios demo
- admin@demo.com / Admin123!
- maestro@demo.com / Maestro123!
- padre@demo.com / Padre123!

## 5) Probar con curl (Windows CMD)
Login:
```bat
curl -i -c cookies.txt -H "Content-Type: application/json" -d "{"email":"maestro@demo.com","password":"Maestro123!"}" http://localhost:3000/auth/login
```

Perfil:
```bat
curl -i -b cookies.txt http://localhost:3000/me
```

Crear bitácora (requiere sesión):
```bat
curl -i -b cookies.txt -H "Content-Type: application/json" -d "{"idNino":1,"comida":true,"siestaMinutos":45,"observaciones":"OK","estadoAnimo":"Feliz"}" http://localhost:3000/bitacora
```

Esperar 60+ segundos sin llamar endpoints y luego:
```bat
curl -i -b cookies.txt http://localhost:3000/me
```
Debe decir sesión expirada por inactividad.

Lockout: intenta 3 veces password incorrecto -> 423 Locked.
