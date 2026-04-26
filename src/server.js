/*
PROYECTO: Sistema de Gestión para Guardería con Autenticación Segura,
Control de Acceso y Protección de Datos para el CAPI Pasito a Pasito – Colegio “Prudencia Ayala.

INSTITUCION: UTEC – Universidad Tecnológica de El Salvador
CURSO: Seguridad de aplicaciones seguras
DOCENTE: Ing. José Manuel Martínez
PRE ESPECIALIDAD: Ingeniería en Ciberseguridad

ESTUDIANTES:
Cabrera Gonzales Josué Balmore  29-2594-2021
Cardona Pérez Karen Vanesa      29-1944-2020
Ponce Sánchez Susan Jeannette   29-0460-2020

FECHA: 01/MARZO/2026
*/

import express from "express";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import cors from "cors";
import dotenv from "dotenv";
dotenv.config();
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

import { poolPromise, sql } from "./db.js";
import { requireAuth, requireRole, assertChildBelongsToParent } from "./auth.js";
import { encryptAesGcm, decryptAesGcm } from "./crypto.js";


dotenv.config();
const app = express();
app.set("trust proxy", 1);
app.use(helmet());
app.use(cors({
  origin: "http://localhost:4200",
  credentials: true
}));
app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());

function signToken(u) {
  return jwt.sign(
    { sub: u.IdUsuario, role: u.IdRole, email: u.Email },
    process.env.JWT_SECRET,
    { expiresIn: "15m" }
  );
}

function setAuthCookie(res, token) {
  res.cookie("auth", token, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    path: "/",         // ← AGREGADO
    maxAge: 900000     // ← AGREGADO (15 minutos)
  });
}

/* -------------------- Auth endpoints -------------------- */
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "Email y password requeridos" });

  try {
    const pool = await poolPromise;
    const r = await pool.request()
      .input("email", sql.NVarChar(100), String(email).trim().toLowerCase())
      .query(`
        SELECT TOP 1
          IdUsuario, Email, PasswordHash, IdRole,
          IntentosFallidos, BloqueadoHasta, EstaActivo
        FROM Usuarios
        WHERE Email=@email
      `);

    const u = r.recordset[0];
    const genericFail = () => res.status(401).json({ error: "Credenciales inválidas" });

    if (!u || !u.EstaActivo) return genericFail();

    if (u.BloqueadoHasta && new Date(u.BloqueadoHasta) > new Date()) {
      return res.status(423).json({ error: "Cuenta bloqueada por intentos fallidos. Intenta luego." });
    }

    const ok = await bcrypt.compare(String(password), String(u.PasswordHash));
    if (!ok) {
      const nextFails = (u.IntentosFallidos || 0) + 1;

      if (nextFails >= 3) {
        await pool.request()
          .input("id",    sql.Int, u.IdUsuario)
          .input("fails", sql.Int, nextFails)
          .query(`
            UPDATE Usuarios
            SET IntentosFallidos = @fails,
                BloqueadoHasta   = DATEADD(minute, 15, GETDATE())
            WHERE IdUsuario = @id
          `);


        return res.status(423).json({ error: "Cuenta bloqueada por intentos fallidos. Intenta luego." });
      }

      await pool.request()
        .input("id",    sql.Int, u.IdUsuario)
        .input("fails", sql.Int, nextFails)
        .query(`
          UPDATE Usuarios
          SET IntentosFallidos = @fails
          WHERE IdUsuario = @id
        `);

      return genericFail();
    }

    await pool.request()
      .input("id", sql.Int, u.IdUsuario)
      .query(`
        UPDATE Usuarios
        SET IntentosFallidos = 0, BloqueadoHasta = NULL, UltimaActividad = GETUTCDATE()
        WHERE IdUsuario = @id
      `);

    const token = signToken(u);
    setAuthCookie(res, token);

console.log("✅ Cookie enviada:", token.substring(0, 20) + "...");

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Error interno" });
  }
});

app.post("/auth/logout", (req, res) => {
  res.clearCookie("auth");
  res.json({ ok: true });
});

app.get("/me", requireAuth, (req, res) => {
  res.json(req.user);
});

app.post("/auth/register", requireAuth, requireRole("Admin"), async (req, res) => {
  try {
    const { email, password, idRole } = req.body;

    const pool = await poolPromise;
    const saltRounds = 12;
    const hash = await bcrypt.hash(password, saltRounds);

    const result = await pool.request()
      .input("Email", sql.NVarChar(100), email)
      .input("Hash", sql.NVarChar(sql.MAX), hash)
      .input("Role", sql.Int, idRole)
      .execute("CrearUsuario");

    res.json({
      ok: true,
      IdUsuario: result.recordset[0].IdUsuario
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ ok: false, msg: "Error al registrar usuario" });
  }
});

/* -------------------- Agregar tutor (Admin) -------------------- */
app.post("/tutores", requireAuth, requireRole("Admin"), async (req, res) => {
  const { idUsuario, nombre, apellido, telefono, direccion } = req.body || {};

  if (!idUsuario || !nombre || !apellido || !telefono || !direccion) {
    return res.status(400).json({ error: "Campos requeridos: idUsuario, nombre, apellido, telefono, direccion" });
  }

  try {
    const pool = await poolPromise;

    // Verificar que el usuario existe y está activo
    const rUser = await pool.request()
      .input("id", sql.Int, Number(idUsuario))
      .query(`SELECT EstaActivo FROM Usuarios WHERE IdUsuario = @id`);

    if (!rUser.recordset[0] || !rUser.recordset[0].EstaActivo) {
      return res.status(400).json({ error: "Usuario no encontrado o inactivo" });
    }

    // Verificar que no exista ya un tutor para este usuario
    const rTutor = await pool.request()
      .input("id", sql.Int, Number(idUsuario))
      .query(`SELECT 1 AS ok FROM Tutores WHERE IdUsuario = @id`);

    if (rTutor.recordset[0]?.ok) {
      return res.status(400).json({ error: "Tutor ya existe para este usuario" });
    }

    // Encriptar datos sensibles
    const telCifrado = encryptAesGcm(String(telefono).trim());
    const dirCifrada = encryptAesGcm(String(direccion).trim());

    // Insertar tutor
    const result = await pool.request()
      .input("idUsuario", sql.Int, Number(idUsuario))
      .input("nombre", sql.NVarChar(100), String(nombre).trim())
      .input("apellido", sql.NVarChar(100), String(apellido).trim())
      .input("tel", sql.NVarChar(sql.MAX), telCifrado)
      .input("dir", sql.NVarChar(sql.MAX), dirCifrada)
      .query(`
        INSERT INTO Tutores (IdUsuario, Nombre, Apellido, TelefonoCifrado, DireccionCifrada)
        OUTPUT INSERTED.IdTutor
        VALUES (@idUsuario, @nombre, @apellido, @tel, @dir)
      `);

    res.status(201).json({ ok: true, IdTutor: result.recordset[0].IdTutor });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al registrar tutor" });
  }
});

/* -------------------- Ver tutores (Admin) -------------------- */
app.get("/tutores", requireAuth, requireRole("Admin"), async (req, res) => {
  try {
    const pool = await poolPromise;
    const r = await pool.request().query(`
      SELECT t.IdTutor, t.IdUsuario, t.Nombre, t.Apellido, t.TelefonoCifrado, t.DireccionCifrada,
             u.Email
      FROM Tutores t
      INNER JOIN Usuarios u ON u.IdUsuario = t.IdUsuario
      ORDER BY t.IdTutor
    `);

    // Desencriptar datos sensibles para vista de admin
    const tutors = r.recordset.map(t => ({
      idTutor: t.IdTutor,
      idUsuario: t.IdUsuario,
      nombre: t.Nombre,
      apellido: t.Apellido,
      telefono: decryptAesGcm(t.TelefonoCifrado),
      direccion: decryptAesGcm(t.DireccionCifrada),
      email: t.Email
    }));

    res.json(tutors);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al obtener tutores" });
  }
});

/* -------------------- Modificar tutor (Admin) -------------------- */
app.put("/tutores/:id", requireAuth, requireRole("Admin"), async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: "ID inválido" });

  const { nombre, apellido, telefono, direccion } = req.body || {};
  if (!nombre || !apellido || !telefono || !direccion) {
    return res.status(400).json({ error: "Campos requeridos: nombre, apellido, telefono, direccion" });
  }

  try {
    const pool = await poolPromise;

    // Verificar que el tutor existe
    const rTutor = await pool.request()
      .input("id", sql.Int, id)
      .query(`SELECT 1 AS ok FROM Tutores WHERE IdTutor = @id`);

    if (!rTutor.recordset[0]?.ok) {
      return res.status(404).json({ error: "Tutor no encontrado" });
    }

    // Encriptar datos sensibles
    const telCifrado = encryptAesGcm(String(telefono).trim());
    const dirCifrada = encryptAesGcm(String(direccion).trim());

    // Actualizar
    const r = await pool.request()
      .input("id", sql.Int, id)
      .input("nombre", sql.NVarChar(100), String(nombre).trim())
      .input("apellido", sql.NVarChar(100), String(apellido).trim())
      .input("tel", sql.NVarChar(sql.MAX), telCifrado)
      .input("dir", sql.NVarChar(sql.MAX), dirCifrada)
      .query(`
        UPDATE Tutores
        SET Nombre=@nombre, Apellido=@apellido, TelefonoCifrado=@tel, DireccionCifrada=@dir
        WHERE IdTutor=@id;
        SELECT @@ROWCOUNT AS affected;
      `);

    if ((r.recordset[0]?.affected || 0) === 0) {
      return res.status(404).json({ error: "Tutor no encontrado" });
    }

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al actualizar tutor" });
  }
});

/* -------------------- Eliminar tutor (Admin) -------------------- */
app.delete("/tutores/:id", requireAuth, requireRole("Admin"), async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: "ID inválido" });

  try {
    const pool = await poolPromise;

    // Verificar que no tenga niños asociados
    const rNinos = await pool.request()
      .input("id", sql.Int, id)
      .query(`SELECT COUNT(*) AS count FROM Ninos WHERE IdTutor = @id`);

    if (rNinos.recordset[0].count > 0) {
      return res.status(400).json({ error: "No se puede eliminar tutor con niños asociados" });
    }

    // Eliminar
    const r = await pool.request()
      .input("id", sql.Int, id)
      .query(`DELETE FROM Tutores WHERE IdTutor=@id; SELECT @@ROWCOUNT AS affected;`);

    if ((r.recordset[0]?.affected || 0) === 0) {
      return res.status(404).json({ error: "Tutor no encontrado" });
    }

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al eliminar tutor" });
  }
});

/* -------------------- Admin endpoints (demo) -------------------- */
app.get("/admin/usuarios", requireAuth, requireRole("Admin"), async (req, res) => {
  const pool = await poolPromise;
  const r = await pool.request().query(`
    SELECT u.IdUsuario, u.Email, r.NombreRole, u.EstaActivo, u.IntentosFallidos, u.BloqueadoHasta, u.UltimaActividad
    FROM Usuarios u INNER JOIN Roles r ON r.IdRole=u.IdRole
    ORDER BY u.IdUsuario
  `);
  res.json(r.recordset);
});

app.put("/admin/usuarios/:id/password", requireAuth, requireRole("Admin"), async (req, res) => {
  const id = Number(req.params.id);
  const { password } = req.body || {};

  if (!Number.isInteger(id)) return res.status(400).json({ error: "ID inválido" });
  if (!password || typeof password !== "string" || password.trim().length < 8) {
    return res.status(400).json({ error: "Password requerido y debe tener al menos 8 caracteres" });
  }

  try {
    const hash = await bcrypt.hash(password.trim(), 12);
    const pool = await poolPromise;

    const r = await pool.request()
      .input("id", sql.Int, id)
      .input("hash", sql.NVarChar(sql.MAX), hash)
      .query(`
        UPDATE Usuarios
        SET PasswordHash = @hash,
            IntentosFallidos = 0,
            BloqueadoHasta = NULL
        WHERE IdUsuario = @id;
        SELECT @@ROWCOUNT AS affected;
      `);

    if ((r.recordset[0]?.affected || 0) === 0) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al cambiar contraseña" });
  }
});

app.put("/admin/usuarios/:id/unlock", requireAuth, requireRole("Admin"), async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: "ID inválido" });

  try {
    const pool = await poolPromise;
    const r = await pool.request()
      .input("id", sql.Int, id)
      .query(`
        UPDATE Usuarios
        SET IntentosFallidos = 0,
            BloqueadoHasta = NULL
        WHERE IdUsuario = @id;
        SELECT @@ROWCOUNT AS affected;
      `);

    if ((r.recordset[0]?.affected || 0) === 0) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al desbloquear usuario" });
  }
});

/* -------------------- Avisos (Maestro/Admin) -------------------- */
app.post("/avisos", requireAuth, requireRole("Maestro", "Admin"), async (req, res) => {
  const { titulo, contenido, imagen, fechaExpiracion } = req.body || {};

  if (!titulo || !contenido) {
    return res.status(400).json({ error: "Campos requeridos: titulo, contenido" });
  }

  try {
    const pool = await poolPromise;
    const result = await pool.request()
      .input("titulo", sql.VarChar(200), String(titulo).trim())
      .input("contenido", sql.VarChar(500), String(contenido).trim())
      .input("imagen", sql.NVarChar(sql.MAX), imagen || null)
      .input("fechaExpiracion", sql.DateTime, fechaExpiracion ? new Date(fechaExpiracion) : null)
      .input("idAutor", sql.Int, req.user.id)
      .query(`
        INSERT INTO Avisos (Titulo, Contenido, imagen, FechaExpiracion, IdAutor)
        OUTPUT INSERTED.id_aviso
        VALUES (@titulo, @contenido, @imagen, @fechaExpiracion, @idAutor)
      `);

    res.status(201).json({
      ok: true,
      id_aviso: result.recordset[0].id_aviso
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al crear aviso" });
  }
})

app.get("/avisos", requireAuth, async (req, res) => {
  try {
    const pool = await poolPromise;
    const r = await pool.request().query(`
      SELECT a.id_aviso, a.Titulo, a.Contenido, a.imagen, a.FechaExpiracion,
             u.Email AS AutorEmail
      FROM Avisos a
      INNER JOIN Usuarios u ON u.IdUsuario = a.IdAutor
      ORDER BY a.id_aviso DESC
    `);

    res.json(r.recordset);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al obtener avisos" });
  }
});

app.get("/avisos/:id", requireAuth, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: "ID inválido" });

  try {
    const pool = await poolPromise;
    const r = await pool.request()
      .input("id", sql.Int, id)
      .query(`
        SELECT a.id_aviso, a.Titulo, a.Contenido, a.imagen, a.FechaExpiracion,
               u.Email AS AutorEmail
        FROM Avisos a
        INNER JOIN Usuarios u ON u.IdUsuario = a.IdAutor
        WHERE a.id_aviso = @id
      `);

    if (!r.recordset[0]) return res.status(404).json({ error: "Aviso no encontrado" });

    res.json(r.recordset[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al obtener aviso" });
  }
});

app.put("/avisos/:id", requireAuth, requireRole("Maestro", "Admin"), async (req, res) => {
  const id = Number(req.params.id);
  const { titulo, contenido, fechaExpiracion, imagen } = req.body || {};

  if (!Number.isInteger(id)) return res.status(400).json({ error: "ID inválido" });
  if (!titulo || !contenido) {
    return res.status(400).json({ error: "Campos requeridos: titulo, contenido" });
  }

  try {
    const pool = await poolPromise;

    const rCheck = await pool.request()
      .input("id", sql.Int, id)
      .query(`SELECT IdAutor FROM Avisos WHERE id_aviso = @id`);

    if (!rCheck.recordset[0]) return res.status(404).json({ error: "Aviso no encontrado" });

    if (req.user.roleName !== "Admin" && rCheck.recordset[0].IdAutor !== req.user.id) {
      return res.status(403).json({ error: "No autorizado" });
    }

    const r = await pool.request()
      .input("id", sql.Int, id)
      .input("titulo", sql.NVarChar(200), String(titulo).trim())
      .input("contenido", sql.NVarChar(sql.MAX), String(contenido).trim())
      .input("imagen", sql.NVarChar(sql.MAX), imagen || null)
      .input("fechaExpiracion", sql.DateTime, fechaExpiracion ? new Date(fechaExpiracion) : null)
      .query(`
        UPDATE Avisos
        SET Titulo = @titulo,
            Contenido = @contenido,
            imagen = @imagen,
            FechaExpiracion = @fechaExpiracion
        WHERE id_aviso = @id;

        SELECT @@ROWCOUNT AS affected;
      `);

    if ((r.recordset[0]?.affected || 0) === 0) {
      return res.status(404).json({ error: "Aviso no encontrado" });
    }

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al actualizar aviso" });
  }
});

app.delete("/avisos/:id", requireAuth, requireRole("Maestro", "Admin"), async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: "ID inválido" });

  try {
    const pool = await poolPromise;
    const r = await pool.request()
      .input("id", sql.Int, id)
      .query(`
        UPDATE Avisos SET EstaActivo = 0 WHERE IdAviso = @id;
        SELECT @@ROWCOUNT AS affected;
      `);

    if ((r.recordset[0]?.affected || 0) === 0) {
      return res.status(404).json({ error: "Aviso no encontrado" });
    }

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al eliminar aviso" });
  }
});

app.put("/avisos/:id/status", requireAuth, requireRole("Maestro", "Admin"), async (req, res) => {
  const id = Number(req.params.id);
  const { estaActivo } = req.body || {};

  if (!Number.isInteger(id)) return res.status(400).json({ error: "ID inválido" });
  if (typeof estaActivo !== "boolean") {
    return res.status(400).json({ error: "estaActivo debe ser true o false" });
  }

  try {
    const pool = await poolPromise;
    const r = await pool.request()
      .input("id", sql.Int, id)
      .input("activo", sql.Bit, estaActivo ? 1 : 0)
      .query(`
        UPDATE Avisos SET EstaActivo = @activo WHERE IdAviso = @id;
        SELECT @@ROWCOUNT AS affected;
      `);

    if ((r.recordset[0]?.affected || 0) === 0) {
      return res.status(404).json({ error: "Aviso no encontrado" });
    }

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al cambiar estado del aviso" });
  }
});

app.post("/ninos", requireAuth, requireRole("Maestro", "Admin"), async (req, res) => {
  const { idTutor, nombre, apellido, fechaNacimiento, alergias, grupo } = req.body || {};

  if (!idTutor || !nombre || !apellido || !fechaNacimiento || !grupo) {
    return res.status(400).json({ error: "Campos requeridos: idTutor, nombre, apellido, fechaNacimiento, grupo" });
  }

  const tutorId = Number(idTutor);
  if (!Number.isInteger(tutorId)) return res.status(400).json({ error: "idTutor inválido" });

  try {
    const pool = await poolPromise;

    // Verificar que el tutor existe
    const rTutor = await pool.request()
      .input("idTutor", sql.Int, tutorId)
      .query(`SELECT 1 AS ok FROM Tutores WHERE IdTutor = @idTutor`);

    if (!rTutor.recordset[0]?.ok) {
      return res.status(404).json({ error: "Tutor no encontrado" });
    }

    const result = await pool.request()
      .input("idTutor",        sql.Int,          tutorId)
      .input("nombre",         sql.NVarChar(100), String(nombre).trim())
      .input("apellido",       sql.NVarChar(100), String(apellido).trim())
      .input("fechaNacimiento",sql.Date,          new Date(fechaNacimiento))
      .input("alergias",       sql.NVarChar(255), alergias ? String(alergias).trim() : null)
      .input("grupo", sql.Int, Number(grupo))
      .query(`
        INSERT INTO Ninos (IdTutor, Nombre, Apellido, FechaNacimiento, Alergias, Grupo)
        OUTPUT INSERTED.IdNino
        VALUES (@idTutor, @nombre, @apellido, @fechaNacimiento, @alergias, @grupo)
      `);

    res.status(201).json({ ok: true, IdNino: result.recordset[0].IdNino });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al registrar niño" });
  }
});


app.get("/ninos", requireAuth, requireRole("Maestro", "Admin"), async (req, res) => {
  try {
    const pool = await poolPromise;
    const r = await pool.request().query(`
      SELECT n.IdNino, n.IdTutor, n.Nombre, n.Apellido, n.FechaNacimiento, n.Alergias, b.nombre_nivel AS Grupo,
             t.Nombre AS TutorNombre, t.Apellido AS TutorApellido
      FROM Ninos n
      INNER JOIN Tutores t ON t.IdTutor = n.IdTutor
      INNER JOIN nivel b ON n.Grupo = b.id_nivel
      ORDER BY n.IdNino DESC
    `);
    res.json(r.recordset);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al obtener niños" });
  }
});

/** Obtener un niño por ID (Maestro o Admin) */
app.get("/ninos/:id", requireAuth, requireRole("Maestro", "Admin"), async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: "ID inválido" });

  try {
    const pool = await poolPromise;
    const r = await pool.request()
      .input("id", sql.Int, id)
      .query(`
        SELECT n.IdNino, n.IdTutor, n.Nombre, n.Apellido, n.FechaNacimiento, n.Alergias, b.nombre_nivel AS Grupo,
               t.Nombre AS TutorNombre, t.Apellido AS TutorApellido
        FROM Ninos n
        INNER JOIN Tutores t ON t.IdTutor = n.IdTutor
        INNER JOIN nivel b ON n.Grupo = b.id_nivel
        WHERE n.IdNino = @id
      `);

    if (!r.recordset[0]) return res.status(404).json({ error: "Niño no encontrado" });
    res.json(r.recordset[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al obtener niño" });
  }
});

/** Actualizar niño (Maestro o Admin) */
app.put("/ninos/:id", requireAuth, requireRole("Maestro", "Admin"), async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: "ID inválido" });

  const { idTutor, nombre, apellido, fechaNacimiento, alergias, grupo } = req.body || {};
  if (!idTutor || !nombre || !apellido || !fechaNacimiento || !grupo)
    return res.status(400).json({ error: "Campos requeridos: idTutor, nombre, apellido, fechaNacimiento, grupo" });

  try {
    const pool = await poolPromise;
    const r = await pool.request()
      .input("id",              sql.Int,           id)
      .input("idTutor",         sql.Int,           Number(idTutor))
      .input("nombre",          sql.NVarChar(100), String(nombre).trim())
      .input("apellido",        sql.NVarChar(100), String(apellido).trim())
      .input("fechaNacimiento", sql.Date,          new Date(fechaNacimiento))
      .input("alergias",        sql.NVarChar(255), alergias ? String(alergias).trim() : null)
      .input("grupo",           sql.NVarChar(50),  String(grupo).trim())
      .query(`
        UPDATE Ninos
        SET IdTutor=@idTutor, Nombre=@nombre, Apellido=@apellido,
            FechaNacimiento=@fechaNacimiento, Alergias=@alergias, Grupo=@grupo
        WHERE IdNino=@id;
        SELECT @@ROWCOUNT AS affected;
      `);

    if ((r.recordset[0]?.affected || 0) === 0)
      return res.status(404).json({ error: "Niño no encontrado" });

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al actualizar niño" });
  }
});

/** Eliminar niño (solo Admin) */
app.delete("/ninos/:id", requireAuth, requireRole("Admin"), async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: "ID inválido" });

  try {
    const pool = await poolPromise;
    const r = await pool.request()
      .input("id", sql.Int, id)
      .query(`DELETE FROM Ninos WHERE IdNino=@id; SELECT @@ROWCOUNT AS affected;`);

    if ((r.recordset[0]?.affected || 0) === 0)
      return res.status(404).json({ error: "Niño no encontrado" });

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al eliminar niño" });
  }
});

/* -------------------- Padre endpoints -------------------- */
/** Listar mis niños (Padre) */
app.get("/padre/ninos", requireAuth, requireRole("Padre"), async (req, res) => {
  const pool = await poolPromise;
  const rTutor = await pool.request()
    .input("idUsuario", sql.Int, req.user.id)
 .query(`SELECT IdTutor, Nombre, Apellido, TelefonoCifrado, DireccionCifrada FROM Tutores WHERE IdUsuario=@idUsuario`);

  const tutor = rTutor.recordset[0];
  if (!tutor) return res.json({ tutor: null, ninos: [] });

  const rNinos = await pool.request()
    .input("idTutor", sql.Int, tutor.IdTutor)
    .query(`SELECT a.IdNino, a.Nombre, a.Apellido, a.FechaNacimiento, a.Alergias, b.nombre_nivel
      FROM Ninos INNER JOIN nivel b ON a.Grupo = b.id_nivel
      WHERE IdTutor=@idTutor ORDER BY IdNino`);

  // Devolvemos datos sensibles desencriptados SOLO para demo (en prod: cuidado con esto)
  const tutorView = {
    idTutor: tutor.IdTutor,
    nombre: tutor.Nombre,
    apellido: tutor.Apellido,
    telefono: decryptAesGcm(tutor.TelefonoCifrado),
    direccion: decryptAesGcm(tutor.DireccionCifrada)
  };

  res.json({ tutor: tutorView, ninos: rNinos.recordset });
});

/** Ver bitácora de un niño (Padre) */
app.get("/padre/ninos/:idNino/bitacora", requireAuth, requireRole("Padre","Admin"), async (req, res) => {
  const idNino = Number(req.params.idNino);
  if (!Number.isInteger(idNino)) return res.status(400).json({ error: "IdNino inválido" });

  const ok = await assertChildBelongsToParent(req.user.id, idNino);
  if (!ok) return res.status(403).json({ error: "No autorizado para este niño" });

  const pool = await poolPromise;
  const r = await pool.request()
    .input("idNino", sql.Int, idNino)
    .query(`
      SELECT TOP 50 IdLog, Fecha, Comida, SiestaMinutos, Observaciones, EstadoAnimo, IdMaestro
      FROM BitacoraDiaria
      WHERE IdNino=@idNino
      ORDER BY Fecha DESC
    `);

  res.json(r.recordset);
});

/* -------------------- Maestro endpoints -------------------- */
/** Registrar bitácora (Maestro o Admin) */
app.post("/bitacora", requireAuth, requireRole("Maestro","Admin"), async (req, res) => {
  const { idNino, comida=false, siestaMinutos=0, observaciones=null, estadoAnimo=null } = req.body || {};
  const ninoId = Number(idNino);
  if (!Number.isInteger(ninoId)) return res.status(400).json({ error: "idNino requerido" });

  const pool = await poolPromise;

  // Verificar que el niño existe
  const rN = await pool.request().input("id", sql.Int, ninoId).query(`SELECT 1 AS ok FROM Ninos WHERE IdNino=@id`);
  if (!rN.recordset[0]?.ok) return res.status(404).json({ error: "Niño no existe" });

  await pool.request()
    .input("idNino", sql.Int, ninoId)
    .input("idMaestro", sql.Int, req.user.id)
    .input("comida", sql.Bit, comida ? 1 : 0)
    .input("siesta", sql.Int, Number(siestaMinutos) || 0)
    .input("obs", sql.NVarChar(sql.MAX), observaciones)
    .input("animo", sql.NVarChar(50), estadoAnimo)
    .query(`
      INSERT INTO BitacoraDiaria (IdNino, IdMaestro, Comida, SiestaMinutos, Observaciones, EstadoAnimo)
      VALUES (@idNino, @idMaestro, @comida, @siesta, @obs, @animo)
    `);

  res.status(201).json({ ok: true });
});

/** Ver bitácora de un niño (Maestro o Admin) */
app.get("/bitacora/:idNino", requireAuth, requireRole("Maestro","Admin"), async (req, res) => {
  const idNino = Number(req.params.idNino);
  if (!Number.isInteger(idNino)) return res.status(400).json({ error: "IdNino inválido" });

  const pool = await poolPromise;
  const r = await pool.request()
    .input("idNino", sql.Int, idNino)
    .query(`
      SELECT IdLog, Fecha, Comida, SiestaMinutos, Observaciones, EstadoAnimo, IdMaestro
      FROM BitacoraDiaria
      WHERE IdNino=@idNino
      ORDER BY Fecha DESC
    `);

  res.json(r.recordset);
});

/** Ver todas las bitácoras (Maestro o Admin) */
app.get("/bitacora", requireAuth, requireRole("Maestro","Admin"), async (req, res) => {
  const pool = await poolPromise;
  const r = await pool.request().query(`
    SELECT b.IdLog, b.Fecha, b.Comida, b.SiestaMinutos, b.Observaciones, b.EstadoAnimo, b.IdMaestro,
           n.Nombre AS NinoNombre, n.Apellido AS NinoApellido
    FROM BitacoraDiaria b
    INNER JOIN Ninos n ON n.IdNino = b.IdNino
    ORDER BY b.Fecha DESC
  `);
  res.json(r.recordset);
});

/* -------------------- Notas de competencias -------------------- */
app.post("/notas-competencias", requireAuth, requireRole("Maestro","Admin"), async (req, res) => {
  const { idNino, competencia, nota, comentarios=null } = req.body || {};
  const ninoId = Number(idNino);
  const idnivel = Number(req.body.idNivel);
  const idcompetencia = Number(req.body.idCompetencia);
  const idreq = Number(req.body.idReq);

  if (!Number.isInteger(ninoId)) return res.status(400).json({ error: "idNino requerido" });
    if (!Number.isInteger(idcompetencia)) return res.status(400).json({ error: "idCompetencia requerido" });
  if(!Number.isInteger(idnivel)) return res.status(400).json({ error: "idNivel requerido" });
  if(!Number.isInteger(idreq) && req.body.idReq !== null) return res.status(400).json({ error: "idReq requerido" });

  const pool = await poolPromise;
  const rN = await pool.request().input("id", sql.Int, ninoId).query(`SELECT 1 AS ok FROM Ninos WHERE IdNino=@id`);
  if (!rN.recordset[0]?.ok) return res.status(404).json({ error: "Niño no existe" });

  const result = await pool.request()
    .input("idNino", sql.Int, ninoId)
    .input("idMaestro", sql.Int, req.user.id)
    .input("idNivel", sql.Int, idnivel)
    .input("idCompetencia", sql.Int, idcompetencia)
    .input("idreq", sql.Int, idreq || null)
    .input("opciones", sql.NVarChar(sql.MAX), req.body.opciones)
    .query(`
      INSERT INTO NotasCompetencias (IdNino, IdMaestro, idnivel, idCompetencia, idreq, opciones)
      OUTPUT INSERTED.id_nota
      VALUES (@idNino, @idMaestro,@idNivel, @idCompetencia, @idreq, @opciones)
    `);

  res.status(201).json({ ok: true, IdNota: result.recordset[0].IdNota });
});

app.get("/notas-competencias", requireAuth, requireRole("Maestro", "Admin"), async (req, res) => {
  try {
    const pool = await poolPromise;
    const r = await pool.request().query(`
      SELECT
        nc.id_nota,
        nc.opciones,
        nc.IdNino,
        n.Nombre       AS NinoNombre,
        n.Apellido     AS NinoApellido,
        nc.IdMaestro,
        u.Email        AS MaestroEmail,
        nv.nombre_nivel     AS NombreNivel,
        c.nombre_competencia AS NombreCompetencia,
        cr.nombre_criterios  AS NombreCriterio
      FROM NotasCompetencias nc
      INNER JOIN Ninos       n  ON n.idnino       = nc.IdNino
      INNER JOIN Usuarios    u  ON u.IdUsuario     = nc.IdMaestro
      INNER JOIN NIVEL       nv ON nv.id_nivel     = nc.idnivel
      INNER JOIN competencias c  ON c.id_comp      = nc.idcompetencia
      INNER JOIN criterios   cr ON cr.id_crit      = nc.idreq
      ORDER BY nc.id_nota DESC
    `);
    res.json(r.recordset);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al obtener evaluaciones" });
  }
});

// GET POR NIÑO
app.get("/notas-competencias/nino/:idNino", requireAuth, requireRole("Maestro", "Admin"), async (req, res) => {
  const idNino = Number(req.params.idNino);
  if (!Number.isInteger(idNino)) return res.status(400).json({ error: "IdNino inválido" });

  try {
    const pool = await poolPromise;
    const r = await pool.request()
      .input("idNino", sql.Int, idNino)
      .query(`
        SELECT
          nc.id_nota,
          nc.opciones,
          nc.IdNino,
          n.Nombre       AS NinoNombre,
          n.Apellido     AS NinoApellido,
          nc.IdMaestro,
          u.Email        AS MaestroEmail,
          nv.nombre_nivel      AS NombreNivel,
          c.nombre_competencia AS NombreCompetencia,
          cr.nombre_criterios  AS NombreCriterio
        FROM NotasCompetencias nc
        INNER JOIN Ninos       n  ON n.idnino       = nc.IdNino
        INNER JOIN Usuarios    u  ON u.IdUsuario     = nc.IdMaestro
        INNER JOIN NIVEL       nv ON nv.id_nivel     = nc.idnivel
        INNER JOIN competencias c  ON c.id_comp      = nc.idcompetencia
        INNER JOIN criterios   cr ON cr.id_crit      = nc.idreq
        WHERE nc.IdNino = @idNino
        ORDER BY nc.id_nota DESC
      `);
    res.json(r.recordset);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al obtener evaluaciones del niño" });
  }
});

// GET POR NIVEL
app.get("/notas-competencias/nivel/:idNivel", requireAuth, requireRole("Maestro", "Admin"), async (req, res) => {
  const idNivel = Number(req.params.idNivel);
  if (!Number.isInteger(idNivel)) return res.status(400).json({ error: "IdNivel inválido" });

  try {
    const pool = await poolPromise;
    const r = await pool.request()
      .input("idNivel", sql.Int, idNivel)
      .query(`
        SELECT
          nc.id_nota,
          nc.opciones,
          nc.IdNino,
          n.Nombre       AS NinoNombre,
          n.Apellido     AS NinoApellido,
          nc.IdMaestro,
          u.Email        AS MaestroEmail,
          nv.nombre_nivel      AS NombreNivel,
          c.nombre_competencia AS NombreCompetencia,
          cr.nombre_criterios  AS NombreCriterio
        FROM NotasCompetencias nc
        INNER JOIN Ninos       n  ON n.idnino       = nc.IdNino
        INNER JOIN Usuarios    u  ON u.IdUsuario     = nc.IdMaestro
        INNER JOIN NIVEL       nv ON nv.id_nivel     = nc.idnivel
        INNER JOIN competencias c  ON c.id_comp      = nc.idcompetencia
        INNER JOIN criterios   cr ON cr.id_crit      = nc.idreq
        WHERE nc.idnivel = @idNivel
        ORDER BY nc.id_nota DESC
      `);
    res.json(r.recordset);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al obtener evaluaciones por nivel" });
  }
});

// PUT
app.put("/notas-competencias/:idNota", requireAuth, requireRole("Maestro", "Admin"), async (req, res) => {
  const idNota = Number(req.params.idNota);
  const { idNivel, idCompetencia, idReq, opciones } = req.body || {};

  if (!Number.isInteger(idNota)) return res.status(400).json({ error: "IdNota inválido" });
  if (!idNivel || !idCompetencia || !idReq || !opciones) {
    return res.status(400).json({ error: "Todos los campos son requeridos" });
  }

  const opcionesValidas = ['Si', 'No'];
  if (!opcionesValidas.includes(opciones)) {
    return res.status(400).json({ error: "Opción inválida" });
  }

  try {
    const pool = await poolPromise;
    const r = await pool.request()
      .input("idNota",        sql.Int,          idNota)
      .input("idNivel",       sql.Int,          Number(idNivel))
      .input("idCompetencia", sql.Int,          Number(idCompetencia))
      .input("idReq",         sql.Int,          Number(idReq))
      .input("opciones",      sql.VarChar(25),  opciones)
      .query(`
        UPDATE NotasCompetencias
        SET idnivel       = @idNivel,
            idcompetencia = @idCompetencia,
            idreq         = @idReq,
            opciones      = @opciones
        WHERE id_nota = @idNota;
        SELECT @@ROWCOUNT AS affected;
      `);

    if ((r.recordset[0]?.affected || 0) === 0) {
      return res.status(404).json({ error: "Evaluación no encontrada" });
    }
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al actualizar evaluación" });
  }
});

// DELETE
app.delete("/notas-competencias/:idNota", requireAuth, requireRole("Maestro", "Admin"), async (req, res) => {
  const idNota = Number(req.params.idNota);
  if (!Number.isInteger(idNota)) return res.status(400).json({ error: "IdNota inválido" });

  try {
    const pool = await poolPromise;
    const r = await pool.request()
      .input("idNota", sql.Int, idNota)
      .query(`
        DELETE FROM NotasCompetencias WHERE id_nota = @idNota;
        SELECT @@ROWCOUNT AS affected;
      `);

    if ((r.recordset[0]?.affected || 0) === 0) {
      return res.status(404).json({ error: "Evaluación no encontrada" });
    }
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al eliminar evaluación" });
  }
});

app.get("/notas-competencias/:idNota", requireAuth, async (req, res) => {
  const idNota = Number(req.params.idNota);

  if (!Number.isInteger(idNota)) {
    return res.status(400).json({ error: "IdNota inválido" });
  }

  try {
    const pool = await poolPromise;
    const r = await pool.request()
      .input("idNota", sql.Int, idNota)
      .query(`
        SELECT
          id_nota,
          IdNino,
          idnivel,
          idcompetencia,
          idreq,
          opciones
        FROM NotasCompetencias
        WHERE id_nota = @idNota
      `);

    if (!r.recordset.length) {
      return res.status(404).json({ error: "No encontrado" });
    }

    res.json(r.recordset[0]);
  } catch (err) {
    res.status(500).json({ error: "Error al obtener evaluación" });
  }
});

/** Check-in (Maestro o Admin) */
app.post("/asistencia/checkin", requireAuth, requireRole("Maestro","Admin"), async (req, res) => {
  const { idNino } = req.body || {};
  const ninoId = Number(idNino);
  if (!Number.isInteger(ninoId)) return res.status(400).json({ error: "idNino requerido" });

  const pool = await poolPromise;
  await pool.request()
    .input("idNino", sql.Int, ninoId)
    .query(`INSERT INTO Asistencia (IdNino) VALUES (@idNino)`);

  res.status(201).json({ ok: true });
});

/** Check-out (Maestro o Admin) */
app.post("/asistencia/checkout", requireAuth, requireRole("Maestro","Admin"), async (req, res) => {
  const { idAsistencia, personaRecoge=null } = req.body || {};
  const asisId = Number(idAsistencia);
  if (!Number.isInteger(asisId)) return res.status(400).json({ error: "idAsistencia requerido" });

  const pool = await poolPromise;
  const r = await pool.request()
    .input("id", sql.Int, asisId)
    .input("p", sql.NVarChar(150), personaRecoge)
    .query(`
      UPDATE Asistencia
      SET HoraSalida = GETDATE(),
          PersonaRecoge = @p
      WHERE IdAsistencia=@id AND HoraSalida IS NULL;

      SELECT @@ROWCOUNT AS affected;
    `);

  if ((r.recordset[0]?.affected || 0) === 0) return res.status(404).json({ error: "Asistencia no encontrada o ya cerrada" });
  res.json({ ok: true });
});

/** Ver últimas asistencias (Maestro o Admin) */
/* ya no es necesario
app.get("/asistencia", requireAuth, requireRole("Maestro","Admin"), async (req, res) => {
  const pool = await poolPromise;
  const r = await pool.request().query(`
    SELECT TOP 50 IdAsistencia, IdNino, HoraEntrada, HoraSalida, PersonaRecoge
    FROM Asistencia
    ORDER BY HoraEntrada DESC
  `);
  res.json(r.recordset);
});
*/

app.get("/asistencia", requireAuth, requireRole("Maestro","Admin"), async (req, res) => {
  const pool = await poolPromise;
  const r = await pool.request().query(`
    SELECT a.IdAsistencia, b.nombre, b.apellido, a.HoraEntrada, a.HoraSalida, a.PersonaRecoge
    FROM Asistencia a
    JOIN Ninos b ON a.IdNino = b.IdNino
    ORDER BY a.idasistencia DESC
  `);
  res.json(r.recordset);
});

/** obtener niveles */
app.get("/niveles", requireAuth, requireRole("Maestro","Admin"), async (req, res) => {
  try {
    const pool = await poolPromise;
    const r = await pool.request().query(`
      SELECT id_nivel, nombre_nivel
      FROM NIVEL
    `);

    res.json(r.recordset);

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al obtener niveles" });
  }
});
app.get("/competencias/:nivelId", requireAuth, requireRole("Maestro", "Admin"), async (req, res) => {
  const nivelId = Number(req.params.nivelId);
  if (!Number.isInteger(nivelId)) return res.status(400).json({ error: "ID inválido" });

  try {
    const pool = await poolPromise;
    const r = await pool.request()
      .input("nivelId", sql.Int, nivelId)
      .query(`
        SELECT id_comp, nombre_competencia, nivel_id
        FROM competencias
        WHERE nivel_id = @nivelId
        ORDER BY id_comp asc
      `);
    res.json(r.recordset);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al obtener competencias" });
  }
});


app.get("/criterios/:competenciaId", requireAuth, requireRole("Maestro", "Admin"), async (req, res) => {
  const competenciaId = Number(req.params.competenciaId);
  if (!Number.isInteger(competenciaId)) return res.status(400).json({ error: "ID inválido" });

  try {
    const pool = await poolPromise;
    const r = await pool.request()
      .input("competenciaId", sql.Int, competenciaId)
      .query(`
        SELECT id_crit, nombre_criterios, comp_id
        FROM criterios
        WHERE comp_id = @competenciaId
        ORDER BY id_crit asc
      `);
    res.json(r.recordset);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al obtener criterios" });
  }
});

app.get("/idusuario", requireAuth, requireRole("Maestro", "Admin"), async (req, res) => {
  try {
    const pool = await poolPromise;
    const r = await pool.request()
      .query(`
        SELECT u.IdUsuario, u.Email
  FROM Usuarios u
  WHERE u.IdRole = 3
  AND NOT EXISTS (
    SELECT 1
    FROM Tutores t
    WHERE t.IdUsuario = u.IdUsuario)
      `);
    res.json(r.recordset);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al obtener id de usuario" });
  }
});

/* -------------------- Health check -------------------- */
app.get("/", (req, res) => res.json({ ok: true, name: "guarderia-api" }));

const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`API lista en http://localhost:${port}`));
