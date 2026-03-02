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
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

import { poolPromise, sql } from "./db.js";
import { requireAuth, requireRole, assertChildBelongsToParent } from "./auth.js";
import { decryptAesGcm } from "./crypto.js";

dotenv.config();

const app = express();
app.use(helmet());
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
    secure: false, // prod: true (https)
    sameSite: "lax",
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
          .input("id", sql.Int, u.IdUsuario)
          .query(`
            UPDATE Usuarios
            SET IntentosFallidos=${nextFails}, BloqueadoHasta=DATEADD(minute, 15, GETDATE())
            WHERE IdUsuario=@id
          `);
      } else {
        await pool.request()
          .input("id", sql.Int, u.IdUsuario)
          .query(`
            UPDATE Usuarios
            SET IntentosFallidos=${nextFails}
            WHERE IdUsuario=@id
          `);
      }

      return genericFail();
    }

    await pool.request()
      .input("id", sql.Int, u.IdUsuario)
      .query(`
        UPDATE Usuarios
        SET IntentosFallidos=0, BloqueadoHasta=NULL, UltimaActividad=GETDATE()
        WHERE IdUsuario=@id
      `);

    const token = signToken(u);
    setAuthCookie(res, token);

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
    .query(`SELECT IdNino, Nombre, Apellido, FechaNacimiento, Alergias, Grupo FROM Ninos WHERE IdTutor=@idTutor ORDER BY IdNino`);

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
app.get("/padre/ninos/:idNino/bitacora", requireAuth, requireRole("Padre"), async (req, res) => {
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
app.get("/asistencia", requireAuth, requireRole("Maestro","Admin"), async (req, res) => {
  const pool = await poolPromise;
  const r = await pool.request().query(`
    SELECT TOP 50 IdAsistencia, IdNino, HoraEntrada, HoraSalida, PersonaRecoge
    FROM Asistencia
    ORDER BY HoraEntrada DESC
  `);
  res.json(r.recordset);
});

/* -------------------- Health check -------------------- */
app.get("/", (req, res) => res.json({ ok: true, name: "guarderia-api" }));

const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`API lista en http://localhost:${port}`));
