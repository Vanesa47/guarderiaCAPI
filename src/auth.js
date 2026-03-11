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

import jwt from "jsonwebtoken";
import { poolPromise, sql } from "./db.js";

export function requireRole(...allowed) {
  return (req, res, next) => {
    const roleName = req.user?.roleName;
    if (!roleName) return res.status(401).json({ error: "No autenticado" });
    if (!allowed.includes(roleName)) return res.status(403).json({ error: "No autorizado" });
    next();
  };
}

/** Auth + timeout 1 minuto basado en Usuarios.UltimaActividad */
export async function requireAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    const token =   (authHeader && authHeader.startsWith("Bearer ") ? authHeader.split(" ")[1] : null)
                    || req.cookies?.auth;
    if (!token) return res.status(401).json({ error: "No autenticado" });

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch {
      return res.status(401).json({ error: "Token inválido/expirado" });
    }

    const pool = await poolPromise;
    const r = await pool.request()
      .input("id", sql.Int, decoded.sub)
      .query(`
        SELECT u.IdUsuario, u.Email, u.IdRole, u.EstaActivo, u.UltimaActividad, r.NombreRole
        FROM Usuarios u
        INNER JOIN Roles r ON r.IdRole = u.IdRole
        WHERE u.IdUsuario = @id
      `);

    const u = r.recordset[0];
    if (!u || !u.EstaActivo) return res.status(401).json({ error: "Usuario inactivo" });

    const last = new Date(u.UltimaActividad);
    const diff = Date.now() - last.getTime();
    if (diff > 60_000) {
      res.clearCookie("auth");
      return res.status(401).json({ error: "Sesión expirada por inactividad (>1 min)" });
    }

    // Sliding update
    await pool.request()
      .input("id", sql.Int, u.IdUsuario)
      .query(`UPDATE Usuarios SET UltimaActividad = GETDATE() WHERE IdUsuario = @id`);

    req.user = {
      id: u.IdUsuario,
      email: u.Email,
      idRole: u.IdRole,
      roleName: u.NombreRole
    };

    next();
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Error interno" });
  }
}

/** Scope helper: devuelve IdTutor del padre (si existe) */
export async function getTutorIdForUser(userId) {
  const pool = await poolPromise;
  const r = await pool.request()
    .input("idUsuario", sql.Int, userId)
    .query(`SELECT IdTutor FROM Tutores WHERE IdUsuario=@idUsuario`);
  return r.recordset[0]?.IdTutor ?? null;
}

/** Padre: valida que el niño pertenezca al tutor del usuario */
export async function assertChildBelongsToParent(userId, idNino) {
  const tutorId = await getTutorIdForUser(userId);
  if (!tutorId) return false;

  const pool = await poolPromise;
  const r = await pool.request()
    .input("idTutor", sql.Int, tutorId)
    .input("idNino", sql.Int, idNino)
    .query(`SELECT 1 AS ok FROM Ninos WHERE IdNino=@idNino AND IdTutor=@idTutor`);
  return !!r.recordset[0]?.ok;
}
