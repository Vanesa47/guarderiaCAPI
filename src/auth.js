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

export async function requireAuth(req, res, next) {
  try {
    const token = req.cookies?.auth;
    if (!token) return res.status(401).json({ error: "No autenticado" });

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (e) {
      return res.status(401).json({ error: "Token inválido/expirado" });
    }

    const pool = await poolPromise;
    const r = await pool.request()
      .input("id", sql.Int, decoded.sub)
      .query(`
        SELECT u.IdUsuario, u.Email, u.IdRole, u.EstaActivo, r.NombreRole,
               DATEDIFF(second, u.UltimaActividad, GETUTCDATE()) AS SegundosInactivo
        FROM Usuarios u
        INNER JOIN Roles r ON r.IdRole = u.IdRole
        WHERE u.IdUsuario = @id
      `);

    const u = r.recordset[0];
    if (!u || !u.EstaActivo) return res.status(401).json({ error: "Usuario inactivo" });

    const timeoutSegundos = Math.floor(Number(process.env.SESSION_TIMEOUT_MS || 1_800_000) / 1000);

    if (u.SegundosInactivo > timeoutSegundos) {
      res.clearCookie("auth");
      return res.status(401).json({ error: "Sesión expirada por inactividad" });
    }

    await pool.request()
      .input("id", sql.Int, u.IdUsuario)
      .query(`UPDATE Usuarios SET UltimaActividad = GETUTCDATE() WHERE IdUsuario = @id`);

    req.user = {
      id: u.IdUsuario,
      email: u.Email,
      idRole: u.IdRole,
      roleName: u.NombreRole
    };

   next();
  } catch (e) {
    console.error("💥 Error en requireAuth:", e);
    res.status(500).json({ error: "Error interno" });
  }
}

export async function getTutorIdForUser(userId) {
  const pool = await poolPromise;
  const r = await pool.request()
    .input("idUsuario", sql.Int, userId)
    .query(`SELECT IdTutor FROM Tutores WHERE IdUsuario=@idUsuario`);
  return r.recordset[0]?.IdTutor ?? null;
}

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
