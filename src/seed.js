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

import dotenv from "dotenv";
dotenv.config();

import bcrypt from "bcrypt";
import { poolPromise, sql } from "./db.js";
import { encryptAesGcm } from "./crypto.js";

async function getRoleId(pool, roleName) {
  const r = await pool.request()
    .input("name", sql.NVarChar(20), roleName)
    .query(`SELECT IdRole FROM Roles WHERE NombreRole = @name`);
  if (!r.recordset[0]) throw new Error(`No existe el rol: ${roleName}. Ejecuta sql/02_seed_roles.sql`);
  return r.recordset[0].IdRole;
}

async function upsertUser(pool, email, plainPassword, idRole) {
  const normalized = String(email).trim().toLowerCase();
  const hash = await bcrypt.hash(plainPassword, 12);

  const existing = await pool.request()
    .input("email", sql.NVarChar(100), normalized)
    .query(`SELECT IdUsuario FROM Usuarios WHERE Email = @email`);

  if (existing.recordset[0]) {
    const id = existing.recordset[0].IdUsuario;
    await pool.request()
      .input("id", sql.Int, id)
      .input("hash", sql.NVarChar(sql.MAX), hash)
      .input("role", sql.Int, idRole)
      .query(`
        UPDATE Usuarios
        SET PasswordHash=@hash, IdRole=@role, IntentosFallidos=0, BloqueadoHasta=NULL, EstaActivo=1, UltimaActividad=GETDATE()
        WHERE IdUsuario=@id
      `);
    return id;
  }

  const ins = await pool.request()
    .input("email", sql.NVarChar(100), normalized)
    .input("hash", sql.NVarChar(sql.MAX), hash)
    .input("role", sql.Int, idRole)
    .query(`
      INSERT INTO Usuarios (Email, PasswordHash, IdRole)
      OUTPUT INSERTED.IdUsuario
      VALUES (@email, @hash, @role)
    `);

  return ins.recordset[0].IdUsuario;
}

async function ensureTutorAndChild(pool, idUsuarioPadre) {
  const tutorExists = await pool.request()
    .input("idUsuario", sql.Int, idUsuarioPadre)
    .query(`SELECT IdTutor FROM Tutores WHERE IdUsuario=@idUsuario`);

  let idTutor;
  if (tutorExists.recordset[0]) {
    idTutor = tutorExists.recordset[0].IdTutor;
  } else {
    const telC = encryptAesGcm("7000-0000");
    const dirC = encryptAesGcm("San Salvador, SV");

    const insTutor = await pool.request()
      .input("idUsuario", sql.Int, idUsuarioPadre)
      .input("nombre", sql.NVarChar(100), "Karen")
      .input("apellido", sql.NVarChar(100), "Cardona")
      .input("tel", sql.NVarChar(sql.MAX), telC)
      .input("dir", sql.NVarChar(sql.MAX), dirC)
      .query(`
        INSERT INTO Tutores (IdUsuario, Nombre, Apellido, TelefonoCifrado, DireccionCifrada)
        OUTPUT INSERTED.IdTutor
        VALUES (@idUsuario, @nombre, @apellido, @tel, @dir)
      `);

    idTutor = insTutor.recordset[0].IdTutor;
  }

  const childExists = await pool.request()
    .input("idTutor", sql.Int, idTutor)
    .query(`SELECT TOP 1 IdNino FROM Ninos WHERE IdTutor=@idTutor ORDER BY IdNino`);

  if (!childExists.recordset[0]) {
    await pool.request()
      .input("idTutor", sql.Int, idTutor)
      .input("nombre", sql.NVarChar(100), "Sofia")
      .input("apellido", sql.NVarChar(100), "Demo")
      .input("fn", sql.Date, "2022-05-10")
      .input("alergias", sql.NVarChar(sql.MAX), "Lactosa")
      .input("grupo", sql.NVarChar(20), "Maternal")
      .query(`
        INSERT INTO Ninos (IdTutor, Nombre, Apellido, FechaNacimiento, Alergias, Grupo)
        VALUES (@idTutor, @nombre, @apellido, @fn, @alergias, @grupo)
      `);
  }
}

async function main() {
  const pool = await poolPromise;

  const adminRole = await getRoleId(pool, "Admin");
  const maestroRole = await getRoleId(pool, "Maestro");
  const padreRole = await getRoleId(pool, "Padre");

  const adminId = await upsertUser(pool, "admin@demo.com", "Admin123!", adminRole);
  const maestroId = await upsertUser(pool, "maestro@demo.com", "Maestro123!", maestroRole);
  const padreId = await upsertUser(pool, "padre@demo.com", "Padre123!", padreRole);

  await ensureTutorAndChild(pool, padreId);

  console.log("Seed completado:");
  console.log(" admin@demo.com / Admin123!");
  console.log(" maestro@demo.com / Maestro123!");
  console.log(" padre@demo.com / Padre123!");
  console.log({ adminId, maestroId, padreId });

  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
