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


IF DB_ID('GuarderiaDB') IS NULL
BEGIN
    CREATE DATABASE GuarderiaDB;
END
GO

USE GuarderiaDB;
GO

/* Limpieza opcional (si re-ejecutas) */
IF OBJECT_ID('dbo.Asistencia', 'U') IS NOT NULL DROP TABLE dbo.Asistencia;
IF OBJECT_ID('dbo.BitacoraDiaria', 'U') IS NOT NULL DROP TABLE dbo.BitacoraDiaria;
IF OBJECT_ID('dbo.Ninos', 'U') IS NOT NULL DROP TABLE dbo.Ninos;
IF OBJECT_ID('dbo.Tutores', 'U') IS NOT NULL DROP TABLE dbo.Tutores;
IF OBJECT_ID('dbo.Usuarios', 'U') IS NOT NULL DROP TABLE dbo.Usuarios;
IF OBJECT_ID('dbo.Roles', 'U') IS NOT NULL DROP TABLE dbo.Roles;
GO

/* 1) Roles */
CREATE TABLE dbo.Roles (
    IdRole INT IDENTITY(1,1) PRIMARY KEY,
    NombreRole NVARCHAR(20) NOT NULL UNIQUE
);
GO

/* 2) Usuarios */
CREATE TABLE dbo.Usuarios (
    IdUsuario INT IDENTITY(1,1) PRIMARY KEY,
    Email NVARCHAR(100) NOT NULL UNIQUE,
    PasswordHash NVARCHAR(MAX) NOT NULL, -- Bcrypt hash
    IdRole INT NOT NULL,
    IntentosFallidos INT NOT NULL CONSTRAINT DF_Usuarios_Intentos DEFAULT 0,
    BloqueadoHasta DATETIME NULL,
    EstaActivo BIT NOT NULL CONSTRAINT DF_Usuarios_Activo DEFAULT 1,
    UltimaActividad DATETIME NOT NULL CONSTRAINT DF_Usuarios_UltAct DEFAULT GETDATE(),
    CONSTRAINT FK_Usuarios_Roles FOREIGN KEY (IdRole) REFERENCES dbo.Roles(IdRole)
);
GO

CREATE INDEX IX_Usuarios_Email ON dbo.Usuarios(Email);
CREATE INDEX IX_Usuarios_Bloqueo ON dbo.Usuarios(BloqueadoHasta);
GO

/* 3) Tutores (datos sensibles cifrados por app) */
CREATE TABLE dbo.Tutores (
    IdTutor INT IDENTITY(1,1) PRIMARY KEY,
    IdUsuario INT NOT NULL UNIQUE,
    Nombre NVARCHAR(100) NOT NULL,
    Apellido NVARCHAR(100) NOT NULL,
    TelefonoCifrado NVARCHAR(MAX) NOT NULL,
    DireccionCifrada NVARCHAR(MAX) NOT NULL,
    CONSTRAINT FK_Tutores_Usuarios FOREIGN KEY (IdUsuario) REFERENCES dbo.Usuarios(IdUsuario)
);
GO

/* 4) Niños (modelo actual: 1 tutor por niño) */
CREATE TABLE dbo.Ninos (
    IdNino INT IDENTITY(1,1) PRIMARY KEY,
    IdTutor INT NOT NULL,
    Nombre NVARCHAR(100) NOT NULL,
    Apellido NVARCHAR(100) NOT NULL,
    FechaNacimiento DATE NOT NULL,
    Alergias NVARCHAR(MAX) NULL,
    Grupo NVARCHAR(20) NULL,
    CONSTRAINT FK_Ninos_Tutores FOREIGN KEY (IdTutor) REFERENCES dbo.Tutores(IdTutor)
);
GO

CREATE INDEX IX_Ninos_Tutor ON dbo.Ninos(IdTutor);
GO

/* 5) Bitácora diaria */
CREATE TABLE dbo.BitacoraDiaria (
    IdLog INT IDENTITY(1,1) PRIMARY KEY,
    IdNino INT NOT NULL,
    IdMaestro INT NOT NULL,
    Fecha DATETIME NOT NULL CONSTRAINT DF_Bitacora_Fecha DEFAULT GETDATE(),
    Comida BIT NOT NULL CONSTRAINT DF_Bitacora_Comida DEFAULT 0,
    SiestaMinutos INT NOT NULL CONSTRAINT DF_Bitacora_Siesta DEFAULT 0,
    Observaciones NVARCHAR(MAX) NULL,
    EstadoAnimo NVARCHAR(50) NULL,
    CONSTRAINT FK_Bitacora_Ninos FOREIGN KEY (IdNino) REFERENCES dbo.Ninos(IdNino),
    CONSTRAINT FK_Bitacora_Usuarios FOREIGN KEY (IdMaestro) REFERENCES dbo.Usuarios(IdUsuario)
);
GO

CREATE INDEX IX_Bitacora_NinoFecha ON dbo.BitacoraDiaria(IdNino, Fecha DESC);
GO

/* 6) Notas de competencias */
CREATE TABLE dbo.NotasCompetencias (
    IdNota INT IDENTITY(1,1) PRIMARY KEY,
    IdNino INT NOT NULL,
    IdMaestro INT NULL,
    Fecha DATETIME NOT NULL CONSTRAINT DF_NotasCompetencias_Fecha DEFAULT GETDATE(),
    Competencia NVARCHAR(100) NOT NULL,
    Nota DECIMAL(4,2) NULL,
    Comentarios NVARCHAR(MAX) NULL,
    CONSTRAINT FK_NotasCompetencias_Ninos FOREIGN KEY (IdNino) REFERENCES dbo.Ninos(IdNino),
    CONSTRAINT FK_NotasCompetencias_Usuarios FOREIGN KEY (IdMaestro) REFERENCES dbo.Usuarios(IdUsuario),
    CONSTRAINT CK_NotasCompetencias_Nota CHECK (Nota BETWEEN 1.00 AND 10.00)
);
GO

/* 7) Asistencia */
CREATE TABLE dbo.Asistencia (
    IdAsistencia INT IDENTITY(1,1) PRIMARY KEY,
    IdNino INT NOT NULL,
    HoraEntrada DATETIME NOT NULL CONSTRAINT DF_Asistencia_Entrada DEFAULT GETDATE(),
    HoraSalida DATETIME NULL,
    PersonaRecoge NVARCHAR(150) NULL,
    CONSTRAINT FK_Asistencia_Ninos FOREIGN KEY (IdNino) REFERENCES dbo.Ninos(IdNino)
);
GO

CREATE INDEX IX_Asistencia_NinoEntrada ON dbo.Asistencia(IdNino, HoraEntrada DESC);
GO
