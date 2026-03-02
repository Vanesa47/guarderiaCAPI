USE GuarderiaDB;
GO

IF NOT EXISTS (SELECT 1 FROM dbo.Roles WHERE NombreRole='Admin')
    INSERT INTO dbo.Roles (NombreRole) VALUES ('Admin');

IF NOT EXISTS (SELECT 1 FROM dbo.Roles WHERE NombreRole='Maestro')
    INSERT INTO dbo.Roles (NombreRole) VALUES ('Maestro');

IF NOT EXISTS (SELECT 1 FROM dbo.Roles WHERE NombreRole='Padre')
    INSERT INTO dbo.Roles (NombreRole) VALUES ('Padre');

SELECT * FROM dbo.Roles;
GO
