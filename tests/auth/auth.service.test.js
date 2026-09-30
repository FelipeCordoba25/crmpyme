// Corrección a la guía: al simular los modelos nunca se carga dotenv,
// así que el secreto del JWT se define aquí para la prueba.
process.env.JWT_SECRET = 'secreto-de-prueba';

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

jest.mock('../../models', () => ({ Usuario: { findOne: jest.fn() }, Rol: {} }));

const { Usuario } = require('../../models');
const authService = require('../../src/modules/auth/auth.service');

let hash;
beforeAll(async () => {
  hash = await bcrypt.hash('Admin123', 10);
});

function crearUsuarioMock(cambios = {}) {
  return {
    id: 1,
    nombre: 'Administrador Inicial',
    passwordHash: hash,
    intentosFallidos: 0,
    bloqueadoHasta: null,
    Rol: { nombre: 'administrador' },
    update: jest.fn(),
    ...cambios,
  };
}

describe('authService.login', () => {
  // Los 2 casos de la guía 

  it('rechaza un correo que no existe', async () => {
    Usuario.findOne.mockResolvedValueOnce(null);
    await expect(authService.login('no-existe@x.com', 'cualquiera'))
      .rejects.toMatchObject({ status: 401, code: 'CREDENCIALES_INVALIDAS' });
  });

  it('genera un token cuando la contraseña es correcta', async () => {
    Usuario.findOne.mockResolvedValueOnce(crearUsuarioMock());
    const resultado = await authService.login('admin@crm.local', 'Admin123');
    expect(resultado.token).toBeDefined();
  });

  // casos extra: cubren los criterios de aceptación de HU-01

  it('con contraseña incorrecta rechaza y suma un intento fallido', async () => {
    const usuario = crearUsuarioMock();
    Usuario.findOne.mockResolvedValueOnce(usuario);
    await expect(authService.login('admin@crm.local', 'claveMala'))
      .rejects.toMatchObject({ status: 401, code: 'CREDENCIALES_INVALIDAS' });
    expect(usuario.update).toHaveBeenCalledWith({ intentosFallidos: 1, bloqueadoHasta: null });
  });

  it('al quinto fallo bloquea la cuenta 5 minutos', async () => {
    const usuario = crearUsuarioMock({ intentosFallidos: 4 });
    Usuario.findOne.mockResolvedValueOnce(usuario);
    await expect(authService.login('admin@crm.local', 'claveMala')).rejects.toMatchObject({ status: 401 });

    const [[datos]] = usuario.update.mock.calls;
    expect(datos.intentosFallidos).toBe(0);
    expect(datos.bloqueadoHasta.getTime()).toBeGreaterThan(Date.now());
  });

  it('con la cuenta bloqueada responde 423 aunque la contraseña sea correcta', async () => {
    const usuario = crearUsuarioMock({ bloqueadoHasta: new Date(Date.now() + 3 * 60000) });
    Usuario.findOne.mockResolvedValueOnce(usuario);
    await expect(authService.login('admin@crm.local', 'Admin123'))
      .rejects.toMatchObject({ status: 423, code: 'CUENTA_BLOQUEADA' });
    expect(usuario.update).not.toHaveBeenCalled();
  });

  it('un login correcto reinicia los intentos y el token lleva el rol, sin la contraseña', async () => {
    const usuario = crearUsuarioMock({ intentosFallidos: 3 });
    Usuario.findOne.mockResolvedValueOnce(usuario);
    const { token } = await authService.login('admin@crm.local', 'Admin123');

    expect(usuario.update).toHaveBeenCalledWith({ intentosFallidos: 0, bloqueadoHasta: null });
    const contenido = jwt.verify(token, process.env.JWT_SECRET);
    expect(contenido.rol).toBe('administrador');
    expect(contenido.passwordHash).toBeUndefined();
  });
});
