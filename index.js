
const express = require('express');

const app = express();
app.use(express.json());

//ruta principal del 
app.get("/", (req, res) => {
  res.send("Raiz Proyecto");
});

const bcrypt = require('bcrypt');
const { Usuario, Rol } = require('./models');
const jwt = require('jsonwebtoken');
app.post('/auth/login', async (req, res) => {
  const { correo, password } = req.body;

  if (!correo || !password) {
    return res.status(400).json({ error: 'Correo y contraseña son obligatorios' });
  }

  const usuario = await Usuario.findOne({ where: { correo }, include: Rol });
  if (!usuario) {
    return res.status(401).json({ error: 'Correo o contraseña incorrectos' });
  }

  if (usuario.bloqueadoHasta && usuario.bloqueadoHasta > new Date()) {
    const minutos = Math.ceil((usuario.bloqueadoHasta - new Date()) / 60000);
    return res.status(423).json({ error: `Cuenta bloqueada. Intenta en ${minutos} minuto(s).` });
  }

  const passwordValido = await bcrypt.compare(password, usuario.passwordHash);
  if (!passwordValido) {
    const nuevosIntentos = usuario.intentosFallidos + 1;
    const bloqueado = nuevosIntentos >= 5;
    await usuario.update({
      intentosFallidos: bloqueado ? 0 : nuevosIntentos,
      bloqueadoHasta: bloqueado ? new Date(Date.now() + 5 * 60000) : null,
    });
    return res.status(401).json({ error: 'Correo o contraseña incorrectos' });
  }

  await usuario.update({ intentosFallidos: 0, bloqueadoHasta: null });
  const usuarioPublico = { id: usuario.id, nombre: usuario.nombre, rol: usuario.Rol.nombre };
  const token = jwt.sign(usuarioPublico, process.env.JWT_SECRET, { expiresIn: '8h' });
  res.json({ token, usuario: usuarioPublico });
});

app.listen(3000, () => {
  console.log("Servidor escuchando en http://localhost:3000");
});
