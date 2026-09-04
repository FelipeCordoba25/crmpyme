
const express = require('express');

const app = express();
app.use(express.json());

//ruta principal del 
app.get("/", (req, res) => {
  res.send("Raiz Proyecto");
});

const bcrypt = require('bcrypt');
const { Usuario, Rol } = require('./models');
app.post('/auth/login', async (req, res) => {
const { correo, password } = req.body;
if (!correo || !password) {
return res.status(400).json({ error: 'Correo y contraseña son obligatorios' });
}
const usuario = await Usuario.findOne({ where: { correo }, include: Rol });
if (!usuario) {
return res.status(401).json({ error: 'Correo o contraseña incorrectos' });
}
const passwordValido = await bcrypt.compare(password, usuario.passwordHash);
if (!passwordValido) {
return res.status(401).json({ error: 'Correo o contraseña incorrectos' });
}
res.json({ id: usuario.id, nombre: usuario.nombre, rol: usuario.Rol.nombre });
});

app.listen(3000, () => {
  console.log("Servidor escuchando en http://localhost:3000");
});
