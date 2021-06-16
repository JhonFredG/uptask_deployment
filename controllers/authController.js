const passport = require('../config/passport');
const Usuarios = require('../models/Usuarios');
const Sequelize = require('sequelize');
const bcrypt = require('bcrypt-nodejs');
const Op = Sequelize.Op;
const crypto = require('crypto');

const enviarEmail = require('../handlers/email')

exports.autentiacarUsuario = passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/iniciar-sesion',
    failureFlash: true,
    badRequestMessage: 'Ambos campos son obligatorios'
});

// Función para revisar si el usuario esta logueado o no
exports.usuarioAutenticado = (req, res, next) => {
    // Si el usuario esta autenticado, adelante
    if(req.isAuthenticated()) {
        return next();
    }

    // Si no esta autenticado, redirigir al formulario
    return res.redirect('/iniciar-sesion');
}

// Función para cerrar sesión
exports.cerrarSesion = (req, res) => {
    req.session.destroy( () => {
        res.redirect('/iniciar-sesion'); // Al cerrar sesion nos lleva al login
    });
}

// Genera un token si el usuario es valido
exports.enviarToken = async (req, res) => {
    // Verificar que el usuario existe
    const { email } = req.body;
    const usuario = await Usuarios.findOne({ where: { email } });

    // Si no existe el usuario
    if(!usuario) {
        req.flash('error', 'No existe esa cuenta');
        res.redirect('/reestablecer')
    }

    // Usuario existe
    usuario.token = crypto.randomBytes(20).toString('hex');
    usuario.expiracion = Date.now() + 3600000;

    await usuario.save();

    // Url de reset
    const resetUrl = `http://${req.headers.host}/reestablecer/${usuario.token}`;
    
    // Envía el correo con el Token
    await enviarEmail.enviar({
        usuario,
        subject: 'Password Reset',
        resetUrl,
        archivo: 'reestablecer-password'
    });


    // Finalizar
    req.flash('correcto', 'Se envio un mensaje a tu correo');
    res.redirect('/iniciar-sesion');
}

exports.validarToken = async (req, res) => {
    const usuario = await Usuarios.findOne({
        where: {
            token: req.params.token
        } 
    });

    // Si no encuentra usuario
    if(!usuario) {
        req.flash('error', 'No Válido');
        res.redirect('/reestablecer');
    }

    // Formulario para generar el password
    res.render('resetPassword', {
        nombrePagina: 'Reestablecer Contraseña'
    });
};

// Cambia el password por uno nuevo
exports.actualizarPassword = async (req, res) => {

    // Verifica el token valido pero tambien la fecha de expiracion
    const usuario = await Usuarios.findOne({
        where: {
            token: req.params.token,
            expiracion: {
                [Op.gte]: Date.now()
            }
        },
    });
    // Verificar si el usuario existe
    if(!usuario) {
        req.flash('error', 'No Válido');
        res.redirect('/reestablecer');
    }

    // Hashear el nuevo password

    usuario.password = bcrypt.hashSync(req.body.password, bcrypt.genSaltSync(10));
    usuario.token = null;
    usuario.expiracion = null;

    // Guardamos el nuevo password
    await usuario.save();

    req.flash('correcto', 'Tu password se ha modificado correctamente');
    res.redirect('/iniciar-sesion');
}