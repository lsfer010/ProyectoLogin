//1 - Invocamos a express
const express = require('express');
const app = express();

//2 - configuramos urlencoded para capturar datos de formulario
app.use(express.urlencoded({extended:false}));
app.use(express.json());

//3 - Invocar dotenv para variables de entorno.
const dotenv = require('dotenv');
dotenv.config({path:'./env/.env'}); //todas las variables de entorno estarán en el directorio env/.env

//4 - Establecer la carpeta public para los recursos de la web.
app.use('/resources', express.static('public'));
app.use('/resources', express.static(__dirname + '/public')); //Esta línea es por si mudamos el proyecto a otro lugar sin tener que volver a configurar algún parámetro.

//5 - Establecer motor de plantillas ejs
app.set('view engine', 'ejs');

//6 - Invocar a módulo de encriptación de contraseñas bcryptjs
const bcryptjs = require('bcryptjs');

//7 - Variables de sesión
const session = require('express-session');
app.use(session({
    secret: 'secret',
    resave: true,
    saveUninitialized: true 
}));

//8 - Invocamos al módulo de conexión de la BBDD
const connection = require('./database/db');
const bcrypt = require('bcryptjs/dist/bcrypt');


//9 - Establecer las rutas
app.get('/login', (req, res) => {
    res.render('login');
});

app.get('/register', (req, res) => {
    res.render('register');
});

//10 - Registro de usuarios

app.post('/register', async (req, res) => {
    const user = req.body.user;
    const name = req.body.name;
    const rol = req.body.rol;
    const pass = req.body.pass;
    let passwordHash = await bcryptjs.hash(pass, 8);
    connection.query('INSERT INTO users SET ? ', {user:user, name:name, rol:rol, pass:passwordHash}, async (error, results) => {
        if(error) {
            console.log('¡Ocurrio un error al registrar el usuario! : ' + error);
            res.render('register', {
                alert: true,
                alertTitle: "Ooops!",
                alertMessage:"Something went wrong!",
                alertIcon: "error",
                showConfirmButton:false,
                timer:1500,
                ruta:'register'
            });
        } else {
            res.render('register', {
                alert: true,
                alertTitle: "Registration",
                alertMessage:"Successful Registration!",
                alertIcon: "success",
                showConfirmButton:false,
                timer:1500,
                ruta:''
            });
        }
    });

});

//11 - Autenticación
app.post("/auth", async (req, res) => {
    const user = req.body.user;
    const password = req.body.pass;
    let passwordHash = await bcryptjs.hash(password, 8);
    if(user && password) {
        connection.query('SELECT * FROM users WHERE user = ?',[user], async (error, results) => {
            if(results.length == 0 || !(await bcryptjs.compare(password, results[0].pass))) { //si no hay ningun resultado porque el nombre de usuario no se encontró o si la pass no es correcta, se manda mensaje de user/pass incorrecto, si no es así se manda OK.
                res.render('login', {
                    alert: true,
                    alertTitle: "Ooops!",
                    alertMessage:"Incorrect username or password!",
                    alertIcon: "error",
                    showConfirmButton: true,
                    timer: false,
                    ruta:'login'
                });
            } else {
                req.session.loggedin = true; //Ayuda para autenticar en las demás páginas.
                req.session.name = results[0].name; //ponemos una variable de sesión para ver el usuario que se autenticó.
                res.render('login', {
                    alert: true,
                    alertTitle: "Welcome!",
                    alertMessage:"Success Login!",
                    alertIcon: "success",
                    showConfirmButton: false,
                    timer: 1500,
                    ruta:''
                });
            }
        });
    } else {
        res.render('login', {
            alert: true,
            alertTitle: "Ooops!",
            alertMessage:"Please enter a valid username and password",
            alertIcon: "warning",
            showConfirmButton: true,
            timer: false,
            ruta:'login'
        });
    }
});

//12 - Auth pages
app.get('/', (req, res) => {
    if(req.session.loggedin) {
        res.render('index', {
            login: true,
            name: req.session.name
        });
    } else {
        res.render('index', {
            login: false,
            name: 'You must log in first'
        });
    }
});

//13 - Para cerrar la sesión
app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/');
    });
});

//14 - Ejecutando el servidor de la aplicación
app.listen(3000, (req, res) => {
    console.log('SERVER RUNNING ON http://localhost:3000');
});