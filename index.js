/*
Запуск:
1. mongod --smallfiles (запуск БД)
2. forever start index.js (список запущенных sudo forever list, остановить forever stop index.js )
2a. node index.js

GIT:
1. Коммит: git commit -am 'text commit'
2. В ГитХаб: git push -u origin master   
3. Из ГитХаб: git pull origin master

*/

const Koa = require('koa'); // ядро
const Router = require('koa-router'); // маршрутизация
const bodyParser = require('koa-bodyparser'); // парсер для POST запросов
const serve = require('koa-static'); // модуль, который отдает статические файлы типа index.html из заданной директории
const logger = require('koa-logger'); // опциональный модуль для логов сетевых запросов. Полезен при разработке.

const passport = require('koa-passport'); //реализация passport для Koa
const LocalStrategy = require('passport-local'); //локальная стратегия авторизации
const JwtStrategy = require('passport-jwt').Strategy; // авторизация через JWT
const ExtractJwt = require('passport-jwt').ExtractJwt; // авторизация через JWT

const jwtsecret = "mysecretkey"; // ключ для подписи JWT
const jwt = require('jsonwebtoken'); // аутентификация  по JWT для hhtp
const socketioJwt = require('socketio-jwt'); // аутентификация  по JWT для socket.io

const socketIO = require('socket.io');

const mongoose = require('mongoose'); // стандартная прослойка для работы с MongoDB
const crypto = require('crypto'); // модуль node.js для выполнения различных шифровальных операций, в т.ч. для создания хэшей.

const app = new Koa();
const router = new Router();
app.use(serve('public'));
app.use(logger());
app.use(bodyParser());

app.use(passport.initialize()); // сначала passport
app.use(router.routes()); // потом маршруты


const server = app.listen(process.env.PORT || '8080', process.env.IP || 'localhost');// запускаем сервер на порту 3000
// const server = app.listen('8001','127.0.0.1');// запускаем сервер на порту 3000


// Add headers
app.use(function (req, res, next) {
    // Website you wish to allow to connect
    res.setHeader('Access-Control-Allow-Origin', 'http://localhost:8000');
    // Request methods you wish to allow
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');
    // Request headers you wish to allow
    res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,content-type');
    // Set to true if you need the website to include cookies in the requests sent
    // to the API (e.g. in case you use sessions)
    res.setHeader('Access-Control-Allow-Credentials', true);
    // Pass to next layer of middleware
    next();
});

mongoose.Promise = Promise; // Просим Mongoose использовать стандартные Промисы
mongoose.set('debug', true);  // Просим Mongoose писать все запросы к базе в консоль. Удобно для отладки кода
mongoose.connect('mongodb://localhost/test'); // Подключаемся к базе test на локальной машине. Если базы нет, она будет создана автоматически.
mongoose.connection.on('error', console.error);

//---------Схема и модель пользователя------------------//

const userSchema = new mongoose.Schema({
  displayName: String,
  email: {
    type: String,
    required: 'Укажите e-mail',
    unique: 'Такой e-mail уже существует'
  },
  passwordHash: String,
  salt: String,
  lists: String,
  listsDate: String,
}, {
  timestamps: true
});

userSchema.virtual('password')
.set(function (password) {
  this._plainPassword = password;
  if (password) {
    this.salt = crypto.randomBytes(128).toString('base64');
    this.passwordHash = crypto.pbkdf2Sync(password, this.salt, 1, 128, 'sha1');
  } else {
    this.salt = undefined;
    this.passwordHash = undefined;
  }
})

.get(function () {
  return this._plainPassword;
});

userSchema.methods.checkPassword = function (password) {
  if (!password) return false;
  if (!this.passwordHash) return false;
  return crypto.pbkdf2Sync(password, this.salt, 1, 128, 'sha1') == this.passwordHash;
};

const User = mongoose.model('User', userSchema);

//----------Passport Local Strategy--------------//

passport.use(new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password',
    session: false
  },
  function (email, password, done) {
    User.findOne({email}, (err, user) => {
      if (err) {
        return done(err);
      }
      
      if (!user || !user.checkPassword(password)) {
        return done(null, false, {message: 'Нет такого пользователя или пароль неверен.'});
      }
      return done(null, user);
    });
  }
  )
);

//----------Passport JWT Strategy--------//

// Ждем JWT в Header

const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeader(),
  secretOrKey: jwtsecret
};

passport.use(new JwtStrategy(jwtOptions, function (payload, done) {
    User.findById(payload.id, (err, user) => {
      if (err) {
        return done(err)
      }
      if (user) {
        done(null, user)
      } else {
        done(null, false)
      }
    })
  })
);

//---Socket Communication-----//
let io = socketIO(server);

io.on('connection', function (socket) {
  // Save List To DB
  socket.on('sendList', function (data) {
    if (typeof socket.decoded_token !== 'undefined') {
      let useremail = socket.decoded_token.email;
      console.log('email: ' + useremail);
      
      User.update({ email: useremail }, { lists: data }, function (err, raw) {
        if (err) console.log(err);
        console.log('The raw response from Mongo was ', raw);
        console.log('Send to room: ', useremail);
        socket.to(useremail).emit('updated_list',  data);
      });
    }
  });
  socket.on("login", function (data) {
    console.log('LOGIN');
    console.log(data);
    let user = JSON.parse(data);
    test_login(user.username, user.password, socket);
  });
  socket.on("register", function (data) {
    console.log('REGISTRATION');
    console.log(data);
    data = JSON.parse(data);
    User.create(data, (err, user) => {
    if (err) {
      socket.emit('registration_error', 'Пользователь с такой почтой уже зарегистрирован.');
    }else{
      socket.emit('registration_result', user);
    }
  });

  });
});

io.on('connection', socketioJwt.authorize({
  secret: jwtsecret,
  timeout: 15000
}))
.on('authenticated', function (socket) {
  Object.keys(io.sockets.sockets).forEach(function(id) {
      console.log("ID:",id)  // socketId
  });
  console.log('Это мое имя из токена: ' + socket.decoded_token.displayName);
  let email = socket.decoded_token.email;
  User.findOne({email}, (err, user) => {
    if (err) {
      console.log(err);
      return (err);
    }
    socket.join(email);
    socket.emit('authenticate_result',  user);
  });
});

function test_login(email, password, socket) {
    User.findOne({email}, (err, user) => {
      if (err) {
        console.log(err);
        return (err);
      }
      console.log(user);
      if (!user || !user.checkPassword(password)) {
        let error = 'К сожалению мы не нашли пользователя с такой почтой и паролем.<br/> Попробуйте еще раз или воспользуйтесь восстановлением пароля.';
        socket.emit('login_result', error);
        console.log(error);
      }else{
        //--payload - информация которую мы храним в токене и можем из него получать
        const payload = {
          id: user.id,
          displayName: user.displayName,
          email: user.email
        };
        const token = jwt.sign(payload, jwtsecret); //здесь создается JWT
        
        let body = {user: user.displayName, token: token};
        // отправляем ответ клиенту
        socket.emit('auth_accept', body);
        console.log(body);
      }
      
    });
  }