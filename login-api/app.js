var express = require('express')
var cors = require('cors')
var app = express()
var bodyParser = require('body-parser')
var jsonParser = bodyParser.json()
const bcrypt = require('bcrypt');
const saltRounds = 10;
var jwt = require('jsonwebtoken');
const secret = 'Basic-login';




app.use(cors())

const mysql = require('mysql2');
// Create the connection to database
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    database: 'mydb',
});

app.post('/register',jsonParser, function (req, res, next) {
    bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
        connection.execute(
            'INSERT INTO users (email, password, fname, lname) VALUES (?, ?, ?, ?)',
            [req.body.email, hash, req.body.fname, req.body.lname],
            function (err, results, fields) {
              if (err) {
                res.json({status: 'error',massage: err})
                return
              }
              res.json({status: 'ok'})
            }
        );
    });
})

app.post('/login',jsonParser, function (req, res, next) {
    connection.execute(
        'SELECT * FROM users WHERE email=?',
        [req.body.email],
        function (err, users, fields) {
          if (err) {
            res.json({status: 'error',massage: err})
            return
          }
          if(users.length == 0){ 
            res.json({status: 'error' ,massage: 'User not found'})
            return
          }
          bcrypt.compare(req.body.password, users[0].password, function(err, islogin) {
            if (islogin) {
              var token = jwt.sign({email: users[0].email }, secret,{ expiresIn: '1h' } );
              res.json({status: 'ok',massage: 'Login Success',token})
              return
            } else {
                res.json({status: 'error',massage: 'Login Failure'})
                return
            }
          });
        }
    );
})

app.post('/authen', jsonParser, function(req, res, next) {
    try{
        const token = req.headers.authorization.split(' ')[1]
        var decoded = jwt.verify(token, secret);
        res.json({status: 'ok',decoded})
    }catch(err){
        res.json({status: 'error', massage: err.message})
    }
    
})

app.listen(3333, function () {
  console.log('Enabled web server listening on port 3333')
})