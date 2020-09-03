//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

const app = express();

app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.get("/", function(req, res){
  res.render("home");
});

app.get("/login", function(req, res){
  res.render("login");
});

app.get("/register", function(req, res){
  res.render("register");
});

app.get("/secrets", function(req, res){
  User.find({"secret": {$ne: null}}, function(err, foundUsers){
    if(err){console.log(err);}
    else{
      if(foundUsers){
        res.render("secrets", {usersWithSecrets: foundUsers});
      }
    }
  });
});

app.get("/logout", function(req, res){
  req.logout();
  res.redirect("/");
});

app.get("/submit", function(req, res){
  if(req.isAuthenticated()){res.render("submit");}
  else {res.redirect("/login");}
});

app.post("/register", function(req, res){
  User.register({username: req.body.username}, req.body.password, function(err, user){
    if(err){console.log(err); res.redirect("/register");}
    else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/login", function(req, res){
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err){
    if(err){
      console.log("sorry");
    }
    else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
    });
  }
});
});

app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;
  User.findById(req.user.id, function(err, foundUser){
    if(err){console.log(err);}
    else{
      if(foundUser){
        foundUser.secret = submittedSecret;
        foundUser.save(function(){res.redirect("/secrets")});
      }
    }
  });
});

app.listen(3000, function(){
  console.log("Hurray! Server started at port 3000.");
});

/***************************Encryption****************************/
/*
const encrypt = require("mongoose-encryption")  //-top
userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ['password']});   //-below userSchema
//the key is stored in .env file which will be ignored when commiting through the use of .gitignore
*/

/***************************Hashing*******************************/
/*
const md5 = require("md5"); //-top
const pass = md5(req.body.password); //in 'app.post("/login", ...)'  second line
password: md5(req.body.password)   //in 'app.post("/register", ...)' in 'const newUser'(json)
*/

/*************************Bcrypt Salting and Hashing**************/
/*
const bcrypt = require("bcrypt");
const saltRounds = 10;

app.post("/register", function(req, res){
  bcrypt.hash(req.body.password, saltRounds, function(err, hash){
    const newUser = new User({
      email: req.body.username,
      password: hash
    });
    newUser.save(function(err){
      if(!err){res.render("secrets")} //only renders when the user creates an account or logins with valid credentials
      else{console.log(err);}
    });
  });
});

app.post("/login", function(req, res){
  const username = req.body.username;
  const pass = req.body.password;

  User.findOne({email: username}, function(err, result){
    if(err){
      console.log(err);
    } else{
        if(result) {
          bcrypt.compare(pass, result.password, function(err, result2){
            if(result2 === true){ res.render("secrets");}
          });
      }
    }
  });
});
*/
