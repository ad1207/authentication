const express = require('express')
const bodyParser = require('body-parser')
const cookieParser = require('cookie-parser')
const session = require('express-session')
const RedisStore = require('connect-redis')
require('dotenv').config();
const jwt = require('jsonwebtoken')
const passport = require('passport');
const JwtStrategy = require('passport-jwt').Strategy
const GoogleStrategy = require('passport-google-oauth20').Strategy
const FacebookStrategy = require('passport-facebook').Strategy

const DATA = [ // should be a database or something persistant
  {email:"test@gmail.com", password:"1234"}, // user data from email-password
  {email:"test2@gmail.com", provider:"facebook"} // user data from OAuth has no password
]

const app = express()

app.use(bodyParser.urlencoded({extended: false}))
app.use(cookieParser())
app.use(session({
    secret: process.env.JWT_SECRET,
    resave: false,
    saveUninitialized: true,
  }))
app.use(passport.initialize())
app.use(passport.session())


function FindOrCreate(user){
    if(CheckUser(user)){
        return user
    }
    else{
        DATA.push(user)
    }
}

function CheckUser(user){
    for(let i=0;i<2;i++){
        if(user.email==DATA[i].email && user.password==DATA[i].password){
            return true
        }
    }
    return false
}


var opts = {}

opts.jwtFromRequest = function(req){
    var token = null;
    if(req && req.cookies){
        token = req.cookies['jwt']
    }
    return token
}

opts.secretOrKey = process.env.JWT_SECRET

passport.use(new JwtStrategy(opts,function(jwt_payload,done){
    console.log("JWT Based auth is called")
    if(CheckUser(jwt_payload.data)){
        return done(null,jwt_payload.data)
    }else{
        return done(null,false)
    }
}))

passport.use(new GoogleStrategy({
    clientID:process.env.GOOGLE_CLIENT_ID,
    clientSecret:process.env.GOOGLE_SECRET,
    callbackURL:'http://localhost:4000/googleRedirect'
    },
    function(accessToken, refreshToken, profile, done){
        console.log(profile)
        console.log("GOOGLE BASED OAUTH VALIDATION IS CALLED")
        return done(null,profile)
    }
))

passport.use(new FacebookStrategy({
    clientID:process.env.FACEBOOK_CLIENT_ID,
    clientSecret:process.env.FACEBOOK_SECRET,
    callbackURL:"http://localhost:5000/facebookRedirect",
    profileFields: ['id','displayName','email','picture']
    },
    function(accessToken,refreshToken,profile,done){
        console.log(profile)
        console.log("FACEBOOK BASED OAUTH VALIDATION IS CALLED")
        return done(null,profile)
    }
))

passport.serializeUser(function(user,done){
    console.log("serialize user")
    done(null,user)
})

passport.deserializeUser(function(obj,done){
    console.log('deserialize user')
    done(null,obj)
})


app.get('/',(req,res)=>{
    res.sendFile('home.html',{root:__dirname+'/public'})
})

app.get('/login', (req,res)=> {
    res.sendFile('login.html',{root:__dirname+'/public'})
})

app.get('/auth/email',(req,res)=> {
    res.sendFile('login_form.html',{root:__dirname+'/public'})
})

app.post('/auth/email',(req,res)=>{
    console.log(req.body.email)
    if(CheckUser(req.body)){
        let token = jwt.sign({
            data:req.body
        }, process.env.JWT_SECRET,
        {expiresIn:'1h'})
        res.cookie('jwt',token)
        res.send(`Log in success ${req.body.email}`)
    }else{
        res.send('Invalid login credentials')
    }
})

app.get('/auth/google', passport.authenticate('google',{scope:['profile','email']}))
app.get('/auth/facebook',passport.authenticate('facebook',{scope:'email'}))

app.get('/googleRedirect',passport.authenticate('google'),(req,res)=>{
    console.log('redirected',req.user)
    let user = {
        displayName: req.user.displayName,
        name:req.user.name.givenName,
        email:req.user._json.email,
        provider: req.user.provider
    }
    console.log(user)
    let token = jwt.sign({
        data:user
    }, process.env.JWT_SECRET, {expiresIn:"1h"})

    res.cookie('jwt',token)
    res.redirect('/')
})


app.get('/facebookRedirect',passport.authenticate('facebook',{scope:'email'}),(req,res)=>{
    console.log('redirected',req.user)
    let user = {
        displayName: req.user.displayName,
        name:req.user.__json.name,
        email:req.user.__json.email,
        provider: req.user.provider
    }
    console.log(user)

    FindOrCreate(user)
    let token = jwt.sign({
        data: user
    }, process.env.JWT_SECRET, {expiresIn:"1h"})
    res.cookie('jwt',token)
    res.redirect('/')
})

const PORT = process.env.PORT || 4000
app.listen(PORT,()=>{
    console.log("PORT")
})



