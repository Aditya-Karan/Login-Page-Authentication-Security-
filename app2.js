require("dotenv").config();
const bodyParser=require("body-parser");
const ejs=require("ejs");
const express=require("express");
const mongoose=require("mongoose");
const encrypt=require("mongoose-encryption"); 
const session=require("express-session");
const passport=require("passport");
const passportLocal=require("passport-local");
const passportLocalMongoose=require("passport-local-mongoose");
const GoogleStrategy=require("passport-google-oauth20").Strategy;
const findOrCreate=require("mongoose-findorcreate");


const app=express();

app.set("view engine","ejs");
app.use(bodyParser.urlencoded({extended:true}));
app.use(express.static("public"));


app.use(session({
    secret:"Our little secret",
    resave:false,
    saveUninitialized:false
}));
app.use(passport.initialize());
app.use(passport.session());


mongoose.connect('mongodb://127.0.0.1:27017/userDB',{useNewUrlParser:true});

const userSchema=new mongoose.Schema({
    email:String,
    password:String,
    googleId:String,
    secret:String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User=new mongoose.model("User",userSchema)

passport.use(User.createStrategy());
passport.serializeUser(function(user, done) {
    done(null,user.id);
});
  
passport.deserializeUser(function(id, done) {
    User.findById(id)
    .then(function(user){
        done(null,user);
    })
    .catch(function(err){
        console.log(err);
    })
});
  

passport.use(new GoogleStrategy({
    clientID:process.env.CLIENT_ID,
    clientSecret:process.env.CLIENT_SECRET,
    callbackURL:"https://localhost:3000/auth/google/secrets",
    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
    },
    function(accessToken, refreshToken, profile, cb){
        console.log(profile);
        User.findOrCreate({googleId:profile.id},function(err,user){
            return cb(err,user);
        });
    }
));

app.post("/register",function(req,res){
    
   User.register({username:req.body.username},req.body.password)
   .then(function(user){
        passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
        })
   })
   .catch(function(err){
        console.log(err);
        res.redirect("/register")
   })
});

app.post("/login",function(req,res){

    const user=new User({
        username:req.body.username,
        password:req.body.password
    });

    req.login(user,function(err){
        if(err){
            console.log(err);
        }
        else{
            passport.authenticate("local")(req,res,function(){
            res.redirect("/secrets");
            })
        }
    })
});


app.post("/submit",function(req,res){
    const submittedSecret=req.body.secret;

    console.log(req.user)

    User.findById(req.user.id)
    .then(function(found){
        if(found){
            found.secret=submittedSecret;
            found.save()
            res.redirect("/secrets");
        };
    })
    .catch(function(err){
        console.log(err);
    })
})

app.get("/auth/google",passport.authenticate("google",{scope:["profile"]}));

app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect("/secrets");
});

app.get("/",function(req,res){
    res.render("home")
})

app.get("/login",function(req,res){
    res.render("login")
})

app.get("/register",function(req,res){
    res.render("register")
})

app.get("/secrets",function(req,res){
    User.find({"secret":{$ne:null}})
    .then(function(found){
        if(found){
            res.render("secrets",{usersWithSecret:found})
        }
    })
    .catch(function(err){
        console.log(err);
    });
});

app.get("/logout",function(req,res){

    req.logout(function(err){
        if(err){
            console.log(err);
        }
        else{
            res.redirect("/");
        }
    })
})

app.get("/submit",function(req,res){
    if(req.isAuthenticated()){
        res.render("submit");
    }
    else{
        res.redirect("/login"); 
   }
})




app.listen(3001,function(req,res){
    console.log("server started")
})