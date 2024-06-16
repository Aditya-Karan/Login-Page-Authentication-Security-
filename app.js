require("dotenv").config();     //Level 2 security - Cipher method
const bodyParser=require("body-parser");
const ejs=require("ejs");
const express=require("express");
const mongoose=require("mongoose");
const encrypt=require("mongoose-encryption"); //Level 2 security
const md5=require("md5");     //Level 3 security - hashing function
const bcrypt=require("bcrypt")    //Level 4 security - password hashed many times
const hashingRounds=10;

const app=express();
app.set("view engine","ejs");
app.use(bodyParser.urlencoded({extended:true}));
app.use(express.static("public"));
mongoose.connect('mongodb://127.0.0.1:27017/userDB',{useNewUrlParser:true});

const userSchema=new mongoose.Schema({
    email:String,
    password:String
});

// userSchema.plugin(encrypt,{secret:process.env.SECRET , encryptedFields:["password"]});  //Level 2 security

const User=new mongoose.model("User",userSchema)

app.post("/register",function(req,res){
    
    // const newUser=new User({         //level 2 security
    //     email:req.body.username,
    //     password:req.body.password
    // })


    // const newUser=new User({         //level 3 security
    //     email:req.body.username,
    //     password:md5(req.body.password)
    // })


    // newUser.save()
    // .then(function(){
    //     res.render("secrets")
    // })
    // .catch(function(err){
    //     console.log(err)
    // });

    
    bcrypt.hash(req.body.password,hashingRounds)     //level 4 security
    .then(function(hash){
        const newUser=new User({         
            email:req.body.username,
            password:hash
        })
    
    
        newUser.save()
        .then(function(){
            res.render("secrets")
        })
        .catch(function(err){
            console.log(err)
        });
    })
    .catch(function(err){
        console.log(err);
    });
});

app.post("/login",function(req,res){
    // const username=req.body.username;   //level 2 and level 3
    // const passwords=req.body.password;

    // User.findOne({email:username})
    // .then(function(found){
    //     if(found){
    //         if(found.password === md5(passwords)){
    //         res.render("secrets")
    //         }
    //     }
    // })
    // .catch(function(err){
    //     console.log(err)
    // });
    


    const username=req.body.username;   //level 4
    const passwords=req.body.password;

    User.findOne({email:username})
    .then(function(found){
        if(found){
            bcrypt.compare(passwords,found.password)
            .then(function(result){
                if(result){
                    res.render("secrets")
                }
            })
            .catch(function(err){
                console.log(err);
            });
        }
    })
    .catch(function(err){
        console.log(err)
    });



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



app.listen(3001,function(req,res){
    console.log("server started")
})