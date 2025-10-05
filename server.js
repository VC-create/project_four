const express = require("express");
const app = express();

app.set("view engine", "ejs");
//makes it so that we can access values the user put in
app.use(express.urlencoded({extended:false}))
app.use(express.static("public"));

//middleware
app.use(function(req,res,next){
    //locals makes it avaible to the views system
    res.locals.errors = [];
    next();
    //first it sets the array then renders the homepage 
});

app.get("/", (req,res)=>{
    res.render("homepage.ejs");
});

app.get("/login", (req,res)=>{
    res.render("login.ejs");
});

app.post("/register", (req,res)=>{
    const errors=[]

    if(typeof req.body.username!=="string") req.body.username=""
    if(typeof req.body.password!=="string") req.body.password=""

    //so that it removes spaces before or after
    req.body.username = req.body.username.trim()

    //if they leave it blank
    if(!req.body.username) errors.push("You must provide a username")
    if(req.body.username && req.body.username.length < 6) errors.push("Username must be at least 6 characters long")
    if(req.body.username && req.body.username.length > 12) errors.push("Username can't exceed 12 characters")
    if(req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)) errors.push("Username can only contain letters and numbers")

    if(!req.body.password) errors.push("You must provide a password")
    if(req.body.password && req.body.password.length < 6) errors.push("Password must be at least 6 characters long")
    if(req.body.password && req.body.password.length > 12) errors.push("Password can't exceed 12 characters")
    
    if (errors.length){
        return res.render("homepage",{errors})
    }
    else{
        res.send("thank you");
    }
});
app.listen(8000);