const express = require("express");
//this imports our database and names it ourApp.db
const db = require("better-sqlite3")("ourApp.db")
//this makes the performace and speed better?????/
db.pragma("journal_mode = WAL")

//database setup here
//can see it by downloading from here https://sqlitebrowser.org/ and clicling open database and choosing ourApp.db
//name of the table is users
//and it has 3 columns: id, username, password

const createTables = db.transaction(() => {
    db.prepare(`
        CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username STRING NOT NULL UNIQUE,
        password STRING NOT NULL
        )
    `).run()
});
createTables();
//database setup ends here



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
    
    //if there are errors, render them on the homepage
    //ex:it shows the error on the homepage
    if (errors.length){
        return res.render("homepage",{errors})
    }

    //save the user into the database
    const ourStatement = db.prepare("INSERT INTO users (username, password) VALUES (?,?)")
    ourStatement.run(req.body.username, req.body.password)
    res.send("thank you")
    //log the user in by giving them a cookie
    //so that they see their logged in page


});

app.listen(3000);