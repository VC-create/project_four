require("dotenv").config();
const sanitizeHTML = require("sanitize-html");
const marked = require("marked");
//previous line configs the .env file so we can access the stuff in it
const express = require("express");
const jwt = require("jsonwebtoken");

//this hashes peoples passwords
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
//this imports our database and names it ourApp.db
const db = require("better-sqlite3")("ourApp.db")
//this makes the performace and speed better
db.pragma("journal_mode = WAL")

//database setup here
//can see it by downloading from here https://sqlitebrowser.org/ and clicling open database and choosing ourApp.db
//name of the table is users
//and it has 3 columns: id, username, password

//db.prepare("DROP TABLE IF EXISTS users").run();
//db.prepare("DROP TABLE IF EXISTS posts").run();
//ran the line abaove to delete the table and recreate it, then it worked fine
//authorid referneces id
const createTables = db.transaction(() => {
    db.prepare(`
        CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username STRING NOT NULL UNIQUE,
        password STRING NOT NULL
        )
    `).run()
    db.prepare(`
        CREATE TABLE IF NOT EXISTS posts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        createdDate TEXT,
        title STRING NOT NULL,
        body TEXT NOT NULL,
        authorid INTEGER,
        FOREIGN KEY(authorid) REFERENCES users (id)
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
app.use(cookieParser())

//middleware
//this function is used for every route in our application;
app.use(function(req,res,next){
    //make our markdown function avialable to views
    //marked.parse turns the text into html 
    res.locals.filterUserHTML = function(content){
        return sanitizeHTML(marked.parse(content), {
            allowedTags: ["p", "br", "ul", "li", "ol", "strong", "bold", "i", "em", "h1", "h2", "h3", "h4", "h5", "h6"] , 
            allowedAttributes: {}
        })
    }
    //locals makes it avaible to the views system
    res.locals.errors = [];

    //try to decode incoming cookie
    //helps to check if user is logged in
    try {
        const decoded = jwt.verify(req.cookies.ourSimpleApp,process.env.JWTSECRET);
        req.user = decoded;
    } catch (error) {
        req.user = false;
    }
    res.locals.user = req.user;
    //console.log(req.user);
    next();
    //first it sets the array then renders the homepage 
});

app.get("/", (req,res)=>{
    //if theyre logged in
    if(req.user){
        //return it so that it doesn't execute the rest of the statement
        const postsStatement = db.prepare("SELECT * FROM posts WHERE authorid = ?");
        //.all() will return an array, multiple objects instead of a single object like .get()
        const posts = postsStatement.all(req.user.userid);
        return res.render("dashboard.ejs", {posts});
    }
    res.render("homepage.ejs");
});

app.get("/login", (req,res)=>{
    res.render("login.ejs");
});

//when the user clicks the logout button, it activates this logout route
//which clears the cookie by saying the name of the cookie which was ourSimpleApp
//and it redirects them to the homepage
app.get("/logout", (req,res)=>{
    res.clearCookie("ourSimpleApp");
    res.redirect("/");
});

app.post("/login",(req,res)=>{
    //check for errors when logging in - when they click the login button
    let errors=[]

    //check to make sure the type is a string and there's no funny buisness
    if(typeof req.body.username!=="string") req.body.username=""
    if(typeof req.body.password!=="string") req.body.password=""

    //if the username or password is empty give error message
    if(req.body.username.trim()=="") errors=["Invalid username/password"];
    if(req.body.username=="") errors=["Invalid username/password"];
    
    //if there is any errors in errors array, show the login page again but with the errors at the top
    if (errors.length){
        return res.render("login.ejs",{errors});
    }

    //now check if the password is a match in the database
    //* means all, the first line selects the column of all usernames
    //the second line gets the username of that specific user
    const userInQuestionStatement = db.prepare("SELECT * FROM users WHERE USERNAME=?");
    const userInQuestion = userInQuestionStatement.get(req.body.username);
    
    //if there isn't a match, return the error right away
    if(!userInQuestion){
        errors = ["Invalid username/password"];
        return res.render("login.ejs",{errors});
    }

    //comapre the password in the databse (userInQuestion.password) with what they entered in req.body
    const matchOrNot = bcrypt.compareSync(req.body.password,userInQuestion.password)
    if(!matchOrNot){
        errors = ["Invalid username/password"];
        return res.render("login.ejs",{errors});
    }

    //give them a cookie if its actually a match and redirect them
    const ourTokenValue = jwt.sign({exp: Math.floor(Date.now()/1000) + 60*60*24,skyColor:"blue",userid:userInQuestion.id, username: userInQuestion.username},process.env.JWTSECRET)
    
    //makes it secure for them
    res.cookie("ourSimpleApp",ourTokenValue,{
        httpOnly:true,
        secure:true,
        sameSite:"strict",
        maxAge:1000 * 60 * 60 * 24
    })

    res.redirect("/");

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

    //check if username already exists
    const usernameStatement = db.prepare("SELECT * FROM users WHERE username=?");
    const usernameCheck = usernameStatement.get(req.body.username);
    if(usernameCheck) errors.push("That username already exists");

    if(!req.body.password) errors.push("You must provide a password")
    if(req.body.password && req.body.password.length < 6) errors.push("Password must be at least 6 characters long")
    if(req.body.password && req.body.password.length > 12) errors.push("Password can't exceed 12 characters")
    
    //if there are errors, render them on the homepage
    //ex:it shows the error on the homepage
    if (errors.length){
        return res.render("homepage.ejs",{errors});
    }

    //hashing the password
    const salt = bcrypt.genSaltSync(10);
    req.body.password = bcrypt.hashSync(req.body.password, salt);
    //save the user into the database
    const ourStatement = db.prepare("INSERT INTO users (username, password) VALUES (?,?)")
    const result = ourStatement.run(req.body.username, req.body.password)

    const lookupStatement = db.prepare("SELECT * FROM users  WHERE ROWID = ?");
    //gets the id from the last user in the database
    const ourUser = lookupStatement.get(result.lastInsertRowid);
    //res.send("thank you")

    //log the user in by giving them a cookie
    //so that they see their logged in page
    const ourTokenValue = jwt.sign({exp: Math.floor(Date.now()/1000) + 60*60*24,skyColor:"blue",userid:ourUser.id, username: ourUser.username},process.env.JWTSECRET)
    
    //makes it secure for them
    res.cookie("ourSimpleApp",ourTokenValue,{
        httpOnly:true,
        secure:true,
        sameSite:"strict",
        maxAge:1000 * 60 * 60 * 24
    })

    res.redirect("/");
});

//create a reusable function to be used by create-post - form of middleware
//checks if userIsLogged in before they can create a post
function mustBeLoggedIn(req,res,next){
    if(req.user){
        return next();
    }
    return res.redirect("/");
}

app.get("/create-post", mustBeLoggedIn, (req,res)=>{
    res.render("create-post.ejs");
});

//use this to check for errors later on, in the create post, edit post, etc routes
function sharedPostValidation(req){
    const errors = [];

    if(typeof req.body.title !=="string") req.body.title="";
    if(typeof req.body.title !=="string") req.body.title="";

    //take out malicious html from database (from the title and body)
    req.body.title = sanitizeHTML(req.body.title.trim(),{allowedTags:[], allowedAttributes: {}});
    req.body.body = sanitizeHTML(req.body.body.trim(),{allowedTags:[], allowedAttributes: {}});

    //check to make sure it isn't empty
    if(!req.body.title) errors.push("You must provide a title");
    if(!req.body.body) errors.push("You must provide content");
    
    return errors;
}

//this just gets all the data that is needed to edit the post, but it doesn't save those edits into the database
//you need a post request to save the changes in the database
app.get("/edit-post/:id", mustBeLoggedIn,(req,res)=>{
    //look up the post in question
    const statement = db.prepare("SELECT * FROM posts WHERE id =?");
    const post = statement.get(req.params.id);

    //check to make sure id of post exists, make sure they're not trying to access page that doesn't exist
    if(!post){
        return res.redirect("/");
    }
    //if not the author, redirect back to homepage /
    if(post.authorid!==req.user.userid){
        return res.redirect("/");
    }
    //otherwise if you are the author, render the edit-post ejs template
    res.render("edit-post", {post});
});

app.post("/edit-post/:id", mustBeLoggedIn,(req,res)=>{
    const statement = db.prepare("SELECT * FROM posts WHERE id =?");
    const post = statement.get(req.params.id);
    if(!post){
        return res.redirect("/");
    }
    if(post.authorid!==req.user.userid){
        return res.redirect("/");
    }
    const errors =sharedPostValidation(req);
    if(errors.length){
        return res.render("edit-post", {errors});
    }
    const updateStatement = db.prepare("UPDATE posts SET title=?, body=? WHERE id=?");
    updateStatement.run(req.body.title, req.body.body, req.params.id);

    res.redirect(`/post/${req.params.id}`);

});

app.post("/delete-post/:id", mustBeLoggedIn,(req,res)=>{
    const statement = db.prepare("SELECT * FROM posts WHERE id =?");
    const post = statement.get(req.params.id);
    if(!post){
        return res.redirect("/");
    }
    if(post.authorid!==req.user.userid){
        return res.redirect("/");
    }

    const deleteStatement = db.prepare("DELETE FROM posts WHERE id=?");
    deleteStatement.run(req.params.id);
    res.redirect("/");
});

//this makes it dynamic so it works with any id, because you don't want to hardcode it
app.get("/post/:id", (req,res)=>{
    //conect the tables by joining them with author id and users.id (its the same thing)
    //now the posts table has the username
    //try to find the id here so you can use it to say who it's posted by 
    const statement = db.prepare("SELECT posts.*, users.username FROM posts INNER JOIN users on posts.authorid = users.id WHERE posts.id = ?");
    const post = statement.get(req.params.id); 

    //if that id doesn't exist for the post, like they're trying to access a page that doesn't exist
    if(!post){
        return res.redirect("/");
    }
    const isAuthor = post.authorid === req.user.userid;
    //return the page that has that post 
    //render it with the ejs template
    //this also passes the isAuthor to the ejs page so you can use it there
    res.render("single-post.ejs", {post, isAuthor}); 
});

//when you submit the form for creating a post, it goes here, because the form is of method POST
app.post("/create-post", mustBeLoggedIn, (req,res)=>{
    const errors = sharedPostValidation(req);
    if(errors.length){
        return res.render("create-post",{errors});
    }
    //save into database by adding it into posts
    //same thing as how we saved the user in /register route
    const ourStatement = db.prepare("INSERT INTO posts(title,body,authorid, createdDate) VALUES (?,?,?,?)");
    const result = ourStatement.run(req.body.title, req.body.body, req.user.userid, new Date().toISOString());
    
    const getPostStatement = db.prepare("SELECT * FROM posts WHERE ROWID = ?");
    const realPost = getPostStatement.get(result.lastInsertRowid);
    //console.log(realPost);
    //so far this just sends them to that unique id for the post, but it doesn't render them a page since that route 
    //with the unique id doesn't exist yet
    res.redirect(`/post/${realPost.id}`);

});

const PORT = 3000;
app.listen(PORT);