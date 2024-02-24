import express from "express";
import bodyParser from "body-parser"
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;

env.config();

app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET,  
  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24
  }
}));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.USER,
  host: process.env.HOST,
  database: process.env.DATABASE,
  password: process.env.PASSWORD,
  port: process.env.PORT,
});

db.connect();

app.get("/", (req, res) => {
    res.render("index.ejs");
});

app.get("/login", (req, res)=>{
    res.render("login.ejs");
})

app.get('/sign_in', (req, res)=>{
    res.render("sign_in.ejs");
})

app.get("/join", (req, res) =>{
    console.log(req.user)
    if(req.isAuthenticated()){
      res.render("join.ejs")
    }else{
      res.redirect("/login")
    }
  })

app.post("/signup", async (req, res) => {
    const email = req.body.newUsername;
    const password = req.body.newPassword;
  
    try {
      const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
        email,
      ]);
  
      if (checkResult.rows.length > 0) {
        res.send("Email already exists. Try logging in.");
      } else {
        //hashing the password and saving it in the database
        bcrypt.hash(password, saltRounds, async (err, hash) => {
          if (err) {
            console.error("Error hashing password:", err);
          } else {
            console.log("Hashed Password:", hash);
            const result = await db.query(
              "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
              [email, hash]
            );
            const user = result.rows[0];
            console.log(user)
            req.login(user, (err) =>{
              console.log("sucess");
              res.redirect("/")
            })
          }
        });
      }
    } catch (err) {
      console.log(err);
    }
});

app.post("/signup", async (req, res) => {
    const newEmail = req.body.username;
    const newPassword = req.body.password;
  
    try {
      const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
        newEmail,
      ]);
  
      if (checkResult.rows.length > 0) {
        res.send("Email already exists. Try logging in.");
      } else {
        //hashing the password and saving it in the database
        bcrypt.hash(newPassword, saltRounds, async (err, hash) => {
          if (err) {
            console.error("Error hashing password:", err);
          } else {
            console.log("Hashed Password:", hash);
            const result = await db.query(
              "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
              [newEmail, hash]
            );
            const user = result.rows[0];
            console.log(user)
            req.login(user, (err) =>{
              console.log("sucess");
              res.redirect("/")
            })
          }
        });
      }
    } catch (err) {
      console.log(err);
    }
  });

app.post("/login", passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login"
  }));

passport.use(new Strategy(async function verify(username, password, cb){
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, result) => {
          if (err) {
            return cb(err);
          } else {
            if (result) {
              return cb(null, user);
            } else {
              return cb(null, false)
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      return cb(err);
    }
  }))
  
  passport.serializeUser((user, cb) =>{
    cb(null, user);
  });
  
  passport.deserializeUser((user, cb) =>{
    cb(null, user);
  });

  app.post("/contact", (req, res) => {
    const name = req.body.name;
    const email = req.body.email;
    const message = req.body.message;
    
    db.query("INSERT INTO queries(name, email, msg) VALUES($1, $2, $3)", [name, email, message], (err, result) => {
      if (err) {
        console.error('Error inserting message into database:', err);
        res.status(500).send('Internal Server Error');
      } else {
        res.send('<script>alert("Message sent successfully"); window.location.href = "/";</script>');
      }
    });
  });
  


app.listen(port, () => {
    console.log(`server running on port ${port}`);
});