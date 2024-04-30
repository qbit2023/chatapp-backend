const express = require("express");
const http = require("http");
const socketIo = require("socket.io");
const bodyParser = require("body-parser");
const passport = require("passport");
const LocalStrategy = require("passport-local");
const bcrypt = require("bcrypt");
const mysql = require("mysql");
const cors = require("cors");
const session = require("express-session");

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// MySQL database configuration
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "root",
  database: "userdb",
});

// Connect to MySQL
db.connect((err) => {
  if (err) {
    console.error("MySQL connection error:", err);
    process.exit(1);
  }
  console.log("Connected to MySQL database");
});

// Express middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json()); // Parse JSON bodies
app.use(
  session({
    secret: "abc123",
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());
app.use(cors());

// Passport configuration
passport.use(
  new LocalStrategy(function verify(username, password, done) {
    db.query(
      "SELECT * FROM users WHERE username = ?",
      [username],
      function (err, rows) {
        if (err) {
          return done(err);
        }
        if (!rows || !rows.length) {
          return done(null, false, { message: "Incorrect username." });
        }
        const user = rows[0];
        bcrypt.compare(password, user.password, function (err, isMatch) {
          if (err) {
            return done(err);
          }
          if (isMatch) {
            return done(null, user);
          } else {
            return done(null, false, { message: "Incorrect password." });
          }
        });
      }
    );
  })
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  db.query("SELECT * FROM users WHERE id = ?", [id], (err, rows) => {
    if (err) {
      console.error("Error in deserializeUser:", err);
      return done(err);
    }
    done(null, rows[0]);
  });
});

// login
app.post("/login", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) {
      console.error("Error in passport.authenticate:", err);
      return next(err);
    }
    if (!user) {
      return res.status(401).json({ message: info.message });
    }
    req.logIn(user, (err) => {
      if (err) {
        console.error("Error in req.logIn:", err);
        return next(err);
      }
      console.log("user: ", user);
      return res.status(200).json({ message: "Login successful", user });
    });
  })(req, res, next);
});

// Implement logout functionality
app.post("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      console.error("Logout error:", err);
      return res.status(500).json({ message: "Error logging out" });
    }
    return res.status(200).json({ message: "Logout successful" });
  });
});

app.post("/register", async (req, res) => {
  const { username, password, mobile } = req.body;
  try {
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);
    db.query(
      "INSERT INTO users (username, password, mobile) VALUES (?, ?, ?)",
      [username, hash, mobile],
      (err, result) => {
        if (err) {
          console.error("Error registering user:", err);
          return res.status(500).json({ message: "Error registering user" });
        }
        return res.status(201).json({ message: "Registration successful" });
      }
    );
  } catch (error) {
    console.error("Error hashing password:", error);
    return res.status(500).json({ message: "Error hashing password" });
  }
});

// Socket.io logic
io.on("connection", (socket) => {
  console.log("a user connected");

  socket.on("join group", ({ username, groupName }) => {
    console.log(`${username} joined group: ${groupName}`);
    socket.groupName = groupName;
    socket.join(groupName);
  });

  socket.on("leave group", ({ username, groupName }) => {
    console.log(`${username} left group: ${groupName}`);
    socket.leave(groupName);
  });

  socket.on("chat message", ({ sender, message }) => {
    const groupName = socket.groupName;
    io.to(groupName).emit("chat message", { sender, message });
    console.log(`${sender} sent message: ${message}`);
  });

  socket.on("disconnect", () => {
    console.log("user disconnected");
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});


