const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const multer = require("multer");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const path = require("path");
const cors = require("cors");
const dotenv = require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5000;

// SQLite database setup
const db = new sqlite3.Database(path.join(__dirname, "database.db"), (err) => {
    if (err) {
        console.error("Could not connect to database", err);
    } else {
        console.log("Connected to SQLite database");
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            password TEXT NOT NULL
        )`);
        db.run(`CREATE TABLE IF NOT EXISTS articles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);
        db.run(`CREATE TABLE IF NOT EXISTS steps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            articleId INTEGER,
            text TEXT,
            image TEXT,
            FOREIGN KEY(articleId) REFERENCES articles(id)
        )`);
    }
});

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use("/uploads", express.static("uploads"));

// Multer setup for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, "uploads/");
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    },
});
const upload = multer({ storage });

// User Registration
app.post("/register", async (req, res) => {
    const { name, password } = req.body;
    db.get("SELECT * FROM users WHERE name = ?", [name], async (err, row) => {
        if (row) {
            return res.status(400).json({ message: "User already exists. Kindly login." });
        }
        if (password.length < 8) {
            return res.status(400).json({ message: "Password must be at least 8 characters long." });
        }
        const hashedPassword = await bcrypt.hash(password, 12);
        db.run("INSERT INTO users (name, password) VALUES (?, ?)", [name, hashedPassword], function (err) {
            if (err) return res.status(500).json({ message: "Error registering user." });
            return res.status(200).json({ message: "Registration Successful", userId: this.lastID });
        });
    });
});

// User Login
app.post("/login", async (req, res) => {
    const { name, password } = req.body;
    db.get("SELECT * FROM users WHERE name = ?", [name], async (err, user) => {
        if (!user) {
            return res.status(400).json({ message: "User not found." });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: "Incorrect Username or Password." });
        }
        const accessToken = jwt.sign({ userId: user.id }, process.env.ACCESS_URL, { expiresIn: "7d" });
        return res.status(200).json({ message: "Successful Login", accessToken, userId: user.id });
    });
});

// Add Article
app.post("/addpost", upload.array("images"), async (req, res) => {
    try {
        const { title, steps } = req.body;
        const parsedSteps = JSON.parse(steps);
        db.run("INSERT INTO articles (title) VALUES (?)", [title], function (err) {
            if (err) return res.status(500).json({ message: "Error creating article." });
            const articleId = this.lastID;
            const stmt = db.prepare("INSERT INTO steps (articleId, text, image) VALUES (?, ?, ?)");
            parsedSteps.forEach((step, index) => {
                stmt.run(articleId, step.text, req.files[index] ? req.files[index].path : null);
            });
            stmt.finalize();
            return res.status(201).json({ message: "Article Created", articleId });
        });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: "Error creating article." });
    }
});

// Get All Articles
app.get("/allarticle", async (req, res) => {
    db.all("SELECT * FROM articles", [], async (err, articles) => {
        if (err) return res.status(500).json({ message: "Error fetching articles." });
        const articlesWithSteps = await Promise.all(
            articles.map((article) => {
                return new Promise((resolve) => {
                    db.all("SELECT * FROM steps WHERE articleId = ?", [article.id], (err, steps) => {
                        resolve({ ...article, steps });
                    });
                });
            })
        );
        return res.status(200).json({ message: "All articles", articles: articlesWithSteps });
    });
});

// Get Single Article
app.get("/allarticle/:id", (req, res) => {
    const { id } = req.params;
    db.get("SELECT * FROM articles WHERE id = ?", [id], (err, article) => {
        if (err) return res.status(500).json({ message: "Error fetching article." });
        if (!article) return res.status(404).json({ message: "Article not found." });
        db.all("SELECT * FROM steps WHERE articleId = ?", [id], (err, steps) => {
            if (err) return res.status(500).json({ message: "Error fetching steps." });
            return res.status(200).json({ ...article, steps });
        });
    });
});

// Validate Token Middleware
const validtoken = (req, res, next) => {
    const token = req.header("Authorization");
    if (!token) return res.status(403).json({ message: "Access denied." });
    const tokenParts = token.split(" ");
    const tokenString = tokenParts[1];
    jwt.verify(tokenString, process.env.ACCESS_URL, (err, decoded) => {
        if (err) return res.status(401).json({ message: "Invalid token." });
        req.userId = decoded.userId;
        next();
    });
};

// Start the server
app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});
