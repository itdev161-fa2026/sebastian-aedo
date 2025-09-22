import express from "express";
import connectDatabase from "./config/db.js";
import { check, validationResult } from "express-validator";
import User from "./models/User.js";
import Post from "./models/Post.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import auth from "./middleware/auth.js";

dotenv.config();

const app = express();

connectDatabase();

app.use(express.json({ extended: false }));

app.get("/", (req, res) =>
  res.send("http get request sent to root api endpoint")
);

app.post(
  "/api/users",
  [
    check("name", "Please enter your name").not().isEmpty(),
    check("email", "Please enter a valid email").isEmail(),
    check(
      "password",
      "Please enter a password with 6 or more characters"
    ).isLength({ min: 6 }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const { name, email, password } = req.body;

    try {
      let user = await User.findOne({ email: email.toLowerCase() });
      if (user) {
        return res.status(400).json({
          errors: [{ msg: "User with this email already exists" }],
        });
      }
      user = new User({
        name,
        email: email.toLowerCase(),
        password,
      });

      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(password, salt);

      await user.save();

      const payload = {
        user: {
          id: user.id,
        },
      };

      jwt.sign(
        payload,
        process.env.JWT_SECRET,
        { expiresIn: "1h" },
        (err, token) => {
          if (err) throw err;
          res.json({
            msg: "User registered successfully",
            token,
          });
        }
      );
    } catch (error) {
      console.error(error.message);
      res.status(500).send("Server error");
    }
  }
);

app.post(
  "/api/auth",
  [
    check("email", "Please include a valid email").isEmail(),
    check("password", "Password is required").exists(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const { email, password } = req.body;

    try {
      let user = await User.findOne({ email: email.toLowerCase() });
      if (!user) {
        return res.status(400).json({
          errors: [{ msg: "Invalid credentials" }],
        });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(400).json({
          errors: [{ msg: "Invalid credentials" }],
        });
      }

      const payload = {
        user: {
          id: user.id,
        },
      };

      jwt.sign(
        payload,
        process.env.JWT_SECRET,
        { expiresIn: "1h" },
        (err, token) => {
          if (err) throw err;
          res.json({
            msg: "User logged in successfully",
            token,
          });
        }
      );
    } catch (error) {
      console.error(error.message);
      res.status(500).send("Server error");
    }
  }
);

app.get("/api/posts", async (req, res) => {
  try {
    const posts = await Post.find()
      .populate("user", "name")
      .sort({ createDate: -1 });

    res.json(posts);
  } catch (error) {
    console.error(error.message);
    res.status(500).send("Server error");
  }
});

app.get("/api/posts/:id", async (req, res) => {
  try {
    const post = await Post.findById(req.params.id).populate("user", "name");

    if (!post) {
      return res.status(404).json({ msg: "Post not found" });
    }
    res.json(post);
  } catch (error) {
    console.error(error.message);
    if (error.kind === "ObjectId") {
      return res.status(404).json({ msg: "Post not found" });
    }
    res.status(500).send("Server error");
  }
});

app.post(
  "/api/posts",
  [
    auth,
    check("title", "Title is required").not().isEmpty(),
    check("body", "Body is required").not().isEmpty(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    try {
      const { title, body } = req.body;

      const newPost = new Post({
        user: req.user.id,
        title,
        body,
      });

      const post = await newPost.save();

      await post.populate("user", "name");

      res.json(post);
    } catch (error) {
      console.error(error.message);
      res.status(500).send("Server error");
    }
  }
);

app.put(
  "/api/posts/:id",
  [
    auth,
    check("title", "Title is required").not().isEmpty(),
    check("body", "Body is required").not().isEmpty(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    try {
      const { title, body } = req.body;

      const post = await Post.findById(req.params.id);

      if (!post) {
        return res.status(404).json({ msg: "Post not found" });
      }

      if (post.user.toString() !== req.user.id) {
        return res.status(401).json({ msg: "User not authorized" });
      }

      post.title = title;
      post.body = body;

      await post.save();
      await post.populate("user", "name");

      res.json(post);
    } catch (error) {
      console.error(error.message);
      if (error.kind === "ObjectId") {
        return res.status(404).json({ msg: "Post not found" });
      }
      res.status(500).send("Server error");
    }
  }
);

app.delete("/api/posts/:id", auth, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);

    if (!post) {
      return res.status(404).json({ msg: "Post not found" });
    }

    if (post.user.toString() !== req.user.id) {
      return res.status(401).json({ msg: "User not authorized" });
    }

    await Post.findByIdAndDelete(req.params.id);

    res.json({ msg: "Post removed" });
  } catch (error) {
    console.error(error.message);
    if (error.kind === "ObjectId") {
      return res.status(404).json({ msg: "Post not found" });
    }
    res.status(500).send("Server error");
  }
});

app.listen(3000, () => console.log(`Express server running on port 3000`));
