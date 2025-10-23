const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");


module.exports = router;


const User = require("../models/user.js");



router.get("/sign-up", (req, res) => {
  res.render("auth/sign-up.ejs");
});

router.post("/sign-up", async (req, res) => {

  // Validate that the password username/password are acceptable.
  const userInDatabase = await User.findOne({ username: req.body.username });
  if (userInDatabase) {
    return res.send("Username already taken.");
  }
  // Validate that the password/confirm password match.
  if (req.body.password !== req.body.confirmPassword) {
    return res.send("Password and Confirm Password must match");
  }
  // Encrypt the password
  const hashedPassword = bcrypt.hashSync(req.body.password, 10);
  req.body.password = hashedPassword;

  // Once all validation is complete... Send the data to the DB
  const user = await User.create(req.body);
  res.send(`Thanks for signing up ${user.username}`);

  res.send("Form submission accepted!");
});





router.get("/sign-in", async (req, res) => {
  res.render("auth/sign-in.ejs");
});

router.post("/sign-in", async (req, res) => {
  // Confirm the user exists
  const userInDatabase = await User.findOne({ username: req.body.username });
  if (!userInDatabase) {
    return res.send("Login failed. Please try again.");
  }

  // Compare provided password with encrypted password
  const validPassword = bcrypt.compareSync(
    req.body.password,
    userInDatabase.password
  );
  if (!validPassword) {
    return res.send("Login failed. Please try again.");
  }

  
  res.send("Request to sign in received!");
});