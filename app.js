const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3");
const { open } = require("sqlite");

// Initialize Express app
const app = express();
app.use(express.json());

// JWT Middleware to authenticate the token
const auth = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  if (authHeader) {
    const token = authHeader.split(" ")[1];
    jwt.verify(token, "SECRET_KEY", (err, user) => {
      if (err) {
        return res.status(401).send("Invalid JWT Token");
      }
      req.user = user;
      next();
    });
  } else {
    res.status(401).send("Invalid JWT Token");
  }
};

// Database setup
const dbPath = "./twitterClone.db";
let db = null;

const initializeDbAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    app.listen(5000, () => {
      console.log("Server started at http://localhost:5000");
    });
  } catch (error) {
    console.error(`Error: ${error.message}`);
    process.exit(1);
  }
};

initializeDbAndServer();

// User Registration API
app.post("/register/", async (req, res) => {
  const { username, name, password, gender } = req.body;

  const userExistsQuery = `SELECT * FROM user WHERE username = ?`;
  const user = await db.get(userExistsQuery, [username]);

  if (user) {
    return res.status(400).send("User already exists");
  }

  if (password.length < 6) {
    return res.status(400).send("Password is too short");
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const insertUserQuery = `INSERT INTO user (name, username, password, gender) VALUES (?, ?, ?, ?)`;

  await db.run(insertUserQuery, [name, username, hashedPassword, gender]);
  res.send("User created successfully");
});

app.post("/login/", async (req, res) => {
  try {
    const { username, password } = req.body;
    const userQuery = `SELECT * FROM user WHERE username = ?`;
    const user = await db.get(userQuery, [username]);

    if (!user) {
      return res.status(400).send("Invalid user");
    }

    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect) {
      return res.status(400).send("Invalid password");
    }

    // Generate JWT token
    const token = jwt.sign({ userId: user.user_id }, "SECRET_KEY");
    res.setHeader("Content-Type", "application/json");
    res.send({ jwtToken: token });
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});

// Protected Routes (your existing API endpoints)
app.get("/user/tweets/feed/", auth, async (req, res) => {
  console.log(auth);
  const { userId } = req.user;
  const getFeedQuery = `
        SELECT tweet, user_id, date_time FROM tweet
        WHERE user_id IN (SELECT following_user_id FROM follower WHERE follower_user_id = ?)
        ORDER BY date_time DESC LIMIT 4`;

  const feed = await db.all(getFeedQuery, [userId]);
  res.send(feed);
});

// Get List of People the User Follows API - Protected
app.get("/user/following/", auth, async (req, res) => {
  const { userId } = req.user;
  const getFollowingQuery = `
    SELECT name FROM user
    WHERE user_id IN (SELECT following_user_id FROM follower WHERE follower_user_id = ?)`;

  const following = await db.all(getFollowingQuery, [userId]);
  res.send(following);
});

// Get List of User's Followers API - Protected
app.get("/user/followers/", auth, async (req, res) => {
  const { userId } = req.user;
  const getFollowersQuery = `
    SELECT name FROM user
    WHERE user_id IN (SELECT follower_user_id FROM follower WHERE following_user_id = ?)`;

  const followers = await db.all(getFollowersQuery, [userId]);
  res.send(followers);
});

// Get User's Tweets API - Protected
app.get("/user/tweets/", auth, async (req, res) => {
  const { userId } = req.user; // Get user ID from JWT
  const getUserTweetsQuery = `SELECT tweet, date_time FROM tweet WHERE user_id = ?`;

  const tweets = await db.all(getUserTweetsQuery, [userId]);

  // Check if there are no tweets
  if (tweets.length === 0) {
    return res.status(200).send([]); // Return an empty array if no tweets
  }

  res.send(tweets);
});

// Get Likes for a Tweet API - Protected
app.get("/tweets/:tweetId/likes/", auth, async (req, res) => {
  const { tweetId } = req.params;
  const { userId } = req.user;

  // Check if the tweet belongs to a followed user
  const checkTweetQuery = `SELECT * FROM tweet WHERE tweet_id = ? AND user_id IN (SELECT following_user_id FROM follower WHERE follower_user_id = ?)`;
  const tweet = await db.get(checkTweetQuery, [tweetId, userId]);

  if (!tweet) {
    return res.status(401).send("Invalid Request");
  }

  const likesQuery = `SELECT username FROM like INNER JOIN user ON like.user_id = user.user_id WHERE tweet_id = ?`;
  const likes = await db.all(likesQuery, [tweetId]);

  res.send(likes);
});

app.get("/tweets/:tweetId/replies/", auth, async (req, res) => {
  const { tweetId } = req.params;
  const { userId } = req.user;

  // Check if the tweet belongs to a followed user
  const checkTweetQuery = `SELECT * FROM tweet WHERE tweet_id = ? AND user_id IN (SELECT following_user_id FROM follower WHERE follower_user_id = ?)`;
  const tweet = await db.get(checkTweetQuery, [tweetId, userId]);

  if (!tweet) {
    return res.status(401).send("Invalid Request");
  }

  const getRepliesQuery = `SELECT reply, user_id, date_time FROM reply WHERE tweet_id = ?`;
  const replies = await db.all(getRepliesQuery, [tweetId]);

  res.send(replies);
});

// Create a Tweet API - Protected
app.post("/user/tweets/", auth, async (req, res) => {
  const { userId } = req.user;
  const { tweet } = req.body;
  const dateTime = new Date().toISOString();

  const createTweetQuery = `INSERT INTO tweet (tweet, user_id, date_time) VALUES (?, ?, ?)`;
  await db.run(createTweetQuery, [tweet, userId, dateTime]);
  res.send("Tweet created successfully");
});

// Delete Tweet API - Protected
app.delete("/tweets/:tweetId/", auth, async (req, res) => {
  const { userId } = req.user;
  const { tweetId } = req.params;

  const checkTweetQuery = `SELECT * FROM tweet WHERE tweet_id = ? AND user_id = ?`;
  const tweet = await db.get(checkTweetQuery, [tweetId, userId]);

  if (!tweet) {
    return res.status(401).send("Invalid Request");
  }

  const deleteTweetQuery = `DELETE FROM tweet WHERE tweet_id = ?`;
  await db.run(deleteTweetQuery, [tweetId]);
  res.send("Tweet Removed");
});

// Get Tweet with Likes and Replies Count API - Protected
// Get Tweet by ID API - Protected
app.get("/tweets/:tweetId/", auth, async (req, res) => {
  const { tweetId } = req.params;
  const { userId } = req.user;

  // Check if the tweet belongs to a followed user
  const checkTweetQuery = `SELECT * FROM tweet WHERE tweet_id = ? AND user_id IN (SELECT following_user_id FROM follower WHERE follower_user_id = ?)`;
  const tweet = await db.get(checkTweetQuery, [tweetId, userId]);

  if (!tweet) {
    return res.status(401).send("Invalid Request");
  }

  res.send(tweet);
});

module.exports = app;
