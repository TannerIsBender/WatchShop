const express = require("express");
// https://expressjs.com/en/guide/routing.html#express-router
const router = express.Router();
const watches = require('./api/watch.json');
router.get("/getProducts", (req, res) => {
    // renders the index.ejs page
    res.json(watches);
});
module.exports = router;