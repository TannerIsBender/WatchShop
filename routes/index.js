const express = require("express");
// https://expressjs.com/en/guide/routing.html#express-router
const router = express.Router();
router.get("/", (req, res) => {
    // renders the index.ejs page
    res.render("index", {
        // This gets rendered as the browsers title
        // it is passed into the ejs page as the variable 'title'
        title: "My Watch Shop"
    })
});
module.exports = router;