const express = require("express");
const app = express();
const port = 3000;
const indexRoutes = require("./routes/index.js");
const apiRoutes = require("./routes/api.js");
var expressLayouts = require('express-ejs-layouts');
// order matters
// Setup ejs as view engine we need the 'ejs' npm module for this
app.set('view engine', 'ejs');
// Express-ejs-layouts handles doing layout files and has
// other nice templating features.
app.use(expressLayouts);
app.use("/", indexRoutes);
app.use("/api", apiRoutes);
app.use(express.static("public"));
app.listen(port, () => console.log(`Example app listening on port ${port}.\nTry opening your browser to http://localhost:${port}!`));