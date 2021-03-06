const express = require("express");
// https://expressjs.com/en/guide/routing.html#express-router
const router = express.Router();
const watches = require("./api/watch.json");
const sql = require("mssql");
const sqlFetch = async (...args) => {
  try {
    const result = await sql.query(...args);
    const resultingRows = result.recordsets[0];
    return resultingRows;
  } catch (err) {
    const err2 = new Error(
      "Something went wrong with that last sql query. View the call stack here and more details in the next error:"
    );
    console.error(err2.message);
    console.log(err2.stack);
    throw err;
  }
};
function getPageAndCount(usersPage, usersCount, totalItems) {
  let page, count;
  if (!usersPage) {
    page = 1;
  } else {
    // parse the string as a decimal (Base 10) number
    page = parseInt(usersPage, 10);
    if (Number.isNaN(page)) {
      page = 1;
    }
  }
  if (!usersCount) {
    count = 6;
  } else {
    // parse the string as a decimal (Base 10) number
    count = parseInt(usersCount, 10);
    if (Number.isNaN(page)) {
      count = 6;
    }
  }
  var pageNum = Math.ceil(totalItems / count);
  // Set the max count can be to totalItems
  count = Math.min(totalItems, count);
  // Set the min count can be to 1
  count = Math.max(1, count);
  // Set the max page can be to pageNum
  page = Math.min(pageNum, page);
  // Set the min page can be to 1
  page = Math.max(1, page);
  return [page, count];
}
router.get("/getProducts", (req, res) => {
  // renders the index.ejs page
  res.json(watches);
});
router.get("/products", async (req, res) => {
  const allProductsCount = await sqlFetch`
            SELECT COUNT(video_id) as count
             FROM videos
     `;
  const findAllCount = allProductsCount[0].count;
  let [page, count] = getPageAndCount(
    req.query.page,
    req.query.count,
    // get first row of returned results
    findAllCount
  );
  const offset = count * (page - 1);
  const products = await sqlFetch`
    SELECT *
    FROM videos
    ORDER BY video_id
    OFFSET ${offset} ROWS
    FETCH NEXT ${count} ROWS ONLY
    `;
  res.json({
    products: products,
    count: findAllCount,
    pageNum: Math.ceil(findAllCount / count)
  });
});
module.exports = router;