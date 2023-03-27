const express = require('express')
const app = express()
const port = 3000

app.get('/', (req, res) => {
  res.send('Hello! This is my 1st week 1st Task')
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})