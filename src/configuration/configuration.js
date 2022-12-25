require('dotenv').config()
module.exports = {
    env: process.env.ENV,
    port: process.env.PORT || 3000
}