const mysql = require('mysql');

const pool = mysql.createPool({
    connectionLimit: 10,
    // host: 'sql5.freemysqlhosting.net',
    // user: 'sql5667871',
    // password: 'glRfrxIQEF',
    // database: 'sql5667871'

    host: 'sql5.freemysqlhosting.net',
    user: 'sql5669286',
    password: 'lswcXzUInT',
    database: 'sql5669286'
  });

module.exports = pool;