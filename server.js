// server.js
require('dotenv').config();
const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const bcrypt = require('bcryptjs'); // bcryptjs pure JS (dễ cài trên Termux)
const mysql = require('mysql2/promise');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended:true }));
app.use(cors()); // dev: cho phép mọi origin. Sau này giới hạn origin để an toàn.
app.use(express.static('public'));

const USERS_JSON = path.join(__dirname, 'users.json');

const DB_HOST = process.env.DB_HOST || 'localhost';
const DB_USER = process.env.DB_USER || 'root';
const DB_PASS = process.env.DB_PASS || '';
const DB_NAME = process.env.DB_NAME || 'manga';

// password policy server-side
function validPassword(pw) {
  if (typeof pw !== 'string') return false;
  if (pw.length < 8) return false;
  if (!(/[a-z]/.test(pw))) return false;
  if (!(/[A-Z]/.test(pw))) return false;
  if (!(/[ #@₫%]/.test(pw))) return false;
  return true;
}

async function getDbConnection(){
  return await mysql.createConnection({
    host: DB_HOST, user: DB_USER, password: DB_PASS, database: DB_NAME
  });
}

async function writeUsersJson(obj){
  await fs.writeFile(USERS_JSON, JSON.stringify(obj, null, 2), 'utf8');
}

async function readUsersJson(){
  try {
    const txt = await fs.readFile(USERS_JSON, 'utf8');
    return JSON.parse(txt || '[]');
  } catch(e){
    return [];
  }
}

// register
app.post('/register', async (req,res)=>{
  const { username, display, email, password } = req.body || {};
  if(!username || !display || !email || !password) return res.status(400).send('Thiếu trường dữ liệu');

  if(!validPassword(password)) return res.status(400).send('Mật khẩu không đạt yêu cầu');

  try {
    const conn = await getDbConnection();
    // check username exists
    const [rows] = await conn.execute('SELECT id FROM users WHERE username = ?', [username]);
    if(rows.length>0){
      await conn.end();
      return res.status(409).send('Tên tài khoản đã tồn tại');
    }

    // hash password
    const hashed = await bcrypt.hash(password, 10);

    // insert into MySQL
    const [r] = await conn.execute(
      'INSERT INTO users (username, display_name, email, password_hash, created_at) VALUES (?, ?, ?, ?, NOW())',
      [username, display, email, hashed]
    );

    await conn.end();

    // append to users.json (backup / mirror)
    const users = await readUsersJson();
    users.push({
      id: r.insertId,
      username,
      display,
      email,
      password_hash: hashed,
      created_at: new Date().toISOString()
    });
    await writeUsersJson(users);

    return res.status(200).send('OK');
  } catch (err) {
    console.error(err);
    return res.status(500).send('Lỗi server');
  }
});

// login
app.post('/login', async (req,res)=>{
  const { username, password } = req.body || {};
  if(!username || !password) return res.status(400).send('Thiếu trường dữ liệu');

  try {
    const conn = await getDbConnection();
    const [rows] = await conn.execute('SELECT id, username, display_name, password_hash FROM users WHERE username = ?', [username]);
    await conn.end();
    if(rows.length === 0) return res.status(401).send('Tài khoản không tồn tại');

    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if(!ok) return res.status(401).send('Sai mật khẩu');

    // trả JSON kèm display name (frontend sử dụng)
    return res.status(200).json({ id: user.id, username: user.username, display: user.display_name });
  } catch(err) {
    console.error(err);
    return res.status(500).send('Lỗi server');
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=> console.log('Server running on port', PORT));
