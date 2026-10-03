require("dotenv").config();
const express=require("express");
const path=require("path");
const fs=require("fs");
const cookieParser=require("cookie-parser");
const bcrypt=require("bcryptjs");
const jwt=require("jsonwebtoken");
const multer=require("multer");
const Database=require("better-sqlite3");

const PORT=Number(process.env.PORT||4000);
const JWT_SECRET=process.env.JWT_SECRET||"dev_secret_change_me_please_12345";
const ADMIN_LOGIN=process.env.ADMIN_LOGIN||"admin";
const ADMIN_PASSWORD=process.env.ADMIN_PASSWORD||"admin123";

const DATA_DIR=path.resolve(process.env.DATA_DIR||"data");
if(!fs.existsSync(DATA_DIR))fs.mkdirSync(DATA_DIR,{recursive:true});
const UPLOAD_DIR=path.join(DATA_DIR,"uploads");
if(!fs.existsSync(UPLOAD_DIR))fs.mkdirSync(UPLOAD_DIR,{recursive:true});

const db=new Database(path.join(DATA_DIR,"shop.db"));
db.pragma("journal_mode=WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS admins(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  login TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);
CREATE TABLE IF NOT EXISTS products(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT NOT NULL DEFAULT 'case',
  name TEXT NOT NULL,
  subtitle TEXT,
  price INTEGER NOT NULL DEFAULT 0,
  old_price INTEGER,
  color TEXT DEFAULT '#2B3BFF',
  badge TEXT,
  models TEXT DEFAULT '[]',
  image TEXT,
  updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
  created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);
CREATE TABLE IF NOT EXISTS settings(
  key TEXT PRIMARY KEY,
  value TEXT
);
CREATE TABLE IF NOT EXISTS visits(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  path TEXT NOT NULL,
  ref TEXT,
  ua TEXT,
  ip TEXT,
  sid TEXT,
  created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);
CREATE INDEX IF NOT EXISTS idx_visits_created ON visits(created_at);
CREATE INDEX IF NOT EXISTS idx_visits_sid ON visits(sid);
CREATE TABLE IF NOT EXISTS telegram_clicks(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  items INTEGER NOT NULL DEFAULT 0,
  total INTEGER NOT NULL DEFAULT 0,
  sid TEXT,
  ua TEXT,
  ip TEXT,
  created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);
CREATE INDEX IF NOT EXISTS idx_tg_created ON telegram_clicks(created_at);
`);

try{
  const cols=db.pragma("table_info(admins)").map(function(c){return c.name});
  if(cols.indexOf("password")===-1){
    db.exec("ALTER TABLE admins ADD COLUMN password TEXT");
    console.log("[migrate] добавлен столбец admins.password (отсутствовал в старой БД)");
  }
}catch(e){
  console.warn("[migrate] не удалось проверить admins.password:",e.message);
  try{db.exec("ALTER TABLE admins ADD COLUMN password TEXT")}catch(_){}
}
try{
  const cols=db.pragma("table_info(products)").map(function(c){return c.name});
  if(cols.indexOf("updated_at")===-1){
    db.exec("ALTER TABLE products ADD COLUMN updated_at INTEGER");
    db.exec("UPDATE products SET updated_at=strftime('%s','now') WHERE updated_at IS NULL");
    console.log("[migrate] добавлен столбец products.updated_at (отсутствовал в старой БД)");
  }else{
    db.exec("UPDATE products SET updated_at=strftime('%s','now') WHERE updated_at IS NULL");
  }
}catch(e){
  console.warn("[migrate] products.updated_at:",e.message);
  try{
    db.exec("ALTER TABLE products ADD COLUMN updated_at INTEGER");
    db.exec("UPDATE products SET updated_at=strftime('%s','now') WHERE updated_at IS NULL");
  }catch(_){}
}

const adminCount=db.prepare("SELECT COUNT(*) AS c FROM admins").get().c;
if(adminCount===0){
  const hash=bcrypt.hashSync(ADMIN_PASSWORD,10);
  db.prepare("INSERT INTO admins(login,password) VALUES(?,?)").run(ADMIN_LOGIN,hash);
  console.log("[init] Создан админ:",ADMIN_LOGIN,"/",ADMIN_PASSWORD);
}else{
  const a=db.prepare("SELECT id,login,password FROM admins WHERE login=? LIMIT 1").get(ADMIN_LOGIN);
  const badHash=!a||!a.password||typeof a.password!=="string"||!/^\$2[aby]\$/.test(a.password)||a.password.length<40;
  if(badHash){
    const hash=bcrypt.hashSync(ADMIN_PASSWORD,10);
    if(a)db.prepare("UPDATE admins SET password=? WHERE id=?").run(hash,a.id);
    else db.prepare("INSERT INTO admins(login,password) VALUES(?,?)").run(ADMIN_LOGIN,hash);
    console.log("[init] Пароль админа пересоздан:",ADMIN_LOGIN,"/",ADMIN_PASSWORD,"(был отсутствующий или битый хэш)");
  }
}
if(!db.prepare("SELECT 1 FROM settings WHERE key='telegram_username'").get()){
  db.prepare("INSERT INTO settings(key,value) VALUES(?,?)").run("telegram_username","");
}

const app=express();
app.use(express.json({limit:"1mb"}));
app.use(cookieParser());

function sid(req,res,next){
  let s=req.cookies&&req.cookies.sid;
  if(!s||!/^[a-zA-Z0-9_-]{16,64}$/.test(s)){
    const rnd=()=>Math.random().toString(36).slice(2,10);
    s=rnd()+rnd();
    res.cookie("sid",s,{httpOnly:true,sameSite:"lax",maxAge:365*24*3600*1000,secure:String(req.headers["x-forwarded-proto"]||req.protocol)==="https"});
  }
  req.sid=s;next();
}
app.use(sid);

const insVisit=db.prepare("INSERT INTO visits(path,ref,ua,ip,sid) VALUES(?,?,?,?,?)");
const lastVisitBySidPath=db.prepare("SELECT id,created_at FROM visits WHERE sid=? AND path=? ORDER BY id DESC LIMIT 1");
app.use(function(req,res,next){
  const m=(req.method||"GET").toUpperCase();
  if(m!=="GET")return next();
  const p=req.path||"/";
  if(/\.[a-zA-Z0-9]{1,6}$/.test(p)&&!/\/admin$/.test(p)&&!/\/$/.test(p))return next();
  if(p.startsWith("/uploads/"))return next();
  const ua=(req.headers["user-agent"]||"").slice(0,260);
  const ip=(req.ip||req.socket&&req.socket.remoteAddress||req.headers["x-forwarded-for"]||"").slice(0,64);
  const ref=(req.headers["referer"]||req.headers["referrer"]||"").slice(0,500)||null;
  const track=function(){try{insVisit.run(p,ref,ua,ip,req.sid)}catch(_){}};
  try{
    const lv=lastVisitBySidPath.get(req.sid,p);
    const now=Math.floor(Date.now()/1000);
    if(!lv||now-lv.created_at>30*60)track();
  }catch(_){track()}
  next();
});

app.use("/uploads",express.static(UPLOAD_DIR,{maxAge:"30d"}));

const storage=multer.diskStorage({
  destination:(_req,_file,cb)=>cb(null,UPLOAD_DIR),
  filename:(_req,file,cb)=>{
    const ext=path.extname(file.originalname||".bin").toLowerCase();
    cb(null,"prod_"+Date.now()+"_"+Math.random().toString(36).slice(2,10)+ext)
  }
});
const upload=multer({
  storage,
  limits:{fileSize:8*1024*1024},
  fileFilter:(_req,file,cb)=>{
    const ok=/^image\/(jpeg|png|webp|gif)$/.test(file.mimetype||"");
    cb(ok?null:new Error("Разрешены только JPG, PNG, WEBP, GIF до 8 МБ"),ok);
  }
});

function requireAuth(req,res,next){
  const token=req.cookies&&req.cookies.token;
  if(!token)return res.status(401).json({error:"Требуется вход"});
  try{
    const d=jwt.verify(token,JWT_SECRET);
    const u=db.prepare("SELECT id,login FROM admins WHERE id=?").get(d.id);
    if(!u)return res.status(401).json({error:"Сессия недействительна"});
    req.admin=u;next();
  }catch(_){return res.status(401).json({error:"Сессия истекла"})}
}

function toProduct(r){
  let m=[];
  try{m=Array.isArray(r.models)?r.models:JSON.parse(r.models||"[]")}catch(_){}
  return {
    id:r.id,type:r.type,name:r.name,subtitle:r.subtitle,
    price:r.price,old_price:r.old_price,color:r.color||"#2B3BFF",
    badge:r.badge,m:m,models:m,image:r.image
  };
}
function getSetting(key){
  const r=db.prepare("SELECT value FROM settings WHERE key=?").get(key);
  return r?r.value:"";
}
function setSetting(key,value){
  db.prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(key,value);
}

app.get("/admin",(_req,res)=>{
  res.sendFile(path.join(__dirname,"public","admin.html"));
});

app.get("/api/products",(_req,res)=>{
  const rows=db.prepare("SELECT * FROM products ORDER BY updated_at DESC, id DESC").all();
  res.json(rows.map(toProduct));
});

app.get("/api/settings",(_req,res)=>{
  const tg=getSetting("telegram_username");
  res.json({ok:true,telegram_username:tg||""});
});

app.post("/api/admin/login",async(req,res)=>{
  try{
    const {login,password}=req.body||{};
    if(!login||!password)return res.status(400).json({error:"Введите логин и пароль"});
    const u=db.prepare("SELECT * FROM admins WHERE login=?").get(String(login).trim());
    if(!u||!u.password)return res.status(401).json({error:"Неверный логин или пароль"});
    const ok=await bcrypt.compare(String(password),String(u.password));
    if(!ok)return res.status(401).json({error:"Неверный логин или пароль"});
    const token=jwt.sign({id:u.id,login:u.login},JWT_SECRET,{expiresIn:"30d"});
    res.cookie("token",token,{
      httpOnly:true,sameSite:"lax",maxAge:30*24*3600*1000,
      secure:String(req.headers["x-forwarded-proto"]||req.protocol)==="https"
    });
    res.json({ok:true,login:u.login});
  }catch(e){res.status(500).json({error:e.message||"Ошибка входа"})}
});

app.post("/api/admin/logout",(_req,res)=>{
  res.clearCookie("token");res.json({ok:true});
});

app.get("/api/admin/me",requireAuth,(req,res)=>{
  res.json({ok:true,login:req.admin.login});
});

app.post("/api/upload",requireAuth,(req,res)=>{
  upload.single("image")(req,res,(err)=>{
    if(err)return res.status(400).json({error:err.message||"Ошибка загрузки"});
    if(!req.file)return res.status(400).json({error:"Файл не выбран"});
    const url="/uploads/"+req.file.filename;
    res.json({ok:true,url});
  });
});

app.get("/api/admin/settings",requireAuth,(req,res)=>{
  res.json({ok:true,telegram_username:getSetting("telegram_username")||""});
});

app.put("/api/admin/settings",requireAuth,(req,res)=>{
  try{
    const body=req.body||{};
    if("telegram_username" in body){
      let raw=String(body.telegram_username||"").trim();
      if(raw.length===0){setSetting("telegram_username","");return res.json({ok:true,telegram_username:""})}
      if(/t\.me\/\+/.test(raw)||/^\+/.test(raw.replace(/^https?:\/\/t\.me\//i,"")))return res.status(400).json({error:"Это приватная ссылка-приглашение. Введите публичный username (например @yourname)"});
      if(/[?&]start=|bot\?/i.test(raw))return res.status(400).json({error:"Введите username человека, а не ссылку на бота или deep-link."});
      let v=raw.replace(/^https?:\/\/(www\.)?t\.me\/(s\/)?/i,"").replace(/^@/,"").split("?")[0].split("/")[0].trim();
      if(v.length<5)return res.status(400).json({error:"Username слишком короткий — в Telegram минимум 5 символов."});
      if(v.length>32)return res.status(400).json({error:"Username слишком длинный — в Telegram максимум 32 символа."});
      if(!/^[a-zA-Z][a-zA-Z0-9_]{4,31}$/.test(v))return res.status(400).json({error:"Некорректный username. Можно: латинские буквы a-Z, цифры 0-9 и нижнее подчёркивание _. Первый символ — буква."});
      setSetting("telegram_username",v);
    }
    res.json({ok:true,telegram_username:getSetting("telegram_username")||""});
  }catch(e){res.status(500).json({error:e.message||"Ошибка сохранения"})}
});

app.post("/api/admin/products",requireAuth,(req,res)=>{
  try{
    const b=req.body||{};
    if(!b.name)return res.status(400).json({error:"Название обязательно"});
    if(!b.type||!["case","glass","film"].includes(b.type))b.type="case";
    const price=Number(b.price)||0;
    const old_price=b.old_price?Number(b.old_price):null;
    const models=JSON.stringify(Array.isArray(b.models)?b.models:[]);
    const info=db.prepare(`INSERT INTO products(type,name,subtitle,price,old_price,color,badge,models,image,updated_at)
      VALUES(?,?,?,?,?,?,?,?,?,strftime('%s','now'))`).run(
      b.type,String(b.name).trim(),
      b.subtitle?String(b.subtitle).trim():null,
      price,old_price,
      b.color?String(b.color):"#2B3BFF",
      b.badge?String(b.badge).trim():null,
      models,
      b.image?String(b.image):null
    );
    const row=db.prepare("SELECT * FROM products WHERE id=?").get(info.lastInsertRowid);
    res.json({ok:true,product:toProduct(row)});
  }catch(e){res.status(500).json({error:e.message||"Ошибка создания"})}
});

app.put("/api/admin/products/:id",requireAuth,(req,res)=>{
  try{
    const id=Number(req.params.id);
    const row=db.prepare("SELECT * FROM products WHERE id=?").get(id);
    if(!row)return res.status(404).json({error:"Товар не найден"});
    const b=req.body||{};
    const type=b.type&&["case","glass","film"].includes(b.type)?b.type:row.type;
    const name=b.name?String(b.name).trim():row.name;
    const subtitle=b.subtitle!==undefined?(b.subtitle?String(b.subtitle).trim():null):row.subtitle;
    const price=b.price!==undefined?(Number(b.price)||0):row.price;
    const old_price=b.old_price!==undefined?(b.old_price?Number(b.old_price):null):row.old_price;
    const color=b.color?String(b.color):row.color;
    const badge=b.badge!==undefined?(b.badge?String(b.badge).trim():null):row.badge;
    const models=JSON.stringify(b.models?b.models:(row.models?JSON.parse(row.models):[]));
    const image=b.image!==undefined?(b.image||null):row.image;
    db.prepare(`UPDATE products SET type=?,name=?,subtitle=?,price=?,old_price=?,color=?,badge=?,models=?,image=?,updated_at=strftime('%s','now') WHERE id=?`).run(
      type,name,subtitle,price,old_price,color,badge,models,image,id
    );
    const up=db.prepare("SELECT * FROM products WHERE id=?").get(id);
    res.json({ok:true,product:toProduct(up)});
  }catch(e){res.status(500).json({error:e.message||"Ошибка обновления"})}
});

app.delete("/api/admin/products/:id",requireAuth,(req,res)=>{
  try{
    const id=Number(req.params.id);
    const row=db.prepare("SELECT * FROM products WHERE id=?").get(id);
    if(!row)return res.status(404).json({error:"Товар не найден"});
    if(row.image){
      const fp=path.join(__dirname,row.image.replace(/^\//,""));
      if(fs.existsSync(fp)&&fp.startsWith(UPLOAD_DIR))try{fs.unlinkSync(fp)}catch(_){}
    }
    db.prepare("DELETE FROM products WHERE id=?").run(id);
    res.json({ok:true});
  }catch(e){res.status(500).json({error:e.message||"Ошибка удаления"})}
});

const insTg=db.prepare("INSERT INTO telegram_clicks(items,total,sid,ua,ip) VALUES(?,?,?,?,?)");
app.post("/api/telegram-click",(req,res)=>{
  try{
    const b=req.body||{};
    const items=Math.max(0,Number(b.items)||0);
    const total=Math.max(0,Number(b.total)||0);
    const ua=(req.headers["user-agent"]||"").slice(0,260);
    const ip=(req.ip||req.socket&&req.socket.remoteAddress||req.headers["x-forwarded-for"]||"").slice(0,64);
    insTg.run(items,total,req.sid,ua,ip);
    res.json({ok:true});
  }catch(e){res.status(500).json({error:e.message||"Ошибка"})}
});

const day=86400;
const qCountSince=(t)=>db.prepare("SELECT COUNT(*) AS c FROM visits WHERE created_at>=?").get(t).c;
const qUniqSince=(t)=>db.prepare("SELECT COUNT(DISTINCT sid) AS c FROM visits WHERE created_at>=?").get(t).c;
const qTgSince=(t)=>db.prepare("SELECT COUNT(*) AS c, COALESCE(SUM(items),0) AS items, COALESCE(SUM(total),0) AS total FROM telegram_clicks WHERE created_at>=?").get(t);
const qTopPaths=db.prepare("SELECT path, COUNT(*) AS c FROM visits GROUP BY path ORDER BY c DESC LIMIT 8").all();

app.get("/api/admin/stats",requireAuth,(_req,res)=>{
  const now=Math.floor(Date.now()/1000);
  const vAll=db.prepare("SELECT COUNT(*) AS c, COUNT(DISTINCT sid) AS u FROM visits").get();
  const v7=qCountSince(now-7*day),u7=qUniqSince(now-7*day);
  const v1=qCountSince(now-day),u1=qUniqSince(now-day);
  const tgAll=qTgSince(0),tg7=qTgSince(now-7*day),tg1=qTgSince(now-day);
  const tops=qTopPaths.map(r=>({path:r.path,c:r.c}));
  res.json({ok:true,visits:{all:vAll.c,uniq_all:vAll.u,last7:v7,uniq7:u7,last24:v1,uniq24:u1},telegram:{all:{clicks:tgAll.c,items:tgAll.items,total:tgAll.total},last7:{clicks:tg7.c,items:tg7.items,total:tg7.total},last24:{clicks:tg1.c,items:tg1.items,total:tg1.total}},top:tops});
});

app.use(express.static(path.join(__dirname,"public"),{index:["index.html"]}));

app.use((err,_req,res,_next)=>{
  console.error(err);
  res.status(500).json({error:err.message||"Ошибка сервера"});
});

app.listen(PORT,()=>{
  console.log(`🚀 Дроп Кейс запущен: http://localhost:${PORT}`);
  console.log(`   Админка: http://localhost:${PORT}/admin`);
});
