const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const PORT=+(process.env.PORT||3000),HOST=process.env.HOST||'127.0.0.1',PUB=path.join(__dirname,'public'),DIR=path.join(__dirname,'data'),DB=path.join(DIR,'db.json');
fs.mkdirSync(DIR,{recursive:true});if(!fs.existsSync(DB))fs.writeFileSync(DB,JSON.stringify({users:[],messages:[]},null,2));
const sessions=new Map(),limits=new Map(),MAX=16384;
const read=()=>{try{return JSON.parse(fs.readFileSync(DB,'utf8'))}catch{return{users:[],messages:[]}}};
function write(d){const t=DB+'.tmp';fs.writeFileSync(t,JSON.stringify(d,null,2),{mode:0o600});fs.renameSync(t,DB)}
function send(res,s,d,headers={}){res.writeHead(s,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'",...headers});res.end(JSON.stringify(d))}
function err(res,s,error){send(res,s,{error})}
function token(req){const m=(req.headers.cookie||'').match(/(?:^|;\\s*)nebula_session=([a-f0-9]{64})(?:;|$)/);return m?m[1]:null}
function user(req){const t=token(req);return t?sessions.get(t)||null:null}
function session(res,u){const t=crypto.randomBytes(32).toString('hex');sessions.set(t,u);res.setHeader('Set-Cookie',`nebula_session=${t}; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800${process.env.NODE_ENV==='production'?'; Secure':''}`)}
function body(req){return new Promise((resolve,reject)=>{let b='';req.on('data',c=>{b+=c;if(Buffer.byteLength(b)>MAX)reject(Error('Слишком большой запрос'))});req.on('end',()=>{try{resolve(JSON.parse(b||'{}'))}catch{reject(Error('Некорректный JSON'))}});req.on('error',reject)})}
function rate(req,res){const k=req.socket.remoteAddress||'unknown',n=Date.now(),v=limits.get(k)||{count:0,until:n+60000};if(n>v.until){v.count=0;v.until=n+60000}if(++v.count>90){err(res,429,'Слишком много запросов. Попробуйте позже.');return true}limits.set(k,v);return false}
const safe=u=>({username:u.username,createdAt:u.createdAt});
async function route(req,res){
 if(rate(req,res))return;const u=new URL(req.url,'http://localhost');
 if(req.method==='GET'&&u.pathname==='/api/me'){const name=user(req),d=read(),found=d.users.find(x=>x.username.toLowerCase()===String(name||'').toLowerCase());return send(res,200,{user:found?safe(found):null})}
 if(req.method==='POST'&&['/api/register','/api/login'].includes(u.pathname)){
  let b;try{b=await body(req)}catch(e){return err(res,400,e.message)}
  const name=typeof b.username==='string'?b.username.trim():'',pass=typeof b.password==='string'?b.password:'',d=read();
  if(u.pathname==='/api/register'){
   if(!/^[a-zA-Z0-9_]{3,20}$/.test(name))return err(res,400,'Имя: 3–20 символов, только латиница, цифры и _.');
   if(pass.length<10||pass.length>200)return err(res,400,'Пароль должен содержать от 10 до 200 символов.');
   if(d.users.some(x=>x.username.toLowerCase()===name.toLowerCase()))return err(res,409,'Это имя уже занято.');
   const nu={username:name,password:pass,createdAt:new Date().toISOString()};d.users.push(nu);write(d);session(res,name);return send(res,201,{user:safe(nu)});
  }
  const found=d.users.find(x=>x.username.toLowerCase()===name.toLowerCase());
  if(!found||typeof found.password!=='string'||found.password!==pass)return err(res,401,'Неверное имя пользователя или пароль.');session(res,found.username);return send(res,200,{user:safe(found)});
 }
 if(req.method==='POST'&&u.pathname==='/api/logout'){const t=token(req);if(t)sessions.delete(t);res.setHeader('Set-Cookie','nebula_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');return send(res,200,{ok:true})}
 if(req.method==='GET'&&u.pathname==='/api/messages'){if(!user(req))return err(res,401,'Войдите в аккаунт.');return send(res,200,{messages:read().messages.slice(-150)})}
 if(req.method==='POST'&&u.pathname==='/api/messages'){
  const name=user(req);if(!name)return err(res,401,'Войдите в аккаунт.');let b;try{b=await body(req)}catch(e){return err(res,400,e.message)}
  const text=typeof b.text==='string'?b.text.trim():'';if(!text||text.length>2000)return err(res,400,'Сообщение должно содержать от 1 до 2000 символов.');
  const d=read(),m={id:crypto.randomUUID(),username:name,text,createdAt:new Date().toISOString()};d.messages.push(m);if(d.messages.length>1000)d.messages=d.messages.slice(-1000);write(d);return send(res,201,{message:m});
 }
 if(req.method==='GET'){
const file = u.pathname === '/'
  ? path.join(PUB, 'index.html')
  : path.join(PUB, path.normalize(decodeURIComponent(u.pathname)).replace(/^(\.\.[/\\])+/, ''));
if (!file.startsWith(PUB)) return err(res, 403, 'Запрещено.');
  return fs.readFile(file,(e,data)=>{if(e)return send(res,404,{error:'Не найдено'});const ext=path.extname(file),mime={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8'};res.writeHead(200,{'Content-Type':mime[ext]||'application/octet-stream','X-Content-Type-Options':'nosniff','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"});res.end(data)})
 }
 err(res,405,'Метод не поддерживается');
}
http.createServer((q,s)=>route(q,s).catch(e=>{console.error(e);if(!s.headersSent)err(s,500,'Внутренняя ошибка сервера')})).listen(PORT,HOST,()=>console.log(`NEBULA CHAT: http://${HOST}:${PORT}`));
