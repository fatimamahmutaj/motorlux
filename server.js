const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT) || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'motorlux-dev-session-secret-change-me';
const SESSION_COOKIE = 'motorlux_session';
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7;
const ROOT = __dirname;
const DATA_DIR = process.env.DATA_DIR || path.join(ROOT, 'data');
const DATA_FILE = path.join(DATA_DIR, 'motorlux-data.json');
const APP_FILE = path.join(ROOT, 'cardealership.html');

const DEFAULT_CARS = [
  {id:1,make:'Toyota',model:'Land Cruiser',year:2023,price:85000,mileage:'12,000',fuel:'Petrol',trans:'Automatic',cat:'suv',cond:'new',status:'available',img:'https://images.unsplash.com/photo-1550355291-bbee04a92027?w=800&q=80',desc:'Full-spec Land Cruiser with sunroof, leather seats, 360 camera, and advanced safety package. Immaculate condition.',color:'Pearl White'},
  {id:2,make:'BMW',model:'5 Series',year:2022,price:52000,mileage:'28,000',fuel:'Petrol',trans:'Automatic',cat:'luxury',cond:'used',status:'available',img:'https://images.unsplash.com/photo-1555215695-3004980ad54e?w=800&q=80',desc:'M-Sport package, panoramic roof, Harman Kardon sound. Service history available. One careful owner.',color:'Mineral Grey'},
  {id:3,make:'Tesla',model:'Model Y',year:2023,price:48000,mileage:'5,000',fuel:'Electric',trans:'Automatic',cat:'electric',cond:'new',status:'available',img:'https://images.unsplash.com/photo-1561580125-028ee3bd62eb?w=800&q=80',desc:'Long Range AWD. Autopilot, 330mi range, over-the-air updates. Full self-driving package available.',color:'Midnight Silver'},
  {id:4,make:'Mercedes-Benz',model:'GLE 450',year:2022,price:71000,mileage:'18,000',fuel:'Hybrid',trans:'Automatic',cat:'luxury',cond:'used',status:'available',img:'https://images.unsplash.com/photo-1618843479313-40f8afb4b4d8?w=800&q=80',desc:'AMG Line, Burmester sound system, air suspension, 7-seater. Stunning inside and out.',color:'Obsidian Black'},
  {id:5,make:'Ford',model:'F-150 Raptor',year:2023,price:67000,mileage:'3,000',fuel:'Petrol',trans:'Automatic',cat:'truck',cond:'new',status:'available',img:'https://images.unsplash.com/photo-1503376780353-7e6692767b70?w=800&q=80',desc:'37 inch off-road tyres, Fox suspension, 450hp twin-turbo V6. The ultimate performance truck.',color:'Velocity Blue'},
  {id:6,make:'Honda',model:'Civic Type R',year:2023,price:38000,mileage:'1,200',fuel:'Petrol',trans:'Manual',cat:'sedan',cond:'new',status:'available',img:'https://images.unsplash.com/photo-1502877338535-766e1452684a?w=800&q=80',desc:'315hp VTEC Turbo, Brembo brakes, rev-matching, data logger. Track-ready, road-legal.',color:'Championship White'},
];

function ensureDataFile(){
  if(!fs.existsSync(DATA_DIR))fs.mkdirSync(DATA_DIR,{recursive:true});
  if(fs.existsSync(DATA_FILE))return;
  const data={
    cars:DEFAULT_CARS,
    users:[{id:1,email:'admin@motorlux.com',password:hashPassword('1234'),role:'admin',name:'Owner',createdAt:'2025-01-01T00:00:00.000Z'}],
    inquiries:[],
    favorites:{}
  };
  writeData(data);
}

function readData(){
  ensureDataFile();
  return JSON.parse(fs.readFileSync(DATA_FILE,'utf8'));
}

function writeData(data){
  fs.writeFileSync(DATA_FILE,JSON.stringify(data,null,2));
}

function nextId(list){
  return list.length?Math.max(...list.map(item=>Number(item.id)||0))+1:1;
}

function hashPassword(password){
  const salt=crypto.randomBytes(16).toString('hex');
  const hash=crypto.pbkdf2Sync(String(password),salt,120000,32,'sha256').toString('hex');
  return `pbkdf2$${salt}$${hash}`;
}

function verifyPassword(password,record){
  if(!record)return false;
  const [scheme,salt,expected]=String(record).split('$');
  if(scheme!=='pbkdf2'||!salt||!expected)return false;
  const actual=crypto.pbkdf2Sync(String(password),salt,120000,32,'sha256').toString('hex');
  return crypto.timingSafeEqual(Buffer.from(actual,'hex'),Buffer.from(expected,'hex'));
}

function cleanUser(user){
  if(!user)return null;
  const {password,...safe}=user;
  return safe;
}

function signJwt(payload){
  const header={alg:'HS256',typ:'JWT'};
  const encodedHeader=base64url(JSON.stringify(header));
  const encodedPayload=base64url(JSON.stringify(payload));
  const sig=crypto.createHmac('sha256',SESSION_SECRET).update(`${encodedHeader}.${encodedPayload}`).digest('base64url');
  return `${encodedHeader}.${encodedPayload}.${sig}`;
}

function verifyJwt(token){
  if(!token)return null;
  const parts=token.split('.');
  if(parts.length!==3)return null;
  const [header,payload,sig]=parts;
  const expected=crypto.createHmac('sha256',SESSION_SECRET).update(`${header}.${payload}`).digest('base64url');
  if(!safeEqual(sig,expected))return null;
  try{
    const decoded=JSON.parse(Buffer.from(payload,'base64url').toString('utf8'));
    if(decoded.exp&&decoded.exp<Math.floor(Date.now()/1000))return null;
    return decoded;
  }catch{return null}
}

function base64url(value){
  return Buffer.from(value).toString('base64url');
}

function safeEqual(a,b){
  const ab=Buffer.from(String(a));
  const bb=Buffer.from(String(b));
  if(ab.length!==bb.length)return false;
  return crypto.timingSafeEqual(ab,bb);
}

function sessionCookie(userId){
  const exp=Math.floor(Date.now()/1000)+SESSION_TTL_SECONDS;
  const token=signJwt({sub:userId,exp});
  return `${SESSION_COOKIE}=${token}; Path=/; Max-Age=${SESSION_TTL_SECONDS}; HttpOnly; SameSite=Lax`;
}

function clearSessionCookie(){
  return `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax`;
}

function parseCookies(req){
  const header=req.headers.cookie||'';
  return Object.fromEntries(header.split(';').map(part=>part.trim()).filter(Boolean).map(part=>{
    const idx=part.indexOf('=');
    return idx===-1?[part,'']:[part.slice(0,idx),decodeURIComponent(part.slice(idx+1))];
  }));
}

function getUserFromRequest(req,data){
  const token=parseCookies(req)[SESSION_COOKIE];
  const payload=verifyJwt(token);
  if(!payload)return null;
  return data.users.find(user=>user.id===Number(payload.sub))||null;
}

function readBody(req){
  return new Promise((resolve,reject)=>{
    let body='';
    req.on('data',chunk=>{
      body+=chunk;
      if(body.length>1_000_000){
        req.destroy();
        reject(new Error('Request body too large'));
      }
    });
    req.on('end',()=>{
      if(!body){resolve({});return}
      try{resolve(JSON.parse(body))}
      catch{reject(new Error('Invalid JSON'))}
    });
    req.on('error',reject);
  });
}

function json(res,status,payload,headers={}){
  res.writeHead(status,{'Content-Type':'application/json; charset=utf-8',...headers});
  res.end(JSON.stringify(payload));
}

function sendError(res,status,message){
  json(res,status,{error:message});
}

function sendApp(res){
  fs.readFile(APP_FILE,(err,content)=>{
    if(err){sendError(res,500,'Unable to load app.');return}
    res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});
    res.end(content);
  });
}

function normalizeEmail(email){
  return String(email||'').trim().toLowerCase();
}

function requireUser(req,res,data){
  const user=getUserFromRequest(req,data);
  if(!user)sendError(res,401,'Please sign in.');
  return user;
}

function requireAdmin(req,res,data){
  const user=requireUser(req,res,data);
  if(!user)return null;
  if(user.role!=='admin'){sendError(res,403,'Admin access required.');return null}
  return user;
}

function carFromBody(body,id){
  return {
    id,
    make:String(body.make||'').trim(),
    model:String(body.model||'').trim(),
    year:Number.parseInt(body.year,10)||new Date().getFullYear(),
    price:Number.parseFloat(body.price)||0,
    mileage:String(body.mileage||'0').trim(),
    fuel:String(body.fuel||'Petrol').trim(),
    trans:String(body.trans||'Automatic').trim(),
    cat:String(body.cat||'sedan').trim(),
    cond:String(body.cond||'used').trim(),
    status:String(body.status||'available').trim(),
    img:String(body.img||'').trim(),
    desc:String(body.desc||'').trim(),
    color:String(body.color||'').trim()
  };
}

async function handleApi(req,res,pathname){
  const data=readData();
  const method=req.method;

  if(pathname==='/api/auth/me'&&method==='GET'){
    const user=getUserFromRequest(req,data);
    json(res,200,{user:cleanUser(user)});
    return;
  }

  if(pathname==='/api/auth/register'&&method==='POST'){
    const body=await readBody(req);
    const name=String(body.name||'').trim();
    const email=normalizeEmail(body.email);
    const password=String(body.password||'');
    if(!name||!email||!password){sendError(res,400,'Please fill in all fields.');return}
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)){sendError(res,400,'Please enter a valid email.');return}
    if(password.length<6){sendError(res,400,'Password must be at least 6 characters.');return}
    if(data.users.some(user=>user.email===email)){sendError(res,409,'An account with this email already exists.');return}
    const user={id:nextId(data.users),email,password:hashPassword(password),role:'client',name,createdAt:new Date().toISOString()};
    data.users.push(user);
    data.favorites[user.id]=[];
    writeData(data);
    json(res,201,{user:cleanUser(user)},{'Set-Cookie':sessionCookie(user.id)});
    return;
  }

  if(pathname==='/api/auth/login'&&method==='POST'){
    const body=await readBody(req);
    const email=normalizeEmail(body.email);
    const password=String(body.password||'');
    const user=data.users.find(item=>item.email===email);
    if(!user||!verifyPassword(password,user.password)){sendError(res,401,'Invalid email or password.');return}
    json(res,200,{user:cleanUser(user)},{'Set-Cookie':sessionCookie(user.id)});
    return;
  }

  if(pathname==='/api/auth/logout'&&method==='POST'){
    json(res,200,{ok:true},{'Set-Cookie':clearSessionCookie()});
    return;
  }

  if(pathname==='/api/auth/profile'&&method==='PUT'){
    const user=requireUser(req,res,data);if(!user)return;
    const body=await readBody(req);
    const name=String(body.name||'').trim();
    const email=normalizeEmail(body.email);
    const password=String(body.password||'');
    if(!name||!email){sendError(res,400,'Name and email are required.');return}
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)){sendError(res,400,'Please enter a valid email.');return}
    if(data.users.some(item=>item.email===email&&item.id!==user.id)){sendError(res,409,'Email already in use.');return}
    if(password&&password.length<6){sendError(res,400,'Password must be at least 6 characters.');return}
    user.name=name;
    user.email=email;
    if(password)user.password=hashPassword(password);
    writeData(data);
    json(res,200,{user:cleanUser(user)});
    return;
  }

  if(pathname==='/api/auth/me'&&method==='DELETE'){
    const user=requireUser(req,res,data);if(!user)return;
    if(user.role==='admin'){sendError(res,400,'Admin accounts cannot be deleted.');return}
    data.users=data.users.filter(item=>item.id!==user.id);
    data.inquiries=data.inquiries.filter(inq=>inq.userId!==user.id);
    delete data.favorites[user.id];
    writeData(data);
    json(res,200,{ok:true},{'Set-Cookie':clearSessionCookie()});
    return;
  }

  if(pathname==='/api/cars'&&method==='GET'){
    json(res,200,{cars:data.cars});
    return;
  }

  if(pathname==='/api/cars'&&method==='POST'){
    requireAdmin(req,res,data);if(res.writableEnded)return;
    const body=await readBody(req);
    const car=carFromBody(body,nextId(data.cars));
    if(!car.make||!car.model){sendError(res,400,'Make and Model are required.');return}
    data.cars.push(car);
    writeData(data);
    json(res,201,{car});
    return;
  }

  const carMatch=pathname.match(/^\/api\/cars\/(\d+)$/);
  if(carMatch&&method==='PUT'){
    requireAdmin(req,res,data);if(res.writableEnded)return;
    const id=Number(carMatch[1]);
    const idx=data.cars.findIndex(car=>car.id===id);
    if(idx===-1){sendError(res,404,'Car not found.');return}
    const car=carFromBody(await readBody(req),id);
    if(!car.make||!car.model){sendError(res,400,'Make and Model are required.');return}
    data.cars[idx]=car;
    writeData(data);
    json(res,200,{car});
    return;
  }

  if(carMatch&&method==='DELETE'){
    requireAdmin(req,res,data);if(res.writableEnded)return;
    const id=Number(carMatch[1]);
    data.cars=data.cars.filter(car=>car.id!==id);
    Object.keys(data.favorites).forEach(userId=>{
      data.favorites[userId]=(data.favorites[userId]||[]).filter(carId=>carId!==id);
    });
    writeData(data);
    json(res,200,{ok:true});
    return;
  }

  if(pathname==='/api/inquiries'&&method==='GET'){
    const user=requireUser(req,res,data);if(!user)return;
    const inquiries=user.role==='admin'?data.inquiries:data.inquiries.filter(inq=>inq.userId===user.id||inq.email===user.email);
    json(res,200,{inquiries});
    return;
  }

  if(pathname==='/api/inquiries'&&method==='POST'){
    const body=await readBody(req);
    const user=getUserFromRequest(req,data);
    const name=String(body.name||'').trim();
    const email=normalizeEmail(body.email);
    const msg=String(body.msg||'').trim();
    if(!name||!email||!msg){sendError(res,400,'Please fill in name, email, and message.');return}
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)){sendError(res,400,'Please enter a valid email.');return}
    const inq={name,email,phone:String(body.phone||'').trim(),msg,date:new Date().toISOString(),userId:user?user.id:null};
    data.inquiries.unshift(inq);
    writeData(data);
    json(res,201,{inquiry:inq});
    return;
  }

  if(pathname==='/api/favorites'&&method==='GET'){
    const user=requireUser(req,res,data);if(!user)return;
    const favorites=user.role==='admin'?[]:(data.favorites[user.id]||[]);
    json(res,200,{favorites});
    return;
  }

  const favMatch=pathname.match(/^\/api\/favorites\/(\d+)$/);
  if(favMatch&&(method==='POST'||method==='DELETE')){
    const user=requireUser(req,res,data);if(!user)return;
    if(user.role==='admin'){sendError(res,403,'Saved cars are available for client accounts.');return}
    const id=Number(favMatch[1]);
    if(!data.cars.some(car=>car.id===id)){sendError(res,404,'Car not found.');return}
    const set=new Set(data.favorites[user.id]||[]);
    if(method==='POST')set.add(id);
    else set.delete(id);
    data.favorites[user.id]=[...set];
    writeData(data);
    json(res,200,{favorites:data.favorites[user.id]});
    return;
  }

  sendError(res,404,'API route not found.');
}

const server=http.createServer(async(req,res)=>{
  const url=new URL(req.url,`http://${req.headers.host||'localhost'}`);
  const pathname=decodeURIComponent(url.pathname);
  try{
    if(pathname==='/healthz'){
      json(res,200,{ok:true});
      return;
    }
    if(pathname.startsWith('/api/')){
      await handleApi(req,res,pathname);
      return;
    }
    if(pathname==='/'||pathname==='/cardealership.html'){
      sendApp(res);
      return;
    }
    sendError(res,404,'Not found.');
  }catch(err){
    console.error(err);
    sendError(res,500,err.message||'Server error.');
  }
});

ensureDataFile();
server.listen(PORT,()=>{
  console.log(`MotorLux running at http://localhost:${PORT}`);
});
