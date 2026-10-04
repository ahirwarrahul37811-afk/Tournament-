const express=require('express'),{Pool}=require('pg'),crypto=require('crypto'),path=require('path');
const {DATABASE_URL,SECRET,ADMIN_PHONE}=process.env;
if(!DATABASE_URL||!SECRET||!ADMIN_PHONE){console.error('Set DATABASE_URL, SECRET and ADMIN_PHONE');process.exit(1)}
const pool=new Pool({connectionString:DATABASE_URL,ssl:/localhost|127\.0\.0\.1/.test(DATABASE_URL)?false:{rejectUnauthorized:false}});
const REF=5,MINW=80,MODES={Solo:1,Duo:2,Squad:4};
const app=express();app.set('trust proxy',1);app.use(express.json({limit:'20kb'}));
app.use((req,res,next)=>{const o=process.env.ALLOWED_ORIGIN;if(o){res.set({'Access-Control-Allow-Origin':o,'Access-Control-Allow-Headers':'Content-Type, Authorization','Access-Control-Allow-Methods':'GET,POST,OPTIONS'});if(req.method=='OPTIONS')return res.sendStatus(204)}next()});
const q=(t,p)=>pool.query(t,p);
async function tx(f){const c=await pool.connect();try{await c.query('BEGIN');const r=await f(c);await c.query('COMMIT');return r}catch(e){await c.query('ROLLBACK');throw e}finally{c.release()}}
const bad=(m,s=400)=>Object.assign(new Error(m),{status:s});
const hash=(pin,salt=crypto.randomBytes(16).toString('hex'))=>salt+':'+crypto.scryptSync(pin,salt,32).toString('hex');
const check=(pin,h)=>{const [s,x]=String(h).split(':'),y=crypto.scryptSync(pin,s,32).toString('hex');return x.length==y.length&&crypto.timingSafeEqual(Buffer.from(x),Buffer.from(y))};
const mac=b=>crypto.createHmac('sha256',SECRET).update(b).digest('base64url');
const sign=uid=>{const b=Buffer.from(JSON.stringify({uid,exp:Date.now()+30*864e5})).toString('base64url');return b+'.'+mac(b)};
const verify=t=>{try{const [b,s]=t.split('.'),e=mac(b);if(s.length!=e.length||!crypto.timingSafeEqual(Buffer.from(s),Buffer.from(e)))return null;const p=JSON.parse(Buffer.from(b,'base64url'));return p.exp>Date.now()?p.uid:null}catch{return null}};
const tries={};const limit=(k,n=8)=>{const t=Date.now(),a=(tries[k]||[]).filter(x=>t-x<6e5);if(a.length>=n)throw bad('Too many attempts. Try again after 10 minutes.',429);a.push(t);tries[k]=a};
const h=f=>async(req,res)=>{try{res.json(await f(req)||{ok:1})}catch(e){if(!e.status)console.error(e);res.status(e.status||500).json({error:e.status?e.message:'Server error'})}};
const needUser=r=>{if(!r.user)throw bad('Please login.',401)};
const needAdmin=r=>{needUser(r);if(!r.user.admin)throw bad('Admin only.',403)};
const credit=async(c,uid,a,n)=>{await c.query('update users set bal=bal+$1 where id=$2',[a,uid]);await c.query('insert into log(uid,a,n) values($1,$2,$3)',[uid,a,n])};
const S=(v,n=60)=>String(v??'').trim().slice(0,n);

app.use(async(req,res,next)=>{try{const t=(req.headers.authorization||'').slice(7),id=t&&verify(t);req.user=id?(await q('select * from users where id=$1',[id])).rows[0]||null:null;if(req.user)req.user.admin=req.user.phone===ADMIN_PHONE;next()}catch(e){next(e)}});

app.post('/api/signup',h(async r=>{const {phone,pin,ref}=r.body,name=S(r.body.name,40);limit('s'+r.ip,10);
 if(!name)throw bad('Enter your name.');if(!/^[6-9]\d{9}$/.test(phone))throw bad('Enter a valid 10-digit mobile number.');if(!/^\d{4,6}$/.test(pin))throw bad('PIN must be 4-6 digits.');
 let by=null;if(ref){const x=(await q('select id from users where code=$1',[S(ref,10).toUpperCase()])).rows[0];if(!x)throw bad('Invalid referral code.');by=x.id}
 try{const u=(await q('insert into users(phone,name,pin_hash,code,ref_by) values($1,$2,$3,$4,$5) returning id',[phone,name,hash(pin),crypto.randomBytes(5).toString('hex').toUpperCase(),by])).rows[0];return {token:sign(u.id)}}
 catch(e){if(e.code=='23505')throw bad('This mobile number already has an account. Please login.',409);throw e}}));
app.post('/api/login',h(async r=>{const phone=S(r.body.phone,12),pin=S(r.body.pin,10);limit('l'+r.ip+phone);
 const u=(await q('select * from users where phone=$1',[phone])).rows[0];if(!u||!check(pin,u.pin_hash))throw bad('Wrong mobile number or PIN.',401);return {token:sign(u.id)}}));

app.get('/api/state',h(async r=>{const u=r.user,s={me:null};
 s.tours=(await q('select t.id,t.game,t.name,t.starts as date,t.mode,t.fee,t.prize,t.slots,t.upi,(select count(*)::int from regs where tid=t.id) as taken from tours t order by t.starts')).rows;
 if(!u)return s;s.me={id:u.id,phone:u.phone,name:u.name,code:u.code,bal:u.bal,admin:u.admin};
 s.regs=(await q('select id,tid,uid,phone,team,players,utr,status from regs where uid=$1 order by id desc',[u.id])).rows;
 s.wd=(await q('select id,uid,amt,upi,s from wd where uid=$1 order by id desc',[u.id])).rows;
 s.log=(await q('select a,n,(extract(epoch from t)*1000)::float8 as t from log where uid=$1 order by id desc limit 100',[u.id])).rows;
 s.rooms=Object.fromEntries((await q("select r.tid,t.room_id,t.room_pass from regs r join tours t on t.id=r.tid where r.uid=$1 and r.status='approved'",[u.id])).rows.map(x=>[x.tid,{room:x.room_id,pass:x.room_pass}]));
 if(u.admin){s.users=(await q('select id,name,phone,bal,code,ref_by as "by",paid from users order by id')).rows;
  s.allRegs=(await q('select id,tid,uid,phone,team,players,utr,status from regs order by id desc')).rows;
  s.allWd=(await q('select w.id,w.uid,u.name,u.phone,w.amt,w.upi,w.s from wd w join users u on u.id=w.uid order by w.id desc')).rows;
  s.allRooms=Object.fromEntries((await q('select id,room_id,room_pass from tours')).rows.map(x=>[x.id,{room:x.room_id,pass:x.room_pass}]))}
 return s}));

app.post('/api/register',h(async r=>{needUser(r);const tid=+r.body.tid,team=S(r.body.team,40),utr=S(r.body.utr,30),pl=r.body.players;
 if(!/^[\w\-]{8,30}$/.test(utr))throw bad('Enter a valid UTR / transaction ID (letters and digits only).');
 return tx(async c=>{const t=(await c.query('select * from tours where id=$1 for update',[tid])).rows[0];if(!t)throw bad('Tournament not found.');
  if(!Array.isArray(pl)||pl.length!=MODES[t.mode]||!team||pl.some(p=>!p||!S(p.n)))throw bad('Fill team and all player names.');
  const players=pl.map(p=>({n:S(p.n,30),u:S(p.u,15)})),gid=players[0].u;if(!/^\d{6,15}$/.test(gid))throw bad('Enter a valid Game UID (digits).');
  await c.query('insert into gids(gid,uid) values($1,$2) on conflict do nothing',[gid,r.user.id]);
  if((await c.query('select uid from gids where gid=$1',[gid])).rows[0].uid!=r.user.id)throw bad('This Game UID is already used by another account.',409);
  if((await c.query('select count(*)::int n from regs where tid=$1',[tid])).rows[0].n>=t.slots)throw bad('Sorry, slots are full.');
  await c.query('savepoint sp');
  try{await c.query('insert into regs(tid,uid,phone,team,players,utr) values($1,$2,$3,$4,$5,$6)',[tid,r.user.id,r.user.phone,team,JSON.stringify(players),utr])}
  catch(e){if(e.code=='23505')throw bad(e.constraint=='regs_utr'?'This UTR was already submitted.':'You are already registered here.',409);throw e}})}));
app.post('/api/withdraw',h(async r=>{needUser(r);const a=+r.body.amt,upi=S(r.body.upi,50);
 if(!Number.isInteger(a)||a<MINW)throw bad('Minimum withdrawal is ₹'+MINW+' (whole rupees).');if(!/^[\w.\-]{2,}@\w{2,}$/.test(upi))throw bad('Enter a valid UPI ID.');
 return tx(async c=>{if(!(await c.query('update users set bal=bal-$1 where id=$2 and bal>=$1 returning id',[a,r.user.id])).rows[0])throw bad('Not enough balance.');
  await c.query('insert into wd(uid,amt,upi) values($1,$2,$3)',[r.user.id,a,upi]);await c.query('insert into log(uid,a,n) values($1,$2,$3)',[r.user.id,-a,'Withdrawal requested'])})}));

app.post('/api/admin/approve',h(async r=>{needAdmin(r);return tx(async c=>{
 const g=(await c.query("update regs set status='approved' where id=$1 and status='pending' returning uid",[+r.body.id])).rows[0];if(!g)throw bad('Already processed.');
 const u=(await c.query('update users set paid=true where id=$1 and paid=false and ref_by is not null returning ref_by,name',[g.uid])).rows[0];
 if(u)await credit(c,u.ref_by,REF,'Referral: '+u.name)})}));
app.post('/api/admin/reject',h(async r=>{needAdmin(r);await q('delete from regs where id=$1',[+r.body.id])}));
app.post('/api/admin/award',h(async r=>{needAdmin(r);const a=+r.body.amt;if(!Number.isInteger(a)||a<1)throw bad('Enter a valid amount.');
 return tx(async c=>{const g=(await c.query("select r.uid,r.team,t.name from regs r join tours t on t.id=r.tid where r.id=$1 and r.status='approved'",[+r.body.id])).rows[0];if(!g)throw bad('Team not found.');
  await credit(c,g.uid,a,'Prize: '+g.name+' ('+g.team+')')})}));
app.post('/api/admin/wd',h(async r=>{needAdmin(r);const s=r.body.s;if(!['paid','rejected'].includes(s))throw bad('Bad status.');
 return tx(async c=>{const w=(await c.query("update wd set s=$2 where id=$1 and s='pending' returning uid,amt,upi",[+r.body.id,s])).rows[0];if(!w)throw bad('Already processed.');
  if(s=='rejected')await credit(c,w.uid,w.amt,'Withdrawal rejected, refunded');else await c.query('insert into log(uid,a,n) values($1,0,$2)',[w.uid,'Withdrawal paid to '+w.upi])})}));
app.post('/api/admin/tour',h(async r=>{needAdmin(r);const b=r.body;if(!S(b.name)||!S(b.date)||!S(b.upi)||!MODES[b.mode]||!['BGMI','Free Fire MAX'].includes(b.game))throw bad('Name, date and UPI are required.');
 await q('insert into tours(game,name,starts,mode,fee,prize,slots,upi) values($1,$2,$3,$4,$5,$6,$7,$8)',[b.game,S(b.name,80),S(b.date,20),b.mode,Math.max(0,+b.fee|0),Math.max(0,+b.prize|0),Math.max(2,+b.slots|0||25),S(b.upi,50)])}));
app.post('/api/admin/room',h(async r=>{needAdmin(r);await q('update tours set room_id=$2,room_pass=$3 where id=$1',[+r.body.id,S(r.body.room,40),S(r.body.pass,40)])}));
app.post('/api/admin/deltour',h(async r=>{needAdmin(r);await q('delete from tours where id=$1',[+r.body.id])}));

app.use(express.static(path.join(__dirname,'public')));

// Start server FIRST
const PORT = process.env.PORT || 3000;

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Arena India running on port ${PORT}`);
});

// Then initialize database
(async()=>{
  await q(`
    create table if not exists users(
      id serial primary key,
      phone text unique not null,
      name text not null,
      pin_hash text not null,
      code text unique not null,
      ref_by int references users(id),
      paid boolean default false,
      bal int default 0 check(bal>=0),
      created timestamptz default now()
    );

    create table if not exists tours(
      id serial primary key,
      game text,
      name text,
      starts text,
      mode text,
      fee int,
      prize int,
      slots int,
      upi text,
      room_id text default '',
      room_pass text default ''
    );

    create table if not exists regs(
      id serial primary key,
      tid int references tours(id) on delete cascade,
      uid int references users(id),
      phone text,
      team text,
      players jsonb,
      utr text,
      status text default 'pending',
      created timestamptz default now(),
      constraint regs_one unique(tid,uid),
      constraint regs_utr unique(utr)
    );

    create table if not exists gids(
      gid text primary key,
      uid int not null
    );

    create table if not exists wd(
      id serial primary key,
      uid int references users(id),
      amt int,
      upi text,
      s text default 'pending',
      created timestamptz default now()
    );

    create table if not exists log(
      id serial primary key,
      uid int references users(id),
      a int,
      n text,
      t timestamptz default now()
    );
  `);

  if(!(await q('select 1 from tours limit 1')).rows.length) {
    await q(`
      insert into tours(game,name,starts,mode,fee,prize,slots,upi)
      values
      ('BGMI','Weekend Chicken Dinner Cup','2026-10-11T20:00','Squad',100,5000,25,'arena@upi'),
      ('Free Fire MAX','Booyah Showdown','2026-10-12T19:00','Duo',50,2500,24,'arena@upi')
    `);
  }

  console.log('Database initialized successfully');

})().catch(e => {
  console.error('DATABASE ERROR:', e);
});
