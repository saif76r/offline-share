const $=s=>document.querySelector(s);
const fmt=n=>n<1024?n+' B':n<1048576?(n/1024).toFixed(1)+' KB':n<1073741824?(n/1048576).toFixed(1)+' MB':(n/1073741824).toFixed(2)+' GB';
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const enc=encodeURIComponent, J=(url,body)=>fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
document.documentElement.dataset.t=localStorage.t||'';
$('#theme').onclick=()=>{const d=document.documentElement;d.dataset.t=(d.dataset.t==='dark'||(!d.dataset.t&&matchMedia('(prefers-color-scheme:dark)').matches))?'light':'dark';localStorage.t=d.dataset.t};
async function act(url,m='POST'){await fetch(url,{method:m});load()}
window.act=act;
window.peer=async id=>{await J('/api/peers/connect',{id});load()};
let mode='discover';
$('#unpair').onclick=()=>act('/api/unpair');
$('#modeBtn').onclick=async()=>{await J('/api/wifi/mode',{mode:mode==='discover'?'legacy':'discover'});load()};
$('#pick').onchange=async e=>{const fd=new FormData();[...e.target.files].forEach(f=>fd.append('files',f));await fetch('/api/outbox',{method:'POST',body:fd});e.target.value='';load()};
const list=(a,f,e)=>a.length?a.map(f).join(''):`<div class="empty">${e}</div>`;
async function load(){
 let s;try{s=await (await fetch('/api/state')).json()}catch{return}
 const w=s.wifi;mode=w.mode;
 $('#conn').innerHTML=s.sessions.length?s.sessions.map(x=>`<div><span class="dot on"></span><b>Phone connected</b><small style="display:block;color:var(--mut)">Device: ${esc(x.name)} · IP: ${esc(x.ip)}</small></div>`).join(''):
  `<div><span class="dot"></span>Waiting for phone</div><small style="color:var(--mut)">This laptop: ${esc(s.device)} · ${esc(s.ips.join(', '))}</small>`;
 $('#pin').textContent=s.pairing.pin;$('#pinTtl').textContent='new PIN in '+s.pairing.expires_in+'s · single use';
 $('#wifi').innerHTML=`<span class="dot ${w.available&&!w.dev?'on':''}"></span>${w.available?(w.dev?'DEV MODE (not Wi-Fi Direct)':'Wi-Fi Direct active · '+(w.mode==='legacy'?'QR mode · '+esc(w.ssid):'discoverable')):'<span class="err">'+esc(w.message||'Starting Wi-Fi Direct…').replace(/\n/g,'<br>')+'</span>'}`;
 $('#event').textContent=w.event||'';
 $('#modeBtn').textContent=mode==='discover'?'Switch to QR mode':'Switch to device list mode';
 $('#peers').innerHTML=w.mode==='legacy'?'<div class="empty">QR mode is on. Phones join using the QR code below.</div>':
  list(w.peers,p=>`<div class="row"><div class="n">📱 ${esc(p.name)}<small>Wi-Fi Direct device</small></div><button data-id="${esc(p.id)}" onclick="peer(this.dataset.id)">Connect</button></div>`,'Searching… open OfflineShare on the phone (it also appears there under Nearby devices).');
 $('#qrbox').hidden=w.mode!=='legacy';
 const key=s.pairing.pin+s.ips.join();if(w.mode==='legacy'&&$('#qr').dataset.p!==key){$('#qr').dataset.p=key;$('#qr').src='/api/qr.png?'+enc(key)}
 const inc=s.incoming;$('#incomingCard').hidden=!inc.length;
 $('#incoming').innerHTML=inc.map(t=>`<div class="row"><div class="n">📄 ${esc(t.name)}<small>${fmt(t.size)} · from ${esc(t.device)} · ${t.state}${t.error?' · '+esc(t.error):''}</small>
  ${t.state==='receiving'?`<div class="bar"><i style="width:${t.size?t.offset/t.size*100:0}%"></i></div>`:''}</div>
  ${t.state==='pending'?`<button class="ghost" onclick="act('/api/transfers/${t.id}/reject')">Reject</button><button onclick="act('/api/transfers/${t.id}/accept')">Accept</button>`:''}</div>`).join('');
 $('#outbox').innerHTML=list(s.outbox,f=>`<div class="row"><div class="n">📄 ${esc(f.name)}<small>${fmt(f.size)} · ready for phone to download</small></div><button class="ghost" onclick="act('/api/outbox/${enc(f.name)}','DELETE')">Remove</button></div>`,'No files queued. Select files — the phone will see them.');
 $('#received').innerHTML=list(s.received,f=>`<div class="row"><div class="n">📄 ${esc(f.name)}<small>${fmt(f.size)}</small></div><a class="btn" href="/api/open/received/${enc(f.name)}" target="_blank">Open</a><button class="red" onclick="confirm('Delete?')&&act('/api/received/${enc(f.name)}','DELETE')">Delete</button></div>`,'Nothing received yet.');
 $('#history').innerHTML=list(s.history,h=>`<div class="row"><small>${new Date(h.ts*1000).toLocaleString()}</small><div class="n">${esc(h.filename)}<small>${esc(h.direction)} · ${fmt(h.size)} · SHA-256 ${esc((h.sha256||'').slice(0,16))}…</small></div><span class="${/Completed|Sent/.test(h.status)?'ok':'err'}">${esc(h.status)}</span></div>`,'No transfers yet.');
}
load();setInterval(load,1500);
