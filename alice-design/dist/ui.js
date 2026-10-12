import { icons } from './icons.js';
export const safeRead=(key,fallback)=>{try{return localStorage.getItem(key)||fallback}catch{return fallback}};
export const safeSave=(key,value)=>{try{localStorage.setItem(key,value)}catch{}};
export const state={lang:safeRead('alice-lang','en'),role:'admin',theme:safeRead('alice-theme','system'),density:safeRead('alice-density','comfortable'),period:60,overview:'operations',license:'active',sampleState:'ready',setupStep:0,modal:null};
export const t=(en,tr)=>state.lang==='tr'?(tr??en):en;
export const esc=x=>String(x??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export const icon=(name,cls='')=>`<svg class="icon ${cls}" viewBox="0 0 24 24" aria-hidden="true">${(icons[name]||icons.Circle).map(([tag,attrs])=>`<${tag} ${Object.entries(attrs).map(([k,v])=>`${k}="${esc(v)}"`).join(' ')}/>`).join('')}</svg>`;
export const btn=(label,action,ico='',variant='',extra='')=>`<button ${extra.includes('type=')?'':'type="button"'} class="btn ${variant}" data-action="${action}" ${extra}>${ico?icon(ico):''}${label}</button>`;
export const link=(label,to,ico='',cls='')=>`<a href="#/${to}" class="${cls}">${ico?icon(ico):''}${label}</a>`;
export const actionLink=(label,action,ico='ArrowUpRight')=>`<button class="text-link" data-action="${action}">${label}${icon(ico)}</button>`;
export const navLink=(label,to,ico='ArrowUpRight')=>link(label,to,ico,'text-link');
export const badge=(label,type='',ico='')=>`<span class="pill ${type}">${ico?icon(ico):'<i class="dot"></i>'}${label}</span>`;
export const statusText=(s)=>({ok:t('Connected','Bağlı'),host_key_changed:t('Identity changed','Kimlik değişti'),unreachable:t('Unreachable','Erişilemiyor'),auth_failed:t('Authentication failed','Kimlik doğrulanamadı'),succeeded:t('Verified','Doğrulandı'),rolled_back:t('Rolled back','Geri alındı'),needs_attention:t('Recovering','Kurtarılıyor'),running:t('In progress','Devam ediyor'),unchanged:t('No change','Değişiklik yok'),pending:t('Queued','Sırada'),success:t('Success','Başarılı'),failure:t('Failed','Başarısız'),denied:t('Denied','Reddedildi'),active:t('Active','Etkin'),overlap:t('Overlap period','Geçiş süresi'),scheduled:t('Scheduled','Planlandı'),admin:t('Administrator','Yönetici'),operator:t('Operator','Operatör'),auditor:t('Auditor','Denetçi')})[s]||s;
export const statusBadge=s=>badge(statusText(s),['ok','succeeded','success','active'].includes(s)?'success':['host_key_changed','auth_failed','failure','denied','rollback_failed'].includes(s)?'danger':['rolled_back','needs_attention','unreachable','overlap'].includes(s)?'warning':['running','pending','scheduled'].includes(s)?'info':'');
export const sourceName=s=>({discovered:t('Nginx discovery','Nginx keşfi'),uploaded:t('Uploaded','Yüklendi'),csr:'CSR',azure_kv:'Azure Key Vault'})[s]||s;
export const sourceIcon=s=>s==='azure_kv'?'Cloud':s==='discovered'?'Server':'FileKey2';
export const expiryLabel=days=>days<=0?t(`Expired ${Math.abs(days)}d ago`,`${Math.abs(days)} gün önce doldu`):t(`${days} days left`,`${days} gün kaldı`);
export const expiryBadge=c=>badge(expiryLabel(c.days),c.days<=0?'danger':c.days<=30?'warning':'success',c.days<=0?'CircleAlert':'Clock3');
export const date=x=>new Intl.DateTimeFormat(state.lang==='tr'?'tr-TR':'en-GB',{day:'2-digit',month:'short',year:'numeric',timeZone:'UTC'}).format(new Date(x));
export const title=(name,description,actions='',eyebrow='')=>`<header class="page-head"><div>${eyebrow?`<div class="eyebrow">${eyebrow}</div>`:''}<h1>${name}</h1>${description?`<p>${description}</p>`:''}</div>${actions?`<div class="page-head-actions">${actions}</div>`:''}</header>`;
export const panel=(name,sub,body,action='',cls='')=>`<section class="panel ${cls}"><header class="panel-head"><div><h2>${name}</h2>${sub?`<p>${sub}</p>`:''}</div>${action}</header>${body}</section>`;
export const panelBody=body=>`<div class="panel-body">${body}</div>`;
export const fact=(key,value)=>`<div class="fact"><div class="fact-label">${key}</div><div class="fact-value">${value}</div></div>`;
export const empty=(name,desc,action='')=>`<div class="empty">${icon('Search')}<h2>${name}</h2><p>${desc}</p>${action}</div>`;
export const table=(heads,rows,label='',cls='')=>`<div class="table-scroll" tabindex="0" role="region" aria-label="${esc(label||t('Data table','Veri tablosu'))}"><table class="data-table ${cls}"><thead><tr>${heads.map(h=>`<th scope="col">${h}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table></div>`;
export const metric=(label,value,note,ico,to,tone='')=>`<a class="metric" href="#/${to}"><div class="metric-label">${label}${icon(ico)}</div><div class="metric-value">${value}</div><div class="metric-foot ${tone}">${note}</div></a>`;
export const options=(items,selected)=>items.map(([value,label])=>`<option value="${esc(value)}" ${String(value)===String(selected)?'selected':''}>${esc(label)}</option>`).join('');
export const searchInput=(value,placeholder,name='q')=>`<label class="search-field">${icon('Search')}<input type="search" name="${name}" data-filter="${name}" value="${esc(value)}" placeholder="${placeholder}" aria-label="${placeholder}" autocomplete="off"></label>`;
export const select=(name,items,value,label)=>`<select class="filter-select" data-filter="${name}" aria-label="${label}">${options(items,value)}</select>`;
export const field=(label,name,value='',type='text',hint='',extra='')=>`<div class="field"><label for="${name}">${label}</label><input type="${type}" id="${name}" name="${name}" value="${esc(value)}" ${extra}>${hint?`<p>${hint}</p>`:''}</div>`;
export const selectField=(label,name,items,value,hint='')=>`<div class="field"><label for="${name}">${label}</label><select id="${name}" name="${name}">${options(items,value)}</select>${hint?`<p>${hint}</p>`:''}</div>`;
export const notice=(heading,copy='',type='',action='')=>`<div class="status-line ${type}">${icon(type==='danger'?'ShieldAlert':type==='warn'?'CircleAlert':'ShieldCheck')}<div class="grow"><strong>${heading}</strong>${copy?`<p>${copy}</p>`:''}</div>${action}</div>`;
export const canOperate=()=>state.role!=='auditor'&&state.license!=='locked';
export const isAdmin=()=>state.role==='admin';
export const canSeeAudit=()=>state.role!=='operator';
export function query(){return new URLSearchParams(location.hash.split('?')[1]||'')}
export function route(){return location.hash.replace(/^#\/?/,'').split('?')[0]||'overview'}
export function download(name,body,type='text/plain'){const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([body],{type}));a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(a.href),1000)}
export function csv(rows){return rows.map(r=>r.map(v=>'"'+String(v??'').replace(/"/g,'""')+'"').join(',')).join('\r\n')}
export const sourceRef=(file)=>`<a href="https://github.com/erenmeren/alice/blob/44521f52ce02fc92e02a89c9d5a2011f3b95c4a9/${file}" target="_blank" rel="noopener" class="text-link"><code>${file}</code>${icon('ArrowUpRight')}</a>`;
