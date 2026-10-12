// Illustrative data only. No connection to Alice, Azure, SSH or a live installation.
export const referenceTime = new Date('2026-10-12T09:42:00Z');
const day = 86400000;
export const atDay = n => new Date(+referenceTime + n * day).toISOString();
export const servers = Array.from({length:18},(_,i)=>({
  id:'srv-'+(i+1),name:['nginx-prod-01','nginx-prod-02','nginx-edge-01','bastion-prod-01','nginx-staging-01','app-worker-01','app-worker-02','nginx-api-01','nginx-api-02','batch-prod-01','monitoring-01','backup-01','nginx-internal-01','nginx-internal-02','build-runner-01','build-runner-02','db-proxy-01','nginx-edge-02'][i],
  host:'10.24.'+(i<8?'1':'2')+'.'+(20+i),port:22,username:'alice',type:i<3||[4,7,8,12,13,17].includes(i)?'nginx':'linux',
  status:i===2?'host_key_changed':i===9?'unreachable':'ok',os:i%4===0?'Debian 12':'Ubuntu 24.04 LTS',lastSeen:i===9?'08:11':'09:'+String(30+i%12).padStart(2,'0'),keys:3+i%5,
  fingerprint:'SHA256:'+['4d7P0X3dM8cJQ7Y6vn0TiFJ1dDZhUEdcTfPXNJ0C3rU','A9qcMnyJu7pnHk82RSgLo3xf78Hna4mnJreYsMwvQzE','6AxbNCmJYmELP4nhSu1PMTZFcaHQJ3K6dMthDQnF5nY'][i%3]
}));
export const vaults=[
  {id:'kv-1',name:'atlas-production',host:'atlas-production.vault.azure.net',status:'ok',auth:'Managed identity',certs:18,keys:8,secrets:12,lastSeen:'09:39'},
  {id:'kv-2',name:'atlas-staging',host:'atlas-staging.vault.azure.net',status:'ok',auth:'Service principal · certificate',certs:9,keys:4,secrets:6,lastSeen:'09:37'},
  {id:'kv-3',name:'atlas-internal',host:'atlas-internal.vault.azure.net',status:'ok',auth:'Service principal · certificate',certs:7,keys:3,secrets:5,lastSeen:'09:35'}
];
const firstNames=['legacy.atlas.example','api.atlas.example','payments.atlas.example','portal.atlas.example','*.atlas.example','internal.atlas.example','auth.atlas.example','assets.atlas.example','status.atlas.example','monitor.atlas.example','webhooks.atlas.example','staging.atlas.example','docs.atlas.example','cdn.atlas.example'];
export const certificates=Array.from({length:124},(_,i)=>{
  const days=[-2,3,6,12,18,26,33,37,41,44,47,52,56,59][i]??(65+((i*13)%275));
  const source=i===1||i===4||i===7||i%5===0&&i>5?'azure_kv':i%4===1?'uploaded':i%7===0?'csr':'discovered';
  const name=firstNames[i]||['service','gateway','app','endpoint'][i%4]+'-'+String(i-13).padStart(2,'0')+'.atlas.example';
  return {id:'crt-'+(i+1),name,days,source,issuer:i%3===0?'DigiCert Global G2':'Atlas Enterprise CA',algorithm:i%3===0?'RSA 3072':'ECDSA P-256',key:i!==0&&i%6!==0,chain:i!==8,notAfter:atDay(days),notBefore:atDay(days-365),locations:i===0?['srv-5']:i===1?['srv-1','srv-2']:i===4?['srv-1','srv-8','srv-9']:[servers[i%18].id],vault:source==='azure_kv'?'kv-'+(i%3+1):null,fingerprint:('A7:4C:2D:09:B1:6F:E8:C3:75:21:98:AD:44:DF:02:9C:'+String(i).padStart(2,'0')+':3E:5B:72:1A:90:C4:DE:68:11:83:FC:07:29:AA:5D')};
});
for (const vault of vaults) vault.certs=certificates.filter(c=>c.vault===vault.id).length;
export const sshKeys=Array.from({length:36},(_,i)=>({id:'key-'+(i+1),name:['deploy-production','alice-connection','legacy-batch','release-bot','ops-readonly','backup-service'][i]||'service-key-'+String(i-5).padStart(2,'0'),type:i===2?'RSA 1024':i%4===3?'RSA 3072':'Ed25519',weak:i===2,managed:i!==2&&i%5!==4,servers:i===0?6:2+i%4,owner:i===1?'alice':i===2?'root':i%3===0?'deploy':'svc-app',rotation:i===0?'overlap':i<6?'scheduled':'none',fingerprint:'SHA256:'+['Bp7q93rW5sV9v0mB7FTsWjYH6Gx8bJz0hXq1x4f2bRU','sL6q1UDKL69PbZvOLrcRdChG0bxrNlZwcTuPXJFknlo','nbD3YqCTqfQmFivYWvjRG81MCptlj91h4KgYmDeE2z0'][i%3]}));
export const deployments=[
  {id:'dep-1842',cert:'crt-2',target:'srv-1',status:'succeeded',at:'09:34:12',duration:'14.2s',by:'System',trigger:'key_vault',verified:'remote'},
  {id:'dep-1841',cert:'crt-2',target:'srv-2',status:'succeeded',at:'09:33:40',duration:'12.8s',by:'System',trigger:'key_vault',verified:'remote'},
  {id:'dep-1840',cert:'crt-4',target:'srv-5',status:'rolled_back',at:'09:18:06',duration:'23.6s',by:'Eren Altan',trigger:'manual',verified:'remote'},
  {id:'dep-1839',cert:'crt-5',target:'srv-8',status:'succeeded',at:'08:52:10',duration:'11.4s',by:'Eren Altan',trigger:'manual',verified:'remote'},
  {id:'dep-1838',cert:'crt-5',target:'srv-9',status:'unchanged',at:'08:51:54',duration:'1.2s',by:'System',trigger:'key_vault',verified:'remote'},
  {id:'dep-1837',cert:'crt-8',target:'srv-3',status:'needs_attention',at:'08:46:03',duration:'—',by:'Eren Altan',trigger:'manual',verified:''},
];
export const auditEvents=[
  {id:18429,time:'09:34:26',actor:'System',action:'certificate.deployed',object:'api.atlas.example',result:'success',ip:'—',ref:'deployments/dep-1842'},
  {id:18428,time:'09:33:53',actor:'System',action:'certificate.deployed',object:'api.atlas.example',result:'success',ip:'—',ref:'deployments/dep-1841'},
  {id:18427,time:'09:18:30',actor:'Eren Altan',action:'certificate.deploy_rolled_back',object:'portal.atlas.example',result:'failure',ip:'10.20.1.42',ref:'deployments/dep-1840'},
  {id:18426,time:'09:05:12',actor:'Eren Altan',action:'auth.login',object:'eren',result:'success',ip:'10.20.1.42',ref:'account'},
  {id:18425,time:'08:52:22',actor:'Eren Altan',action:'certificate.deployed',object:'*.atlas.example',result:'success',ip:'10.20.1.42',ref:'deployments/dep-1839'},
  {id:18424,time:'08:40:00',actor:'System',action:'rotation.overlap',object:'deploy-production',result:'success',ip:'—',ref:'rotations/run-91'},
  {id:18423,time:'08:36:14',actor:'System',action:'target.host_key_changed',object:'nginx-edge-01',result:'failure',ip:'—',ref:'servers/srv-3'},
  {id:18422,time:'08:31:44',actor:'Emre Kaya',action:'license.read',object:'Installation license',result:'denied',ip:'10.20.1.58',ref:'license'},
  {id:18421,time:'02:00:18',actor:'System',action:'backup.created',object:'alice-2026-10-12.enc',result:'success',ip:'—',ref:'settings/backups'}
];
export const users=[{name:'Eren Altan',initials:'EA',email:'eren@atlas.example',role:'admin',auth:'TOTP',status:'active',last:'09:05'},{name:'Aylin Demir',initials:'AD',email:'aylin@atlas.example',role:'admin',auth:'OIDC',status:'active',last:'11 Oct'},{name:'Emre Kaya',initials:'EK',email:'emre@atlas.example',role:'operator',auth:'TOTP',status:'active',last:'08:29'},{name:'Deniz Yılmaz',initials:'DY',email:'deniz@atlas.example',role:'auditor',auth:'TOTP',status:'active',last:'10 Oct'}];
export const certificateCounts=()=>({total:certificates.length,expired:certificates.filter(c=>c.days<=0).length,within7:certificates.filter(c=>c.days<=7).length,within30:certificates.filter(c=>c.days<=30).length,within60:certificates.filter(c=>c.days<=60).length});
