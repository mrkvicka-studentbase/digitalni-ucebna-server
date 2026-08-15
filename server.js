const express = require('express');
const http = require('http');
const crypto = require('node:crypto');
const WebSocket = require('ws');

// Žádná nová závislost. HMAC umí Node sám přes vestavěný modul `node:crypto`
// (na Renderu běží Node, takže je to v pořádku — v rezervační aplikaci na
// Cloudflare Workers by být nesměl, tam se podepisuje přes Web Crypto).
// Instalovat tedy není co, `npm install` zůstává beze změny.

const app = express();
app.use(express.json({ limit: '8mb' }));

// CORS — aby aplikace mohla volat /ai odkudkoli (lokální soubor i budoucí subdoména)
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
});

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// =============================================================================
// PODEPSANÁ VSTUPENKA
// =============================================================================
// Do místnosti ani k AI se nikdo nedostane bez lístku, který vydala rezervační
// aplikace. Lístek má tvar `<obsah>.<podpis>`, obojí v base64url:
//
//   obsah  = JSON {v, sid, room, role, nbf, exp, jmeno, lekce, email}
//   podpis = HMAC-SHA256(UCEBNA_SECRET, obsah)
//
// Tajemství UCEBNA_SECRET musí být na Renderu NASTAVENÉ NA TUTÉŽ HODNOTU jako
// na Cloudflare. Když chybí, server nepustí dovnitř NIKOHO — nenastavené
// tajemství nikdy nesmí znamenat volný přístup.
//
// ROZBÍJÍME ZPĚTNOU KOMPATIBILITU. Dosavadní adresy typu
// `?room=hlavni&role=zak` přestanou fungovat a je to záměr: právě ony byly tou
// dírou. Kdyby si server nechal starou cestu jako záložní, stačilo by ji použít
// a všechna tahle práce by byla k ničemu — žák by si dál smazal `&role=zak`
// a AI by šla volat bez lístku. Postup nasazení je popsaný v NASTAVENI-UCEBNY.md.

/** O kolik smí jít hodiny serveru a klienta mimo, aby to ještě prošlo. */
const TOLERANCE_HODIN_S = 60;

/** Jak dlouho po vypršení lístku se ještě nechá běžet už navázané spojení. */
const DOBEH_SPOJENI_S = 60 * 60;

function base64UrlNaText(hodnota) {
    return Buffer.from(String(hodnota).replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
}

/**
 * Porovnání podpisů v konstantním čase.
 *
 * `timingSafeEqual` vyžaduje stejně dlouhé vstupy, jinak vyhodí výjimku —
 * délka se proto porovná zvlášť. Sama o sobě nic neprozrazuje, protože délka
 * podpisu je vždycky stejná; liší se jedině u zjevného nesmyslu.
 */
function podpisySedi(a, b) {
    const ba = Buffer.from(a);
    const bb = Buffer.from(b);
    if (ba.length !== bb.length) return false;
    return crypto.timingSafeEqual(ba, bb);
}

/**
 * Ověří vstupenku. Vrací { ok: true, obsah } nebo { ok: false, duvod, hlaska }.
 *
 * `hlaska` je česká věta pro uživatele, `duvod` krátký kód do logu.
 * Hláška nikdy neprozrazuje, jestli selhal podpis nebo platnost víc, než je
 * nutné — ale rozlišit prošlý lístek od podvrženého se hodí, jinak by rodič
 * nevěděl, jestli má počkat, nebo si otevřít aplikaci znovu.
 */
function overVstupenku(token) {
    const tajemstvi = process.env.UCEBNA_SECRET;
    if (!tajemstvi) {
        return {
            ok: false,
            duvod: 'bez-tajemstvi',
            hlaska: 'Učebna není na serveru nastavená (chybí UCEBNA_SECRET). Napiš prosím lektorovi.'
        };
    }

    const cely = String(token || '');
    const tecka = cely.indexOf('.');
    if (tecka <= 0 || tecka === cely.length - 1) {
        return { ok: false, duvod: 'tvar', hlaska: 'Odkaz do učebny je neúplný. Otevři ho prosím znovu z aplikace Rezervace.' };
    }

    const telo = cely.slice(0, tecka);
    const podpis = cely.slice(tecka + 1);
    const ocekavany = crypto.createHmac('sha256', tajemstvi).update(telo).digest('base64url');
    if (!podpisySedi(podpis, ocekavany)) {
        return { ok: false, duvod: 'podpis', hlaska: 'Odkaz do učebny není platný. Otevři ho prosím znovu z aplikace Rezervace.' };
    }

    let obsah;
    try {
        obsah = JSON.parse(base64UrlNaText(telo));
    } catch (e) {
        return { ok: false, duvod: 'json', hlaska: 'Odkaz do učebny je poškozený. Otevři ho prosím znovu z aplikace Rezervace.' };
    }

    if (!obsah || obsah.v !== 1) {
        return { ok: false, duvod: 'verze', hlaska: 'Odkaz do učebny je ze starší verze. Otevři ho prosím znovu z aplikace Rezervace.' };
    }
    if (obsah.role !== 'ucitel' && obsah.role !== 'zak') {
        return { ok: false, duvod: 'role', hlaska: 'Odkaz do učebny je poškozený. Otevři ho prosím znovu z aplikace Rezervace.' };
    }
    if (typeof obsah.room !== 'string' || obsah.room.length < 4) {
        return { ok: false, duvod: 'mistnost', hlaska: 'Odkaz do učebny je poškozený. Otevři ho prosím znovu z aplikace Rezervace.' };
    }

    const ted = Math.floor(Date.now() / 1000);
    if (typeof obsah.nbf !== 'number' || typeof obsah.exp !== 'number') {
        return { ok: false, duvod: 'platnost', hlaska: 'Odkaz do učebny je poškozený. Otevři ho prosím znovu z aplikace Rezervace.' };
    }
    if (ted + TOLERANCE_HODIN_S < obsah.nbf) {
        return { ok: false, duvod: 'brzy', hlaska: 'Učebna se otevře až deset minut před začátkem lekce. Zkus to prosím za chvíli.' };
    }
    if (ted - TOLERANCE_HODIN_S > obsah.exp) {
        return { ok: false, duvod: 'prosly', hlaska: 'Lekce už skončila a odkaz do učebny propadl.' };
    }

    return { ok: true, obsah: obsah };
}

// =============================================================================
// WEBSOCKET S MÍSTNOSTMI
// =============================================================================
// Místnost se NEBERE z adresy — bere se z podepsané vstupenky. Kdo lístek nemá,
// dovnitř se nedostane, a kdo ho má, dostane se právě do té jediné místnosti,
// která je v něm podepsaná. Přepsat si ji v adrese nejde: podpis by přestal
// sedět.
wss.on('connection', (ws, req) => {
    const params = new URL(req.url, 'http://localhost').searchParams;
    const overeni = overVstupenku(params.get('t'));

    if (!overeni.ok) {
        console.log(`Odmítnuté připojení do učebny (${overeni.duvod}).`);
        try {
            ws.send(JSON.stringify({ type: 'auth', ok: false, duvod: overeni.duvod, hlaska: overeni.hlaska }));
        } catch (e) { /* spojení se mohlo zavřít dřív, na odmítnutí to nic nemění */ }
        // 4401 = „nepustili jsme tě dovnitř". Klient podle toho pozná, že nemá
        // smysl se dokola připojovat znovu, a ukáže srozumitelnou hlášku.
        ws.close(4401, 'vstupenka');
        return;
    }

    ws.room = overeni.obsah.room;
    ws.role = overeni.obsah.role;
    ws.sid = overeni.obsah.sid;
    ws.exp = overeni.obsah.exp;
    console.log(`Do místnosti "${ws.room}" se připojil ${ws.role}.`);

    ws.send(JSON.stringify({
        type: 'auth',
        ok: true,
        role: ws.role,
        room: ws.room,
        jmeno: String(overeni.obsah.jmeno || ''),
        lekce: String(overeni.obsah.lekce || ''),
        email: String(overeni.obsah.email || '')
    }));

    ws.on('message', (message) => {
        // Několik druhů zpráv patří jedině učiteli: adresa synchronizace, název
        // lekce a jméno žáka, přepínání stránek. Prohlížeč žáka je sice
        // z protistrany nepřijímá, ale spoléhat se na to by znamenalo věřit
        // cizímu kódu. Kontroluje se jen prvních pár bajtů, aby to nezdržovalo
        // kreslení, kterého chodí desítky zpráv za vteřinu.
        if (ws.role !== 'ucitel') {
            const zacatek = typeof message === 'string' ? message.slice(0, 24) : message.toString('utf8', 0, 24);
            if (
                zacatek.startsWith('{"type":"config"') ||
                zacatek.startsWith('{"type":"meta"') ||
                zacatek.startsWith('{"type":"page-switch"')
            ) {
                return;
            }
        }

        wss.clients.forEach((client) => {
            if (client !== ws && client.readyState === WebSocket.OPEN && client.room === ws.room) {
                client.send(message);
            }
        });
    });

    ws.on('close', () => {
        console.log(`Místnost "${ws.room}" opustil ${ws.role}.`);
    });
});

/**
 * Úklid spojení s dávno propadlou vstupenkou.
 *
 * Platnost se schválně NEKONTROLUJE průběžně u každé zprávy: lekce se občas
 * protáhne a nikdo nechce, aby tabule zhasla uprostřed příkladu. Hodina po
 * vypršení už ale žádná lekce neběží, a spojení, které si někdo nechal otevřené
 * přes noc, tady skončí.
 */
setInterval(() => {
    const ted = Math.floor(Date.now() / 1000);
    wss.clients.forEach((client) => {
        if (typeof client.exp === 'number' && ted > client.exp + DOBEH_SPOJENI_S) {
            try { client.close(4403, 'prosle'); } catch (e) { /* spojení už je pryč */ }
        }
    });
}, 5 * 60 * 1000);

// Kontrolní stránka
app.get('/', (req, res) => {
    res.send('Mozek digitální učebny běží a je připraven na spojení!');
});

// ===== AI ASISTENT (Gemini) =====
// Klíč je bezpečně schovaný v proměnné prostředí GEMINI_API_KEY na Renderu.
const AI_SYSTEM_PROMPT =
    'Jsi asistent učitele na digitální tabuli pro doučování (matematika, čeština i další předměty). ' +
    'Učitel ti zadá požadavek (např. "vygeneruj 5 příkladů na sčítání zlomků"). ' +
    'Odpověz VÝHRADNĚ platným JSON objektem ve tvaru {"widgets": ["...", "..."]} — nic jiného. ' +
    'Každá položka pole "widgets" je jeden samostatný blok, který se objeví na tabuli (typicky jeden příklad). ' +
    'Pravidla obsahu: piš česky a stručně; povolené HTML značky jsou pouze <b>, <i>, <u>, <br>, <span>, <sub>, <sup>; ' +
    'zlomky zapisuj VÝHRADNĚ ve tvaru {citatel}/{jmenovatel} — např. {3}/{4}; ' +
    'složené závorky { } používej JEN pro zlomky, nikdy kolem samostatných čísel či výrazů — správně: (6 + 4 - 3), špatně: ({6} + {4} - {3}); ' +
    'odmocniny jako sqrt{...}, mocniny jako x^2; ' +
    'NIKDY nepoužívej zpětné lomítko, LaTeXové příkazy ani znak $; ' +
    'příklady čísluj (<b>1)</b> ...); ' +
    'výsledky ani postupy neuváděj, pokud si je učitel výslovně nevyžádá; ' +
    'maximálně 10 bloků.';

// Záložní seznam, kdyby se nepodařilo načíst modely od Googlu
const AI_MODELS_FALLBACK = [
    'gemini-3.5-flash-lite',
    'gemini-3.1-flash-lite',
    'gemini-2.5-flash-lite',
    'gemini-2.5-flash'
];

// Zjistíme, které textové "flash" modely má klíč k dispozici.
// Lite verze přednostně (nejštědřejší free tier), novější verze první.
let cachedModels = null;
let cachedModelsAt = 0;

async function getAvailableModels(apiKey) {
    const now = Date.now();
    if (cachedModels && (now - cachedModelsAt) < 60 * 60 * 1000) return cachedModels;
    try {
        const r = await fetch('https://generativelanguage.googleapis.com/v1beta/models?pageSize=200&key=' + apiKey);
        const out = await r.json();
        const list = (out.models || [])
            .map(m => (m.name || '').replace('models/', ''))
            .filter(n => /^gemini-\d+(\.\d+)?-flash(-lite)?$/.test(n));
        if (list.length === 0) return AI_MODELS_FALLBACK;
        const version = n => parseFloat(n.match(/^gemini-(\d+(\.\d+)?)/)[1]);
        const isLite = n => n.endsWith('-lite') ? 1 : 0;
        list.sort((a, b) => (isLite(b) - isLite(a)) || (version(b) - version(a)));
        cachedModels = list;
        cachedModelsAt = now;
        console.log('Dostupné AI modely (v pořadí zkoušení): ' + list.join(', '));
        return list;
    } catch (e) {
        return AI_MODELS_FALLBACK;
    }
}

// =============================================================================
// KDO SMÍ NA AI
// =============================================================================
// AI JE JEN PRO UČITELE. Dřív ji chránil nanejvýš PIN uložený v prohlížeči
// a bez nastaveného PINu vůbec nic — klíč ke Gemini tedy mohl vyčerpat kdokoli
// na internetu, komu se adresa dostala do ruky. Teď musí požadavek nést
// podepsanou vstupenku a v ní roli `ucitel`. Žákovský lístek je platný pro
// místnost, ale k AI ho server nepustí.
//
// PIN se tím ruší — nahrazuje ho něco, co se nedá opsat z cizí obrazovky.

/**
 * Vrátí obsah vstupenky, když požadavek smí na AI. Jinak `null` a rovnou odpoví.
 */
function povolAi(req, res) {
    const overeni = overVstupenku(req.body && req.body.t);
    if (!overeni.ok) {
        console.log(`AI odmítnuta (${overeni.duvod}).`);
        res.json({ ok: false, error: overeni.hlaska });
        return null;
    }
    if (overeni.obsah.role !== 'ucitel') {
        console.log('AI odmítnuta (žákovská vstupenka).');
        res.json({ ok: false, error: 'AI asistenta smí použít jen lektor.' });
        return null;
    }
    const strop = zkontrolujStrop(overeni.obsah);
    if (strop) {
        console.log(`AI odmítnuta (strop: ${strop.duvod}).`);
        res.json({ ok: false, error: strop.hlaska });
        return null;
    }
    return overeni.obsah;
}

// =============================================================================
// STROP NA VOLÁNÍ AI
// =============================================================================
// Bezplatný tarif Gemini má denní i minutový limit a majitel se právem bojí, že
// ho někdo vyčerpá. Vstupenka sice pustí k AI jedině lektora, ale i lektorovi to
// může ujet: podržený prst na tlačítku, omylem spuštěná smyčka, dvě otevřené
// tabule naráz. Proto tři stropy nad sebou:
//
//   * na lekci a minutu — brání zaseknutému tlačítku,
//   * na lekci a hodinu — brání tomu, aby jedna hodina spotřebovala celý den,
//   * na celý server a hodinu — poslední pojistka, ať se kvůli jedné lekci
//     nezastaví ostatní.
//
// Počítadla jsou jen v paměti. Když se server na Renderu uspí a probudí,
// vynulují se — a to je v pořádku: nejde o účetnictví, ale o brzdu.
const STROP_LEKCE_MINUTA = 12;
const STROP_LEKCE_HODINA = 100;
const STROP_SERVER_HODINA = 240;

/** Časová razítka volání podle lekce. */
const volaniPodleLekce = new Map();
/** Časová razítka všech volání dohromady. */
let volaniCelkem = [];

function jenNovejsiNez(razitka, hranice) {
    return razitka.filter((cas) => cas > hranice);
}

/** Vrací null, když se volat smí, jinak důvod odmítnutí. */
function zkontrolujStrop(obsah) {
    const ted = Date.now();
    const klic = String(obsah.sid || obsah.room);

    volaniCelkem = jenNovejsiNez(volaniCelkem, ted - 3600_000);
    const lekce = jenNovejsiNez(volaniPodleLekce.get(klic) || [], ted - 3600_000);

    // Úklid, ať mapa neroste donekonečna přes celý den provozu.
    if (volaniPodleLekce.size > 200) {
        volaniPodleLekce.forEach((razitka, k) => {
            if (jenNovejsiNez(razitka, ted - 3600_000).length === 0) volaniPodleLekce.delete(k);
        });
    }

    const zaMinutu = jenNovejsiNez(lekce, ted - 60_000).length;
    if (zaMinutu >= STROP_LEKCE_MINUTA) {
        return { duvod: 'minuta', hlaska: 'AI teď dostala hodně dotazů po sobě. Zkus to prosím za minutu.' };
    }
    if (lekce.length >= STROP_LEKCE_HODINA) {
        return { duvod: 'hodina-lekce', hlaska: 'Tahle lekce už vyčerpala hodinový příděl AI. Zkus to prosím později.' };
    }
    if (volaniCelkem.length >= STROP_SERVER_HODINA) {
        return { duvod: 'hodina-server', hlaska: 'AI je právě přetížená. Zkus to prosím za chvíli.' };
    }

    lekce.push(ted);
    volaniCelkem.push(ted);
    volaniPodleLekce.set(klic, lekce);
    return null;
}

app.post('/ai', async (req, res) => {
    try {
        if (!povolAi(req, res)) return;
        const prompt = String((req.body && req.body.prompt) || '').slice(0, 2000);
        if (!prompt) return res.json({ ok: false, error: 'Chybí zadání.' });

        const apiKey = process.env.GEMINI_API_KEY;
        if (!apiKey) return res.json({ ok: false, error: 'Na serveru není nastaven GEMINI_API_KEY.' });

        let text = null;
        let lastError = null;
        let usedModel = null;

        const models = await getAvailableModels(apiKey);
        for (const model of models) {
            const r = await fetch(
                'https://generativelanguage.googleapis.com/v1beta/models/' + model + ':generateContent?key=' + apiKey,
                {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        systemInstruction: { parts: [{ text: AI_SYSTEM_PROMPT }] },
                        contents: [{ parts: [{ text: prompt }] }],
                        generationConfig: { responseMimeType: 'application/json', temperature: 0.7 }
                    })
                }
            );
            const out = await r.json();

            if (out && out.error) {
                // 429 = vyčerpaný limit, 404 = model neexistuje → zkusíme další model
                lastError = 'Model ' + model + ': ' + (out.error.message || out.error.code);
                console.log('AI model ' + model + ' selhal (' + out.error.code + '), zkouším další...');
                continue;
            }

            const t = out && out.candidates && out.candidates[0]
                && out.candidates[0].content && out.candidates[0].content.parts
                && out.candidates[0].content.parts[0] && out.candidates[0].content.parts[0].text;
            if (t) { text = t; usedModel = model; break; }
            lastError = 'Model ' + model + ' nevrátil text.';
        }

        if (!text) {
            return res.json({ ok: false, error: 'Žádný model teď není dostupný. Poslední chyba: ' + String(lastError).slice(0, 300) });
        }
        console.log('AI odpověděl model: ' + usedModel);

        let parsed;
        try { parsed = JSON.parse(text); }
        catch (e) { return res.json({ ok: false, error: 'AI vrátila neplatný formát, zkus to znovu.' }); }

        const widgets = Array.isArray(parsed.widgets)
            ? parsed.widgets.map(w => String(w)).slice(0, 10)
            : [];
        res.json({ ok: true, widgets: widgets });
    } catch (err) {
        res.json({ ok: false, error: String(err) });
    }
});

// =============================================================================
// AI NÁVRH DOMÁCÍHO ÚKOLU
// =============================================================================
// Volá to REZERVAČNÍ APLIKACE ze svého serveru, ne tabule z prohlížeče: lektor
// dopíše zápis po lekci a chce k probranému učivu příklady na doma.
//
// PROČ VLASTNÍ ADRESA A NE `/ai`:
//   `AI_SYSTEM_PROMPT` je psaný pro tabuli — vrací pole `widgets`, uvnitř má
//   HTML značky (<b>1)</b>) a zlomky ve tvaru {3}/{4}, kterému rozumí jedině
//   vykreslovač tabule. V zadání domácího úkolu, které si rodič přečte
//   v aplikaci i v e-mailu, by to byla nečitelná změť. Odpověď tady je proto
//   HOLÝ TEXT bez jediné značky.
//   `/ai` se nemění ani o čárku, aby tabule fungovala přesně jako dosud.
//
// KDO SMÍ: totéž co u `/ai` — platná vstupenka s rolí `ucitel` a stropy na
// počet volání. Žákovský lístek server odmítne.

const AI_UKOL_PROMPT =
    'Jsi zkušený doučovatel a připravuješ DOMÁCÍ ÚKOL pro jednoho žáka po odučené lekci. ' +
    'Dostaneš téma lekce, poznámky lektora z té hodiny a někdy i ročník žáka. ' +
    'Nejdůležitější pravidlo: příklady musí být PŘESNĚ na to, co je v poznámkách, a na nic jiného. ' +
    'Když lektor probral sčítání, odčítání a násobení zlomků, dej příklady na sčítání, odčítání a násobení zlomků — ' +
    'žádné dělení, žádné převody na desetinná čísla, žádné rozšiřování učiva. ' +
    'Obtížnost přizpůsob ročníku; když ročník nedostaneš, mysli na střed základní školy. ' +
    'Odpověz VÝHRADNĚ platným JSON objektem ve tvaru {"nazev": "...", "priklady": ["...", "..."]} — nic jiného. ' +
    '"nazev" je krátký název úkolu do 60 znaků, který popisuje učivo (např. "Zlomky — sčítání, odčítání a násobení"). ' +
    '"priklady" je 5 až 8 položek a každá je JEDEN samostatný příklad k vypracování, nanejvýš dvě věty. ' +
    'Pokrytí: když poznámky uvádějí víc dovedností, rozděl příklady mezi ně rovnoměrně a u každého ať je poznat, které dovednosti se týká. ' +
    'Zápis: piš česky a POUZE HOLÝM TEXTEM — žádné HTML značky, žádný Markdown, žádné hvězdičky, žádné zpětné lomítko, žádný LaTeX a žádný znak $. ' +
    'Zlomky zapisuj jako 3/4, smíšená čísla jako 2 1/2, mocniny jako x^2, odmocniny jako sqrt(9). ' +
    'Položky NEČÍSLUJ, číslování si doplní aplikace sama. ' +
    'Výsledky ani postup neuváděj — úkol je pro žáka. ' +
    'Když jsou poznámky tak stručné, že z nich nejde poznat, co se probíralo, vrať místo toho ' +
    '{"error": "jedna česká věta o tom, co má lektor do poznámek doplnit"}.';

app.post('/ai-ukol', async (req, res) => {
    try {
        if (!povolAi(req, res)) return;
        // Pokyn nese téma i poznámky z hodiny, takže je delší než dotaz na tabuli.
        const prompt = String((req.body && req.body.prompt) || '').slice(0, 4000);
        if (!prompt) return res.json({ ok: false, error: 'Chybí zadání.' });

        const apiKey = process.env.GEMINI_API_KEY;
        if (!apiKey) return res.json({ ok: false, error: 'Na serveru není nastaven GEMINI_API_KEY.' });

        const models = await getAvailableModels(apiKey);
        let text = null, lastError = null, usedModel = null;

        for (const model of models) {
            const r = await fetch(
                'https://generativelanguage.googleapis.com/v1beta/models/' + model + ':generateContent?key=' + apiKey,
                {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        systemInstruction: { parts: [{ text: AI_UKOL_PROMPT }] },
                        contents: [{ parts: [{ text: prompt }] }],
                        // Nižší teplota než u tabule: úkol, který si přečte rodič,
                        // má být spíš nudně správný než nápaditý.
                        generationConfig: { responseMimeType: 'application/json', temperature: 0.4 }
                    })
                }
            );
            const out = await r.json();

            if (out && out.error) {
                lastError = 'Model ' + model + ': ' + (out.error.message || out.error.code);
                console.log('AI návrh úkolu — model ' + model + ' selhal (' + out.error.code + '), zkouším další...');
                continue;
            }

            const t = out && out.candidates && out.candidates[0]
                && out.candidates[0].content && out.candidates[0].content.parts
                && out.candidates[0].content.parts[0] && out.candidates[0].content.parts[0].text;
            if (t) { text = t; usedModel = model; break; }
            lastError = 'Model ' + model + ' nevrátil text.';
        }

        if (!text) {
            return res.json({ ok: false, error: 'Žádný model teď není dostupný. Poslední chyba: ' + String(lastError).slice(0, 300) });
        }
        console.log('AI návrh úkolu — odpověděl model: ' + usedModel);

        let parsed;
        try { parsed = JSON.parse(text); }
        catch (e) { return res.json({ ok: false, error: 'AI vrátila neplatný formát, zkus to znovu.' }); }

        // AI sama řekla, že z poznámek nepozná, co se probíralo.
        if (parsed && parsed.error) return res.json({ ok: false, error: String(parsed.error).slice(0, 300) });

        const priklady = Array.isArray(parsed.priklady)
            ? parsed.priklady.map(p => String(p)).filter(p => p.trim()).slice(0, 10)
            : [];
        if (priklady.length === 0) return res.json({ ok: false, error: 'AI nevrátila žádné příklady, zkus to znovu.' });

        res.json({ ok: true, nazev: String(parsed.nazev || ''), priklady: priklady });
    } catch (err) {
        res.json({ ok: false, error: String(err) });
    }
});

// ===== AI KONTROLA VÝPOČTU Z OBRÁZKU =====
const AI_CHECK_PROMPT =
    'Jsi laskavý učitel při doučování. Na obrázku je zadání příkladu a žákův postup či výpočet z digitální tabule. ' +
    'Zkontroluj správnost. Odpověz VÝHRADNĚ platným JSON objektem: ' +
    '{"spravne": true|false, "komentar": "..."} ' +
    'Komentář piš česky, maximálně 2 věty. Pokud je výpočet správně, krátce a konkrétně pochval. ' +
    'Pokud je tam chyba, napiš, ve kterém kroku a jakého typu je (např. špatné převedení na společný jmenovatel), ' +
    'ale NEPROZRAZUJ správný výsledek — žák na něj má přijít sám. ' +
    'Pokud na obrázku žádný výpočet není, napiš to do komentáře a spravne nastav false.';

app.post('/ai-check', async (req, res) => {
    try {
        if (!povolAi(req, res)) return;
        const image = String((req.body && req.body.image) || '');
        if (!image) return res.json({ ok: false, error: 'Chybí obrázek.' });

        const apiKey = process.env.GEMINI_API_KEY;
        if (!apiKey) return res.json({ ok: false, error: 'Na serveru není nastaven GEMINI_API_KEY.' });

        const models = await getAvailableModels(apiKey);
        let text = null, lastError = null, usedModel = null;

        for (const model of models) {
            const r = await fetch(
                'https://generativelanguage.googleapis.com/v1beta/models/' + model + ':generateContent?key=' + apiKey,
                {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        systemInstruction: { parts: [{ text: AI_CHECK_PROMPT }] },
                        contents: [{ parts: [
                            { inline_data: { mime_type: 'image/jpeg', data: image } },
                            { text: 'Zkontroluj výpočet na obrázku.' }
                        ] }],
                        generationConfig: { responseMimeType: 'application/json', temperature: 0.3 }
                    })
                }
            );
            const out = await r.json();
            if (out && out.error) {
                lastError = 'Model ' + model + ': ' + (out.error.message || out.error.code);
                continue;
            }
            const t = out && out.candidates && out.candidates[0]
                && out.candidates[0].content && out.candidates[0].content.parts
                && out.candidates[0].content.parts[0] && out.candidates[0].content.parts[0].text;
            if (t) { text = t; usedModel = model; break; }
            lastError = 'Model ' + model + ' nevrátil text.';
        }

        if (!text) return res.json({ ok: false, error: 'Žádný model teď není dostupný: ' + String(lastError).slice(0, 300) });
        console.log('AI kontrola — odpověděl model: ' + usedModel);

        let parsed;
        try { parsed = JSON.parse(text); }
        catch (e) { return res.json({ ok: false, error: 'AI vrátila neplatný formát.' }); }

        res.json({ ok: true, spravne: !!parsed.spravne, komentar: String(parsed.komentar || '') });
    } catch (err) {
        res.json({ ok: false, error: String(err) });
    }
});

// ===== AI ČTENÍ FUNKCE PRO GRAF =====
const AI_GRAPH_PROMPT =
    'Na obrázku z digitální tabule je zápis matematické funkce (např. y = x^2 - 2x + 1, f(x) = 2/x, y = sin x). ' +
    'Přečti ji a odpověz VÝHRADNĚ platným JSON objektem: ' +
    '{"funkce": "čitelný zápis, např. f(x) = x² − 2x + 1", ' +
    '"expr": "JavaScriptový výraz s proměnnou x — POUZE čísla, x, + - * / ( ) a funkce sin( cos( tan( sqrt( abs( log( exp( pow( ; mocniny zapisuj jako x*x nebo pow(x,3)", ' +
    '"vlastnosti": {"definicni_obor": "...", "obor_hodnot": "...", "sudost_lichost": "sudá / lichá / ani jedno", "monotonie": "kde roste a kde klesá", "dalsi": "průsečíky s osami, vrchol, asymptoty (stručně)"}} ' +
    'Vše česky a stručně. Pokud na obrázku žádná funkce není, vrať {"error": "popis problému"}.';

app.post('/ai-graph', async (req, res) => {
    try {
        if (!povolAi(req, res)) return;
        const image = String((req.body && req.body.image) || '');
        if (!image) return res.json({ ok: false, error: 'Chybí obrázek.' });

        const apiKey = process.env.GEMINI_API_KEY;
        if (!apiKey) return res.json({ ok: false, error: 'Na serveru není nastaven GEMINI_API_KEY.' });

        const models = await getAvailableModels(apiKey);
        let text = null, lastError = null;

        for (const model of models) {
            const r = await fetch(
                'https://generativelanguage.googleapis.com/v1beta/models/' + model + ':generateContent?key=' + apiKey,
                {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        systemInstruction: { parts: [{ text: AI_GRAPH_PROMPT }] },
                        contents: [{ parts: [
                            { inline_data: { mime_type: 'image/jpeg', data: image } },
                            { text: 'Přečti funkci na obrázku.' }
                        ] }],
                        generationConfig: { responseMimeType: 'application/json', temperature: 0.2 }
                    })
                }
            );
            const out = await r.json();
            if (out && out.error) { lastError = 'Model ' + model + ': ' + (out.error.message || out.error.code); continue; }
            const t = out && out.candidates && out.candidates[0]
                && out.candidates[0].content && out.candidates[0].content.parts
                && out.candidates[0].content.parts[0] && out.candidates[0].content.parts[0].text;
            if (t) { text = t; break; }
            lastError = 'Model ' + model + ' nevrátil text.';
        }

        if (!text) return res.json({ ok: false, error: 'Žádný model teď není dostupný: ' + String(lastError).slice(0, 300) });

        let parsed;
        try { parsed = JSON.parse(text); }
        catch (e) { return res.json({ ok: false, error: 'AI vrátila neplatný formát.' }); }
        if (parsed.error) return res.json({ ok: false, error: String(parsed.error) });

        res.json({
            ok: true,
            funkce: String(parsed.funkce || ''),
            expr: String(parsed.expr || ''),
            vlastnosti: parsed.vlastnosti || {}
        });
    } catch (err) {
        res.json({ ok: false, error: String(err) });
    }
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server naslouchá na portu ${PORT}`);
});
