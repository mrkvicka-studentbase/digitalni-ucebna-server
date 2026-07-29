const express = require('express');
const http = require('http');
const WebSocket = require('ws');

const app = express();
app.use(express.json({ limit: '2mb' }));

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

// ===== WEBSOCKET S MÍSTNOSTMI =====
// Každé připojení patří do místnosti (?room=jmeno v adrese).
// Zprávy se rozesílají jen ostatním ve stejné místnosti.
wss.on('connection', (ws, req) => {
    const params = new URL(req.url, 'http://localhost').searchParams;
    ws.room = params.get('room') || 'hlavni';
    console.log(`Nový uživatel připojen do místnosti "${ws.room}".`);

    ws.on('message', (message) => {
        wss.clients.forEach((client) => {
            if (client !== ws && client.readyState === WebSocket.OPEN && client.room === ws.room) {
                client.send(message);
            }
        });
    });

    ws.on('close', () => {
        console.log(`Uživatel opustil místnost "${ws.room}".`);
    });
});

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
    'zlomky zapisuj jako a/b, mocniny pomocí <sup> (např. x<sup>2</sup>); ' +
    'příklady čísluj (<b>1)</b> ...); ' +
    'výsledky ani postupy neuváděj, pokud si je učitel výslovně nevyžádá; ' +
    'maximálně 10 bloků.';

// Modely seřazené od nejúspornějšího — když jeden narazí na limit (429)
// nebo neexistuje (404), zkusí se automaticky další v pořadí.
const AI_MODELS = [
    'gemini-2.5-flash-lite',
    'gemini-2.0-flash-lite',
    'gemini-2.5-flash',
    'gemini-2.0-flash'
];

app.post('/ai', async (req, res) => {
    try {
        const prompt = String((req.body && req.body.prompt) || '').slice(0, 2000);
        if (!prompt) return res.json({ ok: false, error: 'Chybí zadání.' });

        const apiKey = process.env.GEMINI_API_KEY;
        if (!apiKey) return res.json({ ok: false, error: 'Na serveru není nastaven GEMINI_API_KEY.' });

        let text = null;
        let lastError = null;
        let usedModel = null;

        for (const model of AI_MODELS) {
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

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server naslouchá na portu ${PORT}`);
});
