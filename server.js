const express = require('express');
const http = require('http');
const WebSocket = require('ws');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

wss.on('connection', (ws) => {
    console.log('Nový uživatel připojen do učebny.');

    // Když server dostane tah od jednoho uživatele, rozešle ho všem ostatním
    ws.on('message', (message) => {
        wss.clients.forEach((client) => {
            if (client !== ws && client.readyState === WebSocket.OPEN) {
                client.send(message);
            }
        });
    });

    ws.on('close', () => {
        console.log('Uživatel opustil učebnu.');
    });
});

// Jednoduchá stránka pro kontrolu, zda server běží
app.get('/', (req, res) => {
    res.send('Mozek digitální učebny běží a je připraven na spojení!');
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server naslouchá na portu ${PORT}`);
});
