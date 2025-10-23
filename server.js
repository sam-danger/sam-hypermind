import express from 'express';
import { WebSocketServer } from 'ws';
import { ethers } from 'ethers';
import cors from 'cors';

const app = express();
app.use(cors());
app.use(express.json());

const PORT = 3000;
const WS_PROVIDER = "wss://eth-mainnet.ws.alchemyapi.io/v2/YOUR_KEY"; // gizli key

// --- Frontend için WebSocket server
const wss = new WebSocketServer({ noServer: true });

// Ethereum WebSocket provider
const provider = new ethers.WebSocketProvider(WS_PROVIDER);

// Yeni blok ve pending tx eventleri
provider.on("block", async (blockNumber)=>{
    const block = await provider.getBlockWithTransactions(blockNumber);
    wss.clients.forEach(client=>{
        if(client.readyState === 1) {
            client.send(JSON.stringify({type:'block', blockNumber, txCount:block.transactions.length, transactions:block.transactions}));
        }
    });
});

provider.on("pending", async (txHash)=>{
    const tx = await provider.getTransaction(txHash);
    if(!tx) return;
    wss.clients.forEach(client=>{
        if(client.readyState === 1) {
            client.send(JSON.stringify({type:'pending', tx}));
        }
    });
});

// --- HTTP upgrade for WS
const server = app.listen(PORT, ()=>console.log(`Backend listening on ${PORT}`));
server.on('upgrade', (request, socket, head)=>{
    wss.handleUpgrade(request, socket, head, ws=>{
        wss.emit('connection', ws, request);
    });
});
