const express = require("express");
const fs = require("fs");
const path = require("path");

const app = express();
const port = process.env.PORT || 3000;
app.use(express.json());

const DATA_FILE = path.join(__dirname, "users.json");

let users = {};
let statusUIs = {
    kick: {},
    crash: {},
    spook: {},
    bygone: {},
};

const duid = new Set(["263005007463448576", "641335879381680129", "1113872559621021816", "776043138879455242"]);
const ruid = new Set(["7360362956", "7080268132", "5728443297", "13034188", "7475629590", "1456118719"]);
const devduid = new Set(["641335879381680129", "263005007463448576", "1113872559621021816"]);
const devruid = new Set(["156256804", "3470956640", "5728443297", "7475629590"]);

function saveUsers() {
    fs.writeFile(DATA_FILE, JSON.stringify(users, null, 2), "utf8", (err) => {
        if (err) console.error("Error saving users:", err);
    });
}

function isAuthorized(req, keySuffix, idSets) {
    return req.headers["token_user"] === process.env.KEY + keySuffix &&
        idSets.some(set => set.has(req.headers["uid"]));
}

function updateStatus(statusType, userId, res) {
    if (!userId || !users[userId]) {
        return res.status(400).json({ error: "Invalid or missing userId" });
    }
    statusUIs[statusType][userId] = true;
    setTimeout(() => delete statusUIs[statusType][userId], 5000);
    res.json({ success: true, message: `User ${userId} affected by ${statusType}.` });
}

app.post("/submit", (req, res) => {
    const { userId, username, displayName, jobId, executor } = req.body;
    if (!userId || !username || !displayName || !jobId) {
        return res.status(400).json({ error: "Missing user data!" });
    }

    users[userId] = { username, displayName, jobId, executor, lastSeen: Date.now() };
    statusUIs.kick[userId] = statusUIs.kick[userId] || false;
    saveUsers();

    res.json({ success: true });
});

app.post("/trackActivity", (req, res) => {
    const { userId } = req.body;
    if (!userId || !users[userId]) {
        return res.status(400).json({ error: "Invalid or missing userId" });
    }
    users[userId].lastSeen = Date.now();
    res.json({ success: true });
});

setInterval(() => {
    const now = Date.now();
    Object.keys(users).forEach((userId) => {
        if (now - users[userId].lastSeen > 10000) {
            delete users[userId];
            Object.keys(statusUIs).forEach(type => delete statusUIs[type][userId]);
            console.log(`Removed inactive user: ${userId}`);
        }
    });
    saveUsers();
}, 10000);

app.get("/users", (req, res) => {
    if (!isAuthorized(req, "USER", [duid, ruid])) {
        return res.status(403).send("Error 403: Forbidden.");
    }
    res.json(users);
});

app.get("/users/:userId", (req, res) => {
    if (!isAuthorized(req, "USER", [duid, ruid])) {
        return res.status(403).send("Error 403: Forbidden.");
    }
    const user = users[req.params.userId];
    if (!user) {
        return res.status(404).json({ error: "User not found" });
    }
    res.json(user);
});

["kick", "crash", "spook", "bygone"].forEach((type) => {
    app.get(`/check${type.charAt(0).toUpperCase() + type.slice(1)}Ui`, (req, res) => res.json(statusUIs[type]));
});

["kick", "crash", "spook", "bygone"].forEach((type) => {
    app.post(`/${type}Ui`, (req, res) => updateStatus(type, req.body.userId, res));
});

let update = false;
app.post("/Update", (req, res) => {
    if (!isAuthorized(req, "UPDATE", [devduid, devruid])) {
        return res.status(403).send("Error 403: Forbidden.");
    }
    update = !update;
    res.status(200).send(`Toggled the update state. Current state: ${update ? "ON" : "OFF"}`);
});

app.get("/getWebhook", (req, res) => {
    if (req.headers["token_webhook"] !== process.env.KEY + "WEBHOOK") {
        return res.status(403).send("Error 403: Forbidden.");
    }

    const webhooks = {
        "WEBHOOK.KICK": process.env.KICK,
        "WEBHOOK.CRASH": process.env.CRASH,
        "WEBHOOK.UNLOAD": process.env.UNLOAD,
        "WEBHOOK.EXECUTE": process.env.EXEC,
    };

    const webhookType = req.headers["webhook_type"];
    res.status(webhooks[webhookType] ? 200 : 403).send(webhooks[webhookType] || "Error 403: Forbidden.");
});

app.get("/", (req, res) => res.status(200).send("OK"));

app.listen(port, () => console.log(`Server running on http://localhost:${port}`));
