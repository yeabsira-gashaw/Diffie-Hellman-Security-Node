const crypto = require("crypto");
const express = require("express");
const app = express();

app.use(express.json());

const serverECDH = crypto.createECDH("secp256k1");
serverECDH.generateKeys();
const serverPublicKey = serverECDH.getPublicKey("base64");

app.get("/api/server-public-key", (req, res) => {
  res.json({ serverPublicKey });
});

app.post("/api/exchange-keys", (req, res) => {
  const clientPublicKey = req.body.clientPublicKey;

  // Compute shared secret for this session
  const sharedSecret = serverECDH.computeSecret(
    clientPublicKey,
    "base64",
    "base64"
  );
  console.log("Shared Secret:", sharedSecret);

  res.json({ message: "Key exchange successful" });
});

app.listen(4000, () => console.log("Server running on port 3000"));
