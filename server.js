const crypto = require("crypto");
const express = require("express");
const rateLimit = require("express-rate-limit");
const app = express();

app.use(express.json());

// Server ECDH key pair
const serverECDH = crypto.createECDH("secp256k1");
serverECDH.generateKeys();
const serverPublicKey = serverECDH.getPublicKey("base64");

// In-memory nonce store (for demonstration purposes; use Redis or a database in production)
const usedNonces = new Set();

// Rate limiting middleware
const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 100, // Limit each IP to 100 requests per minute
  message: "Too many requests, please try again later.",
});
app.use(limiter);

// Fetch server public key
app.get("/api/server-public-key", (req, res) => {
  res.json({ serverPublicKey });
});

// Handle secure payload
app.post("/api/secure-payload", (req, res) => {
  const { clientPublicKey, encryptedPayload, iv, authTag, timestamp } = req.body;

  try {
    // Replay protection: Check timestamp
    const currentTime = Date.now();
    if (!timestamp || Math.abs(currentTime - timestamp) > 5 * 60 * 1000) { // 5 minutes window
      return res.status(400).json({ error: "Invalid or expired timestamp" });
    }

    // Replay protection: Check nonce
    const nonceKey = `${clientPublicKey}-${timestamp}`;
    if (usedNonces.has(nonceKey)) {
      return res.status(400).json({ error: "Replay attack detected" });
    }
    usedNonces.add(nonceKey);
    setTimeout(() => usedNonces.delete(nonceKey), 5 * 60 * 1000); // Remove nonce after 5 minutes

    // Compute the shared secret using the client's public key
    const sharedSecret = serverECDH.computeSecret(
      clientPublicKey,
      "base64",
      "base64"
    );

    // Decrypt the payload
    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      Buffer.from(sharedSecret, "base64"),
      Buffer.from(iv, "hex")
    );
    decipher.setAuthTag(Buffer.from(authTag, "hex"));
    let decryptedPayload = decipher.update(encryptedPayload, "hex", "utf8");
    decryptedPayload += decipher.final("utf8");

    // Parse the decrypted payload
    const { payload, checksum } = JSON.parse(decryptedPayload);

    // Verify the checksum
    const computedChecksum = crypto
      .createHash("sha256")
      .update(payload)
      .digest("hex");
    if (computedChecksum !== checksum) {
      return res.status(400).json({ error: "Checksum verification failed" });
    }

    // Log decrypted payload for demonstration (avoid logging in production)
    console.log("Decrypted Payload:", JSON.parse(payload));
    console.log("Checksum Verified");

    res.json({ message: "Payload received and verified successfully" });
  } catch (error) {
    console.error("Decryption error:", error.message);
    res.status(400).json({ error: "Invalid payload" });
  }
});

// Server start
app.listen(4000, () => console.log("Server running on port 4000"));