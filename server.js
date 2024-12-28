const crypto = require("crypto");
const express = require("express");
const app = express();

app.use(express.json());

const serverECDH = crypto.createECDH("secp256k1");
serverECDH.generateKeys();
const serverPublicKey = serverECDH.getPublicKey("base64");

// Fetch server public key
app.get("/api/server-public-key", (req, res) => {
  res.json({ serverPublicKey });
});

// Handle secure payload
app.post("/api/secure-payload", (req, res) => {
  const { clientPublicKey, encryptedPayload, iv, authTag } = req.body;

  try {
    // Compute the shared secret using the client's public key
    const sharedSecret = serverECDH.computeSecret(
      clientPublicKey,
      "base64",
      "base64"
    );
    console.log("Shared Secret:", sharedSecret);

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

    console.log("Decrypted Payload:", JSON.parse(payload));
    console.log("Checksum Verified");

    res.json({ message: "Payload received and verified successfully" });
  } catch (error) {
    console.error("Decryption error:", error.message);
    res.status(400).json({ error: "Invalid payload" });
  }
});

app.listen(4000, () => console.log("Server running on port 4000"));
