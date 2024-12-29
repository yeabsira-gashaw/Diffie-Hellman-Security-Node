const crypto = require("crypto");
const axios = require("axios");

(async () => {
  try {
    // Fetch the server's public key
    const response = await axios.get("http://localhost:4000/api/server-public-key");
    const serverPublicKey = response.data.serverPublicKey;

    // Generate a new key pair for the session
    const clientECDH = crypto.createECDH("secp256k1");
    clientECDH.generateKeys();
    const clientPublicKey = clientECDH.getPublicKey("base64");

    // Compute the shared secret for this session
    const sharedSecret = clientECDH.computeSecret(
      serverPublicKey,
      "base64",
      "base64"
    );
    console.log("Shared Secret:", sharedSecret);

    // Payload to encrypt
    const payload = JSON.stringify({ message: "Hello, secure world!" });

    // Compute a checksum for the payload
    const checksum = crypto.createHash("sha256").update(payload).digest("hex");
    console.log("Checksum:", checksum);

    // Combine payload and checksum
    const fullPayload = JSON.stringify({ payload, checksum });

    // Encrypt the full payload using the shared secret (AES-256-GCM)
    const iv = crypto.randomBytes(12); // 12-byte IV recommended for AES-GCM
    const cipher = crypto.createCipheriv(
      "aes-256-gcm",
      Buffer.from(sharedSecret, "base64"),
      iv
    );
    let encryptedPayload = cipher.update(fullPayload, "utf8", "hex");
    encryptedPayload += cipher.final("hex");
    const authTag = cipher.getAuthTag().toString("hex");

    // **Potential Enhancement: Add a timestamp or nonce for replay attack protection**
    const timestamp = Date.now();

    // Send the encrypted payload and client's public key to the server
    await axios.post("http://localhost:4000/api/secure-payload", {
      clientPublicKey,
      encryptedPayload,
      iv: iv.toString("hex"),
      authTag,
      timestamp, // Sending the timestamp
    });

    console.log({
      clientPublicKey,
      encryptedPayload,
      iv: iv.toString("hex"),
      authTag,
      timestamp,
    });
    console.log("Encrypted payload with client public key sent to server");
  } catch (error) {
    console.error("Error during the encryption process:", error.message);
    // **Potential Enhancement: Add more specific error handling for network and crypto errors**
  }
})();