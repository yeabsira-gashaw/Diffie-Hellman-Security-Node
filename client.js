const crypto = require("crypto");
const axios = require("axios");

(async () => {
  // Fetch the server's public key
  const response = await axios.get(
    "http://localhost:4000/api/server-public-key"
  );
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

  // Send the client’s public key to the server for this session
  await axios.post("http://localhost:4000/api/exchange-keys", {
    clientPublicKey,
  });

  console.log("Session key exchange complete");
})();
