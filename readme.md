# Secure Communication Solution (Node.js)

A secure communication solution built with Node.js that ensures encrypted payload transmission between a client (mobile app or frontend) and the server using **RSA**, **AES-256-GCM**, and **Diffie-Hellman** for secure key exchange. The solution also incorporates integrity checks with payload hashing and timestamp-based security features.

## Features

- **Encryption & Decryption**: Secure communication between client and server using encryption algorithms (AES-256-GCM).
- **Dynamic Key Exchange**: Secure generation and exchange of encryption keys using Diffie-Hellman.
- **Payload Hashing**: Ensuring integrity by computing a checksum (hash) of the payload.
- **Public Key Infrastructure**: Secure handling of public and private keys using RSA encryption.
- **Session-based Encryption**: The client can generate public/private keys per session, ensuring a dynamic and secure communication channel.

## Usage

### Client-Side (Mobile App or Frontend)

1. **Fetch the server's public key** using the `/api/public-key` endpoint.
2. **Generate a private/public key pair** (client-side).
3. **Encrypt the payload** using **AES-256-GCM** with the client's generated key.
4. **Send the encrypted payload** to the server along with the public key and the checksum of the data for integrity.

### Server-Side (API)

1. **Receive the encrypted payload**.
2. **Decrypt the payload** using the client's public key and the server's private key.
3. **Verify the checksum** to ensure the integrity of the received data.

### Example Routes

#### 1. Generate Server Public Key

- Endpoint: `/api/public-key`
- Method: `GET`
- Description: Fetches the server's public key to enable encryption on the client side.

#### 2. Send Encrypted Payload

- Endpoint: `/api/secure-payload`
- Method: `POST`
- Description: Receives encrypted payload, decrypts it, and verifies its integrity.
- Body:
  ```json
  {
    "clientPublicKey": "client-public-key",
    "encryptedPayload": "encrypted-payload",
    "iv": "initialization-vector",
    "authTag": "authentication-tag",
    "checksum": "payload-checksum"
  }
  ```

## Security Considerations

- **RSA Public Key Encryption**: Ensures confidentiality of the communication by encrypting sensitive data with the public key.
- **AES-256-GCM**: Provides secure encryption of the payload and ensures data integrity using the GCM mode with an authentication tag.
- **Diffie-Hellman**: Securely exchanges keys between the client and server for session-based encryption.
- **Payload Hashing**: Ensures that the data has not been tampered with during transmission by computing a checksum (hash) before sending it.

### IV (Initialization Vector)

The server and client use an **IV** to ensure that each encryption operation produces unique ciphertext, even if the same data is encrypted multiple times. This prevents attackers from analyzing patterns in the encrypted data.

### Dynamic Key Exchange

The solution supports **Diffie-Hellman** key exchange to securely establish a shared key between the client and server without directly transmitting it. The shared key is then used for further encrypting and decrypting payloads.

## Replay Protection

- **Timestamp Validation**: Payloads must include a timestamp that is within a 5-minute window of the server's current time.
- **Nonce Tracking**: Each combination of `clientPublicKey` and `timestamp` is stored temporarily to prevent replay attacks.

## Rate Limiting

Implemented using `express-rate-limit` to restrict the number of requests per minute to 100 per IP address.
