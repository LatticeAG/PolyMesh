# PolyMesh quick start

Install dependencies and run the local, token-protected ping/pong demo:

```sh
npm install
npm run demo
```

`demo.js` starts a numeric-loopback development broker, calls its built-in
ping capability from `client.js`, prints the pong, and closes the broker.

The standalone scripts intentionally use `POLYMESH_TOKEN_FILE` rather than an
inline token. The loopback development profile is not a LAN or remote
deployment profile; use enrolled WSS for those environments.
