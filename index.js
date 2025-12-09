const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const forge = require("node-forge");

const app = express();
app.use(cors());
app.use(bodyParser.json({ limit: "10mb" }));

app.post("/firma", (req, res) => {
  try {
    const { cerB64, keyB64, senha, cadenaOriginal } = req.body;

    if (!cerB64 || !keyB64 || !senha || !cadenaOriginal) {
      return res.status(400).json({
        ok: false,
        error: "Parâmetros faltando (cerB64, keyB64, senha, cadenaOriginal)"
      });
    }

    const keyDer = forge.util.decode64(keyB64);
    const privateKey = forge.pki.decryptRsaPrivateKey(keyDer, senha);

    if (!privateKey) {
      return res.status(400).json({
        ok: false,
        error: "Senha incorreta ou chave privada inválida."
      });
    }

    const md = forge.md.sha256.create();
    md.update(cadenaOriginal, "utf8");
    const signatureBytes = privateKey.sign(md);
    const firma = forge.util.encode64(signatureBytes);

    return res.json({
      ok: true,
      firma,
      cadenaOriginal
    });

  } catch (err) {
    console.error("Erro /firma:", err);
    return res.status(500).json({
      ok: false,
      error: "Erro interno ao gerar firma: " + err.toString()
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Servidor /firma ouvindo na porta " + PORT);
});
