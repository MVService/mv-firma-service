const express    = require("express");
const bodyParser = require("body-parser");
const cors       = require("cors");
const forge      = require("node-forge");

const app = express();
app.use(cors());
app.use(bodyParser.json({ limit: "10mb" }));

// ========== função utilitária: carrega chave DER+senha ==========
function getPrivateKeyFromDerB64(keyB64, senha) {
  // keyB64 = conteúdo do arquivo .KEY em Base64 (DER)
  const derBytes = forge.util.decode64(keyB64);       // bytes DER
  const asn1Encrypted = forge.asn1.fromDer(derBytes); // DER → ASN.1 (PKCS#8 encriptado)

  let privateKeyInfo;
  try {
    // decifra PKCS#8 usando a senha
    privateKeyInfo = forge.pki.decryptPrivateKeyInfo(asn1Encrypted, senha);
  } catch (e) {
    throw new Error("Senha incorreta ou chave privada inválida.");
  }

  if (!privateKeyInfo) {
    throw new Error("Senha incorreta ou chave privada inválida.");
  }

  // ASN.1 (PKCS#8) → objeto chave privada RSA
  const privateKey = forge.pki.privateKeyFromAsn1(privateKeyInfo);
  return privateKey;
}

// ========== função utilitária: assina uma cadeia ==========
function assinarComKeyDerB64(keyB64, senha, cadenaOriginal) {
  const privateKey = getPrivateKeyFromDerB64(keyB64, senha);

  const md = forge.md.sha256.create();
  md.update(cadenaOriginal, "utf8");
  const signatureBytes = privateKey.sign(md);
  const firma = forge.util.encode64(signatureBytes);

  return firma;
}

// ================== ROTA /firma (assinatura da MV) ==================
app.post("/firma", (req, res) => {
  try {
    const { cerB64, keyB64, senha, cadenaOriginal } = req.body;

    if (!cerB64 || !keyB64 || !senha || !cadenaOriginal) {
      return res.status(400).json({
        ok: false,
        error: "Parâmetros faltando (cerB64, keyB64, senha, cadenaOriginal)"
      });
    }

    const firma = assinarComKeyDerB64(keyB64, senha, cadenaOriginal);

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

// ================== ROTA /firmar-login (login VUCEM) ==================
app.post("/firmar-login", (req, res) => {
  try {
    // nomes que vêm do FRONTEND
    const { P_CER_B64, P_KEY_B64, P_SENHA, P_CADENA } = req.body;

    if (!P_CER_B64 || !P_KEY_B64 || !P_SENHA) {
      return res.status(400).json({
        ok: false,
        error: "Parâmetros faltando (P_CER_B64, P_KEY_B64, P_SENHA)"
      });
    }

    const cerB64         = P_CER_B64;                 // ainda não usado aqui
    const keyB64         = P_KEY_B64;
    const senha          = P_SENHA;
    const cadenaOriginal = P_CADENA || "LOGIN-VUCEM";

    const firma = assinarComKeyDerB64(keyB64, senha, cadenaOriginal);

    return res.json({
      ok: true,
      firma,
      cadenaOriginal
    });

  } catch (err) {
    console.error("Erro /firmar-login:", err);
    return res.status(500).json({
      ok: false,
      error: "Erro interno ao gerar firma (login): " + err.toString()
    });
  }
});

// ================== INÍCIO DO SERVIDOR ==================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Servidor de firma ouvindo na porta " + PORT);
});
