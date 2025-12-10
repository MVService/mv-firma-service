const express    = require("express");
const bodyParser = require("body-parser");
const cors       = require("cors");
const forge      = require("node-forge");

const app = express();
app.use(cors());
app.use(bodyParser.json({ limit: "10mb" }));

// Função utilitária: gera assinatura SHA-256 com chave privada em DER (Base64)
function assinarDerBase64(keyB64, senha, cadenaOriginal) {
  // keyB64 = DER em Base64 vindo do frontend
  const keyDerBytes = forge.util.decode64(keyB64);     // bytes binários
  const keyAsn1     = forge.asn1.fromDer(keyDerBytes); // DER → ASN.1
  const privateKey  = forge.pki.decryptRsaPrivateKey(keyAsn1, senha);

  if (!privateKey) {
    throw new Error("Senha incorreta ou chave privada inválida.");
  }

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

    // cerB64 ainda não é usado aqui, mas fica para futura validação
    const firma = assinarDerBase64(keyB64, senha, cadenaOriginal);

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

    const cerB64         = P_CER_B64;                 // ainda não usado
    const keyB64         = P_KEY_B64;
    const senha          = P_SENHA;
    const cadenaOriginal = P_CADENA || "LOGIN-VUCEM";

    const firma = assinarDerBase64(keyB64, senha, cadenaOriginal);

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
