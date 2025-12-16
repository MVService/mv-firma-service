const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const forge = require("node-forge");

const app = express();
app.use(cors());
app.use(bodyParser.json({ limit: "10mb" }));

/**
 * Carrega a chave privada RSA da FIEL a partir de um .KEY
 * enviado em Base64 (PKCS#8 DER encriptado).
 * Retorna um objeto forge.pki.rsa.PrivateKey ou null se falhar.
 */
function loadRsaPrivateKeyFromSatKeyB64(keyB64, password) {
  try {
    // keyB64 = base64 do arquivo .KEY binário
    const keyDer = forge.util.decode64(keyB64);       // string binária
    const keyAsn1 = forge.asn1.fromDer(keyDer);       // DER -> ASN.1

    // decryptPrivateKeyInfo trata EncryptedPrivateKeyInfo (PKCS#8)
    const decryptedInfo = forge.pki.decryptPrivateKeyInfo(keyAsn1, password);

    // converte PrivateKeyInfo ASN.1 em chave RSA utilizável
    const privateKey = forge.pki.privateKeyFromAsn1(decryptedInfo);
    return privateKey;
  } catch (e) {
    console.error("Erro ao decifrar chave PKCS#8:", e);
    return null;
  }
}

/**
 * Função utilitária para assinar uma cadeia com SHA-256/RSA
 */
function signCadena(privateKey, cadenaOriginal) {
  const md = forge.md.sha256.create();
  md.update(cadenaOriginal, "utf8");
  const signatureBytes = privateKey.sign(md);
  return forge.util.encode64(signatureBytes);
}

/**
 * Rota genérica /firma (campos “simples”)
 * body: { cerB64, keyB64, senha, cadenaOriginal }
 */
app.post("/firma", (req, res) => {
  try {
    const { cerB64, keyB64, senha, cadenaOriginal } = req.body;

    if (!cerB64 || !keyB64 || !senha || !cadenaOriginal) {
      return res.status(400).json({
        ok: false,
        error: "Parâmetros faltando (cerB64, keyB64, senha, cadenaOriginal)"
      });
    }

    const privateKey = loadRsaPrivateKeyFromSatKeyB64(keyB64, senha);
    if (!privateKey) {
      return res.status(400).json({
        ok: false,
        error: "Senha incorreta ou chave privada inválida (PKCS#8)."
      });
    }

    const firma = signCadena(privateKey, cadenaOriginal);

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

/**
 * Rota /firmar-login (campos com prefixo P_ vindos do Wix)
 * body: { P_CER_B64, P_KEY_B64, P_SENHA, P_CADENA }
 */
app.post("/firmar-login", (req, res) => {
  try {
    const { P_CER_B64, P_KEY_B64, P_SENHA, P_CADENA } = req.body;

    if (!P_CER_B64 || !P_KEY_B64 || !P_SENHA) {
      return res.status(400).json({
        ok: false,
        error: "Parâmetros faltando (P_CER_B64, P_KEY_B64, P_SENHA)"
      });
    }

    const cerB64         = P_CER_B64;
    const keyB64         = P_KEY_B64;
    const senha          = P_SENHA;
    const cadenaOriginal = P_CADENA || "LOGIN-VUCEM";

    const privateKey = loadRsaPrivateKeyFromSatKeyB64(keyB64, senha);
    if (!privateKey) {
      return res.status(400).json({
        ok: false,
        error: "Senha incorreta ou chave privada inválida (PKCS#8)."
      });
    }

    const firma = signCadena(privateKey, cadenaOriginal);

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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Servidor de firma ouvindo na porta " + PORT);
});
/**
 * Rota /sha1pdf
 * body: { pdfB64 }
 * Retorna SHA1 HEX do binário do PDF
 */
app.post("/sha1pdf", (req, res) => {
  try {
    const { pdfB64 } = req.body;

    if (!pdfB64) {
      return res.status(400).json({
        ok: false,
        error: "pdfB64 não informado"
      });
    }

    // Decodifica Base64 para binário
    const pdfBytes = forge.util.decode64(pdfB64);

    // Calcula SHA1 do BINÁRIO
    const md = forge.md.sha1.create();
    md.update(pdfBytes, "raw");
    const sha1hex = md.digest().toHex();

    return res.json({
      ok: true,
      sha1hex
    });

  } catch (e) {
    console.error("Erro /sha1pdf:", e);
    return res.status(500).json({
      ok: false,
      error: e.toString()
    });
  }
});

