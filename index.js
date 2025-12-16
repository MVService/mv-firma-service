// index.js
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const forge = require("node-forge");
const https = require("https");
const { URL } = require("url");

const app = express();
app.use(cors());

// 100mb para aguentar SOAP com PDF inline em base64
app.use(bodyParser.json({ limit: "100mb" }));

/**
 * Carrega a chave privada RSA da FIEL a partir de um .KEY
 * enviado em Base64 (PKCS#8 DER encriptado).
 * Retorna um objeto forge.pki.rsa.PrivateKey ou null se falhar.
 */
function loadRsaPrivateKeyFromSatKeyB64(keyB64, password) {
  try {
    const keyDer = forge.util.decode64(keyB64); // string binária
    const keyAsn1 = forge.asn1.fromDer(keyDer); // DER -> ASN.1

    const decryptedInfo = forge.pki.decryptPrivateKeyInfo(keyAsn1, password);
    const privateKey = forge.pki.privateKeyFromAsn1(decryptedInfo);

    return privateKey;
  } catch (e) {
    console.error("Erro ao decifrar chave PKCS#8:", e);
    return null;
  }
}

/**
 * Assina uma cadeia com SHA-256/RSA (base64 de saída)
 */
function signCadena(privateKey, cadenaOriginal) {
  const md = forge.md.sha256.create();
  md.update(cadenaOriginal, "utf8");
  const signatureBytes = privateKey.sign(md);
  return forge.util.encode64(signatureBytes);
}

/**
 * /firma
 * body: { cerB64, keyB64, senha, cadenaOriginal }
 */
app.post("/firma", (req, res) => {
  try {
    const { cerB64, keyB64, senha, cadenaOriginal } = req.body || {};

    if (!cerB64 || !keyB64 || !senha || !cadenaOriginal) {
      return res.status(400).json({
        ok: false,
        error: "Parâmetros faltando (cerB64, keyB64, senha, cadenaOriginal)",
      });
    }

    const privateKey = loadRsaPrivateKeyFromSatKeyB64(keyB64, senha);
    if (!privateKey) {
      return res.status(400).json({
        ok: false,
        error: "Senha incorreta ou chave privada inválida (PKCS#8).",
      });
    }

    const firma = signCadena(privateKey, String(cadenaOriginal));

    return res.json({ ok: true, firma, cadenaOriginal });
  } catch (err) {
    console.error("Erro /firma:", err);
    return res.status(500).json({
      ok: false,
      error: "Erro interno ao gerar firma: " + String(err),
    });
  }
});

/**
 * /firmar-login
 * body: { P_CER_B64, P_KEY_B64, P_SENHA, P_CADENA }
 */
app.post("/firmar-login", (req, res) => {
  try {
    const { P_CER_B64, P_KEY_B64, P_SENHA, P_CADENA } = req.body || {};

    if (!P_CER_B64 || !P_KEY_B64 || !P_SENHA) {
      return res.status(400).json({
        ok: false,
        error: "Parâmetros faltando (P_CER_B64, P_KEY_B64, P_SENHA)",
      });
    }

    const cerB64 = P_CER_B64;
    const keyB64 = P_KEY_B64;
    const senha = P_SENHA;
    const cadenaOriginal = P_CADENA || "LOGIN-VUCEM";

    const privateKey = loadRsaPrivateKeyFromSatKeyB64(keyB64, senha);
    if (!privateKey) {
      return res.status(400).json({
        ok: false,
        error: "Senha incorreta ou chave privada inválida (PKCS#8).",
      });
    }

    const firma = signCadena(privateKey, String(cadenaOriginal));

    return res.json({ ok: true, firma, cadenaOriginal });
  } catch (err) {
    console.error("Erro /firmar-login:", err);
    return res.status(500).json({
      ok: false,
      error: "Erro interno ao gerar firma (login): " + String(err),
    });
  }
});

/**
 * /sha1pdf
 * body: { pdfB64 }
 * Retorna SHA1 HEX do binário do PDF (não do texto base64)
 */
app.post("/sha1pdf", (req, res) => {
  try {
    const { pdfB64 } = req.body || {};

    if (!pdfB64) {
      return res.status(400).json({ ok: false, error: "pdfB64 não informado" });
    }

    const pdfBytes = forge.util.decode64(String(pdfB64));
    const md = forge.md.sha1.create();
    md.update(pdfBytes, "raw");
    const sha1hex = md.digest().toHex();

    return res.json({ ok: true, sha1hex });
  } catch (e) {
    console.error("Erro /sha1pdf:", e);
    return res.status(500).json({ ok: false, error: String(e) });
  }
});

/**
 * /soap
 * body: { soapXml, headers?: {..}, url?: "https://..." }
 * Faz proxy POST do XML para VUCEM e devolve status + body.
 */
app.post("/soap", (req, res) => {
  try {
    const soapXml = req.body && req.body.soapXml ? String(req.body.soapXml) : "";
    const extraHeaders =
      req.body && req.body.headers && typeof req.body.headers === "object" ? req.body.headers : {};
    const targetUrl = req.body && req.body.url ? String(req.body.url) : "";

    if (!soapXml) {
      return res.status(400).json({ ok: false, error: "soapXml não informado" });
    }

    // URL real do serviço (endpoint), NÃO o ?wsdl
    const FIXED_VUCEM_URL =
      "https://www.ventanillaunica.gob.mx/ventanilla/DigitalizarDocumentoService";

    const finalUrl = targetUrl || FIXED_VUCEM_URL;

    if (!finalUrl) {
      return res.status(400).json({ ok: false, error: "URL do serviço VUCEM não configurada no Node." });
    }

    // Bloqueia só placeholder (se alguém usar)
    if (finalUrl.includes("COLOQUE_AQUI")) {
      return res.status(400).json({ ok: false, error: "URL do serviço VUCEM não configurada no Node." });
    }

    const u = new URL(finalUrl);

    // Não permitir que o caller sobrescreva Content-Length (dá problema fácil)
    const safeExtraHeaders = { ...extraHeaders };
    delete safeExtraHeaders["Content-Length"];
    delete safeExtraHeaders["content-length"];

    const headers = Object.assign(
      {
        "Content-Type": "text/xml; charset=utf-8",
        "Content-Length": Buffer.byteLength(soapXml, "utf8"),
      },
      safeExtraHeaders
    );

    const options = {
      protocol: u.protocol,
      hostname: u.hostname,
      port: u.port || 443,
      path: u.pathname + (u.search || ""),
      method: "POST",
      headers,
    };

    const request = https.request(options, (resp) => {
      let data = "";
      resp.setEncoding("utf8");
      resp.on("data", (chunk) => (data += chunk));
      resp.on("end", () => {
        return res.json({
          ok: resp.statusCode >= 200 && resp.statusCode < 300,
          httpStatus: resp.statusCode,
          body: data,
        });
      });
    });

    // Timeout para não travar a requisição indefinidamente
    request.setTimeout(60000, () => {
      request.destroy(new Error("Timeout SOAP (60s)"));
    });

    request.on("error", (err) => {
      return res.status(500).json({
        ok: false,
        error: "Erro ao POST SOAP: " + String(err),
      });
    });

    request.write(soapXml, "utf8");
    request.end();
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e) });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Servidor de firma ouvindo na porta " + PORT);
});
