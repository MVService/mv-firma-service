// index.js
// Node service: assinatura (/firma), sha1 pdf multipart (/sha1pdf),
// registro eDocument via Velneo (/edocument/registro), proxy SOAP (/soap)

const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const forge = require("node-forge");
const https = require("https");
const { URL } = require("url");
const multer = require("multer");

// ---- fetch (Node 18+ tem global). Fallback p/ node-fetch v2 (CommonJS).
let fetchFn = global.fetch;
if (!fetchFn) {
  try {
    fetchFn = require("node-fetch");
  } catch (e) {
    console.error("fetch não disponível. Use Node 18+ ou instale node-fetch v2.");
  }
}

const app = express();
app.use(cors());

// 100mb para aguentar SOAP com PDF inline em base64
app.use(bodyParser.json({ limit: "100mb" }));

// multipart/form-data (PDF etc.)
const upload = multer({ limits: { fileSize: 25 * 1024 * 1024 } }); // ajuste se quiser

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
  md.update(String(cadenaOriginal), "utf8");
  const signatureBytes = privateKey.sign(md);
  return forge.util.encode64(signatureBytes);
}

/**
 * /firma
 * body: { cerB64, keyB64, senha, cadenaOriginal }
 * OBS: cerB64 é validado por consistência, mas não é usado para assinar.
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

    const firma = signCadena(privateKey, cadenaOriginal);
    return res.json({ ok: true, firma, cadenaOriginal: String(cadenaOriginal) });
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

    const firma = signCadena(privateKey, cadenaOriginal);
    return res.json({ ok: true, firma, cadenaOriginal: String(cadenaOriginal) });
  } catch (err) {
    console.error("Erro /firmar-login:", err);
    return res.status(500).json({
      ok: false,
      error: "Erro interno ao gerar firma (login): " + String(err),
    });
  }
});

/**
 * /sha1pdf (multipart)
 * form-data: pdf=<arquivo>
 * Retorna SHA1 HEX do binário do PDF
 */
app.post("/sha1pdf", upload.single("pdf"), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ ok: false, error: "PDF ausente (campo 'pdf')." });
    }

    const md = forge.md.sha1.create();
    md.update(req.file.buffer.toString("binary"), "raw");
    const sha1hex = md.digest().toHex();

    return res.json({ ok: true, sha1hex });
  } catch (e) {
    console.error("Erro /sha1pdf:", e);
    return res.status(500).json({ ok: false, error: String(e) });
  }
});

/**
 * /edocument/registro (multipart)
 * form-data:
 *   pdf=<arquivo>
 *   meta=<json string>
 *
 * Faz: transforma PDF -> base64 e chama Velneo (API_EDOCUMENT_REGISTRO) via JSON.
 */
app.post("/edocument/registro", upload.single("pdf"), async (req, res) => {
  try {
    if (!fetchFn) {
      return res.status(500).json({
        ok: false,
        error: "fetch não disponível no Node. Use Node 18+ ou instale node-fetch v2.",
      });
    }

    const meta = JSON.parse(req.body.meta || "{}");

    if (!req.file) {
      return res.status(400).json({ ok: false, error: "PDF ausente (campo 'pdf')." });
    }

    const pdfB64 = req.file.buffer.toString("base64");

    // opcional: calcula sha1 aqui se não veio no meta
    let sha1hex = String(meta.sha1hex || "").trim();
    if (!sha1hex) {
      const md = forge.md.sha1.create();
      md.update(req.file.buffer.toString("binary"), "raw");
      sha1hex = md.digest().toHex();
    }

    const fileItem = {
      correoElectronico: String(meta.correoElectronico || "").trim(),
      idTipoDocumento: String(meta.idTipoDocumento || "").trim(),
      nombreDocumento: String(meta.nombreDocumento || "").trim(),
      rfcConsulta: String(meta.rfcConsulta || "").trim(),
      pdfB64,
      sha1hex,
      cadenaOriginal: String(meta.cadenaOriginal || "").trim(),
      firma: String(meta.firma || "").trim(),
    };

    // valida meta mínimo antes de chamar Velneo
    if (!fileItem.correoElectronico || !fileItem.idTipoDocumento || !fileItem.nombreDocumento) {
      return res.status(400).json({
        ok: false,
        error: "meta incompleto: correoElectronico, idTipoDocumento, nombreDocumento são obrigatórios.",
      });
    }

    const resp = await fetchFn("https://c8.velneo.com:17722/api2/API_EDOCUMENT_REGISTRO", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        P_WSS_USER: meta.P_WSS_USER || "",
        P_WSS_PASS: meta.P_WSS_PASS || "",
        P_CER_B64: meta.P_CER_B64 || "",
        P_FILES_JSON: JSON.stringify([fileItem]),
      }),
    });

    const text = await resp.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch (_) {}

    if (!resp.ok) {
      return res.status(502).json({
        ok: false,
        error: "Velneo respondió HTTP " + resp.status,
        raw: json || text,
      });
    }

    return res.json(json || { ok: true, raw: text });
  } catch (e) {
    console.error("Erro /edocument/registro:", e);
    return res.status(500).json({ ok: false, error: String(e.message || e) });
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

    // default (se não passar url)
    const FIXED_VUCEM_URL = "https://www.ventanillaunica.gob.mx/ventanilla/DigitalizarDocumentoService";
    const finalUrl = targetUrl || FIXED_VUCEM_URL;

    if (!finalUrl || finalUrl.includes("COLOQUE_AQUI")) {
      return res.status(400).json({ ok: false, error: "URL do serviço VUCEM não configurada no Node." });
    }

    const u = new URL(finalUrl);

    if (u.protocol !== "https:") {
      return res.status(400).json({ ok: false, error: "Somente HTTPS é permitido em /soap." });
    }

    // Não permitir que o caller sobrescreva Content-Length
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
      port: u.port ? Number(u.port) : 443,
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
