 /**
 * index.js
 *
 * Node service para:
 *  - /firma            : assina cadenaOriginal com KEY (SAT) + senha
 *  - /firmar-login     : variação do /firma
 *  - /sha1pdf          : calcula SHA1 hex do binário do PDF (multipart ou JSON base64)
 *  - /soap             : proxy SOAP (POST XML) para VUCEM (URL opcional no body)
 *
 * IDEAL Step 5 (eDocument):
 *  - /edocument/registro-json : recebe SOAP do Registro (já montado no Velneo),
 *                               chama VUCEM via /soap, extrai numeroOperacion,
 *                               persiste estado PENDIENTE.
 *  - /edocument/consulta      : recebe numeroOperacion (+ credenciais WSS),
 *                               monta SOAP Consulta, chama VUCEM via /soap,
 *                               se achar eDocument marca FINAL; se fault marca ERROR; senão PENDIENTE.
 *
 * IMPORTANTE:
 *  - Persistência aqui é em memória (Map). Em produção ideal: Redis/Postgres.
 *  - A montagem de SOAP Registro fica no Velneo (você já tem builder).
 *  - A montagem de SOAP Consulta fica aqui, mas exige WSS_USER/WSS_PASS vindos do Velneo.
 */

const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const forge = require("node-forge");
const https = require("https");
const { URL } = require("url");
const multer = require("multer");

// -----------------------------------------------------------------------------
// fetch (Node 18+ tem global). Fallback p/ node-fetch v2 (CommonJS).
// -----------------------------------------------------------------------------
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

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    service: "mv-firma-service",
    ts: Date.now(),
    commit: process.env.RENDER_GIT_COMMIT || "",
  });
});

app.get("/routes", (req, res) => {
  const routes = [];
  app._router.stack.forEach((m) => {
    if (m.route && m.route.path) {
      const methods = Object.keys(m.route.methods || {}).join(",").toUpperCase();
      routes.push(`${methods} ${m.route.path}`);
    }
  });
  res.json({ ok: true, routes });
});

// multipart/form-data (PDF etc.)
const upload = multer({ limits: { fileSize: 25 * 1024 * 1024 } }); // ajuste se quiser

// -----------------------------------------------------------------------------
// STEP 5 - Store em memória (mínimo viável). Troque por Redis/DB para persistência real.
// Chave: numeroOperacion
// Valor: { status, eDocument, error, updatedAt, meta: { docKey, ... } }
// -----------------------------------------------------------------------------
const eDocStore = new Map();

// -----------------------------------------------------------------------------
// Utils: SHA1 HEX do binário
// -----------------------------------------------------------------------------
function sha1HexFromBuffer(buf) {
  const md = forge.md.sha1.create();
  // forge precisa de "binary string"
  md.update(Buffer.from(buf).toString("binary"), "raw");
  return md.digest().toHex(); // lowercase hex
}

function normalizePdfB64(input) {
  let s = String(input || "").trim();
  if (!s) return "";
  // aceita data URL
  if (s.startsWith("data:")) {
    const idx = s.indexOf("base64,");
    if (idx >= 0) s = s.slice(idx + "base64,".length);
  }
  // remove quebras de linha
  s = s.replace(/\s+/g, "");
  return s;
}

function bufferFromPdfB64(pdfB64) {
  const clean = normalizePdfB64(pdfB64);
  if (!clean) return null;
  return Buffer.from(clean, "base64");
}

// -----------------------------------------------------------------------------
// Utils: XML parsing simples (regex) - suficiente para tags específicas
// -----------------------------------------------------------------------------
function pickTag(xml, tag) {
  const re = new RegExp("<\\s*" + tag + "[^>]*>([\\s\\S]*?)<\\s*\\/\\s*" + tag + "\\s*>", "i");
  const m = re.exec(String(xml || ""));
  return m ? String(m[1]).trim() : "";
}

function isSoapFault(xml) {
  const s = String(xml || "");
  return /<\s*(soap:)?Fault\b/i.test(s) || /<\s*faultcode\b/i.test(s);
}

function xmlEscape(s) {
  s = String(s == null ? "" : s);
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function isoNowZ() {
  const d = new Date();
  // sem milissegundos para ficar igual seus scripts
  const pad = (n) => (n < 10 ? "0" : "") + n;
  return (
    d.getUTCFullYear() +
    "-" +
    pad(d.getUTCMonth() + 1) +
    "-" +
    pad(d.getUTCDate()) +
    "T" +
    pad(d.getUTCHours()) +
    ":" +
    pad(d.getUTCMinutes()) +
    ":" +
    pad(d.getUTCSeconds()) +
    "Z"
  );
}

// -----------------------------------------------------------------------------
// Utils: chave privada SAT (.KEY PKCS#8 DER encriptado) e assinatura SHA-256/RSA
// -----------------------------------------------------------------------------
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

function signCadena(privateKey, cadenaOriginal) {
  const md = forge.md.sha256.create();
  md.update(String(cadenaOriginal), "utf8");
  const signatureBytes = privateKey.sign(md);
  return forge.util.encode64(signatureBytes);
}

// -----------------------------------------------------------------------------
// SOAP Proxy: faz POST HTTPS do XML para a URL destino e devolve {ok,httpStatus,body}
// -----------------------------------------------------------------------------
function postSoapToUrl(finalUrl, soapXml, extraHeaders) {
  return new Promise((resolve, reject) => {
    try {
      const u = new URL(finalUrl);

      if (u.protocol !== "https:") {
        return resolve({ ok: false, httpStatus: 0, body: "", error: "Somente HTTPS é permitido." });
      }

      // Não permitir sobrescrever Content-Length
      const safeExtraHeaders = { ...(extraHeaders || {}) };
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
          resolve({
            ok: resp.statusCode >= 200 && resp.statusCode < 300,
            httpStatus: resp.statusCode,
            body: data,
          });
        });
      });

      request.setTimeout(180000, () => {
        request.destroy(new Error("Timeout SOAP (180s)"));
      });

      request.on("error", (err) => {
        resolve({ ok: false, httpStatus: 0, body: "", error: String(err) });
      });

      request.write(soapXml, "utf8");
      request.end();
    } catch (e) {
      reject(e);
    }
  });
}

// -----------------------------------------------------------------------------
// DEFAULT URL: DigitalizarDocumentoService (eDocument Registro/Consulta)
// -----------------------------------------------------------------------------
const DEFAULT_EDOC_URL =
  "https://www.ventanillaunica.gob.mx/ventanilla/DigitalizarDocumentoService";

// ============================================================================
// ENDPOINTS: Firma
// ============================================================================

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

// ============================================================================
// ENDPOINT: SHA1 de PDF
// ============================================================================

/**
 * /sha1pdf
 * Aceita:
 *  A) multipart/form-data: pdf=<arquivo>
 *  B) JSON: { pdfB64: "...." } (aceita também data:application/pdf;base64,...)
 *
 * Retorna SHA1 HEX do binário do PDF
 */
app.post("/sha1pdf", upload.single("pdf"), (req, res) => {
  try {
    // Caso A: multipart
    if (req.file && req.file.buffer && req.file.buffer.length) {
      const sha1hex = sha1HexFromBuffer(req.file.buffer);
      return res.json({ ok: true, sha1hex, mode: "multipart" });
    }

    // Caso B: JSON
    const pdfB64 = req.body && (req.body.pdfB64 || req.body.PDF_B64 || req.body.pdf_base64);
    const buf = bufferFromPdfB64(pdfB64);
    if (buf && buf.length) {
      const sha1hex = sha1HexFromBuffer(buf);
      return res.json({ ok: true, sha1hex, mode: "json" });
    }

    return res.status(400).json({
      ok: false,
      error: "PDF ausente. Envie multipart/form-data com campo 'pdf' OU JSON { pdfB64 }.",
    });
  } catch (e) {
    console.error("Erro /sha1pdf:", e);
    return res.status(500).json({ ok: false, error: String(e) });
  }
});

// ============================================================================
// ENDPOINT: SOAP Proxy
// ============================================================================

/**
 * /soap
 * body: { soapXml, headers?: {..}, url?: "https://..." }
 * Faz proxy POST do XML para VUCEM e devolve status + body.
 */
app.post("/soap", async (req, res) => {
  try {
    const soapXml = req.body && req.body.soapXml ? String(req.body.soapXml) : "";
    const extraHeaders =
      req.body && req.body.headers && typeof req.body.headers === "object" ? req.body.headers : {};
    const targetUrl = req.body && req.body.url ? String(req.body.url) : "";

    if (!soapXml) {
      return res.status(400).json({ ok: false, error: "soapXml não informado" });
    }

    // default (se não passar url)
    const finalUrl = targetUrl || DEFAULT_EDOC_URL;

    if (!finalUrl || finalUrl.includes("COLOQUE_AQUI")) {
      return res.status(400).json({ ok: false, error: "URL do serviço VUCEM não configurada." });
    }

    const out = await postSoapToUrl(finalUrl, soapXml, extraHeaders);

    // padroniza resposta do proxy
    return res.json({
      ok: !!out.ok,
      httpStatus: Number(out.httpStatus || 0),
      body: String(out.body || ""),
      error: out.ok ? "" : String(out.error || ""),
    });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e) });
  }
});

// ============================================================================
// IDEAL Step 5: eDocument
// ============================================================================

/**
 * /edocument/registro-json
 *
 * Recebe SOAP do Registro (montado no Velneo) e registra digitalização.
 * Persistimos o numeroOperacion como PENDIENTE.
 *
 * body:
 * {
 *   soapXml: "<SOAP RegistroDigitalizarDocumento...>",
 *   url?: "https://...DigitalizarDocumentoService",
 *   docKey?: "...",
 *   meta?: { qualquer_coisa }
 * }
 *
 * response:
 *  - { ok:true, status:"PENDIENTE", numeroOperacion:"...", docKey:"..." }
 *  - { ok:false, status:"ERROR", error:"...", rawXml? }
 */
app.post("/edocument/registro-json", async (req, res) => {
  try {
    if (!fetchFn) {
      return res.status(500).json({
        ok: false,
        status: "ERROR",
        error: "fetch não disponível no Node. Use Node 18+ ou instale node-fetch v2.",
      });
    }

    const soapXml = String(req.body?.soapXml || "").trim();
    const url = String(req.body?.url || "").trim() || DEFAULT_EDOC_URL;
    const docKey = String(req.body?.docKey || "").trim();
    const meta = req.body?.meta && typeof req.body.meta === "object" ? req.body.meta : {};

    if (!soapXml) {
      return res.status(400).json({ ok: false, status: "ERROR", error: "soapXml ausente" });
    }

    // 1) chama VUCEM via proxy /soap (interno: função postSoapToUrl)
    const out = await postSoapToUrl(url, soapXml, {});

    if (!out.ok || out.httpStatus < 200 || out.httpStatus >= 300) {
      return res.status(502).json({
        ok: false,
        status: "ERROR",
        error: "Registro SOAP falhou",
        httpStatus: out.httpStatus,
        rawXml: out.body || "",
      });
    }

    if (isSoapFault(out.body)) {
      return res.status(502).json({
        ok: false,
        status: "ERROR",
        error: "SOAP Fault no Registro",
        rawXml: out.body || "",
      });
    }

    // 2) extrai numeroOperacion
    const numeroOperacion =
      pickTag(out.body, "numeroOperacion") || pickTag(out.body, "NumeroOperacion");

    if (!numeroOperacion) {
      return res.status(502).json({
        ok: false,
        status: "ERROR",
        error: "Não achei numeroOperacion no XML do Registro",
        rawXml: out.body || "",
      });
    }

    // 3) persiste como pendente
    eDocStore.set(numeroOperacion, {
      status: "PENDIENTE",
      eDocument: "",
      error: "",
      updatedAt: Date.now(),
      meta: {
        docKey,
        meta,
      },
    });

    return res.json({
      ok: true,
      status: "PENDIENTE",
      numeroOperacion,
      docKey,
    });
  } catch (e) {
    return res.status(500).json({ ok: false, status: "ERROR", error: String(e.message || e) });
  }
});

/**
 * Monta SOAP ConsultaEDocumentDigitalizarDocumento COM WS-Security UsernameToken,
 * porque este serviço costuma exigir WSS_USER/WSS_PASS.
 *
 * OBS: namespace/elementos podem variar por WSDL; esta versão é compatível com seu builder atual
 * (sem prefixo de operação).
 */
function buildSoapConsulta(wssUser, wssPass, numeroOperacion) {
  const created = isoNowZ();

  return (
    '<?xml version="1.0" encoding="UTF-8"?>' +
    '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" ' +
    'xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" ' +
    'xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">' +
    "<soapenv:Header>" +
    '<wsse:Security soapenv:mustUnderstand="1">' +
    '<wsse:UsernameToken wsu:Id="UsernameToken-1">' +
    "<wsse:Username>" +
    xmlEscape(wssUser) +
    "</wsse:Username>" +
    '<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">' +
    xmlEscape(wssPass) +
    "</wsse:Password>" +
    "<wsu:Created>" +
    xmlEscape(created) +
    "</wsu:Created>" +
    "</wsse:UsernameToken>" +
    "</wsse:Security>" +
    "</soapenv:Header>" +
    "<soapenv:Body>" +
    "<ConsultaEDocumentDigitalizarDocumento>" +
    "<numeroOperacion>" +
    xmlEscape(numeroOperacion) +
    "</numeroOperacion>" +
    "</ConsultaEDocumentDigitalizarDocumento>" +
    "</soapenv:Body>" +
    "</soapenv:Envelope>"
  );
}

/**
 * /edocument/consulta
 *
 * body:
 * {
 *   numeroOperacion: "...",
 *   P_WSS_USER: "...",   // obrigatório para montar WSSE
 *   P_WSS_PASS: "...",   // obrigatório para montar WSSE
 *   url?: "https://...DigitalizarDocumentoService"
 * }
 *
 * response (sempre contrato Step 5):
 *  - PENDIENTE: { ok:true, status:"PENDIENTE", numeroOperacion, docKey? }
 *  - FINAL:     { ok:true, status:"FINAL", numeroOperacion, eDocument, docKey? }
 *  - ERROR:     { ok:false,status:"ERROR", numeroOperacion, error, docKey? }
 */
app.post("/edocument/consulta", async (req, res) => {
  try {
    if (!fetchFn) {
      return res.status(500).json({
        ok: false,
        status: "ERROR",
        error: "fetch não disponível no Node. Use Node 18+ ou instale node-fetch v2.",
      });
    }

    const numeroOperacion = String(req.body?.numeroOperacion || "").trim();
    const wssUser = String(req.body?.P_WSS_USER || req.body?.wssUser || "").trim();
    const wssPass = String(req.body?.P_WSS_PASS || req.body?.wssPass || "").trim();
    const url = String(req.body?.url || "").trim() || DEFAULT_EDOC_URL;

    if (!numeroOperacion) {
      return res.status(400).json({ ok: false, status: "ERROR", error: "numeroOperacion ausente" });
    }

    // Busca no store (se não existir, ainda assim tentamos consultar)
    const st = eDocStore.get(numeroOperacion);

    // Se já finalizou, retorna direto
    if (st && (st.status === "FINAL" || st.status === "ERROR")) {
      return res.json({
        ok: st.status === "FINAL",
        status: st.status,
        numeroOperacion,
        eDocument: st.eDocument || "",
        error: st.error || "",
        docKey: st.meta?.docKey || "",
      });
    }

    // Para consultar com WSSE, exigimos credenciais
    if (!wssUser || !wssPass) {
      return res.status(400).json({
        ok: false,
        status: "ERROR",
        error: "P_WSS_USER/P_WSS_PASS são obrigatórios para consulta",
      });
    }

    // 1) monta SOAP Consulta
    const soapXml = buildSoapConsulta(wssUser, wssPass, numeroOperacion);

    // 2) chama VUCEM via proxy /soap
    const out = await postSoapToUrl(url, soapXml, {});

    // Se HTTP falhou, não fechamos como ERROR definitivo (para permitir retry)
    if (!out.ok || out.httpStatus < 200 || out.httpStatus >= 300) {
      // mantém pendente no store
      eDocStore.set(numeroOperacion, {
        status: "PENDIENTE",
        eDocument: "",
        error: "",
        updatedAt: Date.now(),
        meta: st?.meta || {},
      });

      return res.json({
        ok: true,
        status: "PENDIENTE",
        numeroOperacion,
        docKey: st?.meta?.docKey || "",
      });
    }

    // Fault: erro definitivo
    if (isSoapFault(out.body)) {
      eDocStore.set(numeroOperacion, {
        status: "ERROR",
        eDocument: "",
        error: "SOAP Fault na Consulta",
        updatedAt: Date.now(),
        meta: st?.meta || {},
      });

      return res.json({
        ok: false,
        status: "ERROR",
        numeroOperacion,
        error: "SOAP Fault na Consulta",
        docKey: st?.meta?.docKey || "",
      });
    }

    // 3) tenta extrair eDocument
    const eDocument =
      pickTag(out.body, "eDocument") ||
      pickTag(out.body, "EDocument") ||
      pickTag(out.body, "EDOCUMENT") ||
      pickTag(out.body, "idEDocument") ||
      pickTag(out.body, "IdEDocument") ||
      pickTag(out.body, "eDocumentId") ||
      pickTag(out.body, "EDocumentId") ||
      "";

    if (eDocument) {
      eDocStore.set(numeroOperacion, {
        status: "FINAL",
        eDocument,
        error: "",
        updatedAt: Date.now(),
        meta: st?.meta || {},
      });

      return res.json({
        ok: true,
        status: "FINAL",
        numeroOperacion,
        eDocument,
        docKey: st?.meta?.docKey || "",
      });
    }

    // 4) ainda não saiu -> pendente
    eDocStore.set(numeroOperacion, {
      status: "PENDIENTE",
      eDocument: "",
      error: "",
      updatedAt: Date.now(),
      meta: st?.meta || {},
    });

    return res.json({
      ok: true,
      status: "PENDIENTE",
      numeroOperacion,
      docKey: st?.meta?.docKey || "",
    });
  } catch (e) {
    return res.status(500).json({ ok: false, status: "ERROR", error: String(e.message || e) });
  }
});

// ============================================================================
// LISTENER
// ============================================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Servidor ouvindo na porta " + PORT);
});
