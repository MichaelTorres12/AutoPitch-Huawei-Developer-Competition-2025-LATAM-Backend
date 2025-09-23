# src/services/cloud_pipeline.py
import os, re, json, time, base64, hmac, hashlib
from typing import List, Dict, Any, Tuple
from datetime import datetime
from urllib.parse import urlparse, quote, parse_qsl

from dotenv import load_dotenv; load_dotenv()
import requests

# === ENV ===
OBS_ENDPOINT = os.getenv("OBS_ENDPOINT")
OBS_BUCKET_UPLOADS = os.getenv("OBS_BUCKET_UPLOADS", "autopitch-uploads")
OBS_BUCKET_ARTIFACTS = os.getenv("OBS_BUCKET_ARTIFACTS", "autopitch-artifacts")
OBS_AK = os.getenv("OBS_AK")
OBS_SK = os.getenv("OBS_SK")
OBS_REGION = os.getenv("OBS_REGION") or os.getenv("HW_REGION") or "ap-southeast-3"

USE_MPC = os.getenv("USE_MPC", "0") == "1"
USE_SIS = os.getenv("USE_SIS", "0") == "1"
MPC_STRICT = os.getenv("MPC_STRICT", "1") == "1"  # si True, no placeholders: error si falla MPC
SIS_STRICT = os.getenv("SIS_STRICT", "1") == "1"  # si True, no fallback: error si falla SIS

# LLM competencia (ModelArts/Pangu)
COMP_LLM_URL = (os.getenv("COMP_LLM_URL") or "").strip()
COMP_LLM_TOKEN = (os.getenv("COMP_LLM_TOKEN") or "").strip()
COMP_LLM_MODEL = (os.getenv("COMP_LLM_MODEL") or "deepseek-r1-distil-qwen-32b_raziqt").strip()
COMP_LLM_TEMPERATURE = float(os.getenv("COMP_LLM_TEMPERATURE", "0.2"))
COMP_LLM_MAX_TOKENS = int(os.getenv("COMP_LLM_MAX_TOKENS", "600"))

# MPC (audio extraction via template transcoding)
MPC_PROJECT_ID = os.getenv("MPC_PROJECT_ID", "")
MPC_ENDPOINT = os.getenv("MPC_ENDPOINT", "https://mpc.ap-southeast-3.myhuaweicloud.com")
MPC_AUDIO_TEMPLATE_ID = os.getenv("MPC_AUDIO_TEMPLATE_ID", "")
MPC_POLL_INTERVAL_MS = int(os.getenv("MPC_POLL_INTERVAL_MS", "1500"))
MPC_POLL_TIMEOUT_SEC = int(os.getenv("MPC_POLL_TIMEOUT_SEC", "120"))
MPC_TOKEN = (os.getenv("MPC_TOKEN") or "").strip()  # Si presente, usar X-Auth-Token para MPC

# SIS (short-audio con AK/SK)
SIS_PROJECT_ID = os.getenv("SIS_PROJECT_ID", "")
SIS_ENDPOINT = os.getenv("SIS_ENDPOINT", "https://sis-ext.ap-southeast-3.myhuaweicloud.com")
SIS_LANGUAGE = os.getenv("SIS_LANGUAGE", "en-US")  # 'es-ES' o 'en-US'
SIS_TOKEN = (os.getenv("SIS_TOKEN") or "").strip()  # Si presente, usar X-Auth-Token en lugar de firma AK/SK
SIS_PROPERTY = (os.getenv("SIS_PROPERTY") or "").strip()  # Si presente, usar como property de Short Audio

# === OBS SDK (opcional; usaremos principalmente URLs firmadas) ===
try:
    from obs import ObsClient
    _server = (OBS_ENDPOINT or "").replace("https://", "").replace("http://", "")
    _obs = ObsClient(access_key_id=OBS_AK, secret_access_key=OBS_SK, server=_server, is_secure=True)
except Exception:
    _obs = None

# ====== Logging helpers ======
def _now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="milliseconds") + "Z"

_SENSITIVE_KEYS = {"token", "secret", "ak", "sk", "password", "authorization", "x-auth-token"}

def _redact(obj: Any) -> Any:
    try:
        if isinstance(obj, dict):
            out: Dict[str, Any] = {}
            for k, v in obj.items():
                if any(s in k.lower() for s in _SENSITIVE_KEYS):
                    out[k] = "<redacted>"
                else:
                    out[k] = _redact(v)
            return out
        if isinstance(obj, list):
            return [_redact(x) for x in obj]
        return obj
    except Exception:
        return obj

def _log(event: str, **fields: Any) -> None:
    payload = {"ts": _now_iso(), "event": event, **fields}
    try:
        print("[cloud] " + json.dumps(_redact(payload), ensure_ascii=False))
    except Exception:
        try:
            safe = {k: (str(v) if not isinstance(v, (int, float, bool)) else v) for k, v in payload.items()}
            print("[cloud] " + json.dumps(_redact(safe), ensure_ascii=False))
        except Exception:
            print(f"[cloud] {event} <log serialization error>")

def _elapsed_ms(start: float) -> int:
    return int((time.perf_counter() - start) * 1000)

def _iso_now():
    return datetime.utcnow().isoformat() + "Z"

def _fmt_hhmmss_ms(t: float) -> str:
    h = int(t // 3600); m = int((t % 3600)//60); s = int(t % 60); ms = int((t*1000) % 1000)
    return f"{h:02d}:{m:02d}:{s:02d}.{ms:03d}"

# ====== OBS helpers ======
def obs_put_text(bucket: str, key: str, text: str):
    _log("obs.put_text.begin", bucket=bucket, key=key, size_bytes=len(text.encode("utf-8")))
    if not _obs:
        _log("obs.put_text.skip_no_client", bucket=bucket, key=key)
        return
    resp = _obs.putContent(bucket, key, text, headers={'Content-Type': 'text/plain; charset=utf-8'})
    if resp.status < 200 or resp.status >= 300:
        raise RuntimeError(f"OBS putContent error: {resp.status}")
    _log("obs.put_text.ok", bucket=bucket, key=key, status=resp.status)

def obs_put_json(bucket: str, key: str, obj: Any):
    payload = json.dumps(obj, ensure_ascii=False, indent=2)
    obs_put_text(bucket, key, payload)

def obs_signed_get(bucket: str, key: str, expires: int | None = None) -> str:
    _log("obs.signed_get.begin", bucket=bucket, key=key, expires=expires)
    if not _obs:
        url = f"https://{bucket}.obs.{OBS_REGION}.myhuaweicloud.com/{key}"
        _log("obs.signed_get.fallback", url_prefix=url[:80])
        return url
    if expires is None:
        expires = int(os.getenv("OBS_GET_EXPIRES", "86400"))
    res = _obs.createSignedUrl('GET', bucket, key, expires=expires)
    url = res.get('signedUrl')
    _log("obs.signed_get.ok", url_prefix=(url[:80] if isinstance(url, str) else None))
    return url

def _obs_object_exists(bucket: str, key: str) -> bool:
    """Check object existence in OBS robustly.
    - If SDK client available: use getObjectMetadata (does not require signed URL).
    - Else: use signed GET URL and fetch 1 byte (Range 0-0) to avoid 403 on HEAD.
    """
    try:
        if _obs:
            try:
                meta = _obs.getObjectMetadata(bucket, key)
                return 200 <= int(getattr(meta, 'status', 0)) < 300
            except Exception:
                pass
        url = obs_signed_get(bucket, key, expires=60)
        r = requests.get(url, headers={"Range": "bytes=0-0"}, timeout=30)
        return r.status_code in (200, 206)
    except Exception:
        return False

def _obs_read_bytes(bucket: str, key: str) -> bytes:
    url = obs_signed_get(bucket, key, expires=300)
    r = requests.get(url, timeout=120)
    r.raise_for_status()
    return r.content

# ====== Huawei SDK-HMAC-SHA256 signing (AK/SK) ======
def _sdk_now() -> str:
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

def _canonical_query(raw_q: str) -> str:
    parts = parse_qsl(raw_q, keep_blank_values=True)
    parts.sort()
    return "&".join(f"{quote(k, safe='-_.~')}={quote(v, safe='-_.~')}" for k, v in parts)

def _canonical_headers(headers: Dict[str, str]) -> Tuple[str, str]:
    h2 = {k.lower().strip(): re.sub(r"\s+", " ", (v or "").strip()) for k, v in headers.items()}
    signed_keys = sorted(h2.keys())
    canonical = "".join(f"{k}:{h2[k]}\n" for k in signed_keys)
    return canonical, ";".join(signed_keys)

def _sign_sdk_hmac_sha256(ak: str, sk: str, method: str, url: str, headers: Dict[str, str], body: bytes) -> str:
    u = urlparse(url)
    canonical_uri = quote(u.path, safe="/~")
    canonical_query = _canonical_query(u.query or "")
    canonical_headers, signed_headers = _canonical_headers(headers)
    hashed_body = hashlib.sha256(body).hexdigest()
    canonical_request = f"{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{hashed_body}"
    string_to_sign = f"SDK-HMAC-SHA256\n{headers['x-sdk-date']}\n{hashlib.sha256(canonical_request.encode()).hexdigest()}"
    signature = hmac.new(sk.encode(), string_to_sign.encode(), hashlib.sha256).hexdigest()
    return f"SDK-HMAC-SHA256 Access={ak}, SignedHeaders={signed_headers}, Signature={signature}"

def _sdk_request(method: str, url: str, *, body_json: Dict[str, Any] | None = None, body_bytes: bytes | None = None,
                 extra_headers: Dict[str, str] | None = None, timeout: int = 180,
                 include_body_hash_header: bool = True) -> requests.Response:
    """Perform an SDK-HMAC-SHA256 signed request using OBS_AK/SK.

    Some Huawei services (SIS, MPC) accept AK/SK-signed requests via the SDK signature.
    """
    if body_bytes is None:
        body_bytes = json.dumps(body_json or {}, separators=(",", ":")).encode("utf-8")
    parsed = urlparse(url)
    headers: Dict[str, str] = {
        "host": parsed.netloc,
        "content-type": "application/json",
        "x-sdk-date": _sdk_now(),
    }
    if include_body_hash_header:
        headers["x-sdk-content-sha256"] = hashlib.sha256(body_bytes).hexdigest()
    # Per docs, AK/SK requests should include X-Project-Id
    host_lower = parsed.netloc.lower()
    if "mpc." in host_lower and MPC_PROJECT_ID:
        headers["X-Project-Id"] = MPC_PROJECT_ID
    if ("sis." in host_lower or "sis-ext." in host_lower) and SIS_PROJECT_ID:
        headers["X-Project-Id"] = SIS_PROJECT_ID
    if extra_headers:
        headers.update(extra_headers)
    headers["Authorization"] = _sign_sdk_hmac_sha256(OBS_AK or "", OBS_SK or "", method.upper(), url, headers, body_bytes)
    t0 = time.perf_counter()
    r = requests.request(method.upper(), url, headers=headers, data=body_bytes, timeout=timeout)
    _log("sdk.request.response", url=url, status=r.status_code, elapsed_ms=_elapsed_ms(t0))
    return r

# ====== LLM competencia ======
def deepseek_highlights(sentences: List[Dict[str,Any]], top_k=8, language="es") -> List[Dict[str,Any]]:
    url = COMP_LLM_URL
    token = COMP_LLM_TOKEN
    model = COMP_LLM_MODEL
    temperature = COMP_LLM_TEMPERATURE
    max_tokens = COMP_LLM_MAX_TOKENS
    if not url or not token:
        raise RuntimeError("LLM de competencia no configurado (COMP_LLM_URL/COMP_LLM_TOKEN).")

    items = [
        {"i": i,
         "start_sec": float(s.get("start", i*2.0)),
         "end_sec": float(s.get("end", i*2.0+1.5)),
         "text": (s.get("text") or "")[:220]}
        for i, s in enumerate(sentences)
    ]
    prompt = f"""
Eres un analista de demos de software. Selecciona los {top_k} momentos más importantes.
Criterios: cambios de pantalla, acciones clave, decisiones, hallazgos.
Devuelve SOLO JSON: {{"picks":[{{"i":0,"label":"","summary":"","reason":"","confidence":0.7}}]}}

Items:
{json.dumps(items, ensure_ascii=False)}

Responde en {language}. SOLO JSON.
""".strip()

    headers_primary = {"Content-Type": "application/json", "X-Auth-Token": token}
    headers_bearer  = {"Content-Type": "application/json", "Authorization": f"Bearer {token}"}
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": "Eres conciso y SOLO devuelves JSON válido."},
            {"role": "user", "content": prompt}
        ],
        "temperature": temperature,
        "max_tokens": max_tokens
    }

    _log("llm.request.begin", url=url, model=model, temperature=temperature, max_tokens=max_tokens,
         sentences=len(sentences), top_k=top_k, language=language)

    for attempt, headers in enumerate((headers_primary, headers_bearer), start=1):
        t_req = time.perf_counter()
        r = requests.post(url, headers=headers, json=body, timeout=120)
        _log("llm.request.response", attempt=attempt, status=r.status_code,
             elapsed_ms=_elapsed_ms(t_req),
             used_header=("X-Auth-Token" if headers is headers_primary else "Authorization"))
        if r.status_code == 401:
            _log("llm.request.unauthorized", attempt=attempt)
            continue
        r.raise_for_status()
        raw = r.json()["choices"][0]["message"]["content"]
        _log("llm.response.raw", size=len(raw or ""), preview=(raw[:200] if isinstance(raw, str) else None))
        try:
            print("🐳 deepseek.response:", raw, flush=True)
        except Exception:
            pass
        try:
            data = json.loads(raw)
        except Exception:
            m = re.search(r"\{[\s\S]*\}", raw); data = json.loads(m.group(0)) if m else {"picks":[]}

        picks = data.get("picks", [])[:top_k]
        out = []
        for p in picks:
            try:
                idx = int(p.get("i"))
                s = sentences[idx]
                st = float(s.get("start", idx*2.0))
                en = float(s.get("end", st+1.5))
                out.append({
                    "i": idx,
                    "label": (p.get("label") or "Momento clave")[:80],
                    "summary": (p.get("summary") or "")[:300],
                    "reason": (p.get("reason") or "")[:200],
                    "confidence": float(p.get("confidence") or 0.6),
                    "start_sec": st,
                    "end_sec": en,
                    "timestamp": _fmt_hhmmss_ms(st),
                    "timestamp_end": _fmt_hhmmss_ms(en)
                })
            except Exception:
                continue
        _log("llm.response.parsed", picks=len(out))
        return out
    raise RuntimeError("401 Unauthorized del LLM (revisa COMP_LLM_TOKEN/model/url).")

def fallback_highlights(sentences: List[Dict[str,Any]], top_k=8) -> List[Dict[str,Any]]:
    if not sentences:
        _log("fallback.highlights.empty_sentences")
        return []
    n = len(sentences)
    step = max(1, n // max(1, top_k))
    picks, idxs = [], list(range(0, n, step))[:top_k]
    for idx in idxs:
        s = sentences[idx]
        st = float(s.get("start", idx*2.0)); en = float(s.get("end", st+1.5))
        picks.append({
            "i": idx,
            "label": "Momento clave",
            "summary": s.get("text","")[:120],
            "reason": "Seleccionado automáticamente (fallback).",
            "confidence": 0.5,
            "start_sec": st, "end_sec": en,
            "timestamp": _fmt_hhmmss_ms(st),
            "timestamp_end": _fmt_hhmmss_ms(en)
        })
    _log("fallback.highlights.done", total_sentences=n, picks=len(picks))
    return picks

# ====== MPC / SIS ======
def mpc_audio_only(in_bucket: str, in_key: str, out_bucket: str, out_key: str) -> str:
    """
    Si USE_MPC=1: intenta crear una tarea MPC para extraer audio MP3 desde el video en OBS.
    - Usa plantilla MPC indicada por MPC_AUDIO_TEMPLATE_ID.
    - Espera (poll) hasta que el objeto de salida exista o venza el timeout.
    Si USE_MPC=0 o hay error: genera placeholder para no romper el flujo.
    """
    _log("mpc.audio_only.begin", use_mpc=USE_MPC, strict=MPC_STRICT, in_bucket=in_bucket, in_key=in_key, out_bucket=out_bucket, out_key=out_key,
         template_id=MPC_AUDIO_TEMPLATE_ID, poll_ms=MPC_POLL_INTERVAL_MS, timeout_s=MPC_POLL_TIMEOUT_SEC)

    # Si ya existe, úsalo
    if _obs_object_exists(out_bucket, out_key):
        url = f"obs://{out_bucket}/{out_key}"
        _log("mpc.audio_only.found_existing", url=url)
        return url

    # Si no se desea MPC real o falta config mínima, escribe placeholder
    if not USE_MPC or not MPC_PROJECT_ID or not MPC_AUDIO_TEMPLATE_ID:
        if MPC_STRICT:
            raise RuntimeError("MPC deshabilitado o configuración incompleta (MPC_PROJECT_ID/MPC_AUDIO_TEMPLATE_ID).")
        else:
            try:
                obs_put_text(out_bucket, out_key, f"placeholder audio para {in_bucket}/{in_key}")
            except Exception as e:
                _log("mpc.audio_only.placeholder_warn", error=str(e))
            url = f"obs://{out_bucket}/{out_key}"
            _log("mpc.audio_only.done.placeholder", url=url)
            return url

    # Validar que el objeto de entrada existe antes de crear la tarea
    if not _obs_object_exists(in_bucket, in_key):
        raise RuntimeError(f"Objeto de entrada no existe en OBS: obs://{in_bucket}/{in_key}")

    # Intenta crear tarea MPC por plantilla (audio-only)
    # Nota: según documentación de MPC, el endpoint suele ser /v1/{project_id}/template-transcodings
    # El body requiere input (OBS), output (OBS) y template_id.
    try:
        # Priorizar endpoint oficial y forma del body según documentación
        # https://support.huaweicloud.com/intl/en-us/api-mpc/mpc_04_0017.html
        candidate_paths = [
            f"{MPC_ENDPOINT}/v1/{MPC_PROJECT_ID}/transcodings",
            f"{MPC_ENDPOINT}/v1/{MPC_PROJECT_ID}/transcodings/",
            # Fallbacks por variaciones regionales
            f"{MPC_ENDPOINT}/v1/{MPC_PROJECT_ID}/template/transcodings",
            f"{MPC_ENDPOINT}/v1/{MPC_PROJECT_ID}/template/transcodings/",
        ]

        # Construir salida: directorio + nombre usando output_filenames
        try:
            tpl_id_int = int(str(MPC_AUDIO_TEMPLATE_ID).strip()) if str(MPC_AUDIO_TEMPLATE_ID).strip() else None
        except Exception:
            tpl_id_int = None
        out_dir = out_key.rsplit("/", 1)[0] if "/" in out_key else out_key
        out_filename = out_key.split("/")[-1]

        base_io = {
            "input": {"bucket": in_bucket, "location": OBS_REGION, "object": in_key},
            "output": {"bucket": out_bucket, "location": OBS_REGION, "object": out_dir},
        }

        candidate_bodies = []
        if tpl_id_int is not None:
            # Forma recomendada: trans_template_id como ARRAY + output_filenames
            candidate_bodies.append({
                **base_io,
                "trans_template_id": [tpl_id_int],
                "output_filenames": [out_filename],
            })
            # Variante: template_id como ARRAY
            candidate_bodies.append({
                **base_io,
                "template_id": [tpl_id_int],
                "output_filenames": [out_filename],
            })
            # Variante: trans_template_ids (algunos despliegues lo aceptan)
            candidate_bodies.append({
                **base_io,
                "trans_template_ids": [tpl_id_int],
                "output_filenames": [out_filename],
            })
        else:
            # Si no hay template válido, lanzar error claro
            raise RuntimeError("MPC_AUDIO_TEMPLATE_ID inválido; se requiere un ID numérico de plantilla MPC.")

        r = None
        last_err: Dict[str, Any] | None = None
        for url_try in candidate_paths:
            for body_try in candidate_bodies:
                preview = {"input": body_try["input"], "output": body_try["output"]}
                if "output_filenames" in body_try:
                    preview["output_filenames"] = body_try["output_filenames"]
                if "trans_template_id" in body_try:
                    preview["trans_template_id"] = body_try["trans_template_id"]
                if "template_id" in body_try:
                    preview["template_id"] = body_try["template_id"]
                if "trans_template_ids" in body_try:
                    preview["trans_template_ids"] = body_try["trans_template_ids"]
                _log("mpc.task.create.begin", url=url_try, body_preview=str(preview))
                if MPC_TOKEN:
                    headers = {"Content-Type": "application/json", "X-Auth-Token": MPC_TOKEN, "X-Project-Id": MPC_PROJECT_ID}
                    t0 = time.perf_counter()
                    r = requests.post(url_try, headers=headers, json=body_try, timeout=60)
                    _log("mpc.http.response.token", status=r.status_code, elapsed_ms=_elapsed_ms(t0))
                else:
                    r = _sdk_request("POST", url_try, body_json=body_try, timeout=60)
                if r.status_code < 400:
                    break
                last_err = {"status": r.status_code, "text": (r.text[:500] if isinstance(r.text, str) else None)}
                _log("mpc.task.create.error", **last_err)
            if r and r.status_code < 400:
                break
        if not r or r.status_code >= 400:
            raise RuntimeError(f"MPC create task failed: {last_err}")
        task = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        task_id = task.get("task_id") or task.get("id") or task.get("taskId")
        _log("mpc.task.create.ok", task_id=task_id)
    except Exception as e:
        _log("mpc.task.create.exception", error=str(e))
        if MPC_STRICT:
            raise
        else:
            try:
                obs_put_text(out_bucket, out_key, f"placeholder audio para {in_bucket}/{in_key}")
            except Exception:
                pass
            return f"obs://{out_bucket}/{out_key}"

    # Poll hasta que el objeto aparezca en OBS o se cumpla timeout
    started = time.perf_counter()
    last_exists = False
    while True:
        if _obs_object_exists(out_bucket, out_key):
            last_exists = True
            break
        if (time.perf_counter() - started) > MPC_POLL_TIMEOUT_SEC:
            break
        time.sleep(max(0.05, MPC_POLL_INTERVAL_MS / 1000.0))

    url = f"obs://{out_bucket}/{out_key}"
    _log("mpc.audio_only.done", url=url, exists=last_exists)
    if not last_exists:
        if MPC_STRICT:
            raise TimeoutError("Timeout esperando el resultado de MPC (audio MP3 no apareció en OBS a tiempo).")
        else:
            # dejar constancia para facilitar debug
            try:
                obs_put_text(out_bucket, out_key, f"placeholder (timeout esperando MPC) para {in_bucket}/{in_key}")
            except Exception:
                pass
    return url

def _split_sentences_simple(text: str, max_parts: int = 3) -> List[str]:
    text = (text or "").strip()
    if not text:
        return []
    # Dividir por . ! ? (y español) con espacios
    parts = re.split(r'(?<=[\.!\?。！？])\s+', text)
    parts = [p.strip() for p in parts if p.strip()]
    if not parts:
        parts = [text]
    return parts[:max_parts]

def sis_transcribe_from_obs(obs_audio_url: str, language="es-ES") -> Dict[str,Any]:
    """
    Llama a SIS Short-Audio con AK/SK (sin token IAM).
    - Descarga el MP3 desde OBS (URL firmada).
    - Envía base64 en JSON a /v1/{project_id}/asr/short-audio?language=...
    - Genera oraciones y tiempos aproximados.
    """
    _log("sis.transcribe.begin", use_sis=USE_SIS, language=language)
    # Parse OBS URL
    if not obs_audio_url.startswith("obs://"):
        raise RuntimeError("sis_transcribe_from_obs: URL OBS inválida")
    path = obs_audio_url[len("obs://"):]
    bkt, key = path.split("/", 1)

    # Leer bytes del audio (MP3)
    audio_bytes = _obs_read_bytes(bkt, key)
    audio_b64 = base64.b64encode(audio_bytes).decode("utf-8")

    if not USE_SIS:
        # Fallback local de siempre
        demo = [
            {"text":"Bienvenidos al demo.", "start":0.0, "end":2.0},
            {"text":"Aquí mostramos la compra y el reporte.", "start":5.0, "end":10.0},
            {"text":"Exportamos a Excel y finalizamos.", "start":25.0, "end":28.0},
        ]
        out = {"sentences": demo, "duration_sec": 30.0}
        _log("sis.transcribe.done", sentences=len(out["sentences"]), duration_sec=out["duration_sec"])
        return out

    # --- construir payload y firmar / o usar token ---
    sis_endpoint_eff = SIS_ENDPOINT
    if not SIS_TOKEN and "sis-ext." in sis_endpoint_eff:
        # Cuando se usa AK/SK, algunos despliegues requieren el host sin "-ext"
        sis_endpoint_eff = sis_endpoint_eff.replace("sis-ext.", "sis.")
        _log("sis.endpoint.adjust", original=SIS_ENDPOINT, effective=sis_endpoint_eff)

    # Si hay token IAM, usar el esquema de Postman: {"config": {"audio_format","property"}, "data"}
    try:
        if SIS_TOKEN:
            # URL sin query ?language
            url = f"{sis_endpoint_eff}/v1/{SIS_PROJECT_ID}/asr/short-audio"
            # Elegir property
            if SIS_PROPERTY:
                prop = SIS_PROPERTY
            else:
                prop = "english_8k_common" if str(language).lower().startswith("en") else "english_16k_common"
            payload_token = {
                "config": {
                    "audio_format": "mp3",
                    "property": prop,
                },
                "data": audio_b64,
            }
            body_token = json.dumps(payload_token, separators=(",", ":")).encode("utf-8")
            headers = {"Content-Type": "application/json", "X-Auth-Token": SIS_TOKEN}
            t0 = time.perf_counter()
            r = requests.post(url, headers=headers, data=body_token, timeout=180)
            if r.status_code >= 400:
                err_text = r.text if isinstance(r.text, str) else ""
                _log("sis.http.error_body.token", status=r.status_code, text=(err_text[:500] if err_text else None), property=prop)
                # Fallback automático si property inválido (SIS.0032)
                try:
                    err_json = r.json()
                except Exception:
                    err_json = {}
                if str(err_json.get("error_code")) == "SIS.0032" and "property" in str(err_json.get("error_msg", "")):
                    alt_prop = "english_8k_common" if prop != "english_8k_common" else "general_8k"
                    payload_token_alt = {
                        "config": {"audio_format": "mp3", "property": alt_prop},
                        "data": audio_b64,
                    }
                    body_token_alt = json.dumps(payload_token_alt, separators=(",", ":")).encode("utf-8")
                    _log("sis.retry.property_alt", from_property=prop, to_property=alt_prop)
                    r = requests.post(url, headers=headers, data=body_token_alt, timeout=180)
            _log("sis.http.response.token", status=r.status_code, elapsed_ms=_elapsed_ms(t0), property=prop)
            if r.status_code == 401:
                _log("sis.token.unauthorized", hint="Token inválido/expirado")
            r.raise_for_status()
        else:
            url = f"{sis_endpoint_eff}/v1/{SIS_PROJECT_ID}/asr/short-audio?language={language}"
            payload = {
                "audio_format": "mp3",
                "sample_rate": 44100,
                # En SIS short-audio, la clave suele ser 'data' (base64)
                "data": audio_b64
            }
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            # Dos intentos de firma: con y sin x-sdk-content-sha256 (algunos API GW difieren)
            r = _sdk_request("POST", url, body_bytes=body, timeout=180, include_body_hash_header=True)
            if r.status_code == 401:
                _log("sis.retry.alt_signature", reason="401 with body-hash; retrying without hash")
                r = _sdk_request("POST", url, body_bytes=body, timeout=180, include_body_hash_header=False)
            if r.status_code >= 400:
                _log("sis.http.error_body", status=r.status_code, text=(r.text[:500] if isinstance(r.text, str) else None))
            _log("sis.http.response", status=r.status_code)
            r.raise_for_status()
    except requests.exceptions.RequestException as e:
        _log("sis.http.exception", error=str(e))
        if SIS_STRICT:
            raise
        else:
            # Fallback solo si no estricto
            demo = [
                {"text":"(fallback) Bienvenidos al demo.", "start":0.0, "end":2.0},
                {"text":"(fallback) Aquí mostramos la compra y el reporte.", "start":5.0, "end":10.0},
                {"text":"(fallback) Exportamos a Excel y finalizamos.", "start":25.0, "end":28.0},
            ]
            out = {"sentences": demo, "duration_sec": 30.0}
            _log("sis.transcribe.done.fallback", sentences=len(out["sentences"]), duration_sec=out["duration_sec"]) 
            return out

    data = r.json()

    text = (data.get("result") or {}).get("text") or ""
    parts = _split_sentences_simple(text, max_parts=3)

    # Tiempos "aprox": 2s por oración (prototipo). Si luego pasas a Long Audio, reemplazamos por timestamps reales.
    sentences = []
    for i, p in enumerate(parts):
        st = float(i * 2.0)
        en = float(st + max(1.5, min(4.0, max(len(p)/12.0, 2.0))))  # heurística simple 1.5–4.0s
        sentences.append({"text": p, "start": st, "end": en})

    out = {"sentences": sentences, "duration_sec": (sentences[-1]["end"] if sentences else 0.0)}
    _log("sis.transcribe.done", sentences=len(sentences), duration_sec=out["duration_sec"])
    return out

def mpc_snapshots(in_bucket: str, in_key: str, points_hhmmss: List[str],
                  out_bucket: str, out_prefix: str) -> List[str]:
    """
    Captura snapshots reales con MPC en los timestamps indicados.
    - Crea tarea en /v1/{project_id}/thumbnails con tipo DOTS (ms).
    - Usa token (MPC_TOKEN) si está; si no, firma AK/SK.
    - Intenta modo síncrono; si no, hace polling por task_id.
    """
    _log("mpc.snapshots.begin", use_mpc=USE_MPC, points=len(points_hhmmss), out_prefix=out_prefix)

    # Si no hay MPC o falta config mínima, generar placeholders como fallback
    if not USE_MPC or not MPC_PROJECT_ID:
        out = []
        for i, ts in enumerate(points_hhmmss, start=1):
            key = f"{out_prefix}/frame_{i:02d}_{ts.replace(':','-').replace('.','-')}.jpg"
            try:
                obs_put_text(out_bucket, key, f"placeholder frame @ {ts} para {in_key}")
            except Exception as e:
                _log("mpc.snapshots.warn", error=str(e))
            out.append(f"obs://{out_bucket}/{key}")
        _log("mpc.snapshots.done", frames=len(out), mode="placeholder")
        return out

    # Convertir HH:MM:SS.mmm -> milisegundos
    def _hhmmss_ms_to_ms(s: str) -> int:
        try:
            hh, mm, rest = s.split(":")
            ss, ms = rest.split(".")
            return (int(hh)*3600 + int(mm)*60 + int(ss)) * 1000 + int(ms)
        except Exception:
            try:
                # fallback simple 00:00:SS
                hh, mm, ss = s.split(":")
                return (int(hh)*3600 + int(mm)*60 + int(float(ss))) * 1000
            except Exception:
                return 1000

    dots_ms = [_hhmmss_ms_to_ms(ts) for ts in points_hhmmss]
    endpoint = MPC_ENDPOINT.rstrip("/")
    url = f"{endpoint}/v1/{MPC_PROJECT_ID}/thumbnails"

    body = {
        "input": {"bucket": in_bucket, "location": OBS_REGION, "object": in_key},
        "output": {"bucket": out_bucket, "location": OBS_REGION, "object": out_prefix},
        # tar=1 según ejemplos oficiales; no es obligatorio pero lo incluimos
        "tar": 1,
        "thumbnail_para": {
            "type": "DOTS",
            "dots": dots_ms,
            "format": 1,  # 1 = JPG
            # No fijamos width/height para mantener resolución por defecto
            "output_filename": "frame"
        },
        "sync": 1,
    }

    try:
        # Crear tarea (intento token, luego firma)
        if MPC_TOKEN:
            headers = {"Content-Type": "application/json", "X-Auth-Token": MPC_TOKEN, "X-Project-Id": MPC_PROJECT_ID}
            t0 = time.perf_counter()
            r = requests.post(url, headers=headers, json=body, timeout=60)
            _log("mpc.thumbs.create.http.token", status=r.status_code, elapsed_ms=_elapsed_ms(t0))
        else:
            r = _sdk_request("POST", url, body_json=body, timeout=60)

        # Si 400, intentar variantes (quitar tar o sync)
        if r.status_code >= 400:
            _log("mpc.thumbs.create.error", status=r.status_code, text=(r.text[:500] if isinstance(r.text, str) else None))
            # Variante 1: sin tar
            body_v1 = dict(body)
            body_v1.pop("tar", None)
            if MPC_TOKEN:
                r = requests.post(url, headers=headers, json=body_v1, timeout=60)
            else:
                r = _sdk_request("POST", url, body_json=body_v1, timeout=60)
        if r.status_code >= 400:
            # Variante 2: async
            body_v2 = dict(body)
            body_v2["sync"] = 0
            if MPC_TOKEN:
                r = requests.post(url, headers=headers, json=body_v2, timeout=60)
            else:
                r = _sdk_request("POST", url, body_json=body_v2, timeout=60)
        if r.status_code >= 400:
            raise RuntimeError(f"MPC thumbnails create failed: {r.status_code} {r.text[:500] if isinstance(r.text, str) else ''}")

        resp = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        # Caso sync terminado devuelve nombres directamente
        pics: List[str] = []
        base_output_object: str = out_prefix
        if resp.get("status") in ("FINISHED", "SUCCEEDED") and isinstance(resp.get("output"), dict):
            info = resp.get("output", {}).get("thumbnail_info") or []
            base_output_object = resp.get("output", {}).get("object") or base_output_object
            for it in info:
                name = it.get("pic_name")
                if name:
                    pics.append(name)
        task_id = resp.get("task_id")
        _log("mpc.thumbs.create.ok", task_id=task_id, pics=len(pics), base_object=base_output_object)

        # Si no hay pics aún, poll por task_id
        if not pics and task_id:
            poll_url = f"{endpoint}/v1/{MPC_PROJECT_ID}/thumbnails?task_id={task_id}"
            started = time.perf_counter()
            while True:
                if MPC_TOKEN:
                    rr = requests.get(poll_url, headers=headers, timeout=30)
                else:
                    rr = _sdk_request("GET", poll_url, body_json={}, timeout=30)
                if rr.status_code >= 400:
                    _log("mpc.thumbs.poll.error", status=rr.status_code, text=(rr.text[:300] if isinstance(rr.text, str) else None))
                    break
                data = rr.json() if rr.headers.get("content-type", "").startswith("application/json") else {}
                arr = data.get("task_array") or []
                status = None
                output = None
                if arr:
                    status = arr[0].get("status")
                    output = arr[0].get("output")
                if status in ("SUCCEEDED", "FINISHED") and isinstance(output, dict):
                    base_output_object = output.get("object") or base_output_object
                    info = arr[0].get("thumbnail_info") or output.get("thumbnail_info") or []
                    for it in info:
                        name = it.get("pic_name")
                        if name:
                            pics.append(name)
                    break
                if (time.perf_counter() - started) > max(60, MPC_POLL_TIMEOUT_SEC):
                    _log("mpc.thumbs.poll.timeout", task_id=task_id)
                    break
                time.sleep(max(0.1, MPC_POLL_INTERVAL_MS/1000.0))

        # Construir rutas OBS de salida
        out_urls: List[str] = []
        if pics:
            for name in pics:
                # MPC puede crear subcarpeta UUID bajo output.object
                base_dir = base_output_object.rstrip("/") if base_output_object else out_prefix
                key = f"{base_dir}/{name}"
                out_urls.append(f"obs://{out_bucket}/{key}")
            _log("mpc.snapshots.done", frames=len(out_urls), base_object=base_output_object)
            return out_urls

        # Fallback si no pudimos obtener lista de nombres (esquema distinto)
        # Generamos nombres por índice
        out_urls_fallback: List[str] = []
        for i, ts in enumerate(points_hhmmss, start=1):
            base_dir = base_output_object.rstrip("/") if base_output_object else out_prefix
            key = f"{base_dir}/frame_{i:02d}_{ts.replace(':','-').replace('.','-')}.jpg"
            out_urls_fallback.append(f"obs://{out_bucket}/{key}")
        _log("mpc.snapshots.done.fallback_names", frames=len(out_urls_fallback), base_object=base_output_object)
        return out_urls_fallback

    except Exception as e:
        _log("mpc.snapshots.exception", error=str(e))
        # último recurso: placeholders
        out = []
        for i, ts in enumerate(points_hhmmss, start=1):
            key = f"{out_prefix}/frame_{i:02d}_{ts.replace(':','-').replace('.','-')}.jpg"
            try:
                obs_put_text(out_bucket, key, f"placeholder frame @ {ts} para {in_key}")
            except Exception:
                pass
            out.append(f"obs://{out_bucket}/{key}")
        _log("mpc.snapshots.done", frames=len(out), mode="placeholder_on_error")
    return out

def build_srt(sentences: List[Dict[str,Any]]) -> str:
    def H(t):
        h = int(t // 3600); m = int((t % 3600)//60); s = int(t % 60); ms = int((t*1000)%1000)
        return f"{h:02d}:{m:02d}:{s:02d},{ms:03d}"
    lines = []
    for i, s in enumerate(sentences, 1):
        lines += [str(i), f"{H(float(s['start']))} --> {H(float(s['end']))}", s["text"].strip(), ""]
    return "\n".join(lines)

# ====== Orquestación principal ======
def process_upload_doc(upload_doc: Dict[str,Any],
                       *,
                       top_k=8,
                       frame_where="mid",
                       frame_limit=12,
                       make_srt=True,
                       language="es",
                       objective: str | None = None,
                       tone: str | None = None,
                       slides_number: str | None = None) -> Dict[str,Any]:
    _log("pipeline.begin", upload_id=str(upload_doc.get("_id")), key=upload_doc.get("key"),
         top_k=top_k, frame_where=frame_where, frame_limit=frame_limit, make_srt=make_srt, language=language,
         obs_region=OBS_REGION, obs_endpoint=OBS_ENDPOINT, use_mpc=USE_MPC, use_sis=USE_SIS,
         llm_url=COMP_LLM_URL, llm_model=COMP_LLM_MODEL)

    in_key = upload_doc["key"]
    in_bucket = OBS_BUCKET_UPLOADS

    # 1) Audio-only
    upload_id = str(upload_doc["_id"])
    audio_key = f"audio/{upload_id}.mp3"
    t1 = time.perf_counter()
    audio_obs_url = mpc_audio_only(in_bucket, in_key, OBS_BUCKET_ARTIFACTS, audio_key)
    _log("pipeline.step.audio_only", elapsed_ms=_elapsed_ms(t1), audio_key=audio_key)

    # 2) ASR (SIS short-audio o fallback)
    t2 = time.perf_counter()
    asr = sis_transcribe_from_obs(audio_obs_url, language="es-ES" if language.startswith("es") else "en-US")
    sentences = asr.get("sentences", [])
    _log("pipeline.step.asr", elapsed_ms=_elapsed_ms(t2), sentences=len(sentences), duration_sec=asr.get("duration_sec"))
    if not sentences:
        raise RuntimeError("Sin voz detectada")

    # 3) LLM con fallback (si vacío)
    llm_source = "modelarts"; picks: List[Dict[str,Any]] = []
    t3 = time.perf_counter()
    try:
        picks = deepseek_highlights(sentences, top_k=top_k, language=language)[:frame_limit]
    except Exception as e:
        _log("llm.error", error=str(e))
        llm_source = "fallback"

    if not picks:
        picks = fallback_highlights(sentences, top_k=min(top_k, 8))[:frame_limit]
        llm_source = "fallback"
    _log("pipeline.step.llm", elapsed_ms=_elapsed_ms(t3), source=llm_source, picks=len(picks))

    # 4) timestamps -> puntos
    def ts_of(p):
        st, en = float(p["start_sec"]), float(p["end_sec"])
        if frame_where == "start": return max(st, 0.0)
        if frame_where == "end":   return max(en, 0.0)
        return max((st+en)/2.0, 0.0)

    time_points = [_fmt_hhmmss_ms(ts_of(p)) for p in picks] if picks else ["00:00:01.000"]
    _log("pipeline.step.points", points=time_points)

    # 5) Snapshots
    frames_prefix = f"frames/{upload_id}"
    t4 = time.perf_counter()
    frames = mpc_snapshots(in_bucket, in_key, time_points, OBS_BUCKET_ARTIFACTS, frames_prefix)
    _log("pipeline.step.snapshots", elapsed_ms=_elapsed_ms(t4), frames=len(frames))

    # 6) SRT
    srt_key = None
    if make_srt:
        srt_key = f"srt/{upload_id}.srt"
        t5 = time.perf_counter()
        obs_put_text(OBS_BUCKET_ARTIFACTS, srt_key, build_srt(sentences))
        _log("pipeline.step.srt", elapsed_ms=_elapsed_ms(t5), srt_key=srt_key)

    # 7) Guardar JSONs de debug
    try:
        obs_put_json(OBS_BUCKET_ARTIFACTS, f"transcript/{upload_id}.json",
                     {"sentences": sentences, "duration_sec": asr.get("duration_sec")})
        obs_put_json(OBS_BUCKET_ARTIFACTS, f"highlights/{upload_id}.json",
                     {"source": llm_source, "highlights": picks})
    except Exception as e:
        _log("pipeline.step.save_debug.warn", error=str(e))

    # 8) URLs firmadas para abrir
    try:
        input_video_url = obs_signed_get(in_bucket, in_key)
    except Exception:
        input_video_url = None
    try:
        audio_url = obs_signed_get(OBS_BUCKET_ARTIFACTS, audio_key)
    except Exception:
        audio_url = None
    try:
        srt_url = obs_signed_get(OBS_BUCKET_ARTIFACTS, srt_key) if srt_key else None
    except Exception:
        srt_url = None

    frame_urls = []
    for f in frames:
        try:
            if f.startswith("obs://"):
                path = f[len("obs://"):]
                b, k = path.split("/", 1)
                frame_urls.append(obs_signed_get(b, k))
            else:
                frame_urls.append(obs_signed_get(OBS_BUCKET_ARTIFACTS, f))
        except Exception:
            frame_urls.append(None)

    # 9) Pitch deck via LLM (summary, highlights, slides, script)
    pitch_deck: Dict[str, Any] | None = None
    try:
        def _build_pitch_prompt(obj: str | None, tone_in: str | None, slides_in: str | None,
                                sentences_in: List[Dict[str,Any]], picks_in: List[Dict[str,Any]], lang: str) -> str:
            goal = (obj or "Presentación para inversores").strip()
            tone_txt = (tone_in or "ejecutivo").strip()
            slides_txt = (slides_in or "6-8").strip()
            sentences_clean = [{"start": s.get("start"), "end": s.get("end"), "text": (s.get("text", "") or "")[:200]} for s in sentences_in[:50]]
            picks_clean = [{"i": p.get("i"), "label": p.get("label", ""), "summary": p.get("summary", ""),
                            "start_sec": p.get("start_sec"), "end_sec": p.get("end_sec")} for p in picks_in[:20]]
            schema = {
                "summary": "",
                "highlights": [{"label": "", "summary": ""}],
                "slides": [{"title": "", "bullets": [""]}],
                "script": [{"slide": 1, "what_to_say": ""}]
            }
            schema_json = json.dumps(schema, ensure_ascii=False)
            return (
                "Eres un asistente que genera pitch decks. "
                + f"Objetivo: {goal}. Tono: {tone_txt}. Slides: {slides_txt}. "
                + f"Idioma: {lang}. Devuelve SOLO JSON con el esquema: {schema_json}. "
                + "Limita el total de slides al rango/valor indicado y usa los highlights y la transcripción como base. "
                + f"Transcripción (fragmentos): {json.dumps(sentences_clean, ensure_ascii=False)}. "
                + f"Highlights detectados: {json.dumps(picks_clean, ensure_ascii=False)}."
            )

        prompt_pitch = _build_pitch_prompt(objective, tone, slides_number, sentences, picks, language)
        headers_primary = {"Content-Type": "application/json", "X-Auth-Token": COMP_LLM_TOKEN}
        headers_bearer  = {"Content-Type": "application/json", "Authorization": f"Bearer {COMP_LLM_TOKEN}"}
        body_pitch = {
            "model": COMP_LLM_MODEL,
            "messages": [
                {"role": "system", "content": "Devuelves SOLO JSON válido y conciso."},
                {"role": "user", "content": prompt_pitch}
            ],
            "temperature": COMP_LLM_TEMPERATURE,
            "max_tokens": max(2000, COMP_LLM_MAX_TOKENS)
        }
        for attempt, headers in enumerate((headers_primary, headers_bearer), start=1):
            t_req = time.perf_counter()
            rpd = requests.post(COMP_LLM_URL, headers=headers, json=body_pitch, timeout=120)
            _log("llm.pitch.request.response", attempt=attempt, status=rpd.status_code, elapsed_ms=_elapsed_ms(t_req))
            if rpd.status_code == 401:
                continue
            rpd.raise_for_status()
            raw = rpd.json()["choices"][0]["message"]["content"]
            try:
                pitch_deck = json.loads(raw)
            except Exception:
                m = re.search(r"\{[\s\S]*\}", raw)
                pitch_deck = json.loads(m.group(0)) if m else None
            break
    except Exception as e:
        _log("llm.pitch.error", error=str(e))
    # Fallback si el LLM no devolvió nada o dio formato inválido
    if not pitch_deck:
        def _parse_slides_number(val: str | None, available: int) -> int:
            try:
                if not val:
                    return max(1, min(available, 8))
                s = str(val).strip()
                if "-" in s:
                    a, b = s.split("-", 1)
                    lo, hi = int(a), int(b)
                    if hi < lo:
                        lo, hi = hi, lo
                    return max(1, min(available, hi))
                n = int(s)
                return max(1, min(available, n))
            except Exception:
                return max(1, min(available, 8))

        slides_count = _parse_slides_number(slides_number, len(picks) if picks else 1)
        slides: List[Dict[str, Any]] = []
        script: List[Dict[str, Any]] = []
        for i, p in enumerate((picks or [])[:slides_count], start=1):
            title = (p.get("label") or f"Slide {i}")[:80]
            bullet = (p.get("summary") or p.get("reason") or "").strip()
            if not bullet:
                bullet = (sentences[min(int(p.get("i", 0)), len(sentences)-1)].get("text") if sentences else "") or "Punto destacado"
            image_url = frame_urls[i-1] if i-1 < len(frame_urls) else None
            slides.append({"title": title, "bullets": [bullet], "image": image_url})
            script.append({"slide": i, "what_to_say": bullet})
        # summary básico desde primeras oraciones
        base_summary = " ".join([(s.get("text") or "") for s in sentences[:3]]).strip()[:400]
        pitch_deck = {
            "summary": base_summary or "Resumen generado automáticamente del video",
            "highlights": [{"label": (p.get("label") or "Momento"), "summary": (p.get("summary") or "")} for p in (picks or [])],
            "slides": slides,
            "script": script,
        }
        _log("llm.pitch.fallback", slides=len(slides))

    result = {
        "input_video": f"obs://{in_bucket}/{in_key}",
        "audio": audio_obs_url,
        "frames": frames,
        "frames_prefix": frames_prefix,
        "srt_key": srt_key,
        "transcript": {"sentences": sentences, "duration_sec": asr.get("duration_sec")},
        "highlights": picks,
        "llm_source": llm_source,
        "input_video_url": input_video_url,
        "audio_url": audio_url,
        "frame_urls": frame_urls,
        "srt_url": srt_url,
        "pitch_deck": pitch_deck,
        "created_at": _iso_now(),
        "updated_at": _iso_now(),
    }
    _log("pipeline.done", frames=len(frames), has_srt=bool(srt_key), sentences=len(sentences), picks=len(picks))
    return result
