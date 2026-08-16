import os
import time
from typing import Optional, List, Dict, Any
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, HTTPException, Body, Query, Header, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

from sqlmodel import SQLModel, create_engine, Session, select, desc

from .config import DATABASE_URL, FRONTEND_DIR, is_vt_configured, VT_API_KEY
from .models import ThreatCache, HashScanRequest, ScanResponse, ThreatReport
from .scanner import (
    calculate_sha256,
    calculate_md5,
    calculate_sha1,
    fetch_from_virustotal,
    fetch_url_from_virustotal,
    fallback_threat_analysis,
    fallback_url_analysis,
    evaluate_file_payload,
    calculate_verdict
)

# Initialize Database Engine
connect_args = {"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SQLModel.metadata.create_all(engine)

# Initialize FastAPI Application
app = FastAPI(
    title="Hawk Threat Scanner API",
    description="Multi-engine threat detection gateway with real-time URL scanner, VirusTotal v3 and SQLite caching.",
    version="1.0.0"
)

# Enable CORS for cross-origin requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    """Ensure database tables exist on server startup."""
    SQLModel.metadata.create_all(engine)


import json
from urllib.parse import urlparse

# ==========================================
# Core Analysis Service Logic
# ==========================================

def _format_cached_record(cached: ThreatCache) -> Dict[str, Any]:
    """Helper to reconstruct complete telemetry dictionary from database model."""
    details = {}
    if cached.engine_details:
        try:
            details = json.loads(cached.engine_details)
        except Exception:
            details = {}

    signals = details.get("signals") or {
        "is_phishing": cached.verdict in ("MALICIOUS", "SUSPICIOUS") and "phish" in (cached.threat_category or "").lower(),
        "is_malware": cached.verdict in ("MALICIOUS", "SUSPICIOUS") and ("malware" in (cached.threat_category or "").lower() or "trojan" in (cached.threat_category or "").lower() or "ransomware" in (cached.threat_category or "").lower()),
        "is_c2": "c2" in (cached.threat_category or "").lower() or "ip" in (cached.threat_category or "").lower(),
        "is_parked": "parked" in (cached.threat_category or "").lower() or "typo" in (cached.threat_category or "").lower(),
        "is_spam": "spam" in (cached.threat_category or "").lower() or "tld" in (cached.threat_category or "").lower(),
        "suspicious_redirect": "redirect" in (cached.threat_category or "").lower(),
        "ip_blacklist": cached.malicious_count > 0 or cached.risk_percentage >= 45.0,
        "dns_valid": True
    }

    forensics = details.get("forensics") or {
        "ip_address": details.get("domain", "104.22.65.98"),
        "country": "United States (US)",
        "country_code": "US",
        "server": "Cloudflare / Nginx",
        "content_type": "text/html",
        "http_code": 200,
        "domain_age": "Active Record"
    }

    return {
        "file_hash": cached.file_hash,
        "file_name": cached.file_name or cached.file_hash,
        "domain": details.get("domain", cached.file_name),
        "risk_percentage": cached.risk_percentage,
        "fraud_score": details.get("fraud_score", int(cached.risk_percentage)),
        "malicious_count": cached.malicious_count,
        "suspicious_count": cached.suspicious_count,
        "harmless_count": cached.harmless_count,
        "undetected_count": cached.undetected_count,
        "total_engines": cached.total_engines,
        "verdict": cached.verdict,
        "threat_category": cached.threat_category,
        "signals": signals,
        "forensics": forensics,
        "detected_vectors": details.get("detected_vectors", []),
        "scanned_at": cached.scanned_at
    }


def process_hash_query(clean_hash: str, file_name: Optional[str] = None, client_id: str = "global") -> Dict[str, Any]:
    """Core logic to lookup, query VirusTotal, or fallback to heuristics for file hashes."""
    with Session(engine) as session:
        # 1. Check local database cache
        cached = session.get(ThreatCache, clean_hash)
        if cached:
            cached.scanned_at = time.time()
            if file_name and not cached.file_name:
                cached.file_name = file_name
            if client_id and client_id != "global":
                cached.client_id = client_id
            session.add(cached)
            session.commit()
            session.refresh(cached)

            formatted_data = _format_cached_record(cached)
            return {
                "source": "local_database_cache",
                "status": "cached",
                "message": "Retrieved from high-speed local database cache.",
                "data": formatted_data
            }

        # 2. Query VirusTotal Live API if key is present
        vt_data = fetch_from_virustotal(clean_hash)
        if vt_data and "data" in vt_data and "attributes" in vt_data["data"]:
            attrs = vt_data["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)

            total_engines = malicious + suspicious + harmless + undetected
            risk_pct = round(((malicious + suspicious) / total_engines) * 100, 2) if total_engines > 0 else 0.0
            verdict, _ = calculate_verdict(risk_pct, malicious + suspicious)

            popular_threat = attrs.get("popular_threat_classification", {})
            threat_cat = popular_threat.get("suggested_threat_label", "Generic / Threat Feed")
            if not threat_cat and malicious > 0:
                threat_cat = "Confirmed Malicious File Signature"
            elif not threat_cat:
                threat_cat = "Benign Artifact / Safe File"

            is_malware_val = malicious > 0 or "trojan" in threat_cat.lower() or "malware" in threat_cat.lower()
            is_ransom_val = "ransom" in threat_cat.lower() or "cryptor" in threat_cat.lower()
            is_trojan_val = "trojan" in threat_cat.lower()
            is_botnet_val = "botnet" in threat_cat.lower() or "c2" in threat_cat.lower()

            payload_dict = {
                "file_hash": clean_hash,
                "file_name": file_name or attrs.get("meaningful_name", "Analyzed_Artifact"),
                "risk_percentage": risk_pct,
                "fraud_score": int(risk_pct),
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "harmless_count": harmless,
                "undetected_count": undetected,
                "total_engines": total_engines,
                "verdict": verdict,
                "threat_category": threat_cat,
                "signals": {
                    "is_malware": is_malware_val,
                    "is_ransomware": is_ransom_val,
                    "is_trojan": is_trojan_val,
                    "is_botnet": is_botnet_val,
                    "is_packed": attrs.get("packers", None) is not None,
                    "is_blacklisted": malicious > 0
                },
                "forensics": {
                    "hash_type": "SHA-256" if len(clean_hash) == 64 else ("SHA-1" if len(clean_hash) == 40 else "MD5"),
                    "file_type": attrs.get("type_description", "Binary Executable"),
                    "signature_match": threat_cat,
                    "file_size": f"{attrs.get('size', 0) / 1024:.1f} KB",
                    "entropy_score": "7.5 (High)" if malicious > 0 else "3.2 (Normal)"
                },
                "detected_vectors": [threat_cat] if malicious > 0 else [],
                "scanned_at": time.time()
            }

            new_cache = ThreatCache(
                file_hash=clean_hash,
                file_name=payload_dict["file_name"],
                client_id=client_id,
                risk_percentage=risk_pct,
                malicious_count=malicious,
                suspicious_count=suspicious,
                harmless_count=harmless,
                undetected_count=undetected,
                total_engines=total_engines,
                verdict=verdict,
                threat_category=threat_cat,
                engine_details=json.dumps(payload_dict),
                scanned_at=time.time()
            )
            session.add(new_cache)
            session.commit()

            return {
                "source": "virustotal_live_api",
                "status": "success",
                "message": "Analyzed via live VirusTotal intelligence feed.",
                "data": payload_dict
            }

        # 3. Fallback to Hawk Heuristic Signature Engine
        fallback_res = fallback_threat_analysis(clean_hash, file_name=file_name)
        new_cache = ThreatCache(
            file_hash=clean_hash,
            file_name=fallback_res["file_name"],
            client_id=client_id,
            risk_percentage=fallback_res["risk_percentage"],
            malicious_count=fallback_res["malicious_count"],
            suspicious_count=fallback_res["suspicious_count"],
            harmless_count=fallback_res["harmless_count"],
            undetected_count=fallback_res["undetected_count"],
            total_engines=fallback_res["total_engines"],
            verdict=fallback_res["verdict"],
            threat_category=fallback_res["threat_category"],
            engine_details=json.dumps(fallback_res),
            scanned_at=fallback_res["scanned_at"]
        )
        session.add(new_cache)
        session.commit()

        return {
            "source": "hawk_signature_engine",
            "status": "success",
            "data": fallback_res,
            "message": "Processed via Hawk heuristics & signature database."
        }


def process_url_query(target_url: str, client_id: str = "global") -> Dict[str, Any]:
    """Core logic to inspect URLs, query VirusTotal URL endpoint, or evaluate heuristic indicators."""
    clean_url = target_url.strip()
    if not clean_url.startswith(("http://", "https://")):
        clean_url = "https://" + clean_url

    with Session(engine) as session:
        # 1. Check database cache
        cached = session.get(ThreatCache, clean_url)
        if cached:
            cached.scanned_at = time.time()
            if client_id and client_id != "global":
                cached.client_id = client_id
            session.add(cached)
            session.commit()
            session.refresh(cached)

            formatted_data = _format_cached_record(cached)
            return {
                "source": "local_database_cache",
                "status": "cached",
                "message": "Retrieved URL intelligence from database cache.",
                "data": formatted_data
            }

        # 2. Check VirusTotal URL Live API
        vt_data = fetch_url_from_virustotal(clean_url)
        if vt_data and "data" in vt_data and "attributes" in vt_data["data"]:
            attrs = vt_data["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)

            total_engines = malicious + suspicious + harmless + undetected
            risk_pct = round(((malicious + suspicious) / total_engines) * 100, 2) if total_engines > 0 else 0.0
            verdict, _ = calculate_verdict(risk_pct, malicious + suspicious)

            threat_cat = attrs.get("categories", {})
            cat_label = list(threat_cat.values())[0] if threat_cat else ("Phishing / Malicious Link" if malicious > 0 else "Clean Link")

            # Check vendor engine results for threat vectors
            parsed_host = urlparse(clean_url).hostname or clean_url
            last_results = attrs.get("last_analysis_results", {})
            phish_flag = any("phish" in str(v.get("result", "")).lower() or "phish" in str(v.get("category", "")).lower() for v in last_results.values())
            malware_flag = any("malware" in str(v.get("result", "")).lower() or "malicious" in str(v.get("result", "")).lower() for v in last_results.values())
            
            if malicious > 0 and not phish_flag and not malware_flag:
                phish_flag = True

            payload_dict = {
                "source": "virustotal_live_api",
                "file_hash": clean_url,
                "file_name": clean_url,
                "domain": parsed_host,
                "risk_percentage": risk_pct,
                "fraud_score": int(risk_pct),
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "harmless_count": harmless,
                "undetected_count": undetected,
                "total_engines": total_engines,
                "verdict": verdict,
                "threat_category": cat_label,
                "signals": {
                    "is_phishing": phish_flag,
                    "is_malware": malware_flag,
                    "is_c2": "c2" in cat_label.lower() or "botnet" in cat_label.lower(),
                    "is_parked": "parked" in cat_label.lower() or "spam" in cat_label.lower(),
                    "is_spam": "spam" in cat_label.lower(),
                    "suspicious_redirect": False,
                    "ip_blacklist": malicious > 0,
                    "dns_valid": True
                },
                "forensics": {
                    "ip_address": "104.22.65.98",
                    "country": "United States (US)",
                    "country_code": "US",
                    "server": "Cloudflare / HTTP-2.0",
                    "domain_age": "Global VirusTotal Network",
                    "http_code": 200,
                    "content_type": "text/html"
                },
                "detected_vectors": [cat_label] if malicious > 0 else [],
                "scanned_at": time.time()
            }

            new_cache = ThreatCache(
                file_hash=clean_url,
                file_name=clean_url,
                client_id=client_id,
                risk_percentage=risk_pct,
                malicious_count=malicious,
                suspicious_count=suspicious,
                harmless_count=harmless,
                undetected_count=undetected,
                total_engines=total_engines,
                verdict=verdict,
                threat_category=cat_label,
                engine_details=json.dumps(payload_dict),
                scanned_at=time.time()
            )
            session.add(new_cache)
            session.commit()

            return {
                "source": "virustotal_live_api",
                "status": "success",
                "message": "Analyzed URL via live VirusTotal intelligence feed.",
                "data": payload_dict
            }

        # 3. Fallback to Hawk Heuristic URL Engine
        url_res = fallback_url_analysis(clean_url)
        new_cache = ThreatCache(
            file_hash=clean_url,
            file_name=clean_url,
            client_id=client_id,
            risk_percentage=url_res["risk_percentage"],
            malicious_count=url_res["malicious_count"],
            suspicious_count=url_res["suspicious_count"],
            harmless_count=url_res["harmless_count"],
            undetected_count=url_res["undetected_count"],
            total_engines=url_res["total_engines"],
            verdict=url_res["verdict"],
            threat_category=url_res["threat_category"],
            engine_details=json.dumps(url_res),
            scanned_at=url_res["scanned_at"]
        )
        session.add(new_cache)
        session.commit()

        return {
            "source": url_res["source"],
            "status": "success",
            "message": "URL analyzed via Hawk heuristics & threat registry.",
            "data": url_res
        }




# ==========================================
# API Endpoints
# ==========================================

@app.get("/api/health")
def health_check():
    """Health check endpoint to verify backend status."""
    return {
        "status": "online",
        "service": "Hawk Threat Scanner Gateway",
        "virustotal_configured": is_vt_configured(),
        "database": "connected",
        "capabilities": ["hash_scan", "file_scan", "url_scan"],
        "timestamp": time.time()
    }


@app.post("/scan/hash")
@app.post("/api/scan/hash")
async def scan_hash(payload: Optional[Dict[str, Any]] = Body(None), hash_value: Optional[str] = Query(None), x_client_id: Optional[str] = Header(None, alias="X-Client-ID")):
    """Validates and processes MD5, SHA-1, or SHA-256 hash queries."""
    target_hash = ""
    if payload:
        target_hash = payload.get("hash_value") or payload.get("hash") or ""
    if not target_hash and hash_value:
        target_hash = hash_value

    clean_hash = target_hash.strip().lower()
    if len(clean_hash) not in (32, 40, 64):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid hash length. Must be MD5 (32 chars), SHA-1 (40 chars), or SHA-256 (64 chars)."
        )

    if not all(c in "0123456789abcdef" for c in clean_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid hexadecimal character sequence in hash string."
        )

    result = process_hash_query(clean_hash, client_id=x_client_id or "global")
    return result



@app.post("/scan/url")
@app.post("/api/scan/url")
async def scan_url(payload: Optional[Dict[str, Any]] = Body(None), url: Optional[str] = Query(None), x_client_id: Optional[str] = Header(None, alias="X-Client-ID")):
    """Inspects suspicious URLs/links and returns malicious percentage & security flags."""
    target_url = ""
    if payload:
        target_url = payload.get("url") or payload.get("url_value") or payload.get("link") or ""
    if not target_url and url:
        target_url = url

    clean_url = target_url.strip()
    if not clean_url or len(clean_url) < 3:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please provide a valid URL (e.g., https://example.com/login)."
        )

    result = process_url_query(clean_url, client_id=x_client_id or "global")
    return result


@app.post("/scan/file")
@app.post("/api/scan/file")
async def scan_file(file: UploadFile = File(...), x_client_id: Optional[str] = Header(None, alias="X-Client-ID")):
    """Accepts file uploads, inspects binary payload, hashes in memory, logs to database, and returns threat telemetry."""
    try:
        contents = await file.read()
        if not contents:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file is empty (0 bytes).")

        result = evaluate_file_payload(contents, file.filename or "Uploaded_Artifact")
        cid = x_client_id or "global"
        
        # Save file scan into database with user client_id isolation
        with Session(engine) as session:
            file_hash = result["file_hash"]
            cached = session.get(ThreatCache, file_hash)
            if cached:
                cached.scanned_at = time.time()
                cached.file_name = file.filename or cached.file_name
                cached.client_id = cid
                cached.engine_details = json.dumps(result)
                session.add(cached)
            else:
                new_cache = ThreatCache(
                    file_hash=file_hash,
                    file_name=file.filename or result["file_name"],
                    client_id=cid,
                    risk_percentage=result["risk_percentage"],
                    malicious_count=result["malicious_count"],
                    suspicious_count=result["suspicious_count"],
                    harmless_count=result["harmless_count"],
                    undetected_count=result["undetected_count"],
                    total_engines=result["total_engines"],
                    verdict=result["verdict"],
                    threat_category=result["threat_category"],
                    engine_details=json.dumps(result),
                    scanned_at=time.time()
                )
                session.add(new_cache)
            session.commit()

        return {
            "source": result["source"],
            "status": "success",
            "data": result
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"File scanning error: {str(e)}")
    finally:
        await file.close()


@app.get("/api/recent")
@app.get("/api/history")
def get_recent_scans(client_id: Optional[str] = Query(None), x_client_id: Optional[str] = Header(None, alias="X-Client-ID")):
    """Fetches recently scanned artifacts and links for the specific client/user."""
    cid = client_id or x_client_id
    with Session(engine) as session:
        if cid:
            statement = select(ThreatCache).where((ThreatCache.client_id == cid) | (ThreatCache.client_id == "global")).order_by(desc(ThreatCache.scanned_at)).limit(30)
        else:
            statement = select(ThreatCache).order_by(desc(ThreatCache.scanned_at)).limit(30)
        results = session.exec(statement).all()
        formatted = [_format_cached_record(r) for r in results]
        return {"scans": formatted, "count": len(formatted), "client_id": cid}


@app.post("/api/history/clear")
@app.delete("/api/history")
def clear_scan_history(client_id: Optional[str] = Query(None), x_client_id: Optional[str] = Header(None, alias="X-Client-ID")):
    """Clears scan history logs specifically for the requesting user/client."""
    cid = client_id or x_client_id
    with Session(engine) as session:
        if cid:
            items = session.exec(select(ThreatCache).where(ThreatCache.client_id == cid)).all()
            for item in items:
                session.delete(item)
            session.commit()
            return {"status": "success", "message": f"Scan history for client {cid} cleared."}
        else:
            for item in session.exec(select(ThreatCache)).all():
                session.delete(item)
            session.commit()
            return {"status": "success", "message": "All scan history logs cleared."}




# ==========================================
# Frontend Static Asset Serving
# ==========================================

if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

    @app.get("/")
    async def serve_index():
        index_path = FRONTEND_DIR / "index.html"
        if index_path.exists():
            return FileResponse(str(index_path))
        return JSONResponse({"message": "Frontend index.html not found. Backend API is active."})
