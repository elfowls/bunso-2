# app.py
from typing import List, Optional, Literal
from fastapi import FastAPI, UploadFile, File, HTTPException, Body
from pydantic import BaseModel, EmailStr, Field, ConfigDict
import ssl, time, random, smtplib, hashlib, dns.resolver, csv, io, os
from email.utils import parseaddr

APP_NAME = "email-verifier"
VERSION = "1.0.1"

# -------- Tunables / Env --------
DEFAULT_REPEATS = int(os.getenv("REPEATS", "1"))  # 1 = fastest; 2-3 = steadier
JITTER_MIN = float(os.getenv("JITTER_MIN", "0.03"))
JITTER_MAX = float(os.getenv("JITTER_MAX", "0.08"))
GOOGLE_THRESHOLD = float(os.getenv("GOOGLE_THRESHOLD_MS", "60"))
DEFAULT_THRESHOLD = float(os.getenv("DEFAULT_THRESHOLD_MS", "80"))
DNS_TIMEOUT = float(os.getenv("DNS_TIMEOUT", "1.2"))
SMTP_TIMEOUT = float(os.getenv("SMTP_TIMEOUT", "10"))
MAX_BULK = int(os.getenv("MAX_BULK", "1000"))

app = FastAPI(title=APP_NAME, version=VERSION)

# -------- Models --------
class VerifyResponse(BaseModel):
    email: str
    domain: Optional[str] = None
    mx_host: Optional[str] = None
    mx_brand: Optional[str] = None
    result: Literal["valid", "invalid"]
    catch_all: bool = Field(..., serialization_alias="catch-all")  # <- alias for output key
    deliverability: Literal["deliverable", "undeliverable"]

    # Ensure FastAPI can populate by field name, but serialize using alias by default
    model_config = ConfigDict(populate_by_name=True)

class BulkRequest(BaseModel):
    emails: List[EmailStr]
    repeats: Optional[int] = None

# -------- Helpers --------
def get_domain(email: str) -> str:
    _, addr = parseaddr(email)
    if '@' not in addr:
        raise ValueError("Invalid email")
    return addr.split('@', 1)[1].lower().strip()

def impossible_addr(domain: str) -> str:
    token = hashlib.md5(str(random.random()).encode()).hexdigest()[:10]
    return f"{token}-nope-{random.randint(1000,9999)}@{domain}"

def resolve_mx(domain: str, timeout: float = DNS_TIMEOUT):
    try:
        answers = dns.resolver.resolve(domain, 'MX', lifetime=timeout)
        prefs_hosts = sorted(
            [(r.preference, str(r.exchange).rstrip('.')) for r in answers],
            key=lambda x: x[0]
        )
        return [h for _, h in prefs_hosts]
    except Exception:
        return []

def mx_brand_from_host(mx: str) -> str:
    h = (mx or "").lower()
    if 'aspmx' in h or 'google' in h: return 'google'
    if 'outlook' in h or 'protection' in h: return 'microsoft'
    if 'proofpoint' in h: return 'proofpoint'
    if 'mimecast' in h: return 'mimecast'
    if 'zoho' in h: return 'zoho'
    return 'other'

def _smtp_open(mx_host: str, timeout: float = SMTP_TIMEOUT):
    srv = smtplib.SMTP(mx_host, 25, timeout=timeout)
    srv.ehlo("probe.local")
    try:
        srv.mail("<>")
    except Exception:
        srv.mail("<probe@probe.local>")
    return srv

def rcpt_once(srv: smtplib.SMTP, address: str):
    t0 = time.time()
    code, resp = srv.rcpt(address)
    t1 = time.time()
    latency = (t1 - t0) * 1000.0
    accepted = (200 <= code < 300) or code in (451, 452)
    return accepted, round(latency, 1), code

def multi_probe(srv: smtplib.SMTP, addr: str, n: int = 1):
    lats, accs = [], []
    for _ in range(max(1, n)):
        a, lat, _ = rcpt_once(srv, addr)
        lats.append(lat)
        accs.append(a)
        if n > 1:
            time.sleep(random.uniform(JITTER_MIN, JITTER_MAX))
    accepted_any = any(accs)
    mean_lat = round(sum(lats) / len(lats), 1)
    return accepted_any, mean_lat

# -------- Core verification (same method) --------
def verify_email(email: str, repeats: Optional[int] = None) -> VerifyResponse:
    try:
        domain = get_domain(email)
    except Exception:
        return VerifyResponse(
            email=email, domain=None, mx_host=None, mx_brand=None,
            result="invalid", catch_all=False, deliverability="undeliverable"
        )

    mx_list = resolve_mx(domain)
    if not mx_list:
        return VerifyResponse(
            email=email, domain=domain, mx_host=None, mx_brand=None,
            result="invalid", catch_all=False, deliverability="undeliverable"
        )

    mx = mx_list[0]
    brand = mx_brand_from_host(mx)
    reps = DEFAULT_REPEATS if repeats is None else max(1, int(repeats))

    try:
        srv = _smtp_open(mx)
    except Exception:
        return VerifyResponse(
            email=email, domain=domain, mx_host=mx, mx_brand=brand,
            result="invalid", catch_all=False, deliverability="undeliverable"
        )

    try:
        # Step 1: Target
        T_acc, T_mean = multi_probe(srv, email, reps)
        if not T_acc:
            return VerifyResponse(
                email=email, domain=domain, mx_host=mx, mx_brand=brand,
                result="invalid", catch_all=False, deliverability="undeliverable"
            )

        # Step 2: Fake1
        F1 = impossible_addr(domain)
        F1_acc, F1_mean = multi_probe(srv, F1, reps)
        if not F1_acc:
            # Non-catchall → target accepted ⇒ valid
            return VerifyResponse(
                email=email, domain=domain, mx_host=mx, mx_brand=brand,
                result="valid", catch_all=False, deliverability="deliverable"
            )

        # Step 3: Catch-all suspected → Fake2 + timing
        F2 = impossible_addr(domain)
        F2_acc, F2_mean = multi_probe(srv, F2, reps)
        i_mean = (F1_mean + F2_mean) / 2.0
        abs_delta = abs(T_mean - i_mean)
        threshold = GOOGLE_THRESHOLD if brand == "google" else DEFAULT_THRESHOLD
        is_valid = abs_delta >= threshold

        return VerifyResponse(
            email=email, domain=domain, mx_host=mx, mx_brand=brand,
            result="valid" if is_valid else "invalid",
            catch_all=True,
            deliverability="deliverable" if is_valid else "undeliverable"
        )
    finally:
        try: srv.quit()
        except Exception:
            try: srv.close()
            except Exception:
                pass

# -------- Routes --------
@app.get("/")
def root():
    return {"name": APP_NAME, "version": VERSION, "status": "ok"}

@app.post("/verify", response_model=VerifyResponse)
def verify_single(email: EmailStr = Body(..., embed=True), repeats: Optional[int] = None):
    # FastAPI will serialize using the alias "catch-all" automatically
    return verify_email(str(email), repeats=repeats)

@app.post("/bulk", response_model=List[VerifyResponse])
def verify_bulk(req: BulkRequest):
    emails = req.emails or []
    if not emails:
        raise HTTPException(status_code=400, detail="emails list is empty")
    if len(emails) > MAX_BULK:
        raise HTTPException(status_code=413, detail=f"emails exceed MAX_BULK={MAX_BULK}")
    reps = req.repeats
    out: List[VerifyResponse] = []
    for e in emails:
        try:
            out.append(verify_email(str(e), repeats=reps))
        except Exception:
            out.append(VerifyResponse(
                email=str(e), domain=None, mx_host=None, mx_brand=None,
                result="invalid", catch_all=False, deliverability="undeliverable"
            ))
    return out

@app.post("/bulk/csv", response_model=List[VerifyResponse])
async def verify_bulk_csv(file: UploadFile = File(...), repeats: Optional[int] = None):
    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="upload a .csv file")
    content = await file.read()
    try:
        stream = io.StringIO(content.decode("utf-8", errors="ignore"))
        reader = csv.reader(stream)
        emails: List[str] = []
        for row in reader:
            if not row: continue
            val = row[0].strip()
            if val.lower() == "email":  # skip header
                continue
            emails.append(val)
    except Exception:
        raise HTTPException(status_code=400, detail="failed to parse CSV")

    if not emails:
        raise HTTPException(status_code=400, detail="no emails in CSV")
    if len(emails) > MAX_BULK:
        raise HTTPException(status_code=413, detail=f"emails exceed MAX_BULK={MAX_BULK}")

    out: List[VerifyResponse] = []
    for e in emails:
        try:
            out.append(verify_email(e, repeats=repeats))
        except Exception:
            out.append(VerifyResponse(
                email=e, domain=None, mx_host=None, mx_brand=None,
                result="invalid", catch_all=False, deliverability="undeliverable"
            ))
    return out
