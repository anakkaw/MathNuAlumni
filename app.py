#!/usr/bin/env python3
import base64
import csv
import hashlib
import hmac
import html
import io
import json
import mimetypes
import os
import re
import secrets
import smtplib
import sqlite3
import ssl
import sys
import threading
import time
from http import cookies
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse


HOST = "127.0.0.1"
PORT = 8000
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "alumni.db"
UPLOAD_DIR = DATA_DIR / "uploads"
SECRET_KEY = os.environ.get("ALUMNI_SECRET", "change-me-in-production")
SMTP_HOST = os.environ.get("SMTP_HOST", "").strip()
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587") or "587")
SMTP_USER = os.environ.get("SMTP_USER", "").strip()
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER or "no-reply@mathalumni.local")
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "1") == "1"
RESET_TOKEN_TTL_SECONDS = 60 * 30
SESSION_TTL_SECONDS = 60 * 60 * 8
HOT_RELOAD_ENABLED = os.environ.get("HOT_RELOAD", "1") == "1"
HOT_RELOAD_INTERVAL = 1.0
SERVER_BUILD_ID = str(int(time.time()))
MAX_AVATAR_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_AVATAR_REQUEST_BYTES = MAX_AVATAR_UPLOAD_BYTES + (512 * 1024)
HOME_HERO_IMAGE_URL = "https://images.pexels.com/photos/11085463/pexels-photo-11085463.jpeg"
EDUCATION_MAJOR_OPTIONS = {
    "ปริญญาตรี": ("คณิตศาสตร์", "สถิติ", "วิทยาการข้อมูลและการวิเคราะห์"),
    "ปริญญาโท": ("คณิตศาสตร์", "สถิติ", "วิทยาการข้อมูลและการเรียนรู้ของเครื่อง"),
    "ปริญญาเอก": ("คณิตศาสตร์", "สถิติ"),
}
EDUCATION_LEVEL_OPTIONS = tuple(EDUCATION_MAJOR_OPTIONS.keys())
ALL_MAJOR_OPTIONS = tuple(sorted({m for values in EDUCATION_MAJOR_OPTIONS.values() for m in values}))
EMPLOYMENT_OPTIONS = (
    "ได้งานทำตรงสายที่จบ",
    "ได้งานทำไม่ตรงสายที่จบ",
    "กำลังศึกษาต่อ",
    "ยังไม่มีงานทำ",
    "ไม่สะดวกให้ข้อมูล",
)
EMPLOYED_STATUSES = ("ได้งานทำตรงสายที่จบ", "ได้งานทำไม่ตรงสายที่จบ")
ORG_TYPE_OPTIONS = ("หน่วยงานของรัฐ/รัฐวิสาหกิจ", "หน่วยงานเอกชน", "ธุรกิจส่วนตัว")
INCOME_OPTIONS = (
    "ต่ำกว่า 15,000 บาท",
    "15,001 - 20,000 บาท",
    "20,000 - 25,000 บาท",
    "สูงกว่า 25,000 บาท",
)
AUDIT_ACTION_OPTIONS = (
    "admin_create",
    "admin_update",
    "admin_delete",
    "profile_update",
    "avatar_update",
    "password_change",
)
AUDIT_TRACKED_FIELDS = (
    "email",
    "role",
    "full_name",
    "avatar_url",
    "student_id",
    "education_level",
    "major",
    "employment_status",
    "organization_type",
    "monthly_income",
    "company",
    "job_title",
    "workplace_house_no",
    "workplace_subdistrict",
    "workplace_district",
    "workplace_province",
    "workplace_postal_code",
)
POSTAL_DATA_PATH_JSON = DATA_DIR / "thai_postal_codes.json"
POSTAL_DATA_PATH_CSV = DATA_DIR / "thai_postal_codes.csv"
FALLBACK_POSTAL_LOOKUP = {
    "10110": {"district": "คลองเตย", "province": "กรุงเทพมหานคร", "subdistricts": ["คลองเตย", "คลองเตยเหนือ", "พระโขนง"]},
    "10330": {"district": "ปทุมวัน", "province": "กรุงเทพมหานคร", "subdistricts": ["ลุมพินี", "ปทุมวัน", "รองเมือง", "วังใหม่"]},
    "12120": {"district": "คลองหลวง", "province": "ปทุมธานี", "subdistricts": ["คลองหนึ่ง", "คลองสอง", "คลองสาม", "คลองสี่", "คลองห้า", "คลองหก", "คลองเจ็ด"]},
    "13160": {"district": "บางปะอิน", "province": "พระนครศรีอยุธยา", "subdistricts": ["บ้านกรด", "บ้านเลน", "บางปะอิน", "เชียงรากน้อย"]},
    "20110": {"district": "ศรีราชา", "province": "ชลบุรี", "subdistricts": ["ศรีราชา", "สุรศักดิ์", "ทุ่งสุขลา", "บึง"]},
    "21130": {"district": "บ้านฉาง", "province": "ระยอง", "subdistricts": ["บ้านฉาง", "พลา", "สำนักท้อน"]},
    "30000": {"district": "เมืองนครราชสีมา", "province": "นครราชสีมา", "subdistricts": ["ในเมือง", "หัวทะเล", "หนองไผ่ล้อม", "โพธิ์กลาง"]},
    "50000": {"district": "เมืองเชียงใหม่", "province": "เชียงใหม่", "subdistricts": ["ศรีภูมิ", "พระสิงห์", "ช้างม่อย", "หายยา", "วัดเกต"]},
    "50200": {"district": "เมืองเชียงใหม่", "province": "เชียงใหม่", "subdistricts": ["สุเทพ", "ช้างเผือก", "พระสิงห์", "ศรีภูมิ", "หายยา"]},
    "52000": {"district": "เมืองลำปาง", "province": "ลำปาง", "subdistricts": ["เวียงเหนือ", "หัวเวียง", "สวนดอก", "สบตุ๋ย"]},
    "65000": {"district": "เมืองพิษณุโลก", "province": "พิษณุโลก", "subdistricts": ["ในเมือง", "วัดจันทร์", "หัวรอ", "บ้านคลอง"]},
    "83000": {"district": "เมืองภูเก็ต", "province": "ภูเก็ต", "subdistricts": ["ตลาดใหญ่", "ตลาดเหนือ", "รัษฎา", "วิชิต"]},
    "84000": {"district": "เมืองสุราษฎร์ธานี", "province": "สุราษฎร์ธานี", "subdistricts": ["ตลาด", "มะขามเตี้ย", "บางกุ้ง", "บางใบไม้"]},
    "90110": {"district": "หาดใหญ่", "province": "สงขลา", "subdistricts": ["หาดใหญ่", "คอหงส์", "คลองแห", "ควนลัง"]},
}


def normalize_postal_lookup(raw_lookup):
    normalized = {}
    for code, entry in (raw_lookup or {}).items():
        code_text = str(code).strip()
        if not re.fullmatch(r"\d{5}", code_text):
            continue
        district = str((entry or {}).get("district") or "").strip()
        province = str((entry or {}).get("province") or "").strip()
        subdistricts = []
        subdistrict_map = {}
        for subdistrict in (entry or {}).get("subdistricts") or []:
            subdistrict_text = str(subdistrict).strip()
            if not subdistrict_text:
                continue
            if subdistrict_text not in subdistricts:
                subdistricts.append(subdistrict_text)
            subdistrict_map[subdistrict_text] = {"district": district, "province": province}
        normalized[code_text] = {
            "district": district,
            "province": province,
            "subdistricts": subdistricts,
            "subdistrict_map": subdistrict_map,
        }
    return normalized


def build_postal_lookup_from_rows(rows):
    grouped = {}
    for row in rows:
        code = str(row.get("postal_code") or "").strip()
        subdistrict = str(row.get("subdistrict") or "").strip()
        district = str(row.get("district") or "").strip()
        province = str(row.get("province") or "").strip()
        if not re.fullmatch(r"\d{5}", code) or not subdistrict or not district or not province:
            continue
        entry = grouped.setdefault(
            code,
            {"district": district, "province": province, "subdistricts": [], "subdistrict_map": {}},
        )
        if subdistrict not in entry["subdistricts"]:
            entry["subdistricts"].append(subdistrict)
        entry["subdistrict_map"][subdistrict] = {"district": district, "province": province}
    for entry in grouped.values():
        entry["subdistricts"].sort()
    return grouped


def load_postal_lookup():
    if POSTAL_DATA_PATH_JSON.exists():
        try:
            payload = json.loads(POSTAL_DATA_PATH_JSON.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                lookup = normalize_postal_lookup(payload)
                if lookup:
                    return lookup, f"json:{POSTAL_DATA_PATH_JSON.name}"
            if isinstance(payload, list):
                rows = []
                for item in payload:
                    if not isinstance(item, dict):
                        continue
                    rows.append(
                        {
                            "postal_code": item.get("postal_code")
                            or item.get("postcode")
                            or item.get("zipcode")
                            or item.get("zip_code")
                            or item.get("zip"),
                            "subdistrict": item.get("subdistrict")
                            or item.get("tambon")
                            or item.get("district_sub")
                            or item.get("แขวง")
                            or item.get("ตำบล"),
                            "district": item.get("district")
                            or item.get("amphoe")
                            or item.get("district_main")
                            or item.get("เขต")
                            or item.get("อำเภอ"),
                            "province": item.get("province") or item.get("changwat") or item.get("จังหวัด"),
                        }
                    )
                lookup = build_postal_lookup_from_rows(rows)
                if lookup:
                    return lookup, f"json:{POSTAL_DATA_PATH_JSON.name}"
        except Exception as exc:
            print(f"[postal] failed to read {POSTAL_DATA_PATH_JSON}: {exc}")
    if POSTAL_DATA_PATH_CSV.exists():
        try:
            rows = []
            with POSTAL_DATA_PATH_CSV.open("r", encoding="utf-8-sig", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    rows.append(
                        {
                            "postal_code": row.get("postal_code")
                            or row.get("postcode")
                            or row.get("zipcode")
                            or row.get("zip_code")
                            or row.get("zip")
                            or row.get("รหัสไปรษณีย์"),
                            "subdistrict": row.get("subdistrict")
                            or row.get("tambon")
                            or row.get("แขวง")
                            or row.get("ตำบล"),
                            "district": row.get("district")
                            or row.get("amphoe")
                            or row.get("เขต")
                            or row.get("อำเภอ"),
                            "province": row.get("province") or row.get("changwat") or row.get("จังหวัด"),
                        }
                    )
            lookup = build_postal_lookup_from_rows(rows)
            if lookup:
                return lookup, f"csv:{POSTAL_DATA_PATH_CSV.name}"
        except Exception as exc:
            print(f"[postal] failed to read {POSTAL_DATA_PATH_CSV}: {exc}")
    return normalize_postal_lookup(FALLBACK_POSTAL_LOOKUP), "fallback:built-in"


POSTAL_LOOKUP, POSTAL_LOOKUP_SOURCE = load_postal_lookup()
SAMPLE_ALUMNI = [
    ("alumni01@mathalumni.local", "สมชาย วัฒนกุล", "650001", "คณิตศาสตร์", "ได้งานทำตรงสายที่จบ", "หน่วยงานเอกชน", "สูงกว่า 25,000 บาท", "Siam Finance", "Data Analyst", "12/8", "ลุมพินี", "ปทุมวัน", "กรุงเทพมหานคร", "10330"),
    ("alumni02@mathalumni.local", "อารีรัตน์ จันทร์ศรี", "650002", "สถิติ", "ได้งานทำตรงสายที่จบ", "หน่วยงานของรัฐ/รัฐวิสาหกิจ", "20,000 - 25,000 บาท", "สำนักงานสถิติแห่งชาติ", "นักสถิติ", "55", "ศรีภูมิ", "เมืองเชียงใหม่", "เชียงใหม่", "50000"),
    ("alumni03@mathalumni.local", "ณัฐพล ศรีสุข", "650003", "วิทยาการข้อมูลและการวิเคราะห์", "ได้งานทำตรงสายที่จบ", "หน่วยงานเอกชน", "สูงกว่า 25,000 บาท", "AI Works", "Data Scientist", "88/2", "ศรีราชา", "ศรีราชา", "ชลบุรี", "20110"),
    ("alumni04@mathalumni.local", "พรทิพย์ ปัญญา", "650004", "คณิตศาสตร์", "กำลังศึกษาต่อ", None, None, None, None, None, None, None, None, None),
    ("alumni05@mathalumni.local", "ธนากร พูลทรัพย์", "650005", "สถิติ", "ได้งานทำไม่ตรงสายที่จบ", "หน่วยงานเอกชน", "20,000 - 25,000 บาท", "Market Move", "Business Analyst", "111", "ในเมือง", "เมืองนครราชสีมา", "นครราชสีมา", "30000"),
    ("alumni06@mathalumni.local", "วิภาวี วงศ์เจริญ", "650006", "วิทยาการข้อมูลและการวิเคราะห์", "ได้งานทำตรงสายที่จบ", "หน่วยงานเอกชน", "สูงกว่า 25,000 บาท", "CloudNine Tech", "ML Engineer", "7/14", "คลองหนึ่ง", "คลองหลวง", "ปทุมธานี", "12120"),
    ("alumni07@mathalumni.local", "กิตติพงษ์ ทองดี", "650007", "คณิตศาสตร์", "ยังไม่มีงานทำ", None, None, None, None, None, None, None, None, None),
    ("alumni08@mathalumni.local", "ณิชารีย์ แก้วประดับ", "650008", "สถิติ", "ได้งานทำตรงสายที่จบ", "หน่วยงานเอกชน", "20,000 - 25,000 บาท", "Health Metrics", "Data Consultant", "9/9", "ตลาดใหญ่", "เมืองภูเก็ต", "ภูเก็ต", "83000"),
    ("alumni09@mathalumni.local", "ชัยวัฒน์ รุ่งโรจน์", "650009", "วิทยาการข้อมูลและการวิเคราะห์", "ได้งานทำไม่ตรงสายที่จบ", "ธุรกิจส่วนตัว", "15,001 - 20,000 บาท", "ร้านรุ่งโรจน์ดิจิทัล", "ผู้ประกอบการ", "44", "หาดใหญ่", "หาดใหญ่", "สงขลา", "90110"),
    ("alumni10@mathalumni.local", "สุภาวดี ทองแท้", "650010", "คณิตศาสตร์", "ได้งานทำตรงสายที่จบ", "หน่วยงานเอกชน", "20,000 - 25,000 บาท", "Energy Grid", "Operations Analyst", "201", "บ้านฉาง", "บ้านฉาง", "ระยอง", "21130"),
    ("alumni11@mathalumni.local", "ปิยพงษ์ นาคชุม", "650011", "สถิติ", "ได้งานทำไม่ตรงสายที่จบ", "หน่วยงานของรัฐ/รัฐวิสาหกิจ", "15,001 - 20,000 บาท", "Gov Insight", "Policy Analyst", "18", "ในเมือง", "เมืองพิษณุโลก", "พิษณุโลก", "65000"),
    ("alumni12@mathalumni.local", "ชนิดา แสงดาว", "650012", "วิทยาการข้อมูลและการวิเคราะห์", "ได้งานทำตรงสายที่จบ", "หน่วยงานเอกชน", "สูงกว่า 25,000 บาท", "FinMind", "Fraud Analyst", "299", "ตลาด", "เมืองสุราษฎร์ธานี", "สุราษฎร์ธานี", "84000"),
    ("alumni13@mathalumni.local", "ภัทรพล ดวงดี", "650013", "คณิตศาสตร์", "ได้งานทำตรงสายที่จบ", "หน่วยงานเอกชน", "20,000 - 25,000 บาท", "LogiMax", "Optimization Engineer", "21/1", "บ้านเลน", "บางปะอิน", "พระนครศรีอยุธยา", "13160"),
    ("alumni14@mathalumni.local", "สิริพร แซ่ตั้ง", "650014", "สถิติ", "ไม่สะดวกให้ข้อมูล", None, None, None, None, None, None, None, None, None),
    ("alumni15@mathalumni.local", "เดชาธร ใจกล้า", "650015", "วิทยาการข้อมูลและการวิเคราะห์", "ได้งานทำตรงสายที่จบ", "หน่วยงานเอกชน", "สูงกว่า 25,000 บาท", "NextWave Data", "Data Engineer", "77", "เวียงเหนือ", "เมืองลำปาง", "ลำปาง", "52000"),
]


def db_conn():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA temp_store = MEMORY")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def now_iso():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def normalize_postal_code(value):
    text = str(value or "").strip()
    thai_to_arabic = str.maketrans("๐๑๒๓๔๕๖๗๘๙", "0123456789")
    text = text.translate(thai_to_arabic)
    digits = "".join(ch for ch in text if ch.isdigit())
    return digits[:5]


def major_options_for_level(level):
    return EDUCATION_MAJOR_OPTIONS.get(level, ())


def parse_education_form(form, *, allow_blank=False):
    level = (form.get("education_level") or "").strip()
    major = (form.get("major") or "").strip()
    if allow_blank and not level and not major:
        return {"education_level": None, "major": None}, None
    if level not in EDUCATION_LEVEL_OPTIONS:
        return None, "กรุณาเลือกระดับการศึกษาให้ถูกต้อง"
    if major not in major_options_for_level(level):
        return None, "กรุณาเลือกสาขาให้ตรงกับระดับการศึกษา"
    return {"education_level": level, "major": major}, None


def send_password_reset_email(to_email, reset_link):
    if not SMTP_HOST:
        print(f"[password-reset] link for {to_email}: {reset_link}")
        return False
    subject = "ลิงก์สำหรับตั้งรหัสผ่านใหม่ - Math Alumni"
    body = (
        "สวัสดี,\n\n"
        "มีคำขอรีเซ็ตรหัสผ่านสำหรับบัญชีนี้\n"
        f"กรุณาคลิกลิงก์นี้เพื่อเปลี่ยนรหัสผ่าน:\n{reset_link}\n\n"
        f"ลิงก์นี้จะหมดอายุภายใน {RESET_TOKEN_TTL_SECONDS // 60} นาที\n"
        "หากคุณไม่ได้เป็นผู้ขอ กรุณาเพิกเฉยอีเมลนี้"
    )
    message = f"Subject: {subject}\nFrom: {SMTP_FROM}\nTo: {to_email}\nContent-Type: text/plain; charset=utf-8\n\n{body}"
    if SMTP_USE_TLS:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as smtp:
            smtp.starttls(context=ssl.create_default_context())
            if SMTP_USER:
                smtp.login(SMTP_USER, SMTP_PASS)
            smtp.sendmail(SMTP_FROM, [to_email], message.encode("utf-8"))
    else:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=15, context=ssl.create_default_context()) as smtp:
            if SMTP_USER:
                smtp.login(SMTP_USER, SMTP_PASS)
            smtp.sendmail(SMTP_FROM, [to_email], message.encode("utf-8"))
    return True


def row_snapshot(row, fields=AUDIT_TRACKED_FIELDS):
    if not row:
        return {}
    snapshot = {}
    for field in fields:
        value = row[field] if field in row.keys() else None
        snapshot[field] = value
    return snapshot


def diff_snapshots(before, after):
    changes = {}
    for field in AUDIT_TRACKED_FIELDS:
        old = (before or {}).get(field)
        new = (after or {}).get(field)
        if old != new:
            changes[field] = {"from": old, "to": new}
    return changes


def log_user_audit(conn, actor_id, user_id, action, changes):
    if action not in AUDIT_ACTION_OPTIONS:
        return
    payload = json.dumps(changes or {}, ensure_ascii=False)
    conn.execute(
        "INSERT INTO audit_logs (actor_id, user_id, action, changes_json, created_at) VALUES (?, ?, ?, ?, ?)",
        (actor_id, user_id, action, payload, now_iso()),
    )


def summarize_audit_changes(changes_json):
    try:
        parsed = json.loads(changes_json or "{}")
    except Exception:
        parsed = {}
    if not isinstance(parsed, dict) or not parsed:
        return "-"
    if "created" in parsed and isinstance(parsed["created"], dict):
        return "สร้างผู้ใช้ใหม่"
    if "deleted" in parsed and isinstance(parsed["deleted"], dict):
        return "ลบข้อมูลผู้ใช้"
    parts = []
    for field, detail in parsed.items():
        if not isinstance(detail, dict):
            continue
        old = detail.get("from")
        new = detail.get("to")
        old_text = "-" if old in (None, "") else str(old)
        new_text = "-" if new in (None, "") else str(new)
        parts.append(f"{field}: {old_text} -> {new_text}")
        if len(parts) >= 4:
            break
    return "; ".join(parts) if parts else "-"


def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1)
    return f"{base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(digest).decode()}"


def verify_password(password, stored):
    try:
        salt_b64, digest_b64 = stored.split("$", 1)
        salt = base64.urlsafe_b64decode(salt_b64.encode())
        expected = base64.urlsafe_b64decode(digest_b64.encode())
        got = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1)
        return hmac.compare_digest(got, expected)
    except Exception:
        return False


def encode_session(user_id):
    exp = int(time.time()) + SESSION_TTL_SECONDS
    nonce = secrets.token_hex(8)
    payload = f"{user_id}:{exp}:{nonce}".encode("utf-8")
    sig = hmac.new(SECRET_KEY.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    raw = payload + b"." + sig.encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def decode_session(token):
    try:
        raw = base64.urlsafe_b64decode(token.encode("ascii"))
        payload, sig = raw.rsplit(b".", 1)
        expected = hmac.new(SECRET_KEY.encode("utf-8"), payload, hashlib.sha256).hexdigest().encode("utf-8")
        if not hmac.compare_digest(sig, expected):
            return None
        user_id_text, exp_text, _ = payload.decode("utf-8").split(":")
        if int(exp_text) < int(time.time()):
            return None
        return int(user_id_text)
    except Exception:
        return None


def init_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    conn = db_conn()
    with conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin', 'alumni')),
                full_name TEXT NOT NULL,
                avatar_url TEXT,
                student_id TEXT,
                education_level TEXT,
                major TEXT,
                employment_status TEXT,
                organization_type TEXT,
                monthly_income TEXT,
                company TEXT,
                job_title TEXT,
                workplace_house_no TEXT,
                workplace_subdistrict TEXT,
                workplace_district TEXT,
                workplace_province TEXT,
                workplace_postal_code TEXT,
                location TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_id INTEGER,
                user_id INTEGER,
                action TEXT NOT NULL,
                changes_json TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT NOT NULL UNIQUE,
                expires_at INTEGER NOT NULL,
                used_at INTEGER,
                created_at INTEGER NOT NULL
            )
            """
        )
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
        if "avatar_url" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN avatar_url TEXT")
        if "student_id" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN student_id TEXT")
        if "education_level" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN education_level TEXT")
        if "employment_status" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN employment_status TEXT")
        if "organization_type" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN organization_type TEXT")
        if "monthly_income" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN monthly_income TEXT")
        if "workplace_house_no" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN workplace_house_no TEXT")
        if "workplace_subdistrict" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN workplace_subdistrict TEXT")
        if "workplace_district" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN workplace_district TEXT")
        if "workplace_province" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN workplace_province TEXT")
        if "workplace_postal_code" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN workplace_postal_code TEXT")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_name ON users(full_name)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_major ON users(major)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_student_id ON users(student_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_role_major ON users(role, major)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_role_education_level ON users(role, education_level)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_employment_status ON users(employment_status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_role_employment_status ON users(role, employment_status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_role_org_type ON users(role, organization_type)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_role_monthly_income ON users(role, monthly_income)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_role_workplace_province ON users(role, workplace_province)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_intake_prefix ON users(substr(student_id, 1, 2))")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_id ON audit_logs(actor_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_reset_tokens_token ON password_reset_tokens(token)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_reset_tokens_user_id ON password_reset_tokens(user_id)")

        count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        if count == 0:
            ts = now_iso()
            conn.execute(
                """
                INSERT INTO users (email, password_hash, role, full_name, avatar_url, student_id, education_level, major, employment_status, organization_type, monthly_income, company, job_title, workplace_house_no, workplace_subdistrict, workplace_district, workplace_province, workplace_postal_code, location, created_at, updated_at)
                VALUES (?, ?, 'admin', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "admin@mathalumni.local",
                    hash_password("Admin123!"),
                    "System Admin",
                    "https://images.unsplash.com/photo-1544723795-3fb6469f5b39?auto=format&fit=crop&w=200&q=80",
                    "A000001",
                    "ปริญญาตรี",
                    "คณิตศาสตร์",
                    "ไม่สะดวกให้ข้อมูล",
                    None,
                    None,
                    "Math Alumni Office",
                    "Administrator",
                    None,
                    None,
                    None,
                    "Bangkok",
                    None,
                    "Bangkok",
                    ts,
                    ts,
                ),
            )
        conn.execute("DELETE FROM users WHERE email = ? AND role = 'alumni'", ("alumni@mathalumni.local",))
        sample_password_hash = hash_password("Alumni123!")
        sample_ts = now_iso()
        for sample in SAMPLE_ALUMNI:
            (
                email,
                full_name,
                student_id,
                major,
                employment_status,
                organization_type,
                monthly_income,
                company,
                job_title,
                workplace_house_no,
                workplace_subdistrict,
                workplace_district,
                workplace_province,
                workplace_postal_code,
            ) = sample
            conn.execute(
                """
                INSERT INTO users (email, password_hash, role, full_name, avatar_url, student_id, education_level, major, employment_status, organization_type, monthly_income, company, job_title, workplace_house_no, workplace_subdistrict, workplace_district, workplace_province, workplace_postal_code, created_at, updated_at)
                VALUES (?, ?, 'alumni', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(email) DO UPDATE SET
                  role = 'alumni',
                  full_name = excluded.full_name,
                  avatar_url = excluded.avatar_url,
                  student_id = excluded.student_id,
                  education_level = excluded.education_level,
                  major = excluded.major,
                  employment_status = excluded.employment_status,
                  organization_type = excluded.organization_type,
                  monthly_income = excluded.monthly_income,
                  company = excluded.company,
                  job_title = excluded.job_title,
                  workplace_house_no = excluded.workplace_house_no,
                  workplace_subdistrict = excluded.workplace_subdistrict,
                  workplace_district = excluded.workplace_district,
                  workplace_province = excluded.workplace_province,
                  workplace_postal_code = excluded.workplace_postal_code,
                  updated_at = excluded.updated_at
                """,
                (
                    email,
                    sample_password_hash,
                    full_name,
                    f"https://api.dicebear.com/9.x/initials/svg?seed={student_id}",
                    student_id,
                    "ปริญญาตรี",
                    major,
                    employment_status,
                    organization_type,
                    monthly_income,
                    company,
                    job_title,
                    workplace_house_no,
                    workplace_subdistrict,
                    workplace_district,
                    workplace_province,
                    workplace_postal_code,
                    sample_ts,
                    sample_ts,
                ),
            )
        conn.execute(
            """
            UPDATE users
            SET workplace_province = location
            WHERE workplace_province IS NULL AND location IS NOT NULL AND location != ''
            """
        )
        conn.execute(
            """
            UPDATE users
            SET organization_type = 'หน่วยงานของรัฐ/รัฐวิสาหกิจ'
            WHERE organization_type = 'ราชการ'
            """
        )
        conn.execute(
            """
            UPDATE users
            SET organization_type = 'หน่วยงานเอกชน'
            WHERE organization_type = 'เอกชน'
            """
        )
        conn.execute(
            """
            UPDATE users
            SET education_level = 'ปริญญาตรี'
            WHERE role = 'alumni' AND (education_level IS NULL OR education_level NOT IN (?, ?, ?))
            """,
            (EDUCATION_LEVEL_OPTIONS[0], EDUCATION_LEVEL_OPTIONS[1], EDUCATION_LEVEL_OPTIONS[2]),
        )
        conn.execute(
            """
            UPDATE users
            SET major = ?
            WHERE role = 'alumni' AND education_level = 'ปริญญาตรี' AND (major IS NULL OR major NOT IN (?, ?, ?))
            """,
            (
                EDUCATION_MAJOR_OPTIONS["ปริญญาตรี"][0],
                EDUCATION_MAJOR_OPTIONS["ปริญญาตรี"][0],
                EDUCATION_MAJOR_OPTIONS["ปริญญาตรี"][1],
                EDUCATION_MAJOR_OPTIONS["ปริญญาตรี"][2],
            ),
        )
        conn.execute(
            """
            UPDATE users
            SET employment_status = ?
            WHERE role = 'alumni' AND (employment_status IS NULL OR employment_status NOT IN (?, ?, ?, ?, ?))
            """,
            (
                "ไม่สะดวกให้ข้อมูล",
                EMPLOYMENT_OPTIONS[0],
                EMPLOYMENT_OPTIONS[1],
                EMPLOYMENT_OPTIONS[2],
                EMPLOYMENT_OPTIONS[3],
                EMPLOYMENT_OPTIONS[4],
            ),
        )
        conn.execute(
            """
            UPDATE users
            SET organization_type = NULL, monthly_income = NULL, company = NULL, job_title = NULL, workplace_house_no = NULL, workplace_subdistrict = NULL, workplace_district = NULL, workplace_province = NULL, workplace_postal_code = NULL, location = NULL
            WHERE role = 'alumni' AND employment_status NOT IN (?, ?)
            """,
            EMPLOYED_STATUSES,
        )
        conn.execute(
            """
            UPDATE users
            SET location = TRIM(
                COALESCE(workplace_house_no, '') || ' ' ||
                COALESCE(workplace_subdistrict, '') || ' ' ||
                COALESCE(workplace_district, '') || ' ' ||
                COALESCE(workplace_province, '') || ' ' ||
                COALESCE(workplace_postal_code, '')
            )
            WHERE role = 'alumni'
            """
        )
    conn.close()


def html_page(title, body, user=None):
    nav = "<a class='nav-link' href='/'>หน้าแรก</a><a class='nav-link' href='/login'>เข้าสู่ระบบ</a><a class='nav-link' href='/register'>สมัครสมาชิก</a>"
    if user:
        nav = (
            "<a class='nav-link' href='/'>หน้าแรก</a>"
            "<a class='nav-link' href='/dashboard'>ข้อมูลส่วนตัว</a>"
            + ("<a class='nav-link' href='/admin/users'>จัดการข้อมูล</a>" if user["role"] == "admin" else "")
            + "<form method='post' action='/logout' style='display:inline'><button class='btn btn-ghost' type='submit'>ออกจากระบบ</button></form>"
        )
    return f"""<!DOCTYPE html>
<html lang='th'>
<head>
  <meta charset='UTF-8' />
  <meta name='viewport' content='width=device-width, initial-scale=1' />
  <title>{html.escape(title)}</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Anuphan:wght@400;500;600;700&display=swap');
    :root {{
      --bg: #fffdfd;
      --ink: #0f172a;
      --muted: #475569;
      --card: rgba(255, 255, 255, 0.98);
      --line: rgba(226, 232, 240, 0.92);
      --primary: #b91c1c;
      --primary-2: #991b1b;
      --danger: #9f1239;
      --surface-2: #fff7f7;
      --accent-a: #dc2626;
      --accent-b: #b91c1c;
      --accent-c: #7f1d1d;
    }}
    body {{
      margin: 0;
      font-family: "Anuphan", "Noto Sans Thai", "Prompt", "Segoe UI", Tahoma, sans-serif;
      background:
        radial-gradient(circle at 90% -8%, rgba(254, 202, 202, 0.2) 0%, transparent 38%),
        radial-gradient(circle at -3% 18%, rgba(254, 226, 226, 0.34) 0%, transparent 30%),
        linear-gradient(180deg, #fffdfd 0%, #fff8f8 52%, #ffffff 100%);
      color: var(--ink);
      min-height: 100vh;
    }}
    .wrap {{
      max-width: 1120px;
      margin: 22px auto 32px;
      padding: 0 16px;
    }}
    .brand {{
      display: flex;
      align-items: center;
      gap: 10px;
      font-weight: 700;
      letter-spacing: 0.2px;
    }}
    .brand-dot {{
      width: 13px;
      height: 13px;
      border-radius: 999px;
      background: linear-gradient(140deg, var(--primary), #b91c1c);
      box-shadow: 0 0 0 6px rgba(248, 113, 113, 0.18);
    }}
    .card {{
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 20px 20px 18px;
      margin-bottom: 16px;
      box-shadow: 0 8px 18px rgba(15, 23, 42, 0.05);
      position: relative;
      overflow: hidden;
      animation: fade-up 0.35s ease both;
    }}
    .card::before {{
      content: "";
      position: absolute;
      inset: 0 0 auto 0;
      height: 2px;
      background: linear-gradient(90deg, #ef4444, #f43f5e);
      opacity: 0.7;
    }}
    .topbar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 16px;
      gap: 10px;
      background: rgba(255, 255, 255, 0.66);
      border: none;
      border-radius: 0;
      padding: 6px 2px 10px;
      box-shadow: none;
      border-bottom: 1px solid #e2e8f0;
      border-top: 1px solid rgba(255, 255, 255, 0.68);
      backdrop-filter: blur(6px);
      position: sticky;
      top: 10px;
      z-index: 5;
    }}
    .nav {{
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
      justify-content: flex-end;
    }}
    .nav-link, .btn, button {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      text-decoration: none;
      border: 1px solid transparent;
      border-radius: 8px;
      padding: 9px 14px;
      font-size: 0.9rem;
      line-height: 1.2;
      font-weight: 600;
      font-family: inherit;
      letter-spacing: 0.1px;
      box-sizing: border-box;
      min-height: 40px;
      white-space: nowrap;
      cursor: pointer;
      transition: transform 0.18s ease, box-shadow 0.18s ease, border-color 0.18s ease, background 0.18s ease, color 0.18s ease;
    }}
    .btn, button {{
      margin-top: 12px;
      border: none;
      background: linear-gradient(135deg, #dc2626, #b91c1c 58%, #7f1d1d);
      color: #fff;
      box-shadow: 0 10px 18px rgba(185, 28, 28, 0.26);
    }}
    .btn:hover, button:hover {{
      transform: translateY(-1px);
      box-shadow: 0 12px 24px rgba(185, 28, 28, 0.3);
    }}
    .nav-link {{
      margin-top: 0;
      color: #1e293b;
      background: #ffffff;
      border-color: #dbe2ea;
      box-shadow: none;
    }}
    .nav-link:hover {{
      border-color: #fca5a5;
      color: #b91c1c;
      transform: translateY(-1px);
      box-shadow: 0 10px 18px rgba(239, 68, 68, 0.14);
    }}
    h1, h2 {{
      margin: 4px 0 12px;
      line-height: 1.3;
      letter-spacing: 0.2px;
    }}
    .muted {{ color: var(--muted); font-size: 0.93rem; margin: 0; }}
    .hero {{
      display: grid;
      gap: 12px;
      padding: 4px 0;
    }}
    .hero-title {{
      margin: 0;
      font-size: 1.6rem;
      color: #111827;
    }}
    .section-head {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 12px;
      margin-bottom: 8px;
    }}
    .kpi-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(185px, 1fr));
      gap: 12px;
      margin-top: 12px;
    }}
    .kpi {{
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #ffffff;
      padding: 12px;
      position: relative;
      overflow: hidden;
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.92);
    }}
    .kpi::after {{
      content: "";
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 3px;
      border-radius: 0;
      background: linear-gradient(90deg, #dc2626, #be123c);
    }}
    .kpi .label {{
      color: var(--muted);
      font-size: 0.83rem;
      margin-bottom: 6px;
    }}
    .kpi .value {{
      font-size: 1.45rem;
      font-weight: 700;
    }}
    .chart {{
      margin-top: 14px;
      display: grid;
      gap: 11px;
    }}
    .chart-head {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 0.82rem;
      color: #64748b;
      padding-bottom: 3px;
      border-bottom: 1px dashed #e2e8f0;
    }}
    .chart-row {{
      display: grid;
      grid-template-columns: minmax(165px, 1.25fr) 2fr 70px;
      gap: 12px;
      align-items: center;
    }}
    .chart-meta {{
      display: grid;
      gap: 2px;
    }}
    .chart-label {{
      font-weight: 600;
      color: #0f172a;
      font-size: 0.89rem;
      line-height: 1.2;
    }}
    .chart-sub {{
      font-size: 0.76rem;
      color: #64748b;
    }}
    .chart-track {{
      height: 14px;
      border-radius: 5px;
      background: linear-gradient(180deg, #f8fafc, #eef2f7);
      overflow: hidden;
      border: 1px solid #e2e8f0;
    }}
    .chart-fill {{
      height: 100%;
      min-width: 0;
      border-radius: 4px;
      background: linear-gradient(120deg, #dc2626, #be123c 62%, #9f1239);
    }}
    .chart-fill-org {{
      background: linear-gradient(120deg, #b91c1c, #7f1d1d 68%, #450a0a);
    }}
    .chart-fill-income {{
      background: linear-gradient(120deg, #dc2626, #ef4444 62%, #fb7185);
    }}
    .chart-fill-province {{
      background: linear-gradient(120deg, #7f1d1d, #991b1b 62%, #be123c);
    }}
    .chart-count {{
      text-align: right;
      font-weight: 700;
      color: #7f1d1d;
      font-variant-numeric: tabular-nums;
      letter-spacing: 0.1px;
    }}
    .chart-empty {{
      color: #64748b;
      font-size: 0.86rem;
      padding: 6px 0;
    }}
    .home-hero {{
      position: relative;
      overflow: hidden;
      background: linear-gradient(135deg, #7f1d1d 0%, #b91c1c 58%, #dc2626 100%);
      color: #fff7f7;
      border-radius: 10px;
      padding: 24px 20px;
      border: 1px solid rgba(254, 202, 202, 0.55);
      box-shadow: 0 16px 28px rgba(127, 29, 29, 0.26);
    }}
    .home-hero::after {{
      content: "";
      position: absolute;
      width: 220px;
      height: 220px;
      border-radius: 999px;
      right: -70px;
      top: -85px;
      background: radial-gradient(circle, rgba(255,255,255,0.25) 0%, rgba(255,255,255,0) 70%);
    }}
    .home-hero-grid {{
      display: grid;
      grid-template-columns: 1.15fr 0.85fr;
      gap: 18px;
      align-items: center;
      position: relative;
      z-index: 1;
    }}
    .home-hero-media {{
      border-radius: 8px;
      overflow: hidden;
      border: 1px solid rgba(255, 255, 255, 0.28);
      box-shadow: 0 14px 28px rgba(69, 10, 10, 0.28);
      min-height: 210px;
      background: rgba(255, 255, 255, 0.08);
    }}
    .home-hero-media img {{
      width: 100%;
      height: 100%;
      min-height: 210px;
      object-fit: cover;
      display: block;
    }}
    .home-hero p {{
      margin: 0;
      color: #fee2e2;
    }}
    .home-title {{
      margin: 0 0 6px;
      font-size: clamp(1.45rem, 2.8vw, 2rem);
      letter-spacing: 0.1px;
      color: #ffffff;
    }}
    .home-layout {{
      margin-top: 12px;
      display: grid;
      grid-template-columns: 1.1fr 1fr;
      gap: 14px;
    }}
    .home-panel {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
      background: #ffffff;
    }}
    .home-panel h2 {{
      margin: 0 0 8px;
      font-size: 1.05rem;
    }}
    .login-cta {{
      margin-top: 14px;
      border: 1px solid #fecaca;
      border-radius: 8px;
      padding: 14px;
      background: linear-gradient(120deg, #fff7f7, #fff3f4);
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
    }}
    .login-cta strong {{
      display: block;
      margin-bottom: 4px;
      color: #b91c1c;
      font-size: 1rem;
    }}
    .hero-actions {{
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      margin-top: 6px;
    }}
    .form-section {{
      margin-top: 12px;
      padding: 12px;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      background: rgba(255, 255, 255, 0.88);
    }}
    .form-section-title {{
      margin: 0 0 8px;
      font-size: 0.96rem;
      color: #334155;
      font-weight: 700;
    }}
    .chart.compact {{
      margin-top: 8px;
      gap: 10px;
    }}
    .chart.compact .chart-row {{
      grid-template-columns: minmax(150px, 1.2fr) 2fr 68px;
      gap: 10px;
    }}
    .status-light {{
      display: inline-block;
      padding: 4px 9px;
      border-radius: 999px;
      font-size: 0.78rem;
      border: 1px solid rgba(255,255,255,0.4);
      color: #fff;
      background: rgba(255,255,255,0.14);
      margin-bottom: 6px;
    }}
    .avatar {{
      width: 44px;
      height: 44px;
      border-radius: 999px;
      object-fit: cover;
      border: 2px solid #fda4af;
      background: #fff1f2;
    }}
    .avatar-lg {{
      width: 72px;
      height: 72px;
      border-radius: 999px;
      object-fit: cover;
      border: 2px solid #fda4af;
      background: #fff1f2;
    }}
    .avatar-row {{
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 6px;
    }}
    label {{
      display: block;
      margin: 11px 0 6px;
      font-size: 0.88rem;
      font-weight: 600;
      color: #1e293b;
    }}
    input, select {{
      width: 100%;
      box-sizing: border-box;
      border: 1px solid #cbd5e1;
      border-radius: 8px;
      padding: 10px 12px;
      font-size: 0.95rem;
      background: rgba(255, 255, 255, 0.96);
      color: var(--ink);
      height: 42px;
      -webkit-appearance: none;
      -moz-appearance: none;
      appearance: none;
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.9);
      transition: all 0.2s ease;
    }}
    select {{
      padding-right: 38px;
      background-image:
        linear-gradient(45deg, transparent 50%, #dc2626 50%),
        linear-gradient(135deg, #dc2626 50%, transparent 50%),
        linear-gradient(to right, #e2e8f0, #e2e8f0);
      background-position:
        calc(100% - 18px) calc(50% - 3px),
        calc(100% - 13px) calc(50% - 3px),
        calc(100% - 34px) 50%;
      background-size: 6px 6px, 6px 6px, 1px 18px;
      background-repeat: no-repeat;
    }}
    input:focus, select:focus {{
      outline: none;
      border-color: rgba(239, 68, 68, 0.72);
      box-shadow: 0 0 0 3px rgba(244, 63, 94, 0.16), 0 8px 16px rgba(239, 68, 68, 0.08);
    }}
    input.postal-locked,
    input.postal-locked:focus {{
      background: #f8fafc;
      color: #475569;
      border-color: #cbd5e1;
      box-shadow: none;
      cursor: not-allowed;
    }}
    .row {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; }}
    .row-tight {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 10px; }}
    .employed-only {{ transition: opacity 0.2s ease; }}
    .dashboard-filters {{
      margin-top: 6px;
      padding: 14px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: linear-gradient(180deg, rgba(255, 255, 255, 0.98), rgba(255, 248, 248, 0.98));
    }}
    .filter-actions {{
      margin-top: 10px;
      display: flex;
      justify-content: flex-end;
      gap: 8px;
    }}
    .chart-section {{
      margin-top: 14px;
      padding-top: 12px;
      border-top: 1px solid var(--line);
    }}
    .btn-ghost {{
      margin-top: 0;
      background: #ffffff;
      border: 1px solid #d1d5db;
      color: #334155;
      padding: 7px 11px;
      font-size: 0.88rem;
      box-shadow: none;
    }}
    .btn-soft {{
      background: #fff5f5;
      color: #991b1b;
      border: 1px solid #fca5a5;
    }}
    .btn-danger {{
      background: linear-gradient(140deg, #e11d48, #9d174d);
    }}
    .btn-inline {{
      margin-top: 0;
      min-height: 38px;
    }}
    .table-wrap {{
      border: 1px solid var(--line);
      border-radius: 8px;
      overflow: auto;
      background: #fff;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.92rem;
      overflow: hidden;
    }}
    th, td {{
      border-bottom: 1px solid var(--line);
      padding: 10px 8px;
      text-align: left;
      vertical-align: top;
    }}
    th {{
      font-weight: 700;
      color: #7f1d1d;
      background: linear-gradient(180deg, #fff7f7 0%, #fee2e2 100%);
      border-bottom: 2px solid #fca5a5;
      position: sticky;
      top: 0;
      z-index: 1;
    }}
    tbody tr:nth-child(even) {{
      background: rgba(254, 242, 242, 0.8);
    }}
    tbody tr:hover {{
      background: rgba(254, 226, 226, 0.9);
    }}
    .actions {{
      display: flex;
      gap: 8px;
      align-items: center;
      flex-wrap: wrap;
    }}
    .actions-table {{
      justify-content: flex-end;
      flex-wrap: nowrap;
      gap: 10px;
    }}
    .actions-table form {{
      margin: 0;
    }}
    .btn-action {{
      min-width: 92px;
      min-height: 42px;
      padding: 9px 12px;
    }}
    .actions-right {{
      display: flex;
      justify-content: flex-end;
      gap: 8px;
      align-items: center;
      margin-top: 12px;
    }}
    .status {{
      display: inline-block;
      background: linear-gradient(100deg, #fff5f5, #fff1f2);
      color: #991b1b;
      border: 1px solid #fecaca;
      padding: 5px 10px;
      border-radius: 6px;
      font-size: 0.83rem;
      font-weight: 600;
    }}
    .error-text {{
      color: var(--danger);
      background: rgba(190, 18, 60, 0.09);
      border: 1px solid rgba(190, 18, 60, 0.16);
      padding: 8px 10px;
      border-radius: 6px;
      margin: 10px 0;
    }}
    .postal-feedback {{
      margin: 6px 0 0;
      font-size: 0.82rem;
      line-height: 1.4;
    }}
    .postal-feedback.error {{
      color: #be123c;
      font-weight: 600;
    }}
    .login-grid {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 14px;
      align-items: stretch;
    }}
    .login-side {{
      border: 1px solid var(--line);
      border-radius: 8px;
      background: linear-gradient(155deg, #701a1a 0%, #991b1b 56%, #b91c1c 100%);
      color: #fff5f5;
      padding: 16px;
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.2);
    }}
    @keyframes fade-up {{
      from {{
        opacity: 0;
        transform: translateY(6px);
      }}
      to {{
        opacity: 1;
        transform: translateY(0);
      }}
    }}
    .login-side h3 {{
      margin-top: 0;
      margin-bottom: 10px;
    }}
    .login-side ul {{
      margin: 8px 0 0;
      padding-left: 18px;
      line-height: 1.6;
      font-size: 0.92rem;
    }}
    @media (max-width: 720px) {{
      .topbar {{
        flex-direction: column;
        align-items: flex-start;
      }}
      .nav {{
        justify-content: flex-start;
      }}
      .card {{
        padding: 15px 14px;
      }}
      .login-grid {{
        grid-template-columns: 1fr;
      }}
      .home-layout {{
        grid-template-columns: 1fr;
      }}
      .home-hero-grid {{
        grid-template-columns: 1fr;
      }}
    }}
  </style>
</head>
<body>
  <div class='wrap'>
    <div class='topbar'>
      <div class='brand'><span class='brand-dot'></span>ระบบฐานข้อมูลศิษย์เก่าภาควิชาคณิตศาสตร์</div>
      <div class='nav'>{nav}</div>
    </div>
    {body}
  </div>
</body>
<script>
(() => {{
  const currentBuild = "{SERVER_BUILD_ID}";
  const employedStatuses = new Set(["ได้งานทำตรงสายที่จบ", "ได้งานทำไม่ตรงสายที่จบ"]);
  const postalLookup = {json.dumps(POSTAL_LOOKUP, ensure_ascii=False)};
  const educationMajorOptions = {json.dumps(EDUCATION_MAJOR_OPTIONS, ensure_ascii=False)};
  const allMajorOptions = {json.dumps(ALL_MAJOR_OPTIONS, ensure_ascii=False)};

  function toggleEmploymentFields(form) {{
    const statusSelect = form.querySelector(".employment-select");
    const wraps = form.querySelectorAll(".employed-only");
    if (!statusSelect || !wraps.length) return;
    const show = employedStatuses.has(statusSelect.value);
    for (const wrap of wraps) {{
      wrap.style.display = show ? "" : "none";
      wrap.style.opacity = show ? "1" : "0";
      for (const input of wrap.querySelectorAll("input,select")) {{
        input.disabled = !show;
      }}
    }}
  }}

  function initEmploymentUI() {{
    for (const form of document.querySelectorAll("form")) {{
      const statusSelect = form.querySelector(".employment-select");
      if (!statusSelect) continue;
      statusSelect.addEventListener("change", () => toggleEmploymentFields(form));
      toggleEmploymentFields(form);
    }}
  }}

  function initEducationMajorUI() {{
    for (const form of document.querySelectorAll("form")) {{
      const levelSelect = form.querySelector(".education-level-select");
      const majorSelect = form.querySelector(".major-select");
      if (!levelSelect || !majorSelect) continue;
      const sync = () => {{
        const selectedMajor = majorSelect.dataset.selected || majorSelect.value || "";
        const majors = levelSelect.value ? (educationMajorOptions[levelSelect.value] || []) : allMajorOptions;
        const options = ["<option value=''>-- เลือกสาขา --</option>"];
        for (const major of majors) {{
          const selected = major === selectedMajor ? "selected" : "";
          options.push(`<option value="${{major}}" ${{selected}}>${{major}}</option>`);
        }}
        majorSelect.innerHTML = options.join("");
        majorSelect.dataset.selected = "";
      }};
      levelSelect.addEventListener("change", sync);
      sync();
    }}
  }}

  function initDashboardFilters() {{
    const form = document.querySelector("form.dashboard-filters");
    if (!form) return;
    for (const select of form.querySelectorAll("select")) {{
      select.addEventListener("change", () => form.submit());
    }}
  }}

  function setSubdistrictOptions(select, values, selectedValue) {{
    const options = ["<option value=''>-- เลือกตำบล --</option>"];
    for (const value of values) {{
      const selected = value === selectedValue ? "selected" : "";
      options.push(`<option value="${{value}}" ${{selected}}>${{value}}</option>`);
    }}
    if (selectedValue && !values.includes(selectedValue)) {{
      options.push(`<option value="${{selectedValue}}" selected>${{selectedValue}}</option>`);
    }}
    select.innerHTML = options.join("");
  }}

  function updateDistrictProvinceBySubdistrict(entry, subdistrictValue, district, province) {{
    const mapping = entry && entry.subdistrict_map ? entry.subdistrict_map[subdistrictValue] : null;
    if (mapping) {{
      district.value = mapping.district || "";
      province.value = mapping.province || "";
      return;
    }}
    district.value = (entry && entry.district) || "";
    province.value = (entry && entry.province) || "";
  }}

  function applyPostalLookup(form) {{
    const postal = form.querySelector("input[name='workplace_postal_code']");
    const district = form.querySelector("input[name='workplace_district']");
    const province = form.querySelector("input[name='workplace_province']");
    const subdistrict = form.querySelector("select[name='workplace_subdistrict']");
    const feedback = postal ? postal.parentElement.querySelector(".postal-feedback") : null;
    if (!postal || !district || !province || !subdistrict) return;

    const thaiDigits = "๐๑๒๓๔๕๖๗๘๙";
    const arabicDigits = "0123456789";
    const normalized = postal.value
      .trim()
      .split("")
      .map((ch) => {{
        const i = thaiDigits.indexOf(ch);
        return i >= 0 ? arabicDigits[i] : ch;
      }})
      .join("")
      .replace(/\D/g, "")
      .slice(0, 5);
    if (postal.value !== normalized) {{
      postal.value = normalized;
    }}
    const code = normalized;
    const savedSelected = subdistrict.dataset.selected || subdistrict.value || "";
    const entry = postalLookup[code];
    district.readOnly = true;
    province.readOnly = true;
    district.classList.add("postal-locked");
    province.classList.add("postal-locked");
    if (entry) {{
      setSubdistrictOptions(subdistrict, entry.subdistricts || [], savedSelected);
      updateDistrictProvinceBySubdistrict(entry, subdistrict.value || savedSelected, district, province);
      subdistrict.dataset.selected = "";
      if (feedback) {{
        feedback.textContent = "พบข้อมูลแล้ว ระบบกรอกอำเภอและจังหวัดให้อัตโนมัติ";
        feedback.classList.remove("error");
        feedback.classList.add("muted");
      }}
    }} else {{
      district.value = "";
      province.value = "";
      setSubdistrictOptions(subdistrict, [], "");
      if (feedback) {{
        if (code.length === 5) {{
          feedback.textContent = "ไม่พบรหัสนี้ในฐานข้อมูลระบบ (รหัสอาจถูกต้อง) กรุณาติดต่อผู้ดูแลเพื่อเพิ่มข้อมูล";
          feedback.classList.remove("muted");
          feedback.classList.add("error");
        }} else {{
          feedback.textContent = "กรอกรหัสไปรษณีย์ 5 หลักเพื่อค้นหาอำเภอและจังหวัดอัตโนมัติ";
          feedback.classList.remove("error");
          feedback.classList.add("muted");
        }}
      }}
    }}
  }}

  function initPostalLookupUI() {{
    for (const form of document.querySelectorAll("form")) {{
      const postal = form.querySelector("input[name='workplace_postal_code']");
      const subdistrict = form.querySelector("select[name='workplace_subdistrict']");
      if (!postal) continue;
      postal.addEventListener("input", () => applyPostalLookup(form));
      postal.addEventListener("change", () => applyPostalLookup(form));
      if (subdistrict) {{
        subdistrict.addEventListener("change", () => applyPostalLookup(form));
      }}
      applyPostalLookup(form);
    }}
  }}

  initEmploymentUI();
  initEducationMajorUI();
  initDashboardFilters();
  initPostalLookupUI();
  async function checkBuild() {{
    try {{
      const res = await fetch("/__build", {{ cache: "no-store" }});
      if (!res.ok) return;
      const nextBuild = (await res.text()).trim();
      if (nextBuild && nextBuild !== currentBuild) {{
        window.location.reload();
      }}
    }} catch (_) {{
      // Ignore transient errors while server is restarting.
    }}
  }}
  setInterval(checkBuild, 1200);
}})();
</script>
</html>"""


def esc(value):
    if value is None:
        return ""
    return html.escape(str(value))


def avatar_html(url, name, size="avatar"):
    safe_name = esc(name or "รูปประจำตัว")
    safe_url = esc(url or "")
    if safe_url:
        return f"<img class='{size}' src='{safe_url}' alt='รูปโปรไฟล์ {safe_name}' loading='lazy' />"
    initial = safe_name[:1].upper() if safe_name else "?"
    return f"<div class='{size}' style='display:flex;align-items:center;justify-content:center;font-weight:700;color:#be123c'>{initial}</div>"


def workplace_address_text(house_no, subdistrict, district, province, postal_code):
    parts = []
    if house_no:
        parts.append(f"บ้านเลขที่ {house_no}")
    if subdistrict:
        parts.append(f"ตำบล{subdistrict}")
    if district:
        parts.append(f"อำเภอ{district}")
    if province:
        parts.append(f"จังหวัด{province}")
    if postal_code:
        parts.append(postal_code)
    return " ".join(parts)


def build_avatar_filename(user_id, original_name):
    ext = Path(original_name or "").suffix.lower()
    if ext not in {".png", ".jpg", ".jpeg", ".gif", ".webp"}:
        ext = ".jpg"
    stamp = int(time.time())
    return f"user-{user_id}-{stamp}-{secrets.token_hex(4)}{ext}"


def is_allowed_image_content(content_type):
    return content_type in {"image/jpeg", "image/png", "image/gif", "image/webp"}


def education_level_select(name, selected="", required=False, css_class="education-level-select"):
    selected = selected or ""
    options = []
    if not required:
        options.append("<option value=''>-- เลือกระดับการศึกษา --</option>")
    for level in EDUCATION_LEVEL_OPTIONS:
        is_selected = "selected" if selected == level else ""
        options.append(f"<option value='{esc(level)}' {is_selected}>{esc(level)}</option>")
    req = "required" if required else ""
    return f"<select name='{esc(name)}' class='{esc(css_class)}' {req}>{''.join(options)}</select>"


def major_select(name, selected="", required=False, level=None, css_class=""):
    selected = selected or ""
    level = level or ""
    options_source = major_options_for_level(level) if level else ALL_MAJOR_OPTIONS
    options = []
    if not required:
        options.append("<option value=''>-- เลือกสาขา --</option>")
    for major in options_source:
        is_selected = "selected" if selected == major else ""
        options.append(f"<option value='{esc(major)}' {is_selected}>{esc(major)}</option>")
    req = "required" if required else ""
    cls = f" class='{esc(css_class)}'" if css_class else ""
    return f"<select name='{esc(name)}'{cls} {req}>{''.join(options)}</select>"


def employment_select(name, selected="", required=False, css_class="employment-select"):
    selected = selected or ""
    options = []
    if not required:
        options.append("<option value=''>-- เลือกสถานะการทำงาน --</option>")
    for status in EMPLOYMENT_OPTIONS:
        is_selected = "selected" if selected == status else ""
        options.append(f"<option value='{esc(status)}' {is_selected}>{esc(status)}</option>")
    req = "required" if required else ""
    return f"<select name='{esc(name)}' class='{esc(css_class)}' {req}>{''.join(options)}</select>"


def org_type_select(name, selected="", required=False):
    selected = selected or ""
    options = []
    if not required:
        options.append("<option value=''>-- เลือกประเภทหน่วยงาน --</option>")
    for org_type in ORG_TYPE_OPTIONS:
        is_selected = "selected" if selected == org_type else ""
        options.append(f"<option value='{esc(org_type)}' {is_selected}>{esc(org_type)}</option>")
    req = "required" if required else ""
    return f"<select name='{esc(name)}' {req}>{''.join(options)}</select>"


def income_select(name, selected="", required=False):
    selected = selected or ""
    options = []
    if not required:
        options.append("<option value=''>-- เลือกช่วงรายได้ต่อเดือน --</option>")
    for income in INCOME_OPTIONS:
        is_selected = "selected" if selected == income else ""
        options.append(f"<option value='{esc(income)}' {is_selected}>{esc(income)}</option>")
    req = "required" if required else ""
    return f"<select name='{esc(name)}' {req}>{''.join(options)}</select>"


def subdistrict_select(name, selected="", required=False):
    selected = selected or ""
    req = "required" if required else ""
    placeholder = "-- เลือกตำบล (กรอกรหัสไปรษณีย์ก่อน) --"
    selected_option = f"<option value='{esc(selected)}' selected>{esc(selected)}</option>" if selected else ""
    return (
        f"<select name='{esc(name)}' class='postal-subdistrict' data-selected='{esc(selected)}' {req}>"
        f"<option value=''>{placeholder}</option>{selected_option}"
        "</select>"
    )


def postal_locked_input(name, value=""):
    return f"<input name='{esc(name)}' value='{esc(value)}' class='postal-locked' readonly />"


def postal_code_input(name, value=""):
    normalized = normalize_postal_code(value)
    return (
        f"<input name='{esc(name)}' value='{esc(normalized)}' maxlength='5' inputmode='numeric' pattern='\\d{{5}}' />"
        "<p class='postal-feedback muted' aria-live='polite'>กรอกรหัสไปรษณีย์ 5 หลักเพื่อค้นหาอำเภอและจังหวัดอัตโนมัติ</p>"
    )


def parse_employment_form(form):
    status = (form.get("employment_status") or "").strip()
    if status not in EMPLOYMENT_OPTIONS:
        return None, "กรุณาเลือกสถานะการทำงานให้ถูกต้อง"

    organization_type = (form.get("organization_type") or "").strip() or None
    monthly_income = (form.get("monthly_income") or "").strip() or None
    company = (form.get("company") or "").strip() or None
    job_title = (form.get("job_title") or "").strip() or None
    workplace_house_no = (form.get("workplace_house_no") or "").strip() or None
    workplace_subdistrict = (form.get("workplace_subdistrict") or "").strip() or None
    workplace_district = (form.get("workplace_district") or "").strip() or None
    workplace_province = (form.get("workplace_province") or "").strip() or None
    workplace_postal_code = normalize_postal_code(form.get("workplace_postal_code")) or None

    if status in EMPLOYED_STATUSES:
        if not company or not job_title or not organization_type or not monthly_income:
            return None, "กรุณากรอกตำแหน่งงาน ประเภทหน่วยงาน สถานที่ทำงาน และรายได้ต่อเดือนให้ครบถ้วน"
        if not workplace_house_no or not workplace_subdistrict or not workplace_postal_code:
            return None, "กรุณากรอกที่อยู่สถานที่ทำงานให้ครบ: บ้านเลขที่ ตำบล และรหัสไปรษณีย์"
        if not re.fullmatch(r"\d{5}", workplace_postal_code):
            return None, "กรุณากรอกรหัสไปรษณีย์ 5 หลักให้ถูกต้อง"
        postal_entry = POSTAL_LOOKUP.get(workplace_postal_code)
        if not postal_entry:
            return None, "รหัสไปรษณีย์นี้ยังไม่ถูกเพิ่มในระบบ กรุณาติดต่อผู้ดูแลเพื่ออัปเดตฐานข้อมูลรหัสไปรษณีย์"
        subdistrict_map = postal_entry.get("subdistrict_map") or {}
        location = subdistrict_map.get(workplace_subdistrict)
        if not location:
            return None, "กรุณาเลือกตำบลให้ตรงกับรหัสไปรษณีย์"
        workplace_district = location.get("district") or postal_entry.get("district") or None
        workplace_province = location.get("province") or postal_entry.get("province") or None
        if not workplace_district or not workplace_province:
            return None, "รหัสไปรษณีย์นี้ยังไม่ถูกเพิ่มในระบบ กรุณาติดต่อผู้ดูแลเพื่ออัปเดตฐานข้อมูลรหัสไปรษณีย์"
        if organization_type not in ORG_TYPE_OPTIONS:
            return None, "กรุณาเลือกประเภทหน่วยงานให้ถูกต้อง"
        if monthly_income not in INCOME_OPTIONS:
            return None, "กรุณาเลือกรายได้เฉลี่ยต่อเดือนให้ถูกต้อง"
    else:
        organization_type = None
        monthly_income = None
        company = None
        job_title = None
        workplace_house_no = None
        workplace_subdistrict = None
        workplace_district = None
        workplace_province = None
        workplace_postal_code = None

    return {
        "employment_status": status,
        "organization_type": organization_type,
        "monthly_income": monthly_income,
        "company": company,
        "job_title": job_title,
        "workplace_house_no": workplace_house_no,
        "workplace_subdistrict": workplace_subdistrict,
        "workplace_district": workplace_district,
        "workplace_province": workplace_province,
        "workplace_postal_code": workplace_postal_code,
    }, None


class AlumniHandler(BaseHTTPRequestHandler):
    def send_html(self, status, title, content, user=None):
        page = html_page(title, content, user=user)
        body = page.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    def absolute_url(self, path):
        host = self.headers.get("Host", f"{HOST}:{PORT}")
        return f"http://{host}{path}"

    def send_csv(self, filename, content_text):
        data = ("\ufeff" + content_text).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def parse_form(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8")
        form = parse_qs(raw)
        return {k: v[0].strip() for k, v in form.items()}

    def parse_multipart(self):
        content_type = self.headers.get("Content-Type", "")
        match = re.search(r'boundary="?([^";]+)"?', content_type)
        if "multipart/form-data" not in content_type or not match:
            return {}

        boundary = match.group(1).encode("utf-8")
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        parts = raw.split(b"--" + boundary)
        parsed = {}

        for part in parts:
            part = part.strip()
            if not part or part == b"--":
                continue
            header_blob, separator, payload = part.partition(b"\r\n\r\n")
            if not separator:
                continue
            headers = {}
            for line in header_blob.decode("utf-8", errors="ignore").split("\r\n"):
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip().lower()] = value.strip()

            disp = headers.get("content-disposition", "")
            name_match = re.search(r'name="([^"]+)"', disp)
            if not name_match:
                continue
            field_name = name_match.group(1)
            if payload.endswith(b"\r\n"):
                payload = payload[:-2]

            file_match = re.search(r'filename="([^"]*)"', disp)
            if file_match and file_match.group(1):
                parsed[field_name] = {
                    "filename": file_match.group(1),
                    "content_type": headers.get("content-type", ""),
                    "data": payload,
                }
            else:
                parsed[field_name] = payload.decode("utf-8", errors="ignore").strip()

        return parsed

    def send_binary_file(self, file_path):
        if not file_path.exists() or not file_path.is_file():
            self.send_html(404, "ไม่พบไฟล์", "<div class='card'><h2>404</h2><p>ไม่พบไฟล์ที่ร้องขอ</p></div>")
            return
        data = file_path.read_bytes()
        content_type = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "public, max-age=86400")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def current_user(self):
        cookie_header = self.headers.get("Cookie")
        if not cookie_header:
            return None
        jar = cookies.SimpleCookie()
        jar.load(cookie_header)
        if "session" not in jar:
            return None
        user_id = decode_session(jar["session"].value)
        if not user_id:
            return None
        conn = db_conn()
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        conn.close()
        return user

    def set_session(self, user_id):
        token = encode_session(user_id)
        self.send_header("Set-Cookie", f"session={token}; HttpOnly; Path=/; SameSite=Lax")

    def clear_session(self):
        self.send_header("Set-Cookie", "session=deleted; Max-Age=0; HttpOnly; Path=/; SameSite=Lax")

    def require_auth(self):
        user = self.current_user()
        if not user:
            self.redirect("/login")
            return None
        return user

    def require_admin(self):
        user = self.require_auth()
        if not user:
            return None
        if user["role"] != "admin":
            self.send_html(403, "ไม่มีสิทธิ์เข้าถึง", "<div class='card'><h2>ไม่มีสิทธิ์เข้าถึง</h2><p>หน้านี้สำหรับผู้ดูแลระบบเท่านั้น</p></div>", user=user)
            return None
        return user

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path == "/__build":
            body = SERVER_BUILD_ID.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if path.startswith("/uploads/"):
            filename = os.path.basename(path.replace("/uploads/", "", 1))
            if not filename:
                self.send_html(404, "ไม่พบไฟล์", "<div class='card'><h2>404</h2><p>ไม่พบไฟล์ที่ร้องขอ</p></div>")
                return
            self.send_binary_file(UPLOAD_DIR / filename)
            return

        if path == "/":
            user = self.current_user()
            major_filter = qs.get("major", [""])[0].strip()
            if major_filter not in ALL_MAJOR_OPTIONS:
                major_filter = ""
            level_filter = qs.get("education_level", [""])[0].strip()
            if level_filter not in EDUCATION_LEVEL_OPTIONS:
                level_filter = ""
            intake_filter = qs.get("intake", [""])[0].strip()
            conn = db_conn()
            intake_options = [
                row["intake"]
                for row in conn.execute(
                    "SELECT DISTINCT substr(student_id, 1, 2) AS intake FROM users WHERE role='alumni' AND student_id IS NOT NULL AND length(student_id) >= 2 AND substr(student_id, 1, 2) GLOB '[0-9][0-9]' ORDER BY intake DESC"
                ).fetchall()
                if row["intake"]
            ]
            if intake_filter not in intake_options:
                intake_filter = ""
            where_clause = "WHERE role='alumni'"
            params = []
            if level_filter:
                where_clause += " AND education_level = ?"
                params.append(level_filter)
            if major_filter:
                where_clause += " AND major = ?"
                params.append(major_filter)
            if intake_filter:
                where_clause += " AND substr(student_id, 1, 2) = ?"
                params.append(intake_filter)

            alumni_count = conn.execute(f"SELECT COUNT(*) AS c FROM users {where_clause}", params).fetchone()["c"]
            level_counts = {
                row["education_level"]: row["c"]
                for row in conn.execute(
                    f"SELECT education_level, COUNT(*) AS c FROM users {where_clause} GROUP BY education_level",
                    params,
                ).fetchall()
            }
            status_counts = {status: 0 for status in EMPLOYMENT_OPTIONS}
            status_rows = conn.execute(
                f"SELECT employment_status, COUNT(*) AS c FROM users {where_clause} GROUP BY employment_status",
                params,
            ).fetchall()
            for row in status_rows:
                if row["employment_status"] in status_counts:
                    status_counts[row["employment_status"]] = row["c"]
            employed_count = status_counts["ได้งานทำตรงสายที่จบ"] + status_counts["ได้งานทำไม่ตรงสายที่จบ"]
            employed_rate = 0.0 if alumni_count == 0 else (employed_count * 100.0 / alumni_count)
            employed_where = f"{where_clause} AND employment_status IN (?, ?)"
            employed_params = [*params, EMPLOYED_STATUSES[0], EMPLOYED_STATUSES[1]]
            org_counts = {org_type: 0 for org_type in ORG_TYPE_OPTIONS}
            org_rows = conn.execute(
                f"SELECT organization_type, COUNT(*) AS c FROM users {employed_where} GROUP BY organization_type",
                employed_params,
            ).fetchall()
            for row in org_rows:
                org_type = row["organization_type"] if row["organization_type"] in ORG_TYPE_OPTIONS else None
                if org_type:
                    org_counts[org_type] = row["c"]
            income_counts = {income: 0 for income in INCOME_OPTIONS}
            income_rows = conn.execute(
                f"SELECT monthly_income, COUNT(*) AS c FROM users {employed_where} AND monthly_income IS NOT NULL GROUP BY monthly_income",
                employed_params,
            ).fetchall()
            for row in income_rows:
                income = row["monthly_income"] if row["monthly_income"] in INCOME_OPTIONS else None
                if income:
                    income_counts[income] = row["c"]
            total_with_province = conn.execute(
                f"SELECT COUNT(*) AS c FROM users {employed_where} AND workplace_province IS NOT NULL AND TRIM(workplace_province) != ''",
                employed_params,
            ).fetchone()["c"]
            province_rows = conn.execute(
                f"""
                SELECT workplace_province AS province, COUNT(*) AS c
                FROM users {employed_where} AND workplace_province IS NOT NULL AND TRIM(workplace_province) != ''
                GROUP BY workplace_province
                ORDER BY c DESC, workplace_province ASC
                LIMIT 5
                """,
                employed_params,
            ).fetchall()
            conn.close()

            total_status = sum(status_counts.values())
            chart_rows = []
            for status in EMPLOYMENT_OPTIONS:
                count = status_counts.get(status, 0)
                pct = 0.0 if total_status == 0 else (count * 100.0 / total_status)
                width = max(0, min(100, pct))
                chart_rows.append(
                    f"<div class='chart-row'><div class='chart-meta'><div class='chart-label'>{esc(status)}</div><div class='chart-sub'>{count} คน</div></div><div class='chart-track'><div class='chart-fill' style='width:{width:.1f}%;'></div></div><div class='chart-count'>{pct:.1f}%</div></div>"
                )
            chart_html = f"<div class='chart-head'><span>ฐานข้อมูล</span><span>{total_status} คน</span></div>" + "".join(chart_rows)
            total_org = sum(org_counts.values())
            org_chart_rows = []
            for org_type in ORG_TYPE_OPTIONS:
                count = org_counts.get(org_type, 0)
                pct = 0.0 if total_org == 0 else (count * 100.0 / total_org)
                width = max(0, min(100, pct))
                org_chart_rows.append(
                    f"<div class='chart-row'><div class='chart-meta'><div class='chart-label'>{esc(org_type)}</div><div class='chart-sub'>{count} คน</div></div><div class='chart-track'><div class='chart-fill chart-fill-org' style='width:{width:.1f}%;'></div></div><div class='chart-count'>{pct:.1f}%</div></div>"
                )
            org_chart_html = f"<div class='chart-head'><span>ฐานผู้มีงานทำ</span><span>{total_org} คน</span></div>" + "".join(org_chart_rows)
            total_income = sum(income_counts.values())
            income_chart_rows = []
            for income in INCOME_OPTIONS:
                count = income_counts.get(income, 0)
                pct = 0.0 if total_income == 0 else (count * 100.0 / total_income)
                width = max(0, min(100, pct))
                income_chart_rows.append(
                    f"<div class='chart-row'><div class='chart-meta'><div class='chart-label'>{esc(income)}</div><div class='chart-sub'>{count} คน</div></div><div class='chart-track'><div class='chart-fill chart-fill-income' style='width:{width:.1f}%;'></div></div><div class='chart-count'>{pct:.1f}%</div></div>"
                )
            income_chart_html = f"<div class='chart-head'><span>ฐานผู้มีรายได้</span><span>{total_income} คน</span></div>" + "".join(income_chart_rows)
            province_chart_rows = []
            for row in province_rows:
                count = row["c"]
                pct = 0.0 if total_with_province == 0 else (count * 100.0 / total_with_province)
                width = max(0, min(100, pct))
                province_chart_rows.append(
                    f"<div class='chart-row'><div class='chart-meta'><div class='chart-label'>{esc(row['province'])}</div><div class='chart-sub'>{count} คน</div></div><div class='chart-track'><div class='chart-fill chart-fill-province' style='width:{width:.1f}%;'></div></div><div class='chart-count'>{pct:.1f}%</div></div>"
                )
            province_chart_html = (
                f"<div class='chart-head'><span>ฐานผู้ระบุจังหวัด</span><span>{total_with_province} คน</span></div>"
                + ("".join(province_chart_rows) if province_chart_rows else "<div class='chart-empty'>ยังไม่มีข้อมูลจังหวัดที่ทำงาน</div>")
            )
            intake_options_html = "".join(
                f"<option value='{esc(code)}' {'selected' if intake_filter == code else ''}>ปีรับเข้า {esc(code)}</option>"
                for code in intake_options
            )

            body = f"""
            <div class='card'>
              <div class='home-hero'>
                <div class='home-hero-grid'>
                  <div>
                    <h1 class='home-title'>ข้อมูลภาพรวมของศิษย์เก่า</h1>
                    <p>สำรวจแนวโน้มสถานะการทำงานและประเภทหน่วยงาน ด้วยตัวกรองสาขาและปีรับเข้า</p>
                    <div class='hero-actions'>
                      <a class='btn btn-inline' href='/login'>เข้าสู่ระบบ</a>
                      <a class='nav-link btn-inline' href='/register'>สมัครสมาชิกศิษย์เก่า</a>
                    </div>
                  </div>
                  <div class='home-hero-media'>
                    <img src='{esc(HOME_HERO_IMAGE_URL)}' alt='ภาพบรรยากาศพิธีรับปริญญา' loading='lazy' />
                  </div>
                </div>
              </div>
              <form method='get' action='/' class='dashboard-filters'>
                <div class='row-tight'>
                  <div><label>กรองตามระดับการศึกษา</label>{education_level_select("education_level", level_filter)}</div>
                  <div><label>กรองตามสาขา</label>{major_select("major", major_filter, level=level_filter, css_class="major-select")}</div>
                  <div><label>กรองตามปีที่รับเข้า</label><select name='intake'><option value=''>-- ทุกปีรับเข้า --</option>{intake_options_html}</select></div>
                </div>
              </form>
              <div class='kpi-grid'>
                <div class='kpi'><div class='label'>จำนวนศิษย์เก่าที่แสดง</div><div class='value'>{alumni_count}</div></div>
                <div class='kpi'><div class='label'>อัตรามีงานทำ</div><div class='value'>{employed_rate:.1f}%</div></div>
                <div class='kpi'><div class='label'>ปริญญาตรี</div><div class='value'>{level_counts.get("ปริญญาตรี", 0)}</div></div>
                <div class='kpi'><div class='label'>ปริญญาโท</div><div class='value'>{level_counts.get("ปริญญาโท", 0)}</div></div>
                <div class='kpi'><div class='label'>ปริญญาเอก</div><div class='value'>{level_counts.get("ปริญญาเอก", 0)}</div></div>
              </div>
              <div class='home-layout'>
                <div class='home-panel'>
                  <div class='section-head'>
                    <h2>สถานะการทำงาน</h2>
                    <span class='status'>{esc(level_filter) if level_filter else "ทุกระดับ"} | {esc(major_filter) if major_filter else "ทุกสาขา"} | {('ปี ' + esc(intake_filter)) if intake_filter else "ทุกปีรับเข้า"}</span>
                  </div>
                  <div class='chart compact'>{chart_html}</div>
                </div>
                <div class='home-panel'>
                  <div class='section-head'>
                    <h2>ประเภทหน่วยงาน</h2>
                    <span class='status'>นับเฉพาะผู้ที่ได้งานทำ</span>
                  </div>
                  <div class='chart compact'>{org_chart_html}</div>
                </div>
                <div class='home-panel'>
                  <div class='section-head'>
                    <h2>เงินเดือน/รายได้เฉลี่ยต่อเดือน</h2>
                    <span class='status'>เฉพาะผู้ที่มีรายได้</span>
                  </div>
                  <div class='chart compact'>{income_chart_html}</div>
                </div>
                <div class='home-panel'>
                  <div class='section-head'>
                    <h2>จังหวัดที่ทำงาน</h2>
                    <span class='status'>Top 5 จังหวัด</span>
                  </div>
                  <div class='chart compact'>{province_chart_html}</div>
                </div>
              </div>
              <div class='login-cta'>
                <div>
                  <strong>จัดการข้อมูลเพิ่มเติม</strong>
                  <p class='muted'>เข้าสู่ระบบเพื่อดูรายละเอียดรายบุคคลและจัดการข้อมูลศิษย์เก่า</p>
                </div>
                <a class='btn btn-inline' href='/login'>ไปหน้าเข้าสู่ระบบ</a>
              </div>
            </div>
            """
            self.send_html(200, "หน้าแรก", body, user=user)
            return

        if path == "/login":
            msg = qs.get("msg", [""])[0]
            body = f"""
            <div class='card'>
              <div class='section-head'>
                <div class='hero'>
                  <h1 class='hero-title'>แพลตฟอร์มเครือข่ายศิษย์เก่า</h1>
                  <p class='muted'>เข้าสู่ระบบเพื่อจัดการข้อมูลส่วนตัว ค้นหาศิษย์เก่า และอัปเดตฐานข้อมูลกลาง</p>
                </div>
              </div>
              <div class='login-grid'>
                <div>
                  {f"<p class='error-text'>{esc(msg)}</p>" if msg else ""}
                  <form method='post' action='/login'>
                    <label>อีเมล</label>
                    <input type='email' name='email' placeholder='name@example.com' required />
                    <label>รหัสผ่าน</label>
                    <input type='password' name='password' placeholder='กรอกรหัสผ่าน' required />
                    <button type='submit'>เข้าสู่ระบบ</button>
                  </form>
                  <p class='muted' style='margin-top:10px'>ยังไม่มีบัญชี? <a href='/register'>สมัครสมาชิกใหม่</a> | <a href='/forgot-password'>ลืมรหัสผ่าน</a></p>
                </div>
                <div class='login-side'>
                  <h3>คำแนะนำการใช้งาน</h3>
                  <ul>
                    <li>หากยังไม่มีบัญชี สามารถสมัครสมาชิกได้ทันที</li>
                    <li>กรณีลืมรหัสผ่าน สามารถขอลิงก์รีเซ็ตรหัสผ่านได้</li>
                  </ul>
                </div>
              </div>
            </div>
            """
            self.send_html(200, "เข้าสู่ระบบ", body)
            return

        if path == "/forgot-password":
            msg = qs.get("msg", [""])[0]
            body = f"""
            <div class='card'>
              <div class='section-head'>
                <div class='hero'>
                  <span class='status'>ลืมรหัสผ่าน</span>
                  <h1 class='hero-title'>ขอตั้งรหัสผ่านใหม่</h1>
                  <p class='muted'>กรอกอีเมลที่ใช้สมัคร ระบบจะส่งลิงก์สำหรับตั้งรหัสผ่านใหม่ไปให้</p>
                </div>
              </div>
              {f"<p class='status'>{esc(msg)}</p>" if msg else ""}
              <form method='post' action='/forgot-password'>
                <label>อีเมล</label>
                <input type='email' name='email' required />
                <button type='submit'>ส่งลิงก์รีเซ็ตรหัสผ่าน</button>
              </form>
            </div>
            """
            self.send_html(200, "ลืมรหัสผ่าน", body)
            return

        if path == "/reset-password":
            token = qs.get("token", [""])[0].strip()
            if not token:
                self.send_html(400, "ลิงก์ไม่ถูกต้อง", "<div class='card'><h2>ลิงก์ไม่ถูกต้อง</h2><p>ไม่พบ token สำหรับรีเซ็ตรหัสผ่าน</p></div>")
                return
            msg = qs.get("msg", [""])[0]
            body = f"""
            <div class='card'>
              <div class='section-head'>
                <div class='hero'>
                  <span class='status'>ตั้งรหัสผ่านใหม่</span>
                  <h1 class='hero-title'>รีเซ็ตรหัสผ่าน</h1>
                  <p class='muted'>กรอกรหัสผ่านใหม่ 2 ครั้งเพื่อยืนยัน</p>
                </div>
              </div>
              {f"<p class='error-text'>{esc(msg)}</p>" if msg else ""}
              <form method='post' action='/reset-password'>
                <input type='hidden' name='token' value='{esc(token)}' />
                <label>รหัสผ่านใหม่</label>
                <input type='password' name='password' required />
                <label>ยืนยันรหัสผ่านใหม่</label>
                <input type='password' name='confirm_password' required />
                <button type='submit'>บันทึกรหัสผ่านใหม่</button>
              </form>
            </div>
            """
            self.send_html(200, "รีเซ็ตรหัสผ่าน", body)
            return

        if path == "/register":
            msg = qs.get("msg", [""])[0]
            body = f"""
            <div class='card'>
              <div class='section-head'>
                <div class='hero'>
                  <span class='status'>ผู้ใช้ใหม่</span>
                  <h1 class='hero-title'>สมัครสมาชิกศิษย์เก่า</h1>
                  <p class='muted'>สร้างบัญชีเพื่อจัดการโปรไฟล์และเข้าถึงเครือข่ายศิษย์เก่า</p>
                </div>
              </div>
              {f"<p class='error-text'>{esc(msg)}</p>" if msg else ""}
              <form method='post' action='/register'>
                <div class='form-section'>
                  <h3 class='form-section-title'>ข้อมูลส่วนตัว</h3>
                  <div class='row'>
                    <div><label>ชื่อ - นามสกุล</label><input name='full_name' required /></div>
                    <div><label>รหัสนิสิต</label><input name='student_id' required /></div>
                  </div>
                  <div class='row'>
                    <div><label>ระดับการศึกษา</label>{education_level_select("education_level", "ปริญญาตรี", required=True)}</div>
                    <div><label>สาขา</label>{major_select("major", level="ปริญญาตรี", required=True, css_class="major-select")}</div>
                    <div><label>อีเมล</label><input type='email' name='email' required /></div>
                    <div><label>รหัสผ่าน</label><input type='password' name='password' required /></div>
                  </div>
                </div>
                <div class='form-section'>
                  <h3 class='form-section-title'>ข้อมูลการทำงาน</h3>
                  <div class='row'>
                    <div><label>สถานะการทำงาน</label>{employment_select("employment_status", required=True)}</div>
                  </div>
                  <div class='row employed-only'>
                    <div><label>ตำแหน่งงาน</label><input name='job_title' /></div>
                    <div><label>ประเภทหน่วยงาน</label>{org_type_select("organization_type")}</div>
                    <div><label>เงินเดือน/รายได้เฉลี่ยต่อเดือน</label>{income_select("monthly_income")}</div>
                    <div><label>สถานที่ทำงาน</label><input name='company' /></div>
                  </div>
                  <div class='row employed-only'>
                    <div><label>บ้านเลขที่</label><input name='workplace_house_no' /></div>
                    <div><label>รหัสไปรษณีย์</label>{postal_code_input("workplace_postal_code")}</div>
                    <div><label>ตำบล</label>{subdistrict_select("workplace_subdistrict")}</div>
                    <div><label>อำเภอ</label>{postal_locked_input("workplace_district")}</div>
                    <div><label>จังหวัด</label>{postal_locked_input("workplace_province")}</div>
                  </div>
                </div>
                <button type='submit'>สมัครสมาชิก</button>
              </form>
            </div>
            """
            self.send_html(200, "สมัครสมาชิก", body)
            return

        if path == "/dashboard":
            user = self.require_auth()
            if not user:
                return
            msg = qs.get("msg", [""])[0]
            err = qs.get("err", [""])[0]
            role_text = "ผู้ดูแลระบบ" if user["role"] == "admin" else "ศิษย์เก่า"
            workplace_text = workplace_address_text(
                user["workplace_house_no"],
                user["workplace_subdistrict"],
                user["workplace_district"],
                user["workplace_province"],
                user["workplace_postal_code"],
            )
            profile_block = self.profile_form_html(user, self.path)
            body = f"""
            <div class='card'>
              <div class='section-head'>
                <div class='hero'>
                  <h1 class='hero-title'>ข้อมูลส่วนตัว</h1>
                  <p class='muted'>แสดงข้อมูลบัญชีของคุณ และสามารถแก้ไขได้จากฟอร์มด้านล่าง</p>
                </div>
              </div>
              {f"<p class='status'>{esc(msg)}</p>" if msg else ""}
              {f"<p class='error-text'>{esc(err)}</p>" if err else ""}
              <div class='avatar-row' style='margin-bottom:12px'>
                {avatar_html(user["avatar_url"], user["full_name"], "avatar-lg")}
                <div>
                  <div style='font-size:1.1rem;font-weight:700'>{esc(user["full_name"])}</div>
                  <div class='muted'>{esc(user["email"])} | {role_text}</div>
                </div>
              </div>
              <div class='row'>
                <div><label>รหัสนิสิต</label><input value='{esc(user["student_id"] or "-")}' readonly /></div>
                <div><label>ระดับการศึกษา</label><input value='{esc(user["education_level"] or "-")}' readonly /></div>
                <div><label>สาขา</label><input value='{esc(user["major"] or "-")}' readonly /></div>
                <div><label>สถานะการทำงาน</label><input value='{esc(user["employment_status"] or "-")}' readonly /></div>
                <div><label>ตำแหน่งงาน</label><input value='{esc(user["job_title"] or "-")}' readonly /></div>
              </div>
              <div class='row'>
                <div><label>สถานที่ทำงาน</label><input value='{esc(user["company"] or "-")}' readonly /></div>
                <div><label>ประเภทหน่วยงาน</label><input value='{esc(user["organization_type"] or "-")}' readonly /></div>
                <div><label>รายได้เฉลี่ยต่อเดือน</label><input value='{esc(user["monthly_income"] or "-")}' readonly /></div>
                <div><label>ที่อยู่สถานที่ทำงาน</label><input value='{esc(workplace_text or "-")}' readonly /></div>
              </div>
            </div>
            {profile_block}
            """
            self.send_html(200, "ข้อมูลส่วนตัว", body, user=user)
            return

        if path == "/search":
            user = self.require_admin()
            if not user:
                return
            self.redirect("/admin/users")
            return

        if path == "/admin/users/export.csv":
            user = self.require_admin()
            if not user:
                return
            query_name = qs.get("name", [""])[0].strip()
            role_filter = qs.get("role", [""])[0].strip()
            if role_filter not in {"", "admin", "alumni"}:
                role_filter = ""
            level_filter = qs.get("education_level", [""])[0].strip()
            if level_filter not in EDUCATION_LEVEL_OPTIONS:
                level_filter = ""
            major_filter = qs.get("major", [""])[0].strip()
            if major_filter not in ALL_MAJOR_OPTIONS:
                major_filter = ""
            status_filter = qs.get("employment_status", [""])[0].strip()
            if status_filter not in EMPLOYMENT_OPTIONS:
                status_filter = ""
            intake_filter = qs.get("intake", [""])[0].strip()
            if not re.fullmatch(r"\d{2}", intake_filter or ""):
                intake_filter = ""
            sort_key = qs.get("sort", ["name_asc"])[0].strip()
            sort_map = {
                "name_asc": "full_name COLLATE NOCASE ASC",
                "name_desc": "full_name COLLATE NOCASE DESC",
                "role_asc": "CASE role WHEN 'alumni' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END ASC",
                "role_desc": "CASE role WHEN 'admin' THEN 0 WHEN 'alumni' THEN 1 ELSE 2 END ASC",
                "major_asc": "major COLLATE NOCASE ASC",
                "major_desc": "major COLLATE NOCASE DESC",
            }
            order_by = sort_map.get(sort_key, sort_map["name_asc"])
            filter_clauses = []
            filter_params = []
            if query_name:
                filter_clauses.append("full_name LIKE ?")
                filter_params.append(f"%{query_name}%")
            if role_filter:
                filter_clauses.append("role = ?")
                filter_params.append(role_filter)
            if level_filter:
                filter_clauses.append("education_level = ?")
                filter_params.append(level_filter)
            if major_filter:
                filter_clauses.append("major = ?")
                filter_params.append(major_filter)
            if status_filter:
                filter_clauses.append("employment_status = ?")
                filter_params.append(status_filter)
            if intake_filter:
                filter_clauses.append("substr(student_id, 1, 2) = ?")
                filter_params.append(intake_filter)
            users_sql = (
                "SELECT id, email, role, full_name, student_id, education_level, major, employment_status, organization_type, monthly_income, "
                "company, job_title, workplace_house_no, workplace_subdistrict, workplace_district, workplace_province, workplace_postal_code "
                "FROM users"
            )
            if filter_clauses:
                users_sql += " WHERE " + " AND ".join(filter_clauses)
            users_sql += f" ORDER BY {order_by}, id ASC"
            conn = db_conn()
            rows = conn.execute(users_sql, filter_params).fetchall()
            conn.close()

            out = io.StringIO()
            writer = csv.writer(out)
            writer.writerow(
                [
                    "id",
                    "full_name",
                    "email",
                    "role",
                    "student_id",
                    "education_level",
                    "major",
                    "employment_status",
                    "organization_type",
                    "monthly_income",
                    "company",
                    "job_title",
                    "workplace_address",
                ]
            )
            for r in rows:
                writer.writerow(
                    [
                        r["id"],
                        r["full_name"] or "",
                        r["email"] or "",
                        r["role"] or "",
                        r["student_id"] or "",
                        r["education_level"] or "",
                        r["major"] or "",
                        r["employment_status"] or "",
                        r["organization_type"] or "",
                        r["monthly_income"] or "",
                        r["company"] or "",
                        r["job_title"] or "",
                        workplace_address_text(
                            r["workplace_house_no"],
                            r["workplace_subdistrict"],
                            r["workplace_district"],
                            r["workplace_province"],
                            r["workplace_postal_code"],
                        ),
                    ]
                )
            stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime())
            self.send_csv(f"admin-users-{stamp}.csv", out.getvalue())
            return

        if path == "/admin/users":
            user = self.require_admin()
            if not user:
                return
            query_name = qs.get("name", [""])[0].strip()
            role_filter = qs.get("role", [""])[0].strip()
            if role_filter not in {"", "admin", "alumni"}:
                role_filter = ""
            level_filter = qs.get("education_level", [""])[0].strip()
            if level_filter not in EDUCATION_LEVEL_OPTIONS:
                level_filter = ""
            major_filter = qs.get("major", [""])[0].strip()
            if major_filter not in ALL_MAJOR_OPTIONS:
                major_filter = ""
            status_filter = qs.get("employment_status", [""])[0].strip()
            if status_filter not in EMPLOYMENT_OPTIONS:
                status_filter = ""
            intake_filter = qs.get("intake", [""])[0].strip()
            sort_key = qs.get("sort", ["name_asc"])[0].strip()
            sort_map = {
                "name_asc": "full_name COLLATE NOCASE ASC",
                "name_desc": "full_name COLLATE NOCASE DESC",
                "role_asc": "CASE role WHEN 'alumni' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END ASC",
                "role_desc": "CASE role WHEN 'admin' THEN 0 WHEN 'alumni' THEN 1 ELSE 2 END ASC",
                "major_asc": "major COLLATE NOCASE ASC",
                "major_desc": "major COLLATE NOCASE DESC",
            }
            order_by = sort_map.get(sort_key, sort_map["name_asc"])
            audit_user_id = qs.get("audit_user_id", [""])[0].strip()
            if not audit_user_id.isdigit():
                audit_user_id = ""
            audit_action = qs.get("audit_action", [""])[0].strip()
            if audit_action and audit_action not in AUDIT_ACTION_OPTIONS:
                audit_action = ""
            edit_id_text = qs.get("edit_id", [""])[0].strip()
            edit_id = None
            if edit_id_text.isdigit():
                edit_id = int(edit_id_text)
            conn = db_conn()
            intake_options = [
                row["intake"]
                for row in conn.execute(
                    "SELECT DISTINCT substr(student_id, 1, 2) AS intake FROM users WHERE student_id IS NOT NULL AND length(student_id) >= 2 AND substr(student_id, 1, 2) GLOB '[0-9][0-9]' ORDER BY intake DESC"
                ).fetchall()
                if row["intake"]
            ]
            if intake_filter not in intake_options:
                intake_filter = ""
            total_user_count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
            filter_clauses = []
            filter_params = []
            if query_name:
                filter_clauses.append("full_name LIKE ?")
                filter_params.append(f"%{query_name}%")
            if role_filter:
                filter_clauses.append("role = ?")
                filter_params.append(role_filter)
            if level_filter:
                filter_clauses.append("education_level = ?")
                filter_params.append(level_filter)
            if major_filter:
                filter_clauses.append("major = ?")
                filter_params.append(major_filter)
            if status_filter:
                filter_clauses.append("employment_status = ?")
                filter_params.append(status_filter)
            if intake_filter:
                filter_clauses.append("substr(student_id, 1, 2) = ?")
                filter_params.append(intake_filter)
            users_sql = "SELECT id, email, role, full_name, avatar_url, student_id, education_level, major, employment_status, organization_type, monthly_income, company, job_title, workplace_house_no, workplace_subdistrict, workplace_district, workplace_province, workplace_postal_code FROM users"
            if filter_clauses:
                users_sql += " WHERE " + " AND ".join(filter_clauses)
            users_sql += f" ORDER BY {order_by}, id ASC"
            rows = conn.execute(users_sql, filter_params).fetchall()
            audit_clauses = []
            audit_params = []
            if audit_user_id:
                audit_clauses.append("a.user_id = ?")
                audit_params.append(int(audit_user_id))
            if audit_action:
                audit_clauses.append("a.action = ?")
                audit_params.append(audit_action)
            audit_sql = """
                SELECT
                    a.id,
                    a.actor_id,
                    a.user_id,
                    a.action,
                    a.changes_json,
                    a.created_at,
                    actor.full_name AS actor_name,
                    target.full_name AS target_name
                FROM audit_logs a
                LEFT JOIN users actor ON actor.id = a.actor_id
                LEFT JOIN users target ON target.id = a.user_id
            """
            if audit_clauses:
                audit_sql += " WHERE " + " AND ".join(audit_clauses)
            audit_sql += " ORDER BY a.created_at DESC, a.id DESC LIMIT 200"
            audit_rows = conn.execute(audit_sql, audit_params).fetchall()
            conn.close()
            edit_row = next((r for r in rows if r["id"] == edit_id), None)
            row_html = "".join(
                self.admin_list_row_html(
                    r,
                    edit_id,
                    query_name,
                    role_filter,
                    level_filter,
                    major_filter,
                    status_filter,
                    intake_filter,
                    sort_key,
                )
                for r in rows
            )
            role_filter_options = (
                f"<option value='' {'selected' if not role_filter else ''}>ทุกบทบาท</option>"
                f"<option value='alumni' {'selected' if role_filter == 'alumni' else ''}>ศิษย์เก่า</option>"
                f"<option value='admin' {'selected' if role_filter == 'admin' else ''}>ผู้ดูแลระบบ</option>"
            )
            status_filter_options = (
                f"<option value='' {'selected' if not status_filter else ''}>ทุกสถานะ</option>"
                + "".join(
                    f"<option value='{esc(status)}' {'selected' if status_filter == status else ''}>{esc(status)}</option>"
                    for status in EMPLOYMENT_OPTIONS
                )
            )
            intake_filter_options = "<option value=''>ทุกปีรับเข้า</option>" + "".join(
                f"<option value='{esc(code)}' {'selected' if intake_filter == code else ''}>ปีรับเข้า {esc(code)}</option>"
                for code in intake_options
            )
            sort_options = (
                f"<option value='name_asc' {'selected' if sort_key == 'name_asc' else ''}>ชื่อ (ก-ฮ)</option>"
                f"<option value='name_desc' {'selected' if sort_key == 'name_desc' else ''}>ชื่อ (ฮ-ก)</option>"
                f"<option value='role_asc' {'selected' if sort_key == 'role_asc' else ''}>บทบาท (ศิษย์เก่าก่อน)</option>"
                f"<option value='role_desc' {'selected' if sort_key == 'role_desc' else ''}>บทบาท (แอดมินก่อน)</option>"
                f"<option value='major_asc' {'selected' if sort_key == 'major_asc' else ''}>สาขา (ก-ฮ)</option>"
                f"<option value='major_desc' {'selected' if sort_key == 'major_desc' else ''}>สาขา (ฮ-ก)</option>"
            )
            export_qs = {}
            if query_name:
                export_qs["name"] = query_name
            if role_filter:
                export_qs["role"] = role_filter
            if level_filter:
                export_qs["education_level"] = level_filter
            if major_filter:
                export_qs["major"] = major_filter
            if status_filter:
                export_qs["employment_status"] = status_filter
            if intake_filter:
                export_qs["intake"] = intake_filter
            if sort_key:
                export_qs["sort"] = sort_key
            export_url = "/admin/users/export.csv"
            if export_qs:
                export_url += "?" + urlencode(export_qs)
            action_options = (
                f"<option value='' {'selected' if not audit_action else ''}>ทุกประเภท</option>"
                f"<option value='admin_create' {'selected' if audit_action == 'admin_create' else ''}>สร้างผู้ใช้</option>"
                f"<option value='admin_update' {'selected' if audit_action == 'admin_update' else ''}>แก้ไขโดยแอดมิน</option>"
                f"<option value='admin_delete' {'selected' if audit_action == 'admin_delete' else ''}>ลบโดยแอดมิน</option>"
                f"<option value='profile_update' {'selected' if audit_action == 'profile_update' else ''}>ผู้ใช้แก้ไขข้อมูลส่วนตัว</option>"
                f"<option value='avatar_update' {'selected' if audit_action == 'avatar_update' else ''}>อัปโหลดรูปโปรไฟล์</option>"
                f"<option value='password_change' {'selected' if audit_action == 'password_change' else ''}>ผู้ใช้เปลี่ยนรหัสผ่าน</option>"
            )
            user_options = ["<option value=''>ทุกผู้ใช้</option>"]
            for r in rows:
                selected = "selected" if audit_user_id and int(audit_user_id) == r["id"] else ""
                user_options.append(f"<option value='{r['id']}' {selected}>{esc(r['full_name'])} (#{r['id']})</option>")
            audit_rows_html = "".join(
                f"<tr><td>{esc(r['created_at'])}</td><td>{esc(r['actor_name'] or '-')}</td><td>{esc(r['target_name'] or '-')}</td><td>{esc(r['action'])}</td><td>{esc(summarize_audit_changes(r['changes_json']))}</td></tr>"
                for r in audit_rows
            )
            edit_panel = ""
            if edit_row:
                edit_panel = f"""
                <div class='card'>
                  <div class='section-head'>
                    <h2>แก้ไขข้อมูลผู้ใช้ #{edit_row["id"]}</h2>
                  </div>
                  {self.admin_edit_form_html(edit_row)}
                </div>
                """
            body = f"""
            <div class='card'>
              <div class='section-head'>
                <div class='hero'>
                  <h1 class='hero-title'>จัดการข้อมูลผู้ใช้งาน</h1>
                  <p class='muted'>เพิ่ม แก้ไข และลบข้อมูลผู้ใช้งานจากศูนย์กลางในหน้าเดียว</p>
                </div>
                <span class='status'>แสดงผล {len(rows)} จากทั้งหมด {total_user_count} รายการ</span>
              </div>
            </div>
            <div class='card'>
              <h2>เพิ่มผู้ใช้ใหม่</h2>
              <form method='post' action='/admin/users/create'>
                <div class='row'>
                  <div><label>ชื่อ - นามสกุล</label><input name='full_name' required /></div>
                  <div><label>อีเมล</label><input type='email' name='email' required /></div>
                  <div><label>รหัสผ่าน</label><input type='password' name='password' required /></div>
                </div>
                <div class='row'>
                  <div><label>ลิงก์รูปประจำตัว (URL)</label><input name='avatar_url' placeholder='https://...' /></div>
                  <div><label>รหัสนิสิต</label><input name='student_id' /></div>
                </div>
                <div class='row'>
                  <div><label>บทบาท</label><select name='role'><option value='alumni'>ศิษย์เก่า</option><option value='admin'>ผู้ดูแลระบบ</option></select></div>
                  <div><label>ระดับการศึกษา</label>{education_level_select("education_level", "ปริญญาตรี")}</div>
                  <div><label>สาขา</label>{major_select("major", level="ปริญญาตรี", css_class="major-select")}</div>
                  <div><label>สถานะการทำงาน</label>{employment_select("employment_status", "ไม่สะดวกให้ข้อมูล")}</div>
                </div>
                <div class='row employed-only'>
                  <div><label>ตำแหน่งงาน</label><input name='job_title' /></div>
                  <div><label>ประเภทหน่วยงาน</label>{org_type_select("organization_type")}</div>
                  <div><label>เงินเดือน/รายได้เฉลี่ยต่อเดือน</label>{income_select("monthly_income")}</div>
                  <div><label>สถานที่ทำงาน</label><input name='company' /></div>
                </div>
                <div class='row employed-only'>
                  <div><label>บ้านเลขที่</label><input name='workplace_house_no' /></div>
                  <div><label>รหัสไปรษณีย์</label>{postal_code_input("workplace_postal_code")}</div>
                  <div><label>ตำบล</label>{subdistrict_select("workplace_subdistrict")}</div>
                  <div><label>อำเภอ</label>{postal_locked_input("workplace_district")}</div>
                  <div><label>จังหวัด</label>{postal_locked_input("workplace_province")}</div>
                </div>
                <button type='submit'>บันทึกผู้ใช้ใหม่</button>
              </form>
            </div>
            <div class='card'>
              <h2>รายการผู้ใช้ทั้งหมด</h2>
              <form method='get' action='/admin/users'>
                <div class='row-tight'>
                  <div><label>ค้นหาตามชื่อ</label><input name='name' value='{esc(query_name)}' placeholder='พิมพ์ชื่อ - นามสกุล' /></div>
                  <div><label>บทบาท</label><select name='role'>{role_filter_options}</select></div>
                  <div><label>ระดับการศึกษา</label>{education_level_select("education_level", level_filter, css_class="education-level-select")}</div>
                  <div><label>สาขา</label>{major_select("major", major_filter, level=level_filter, css_class="major-select")}</div>
                  <div><label>สถานะการทำงาน</label><select name='employment_status'>{status_filter_options}</select></div>
                  <div><label>ปีรับเข้า</label><select name='intake'>{intake_filter_options}</select></div>
                  <div><label>เรียงลำดับ</label><select name='sort'>{sort_options}</select></div>
                </div>
                <div class='actions'>
                  <button type='submit'>ค้นหา</button>
                  <a class='nav-link' href='/admin/users'>ล้างตัวกรอง</a>
                  <a class='nav-link' href='{export_url}'>ส่งออก CSV</a>
                </div>
              </form>
              <div class='table-wrap'>
                <table>
                  <thead><tr><th>รหัส</th><th>ชื่อ</th><th>อีเมล</th><th>บทบาท</th><th>รหัสนิสิต</th><th>ระดับ</th><th>สาขา</th><th>สถานะการทำงาน</th><th>การจัดการ</th></tr></thead>
                  <tbody>{row_html or "<tr><td colspan='9' class='muted'>ไม่พบข้อมูลผู้ใช้</td></tr>"}</tbody>
                </table>
              </div>
            </div>
            {edit_panel}
            <div class='card'>
              <div class='section-head'>
                <h2>ประวัติการแก้ไขข้อมูลผู้ใช้</h2>
                <span class='status'>แสดงล่าสุด {len(audit_rows)} รายการ</span>
              </div>
              <form method='get' action='/admin/users'>
                <div class='row-tight'>
                  <div><label>ผู้ใช้</label><select name='audit_user_id'>{''.join(user_options)}</select></div>
                  <div><label>ประเภทการแก้ไข</label><select name='audit_action'>{action_options}</select></div>
                </div>
                <div class='actions'>
                  <button type='submit'>ดูประวัติ</button>
                  <a class='nav-link' href='/admin/users'>ล้างตัวกรอง</a>
                </div>
              </form>
              <div class='table-wrap'>
                <table>
                  <thead><tr><th>เวลา</th><th>ผู้กระทำ</th><th>ผู้ใช้เป้าหมาย</th><th>ประเภท</th><th>รายละเอียด</th></tr></thead>
                  <tbody>{audit_rows_html or "<tr><td colspan='5' class='muted'>ยังไม่มีประวัติการแก้ไข</td></tr>"}</tbody>
                </table>
              </div>
            </div>
            """
            self.send_html(200, "จัดการผู้ใช้งาน", body, user=user)
            return

        self.send_html(404, "ไม่พบหน้าที่ต้องการ", "<div class='card'><h2>404</h2><p>ไม่พบหน้าที่คุณร้องขอ</p></div>")

    def profile_form_html(self, user, action_path):
        return f"""
        <div class='card'>
          <div class='section-head'>
            <h2>ข้อมูลส่วนตัวของฉัน</h2>
            <span class='status'>แก้ไขได้ตลอดเวลา</span>
          </div>
          <form method='post' action='/profile/avatar' enctype='multipart/form-data'>
            <div class='avatar-row'>
              {avatar_html(user["avatar_url"], user["full_name"], "avatar-lg")}
              <div>
                <label>อัปโหลดรูปประจำตัว</label>
                <input type='file' name='avatar_file' accept='image/png,image/jpeg,image/gif,image/webp' required />
                <p class='muted'>ไฟล์ที่รองรับ: JPG, PNG, GIF, WEBP (ไม่เกิน 5MB)</p>
              </div>
            </div>
            <button type='submit'>อัปโหลดรูปใหม่</button>
          </form>
          <form method='post' action='/profile/update'>
            <div class='form-section'>
              <h3 class='form-section-title'>ข้อมูลส่วนตัว</h3>
              <label>ชื่อ - นามสกุล</label>
              <input name='full_name' value='{esc(user["full_name"])}' required />
              <div class='row'>
                <div><label>รหัสนิสิต</label><input name='student_id' value='{esc(user["student_id"])}' /></div>
                <div><label>ระดับการศึกษา</label>{education_level_select("education_level", user["education_level"] or "ปริญญาตรี", required=True)}</div>
                <div><label>สาขา</label>{major_select("major", user["major"], required=True, level=user["education_level"] or "ปริญญาตรี", css_class="major-select")}</div>
              </div>
            </div>
            <div class='form-section'>
              <h3 class='form-section-title'>ข้อมูลการทำงาน</h3>
              <div class='row'>
                <div><label>สถานะการทำงาน</label>{employment_select("employment_status", user["employment_status"] or "ไม่สะดวกให้ข้อมูล", required=True)}</div>
              </div>
              <div class='row employed-only'>
                <div><label>ตำแหน่งงาน</label><input name='job_title' value='{esc(user["job_title"])}' /></div>
                <div><label>ประเภทหน่วยงาน</label>{org_type_select("organization_type", user["organization_type"])}</div>
                <div><label>เงินเดือน/รายได้เฉลี่ยต่อเดือน</label>{income_select("monthly_income", user["monthly_income"])}</div>
                <div><label>สถานที่ทำงาน</label><input name='company' value='{esc(user["company"])}' /></div>
              </div>
              <div class='row employed-only'>
                <div><label>บ้านเลขที่</label><input name='workplace_house_no' value='{esc(user["workplace_house_no"])}' /></div>
                <div><label>รหัสไปรษณีย์</label>{postal_code_input("workplace_postal_code", user["workplace_postal_code"])}</div>
                <div><label>ตำบล</label>{subdistrict_select("workplace_subdistrict", user["workplace_subdistrict"])}</div>
                <div><label>อำเภอ</label>{postal_locked_input("workplace_district", user["workplace_district"])}</div>
                <div><label>จังหวัด</label>{postal_locked_input("workplace_province", user["workplace_province"])}</div>
              </div>
            </div>
            <button type='submit'>บันทึกข้อมูล</button>
          </form>
          <form method='post' action='/profile/password'>
            <div class='section-head' style='margin-top:6px'>
              <h2>เปลี่ยนรหัสผ่าน</h2>
            </div>
            <div class='row'>
              <div><label>รหัสผ่านปัจจุบัน</label><input type='password' name='current_password' required /></div>
              <div><label>รหัสผ่านใหม่</label><input type='password' name='new_password' required /></div>
              <div><label>ยืนยันรหัสผ่านใหม่</label><input type='password' name='confirm_new_password' required /></div>
            </div>
            <button type='submit'>บันทึกรหัสผ่านใหม่</button>
          </form>
        </div>
        """

    def admin_list_row_html(
        self,
        row,
        active_edit_id=None,
        query_name="",
        role_filter="",
        level_filter="",
        major_filter="",
        status_filter="",
        intake_filter="",
        sort_key="name_asc",
    ):
        status_badge = "<span class='status'>กำลังแก้ไข</span>" if active_edit_id == row["id"] else ""
        edit_qs = {"edit_id": row["id"]}
        if query_name:
            edit_qs["name"] = query_name
        if role_filter:
            edit_qs["role"] = role_filter
        if level_filter:
            edit_qs["education_level"] = level_filter
        if major_filter:
            edit_qs["major"] = major_filter
        if status_filter:
            edit_qs["employment_status"] = status_filter
        if intake_filter:
            edit_qs["intake"] = intake_filter
        if sort_key:
            edit_qs["sort"] = sort_key
        edit_url = "/admin/users?" + urlencode(edit_qs)
        history_qs = {"audit_user_id": row["id"]}
        if query_name:
            history_qs["name"] = query_name
        if role_filter:
            history_qs["role"] = role_filter
        if level_filter:
            history_qs["education_level"] = level_filter
        if major_filter:
            history_qs["major"] = major_filter
        if status_filter:
            history_qs["employment_status"] = status_filter
        if intake_filter:
            history_qs["intake"] = intake_filter
        if sort_key:
            history_qs["sort"] = sort_key
        history_url = "/admin/users?" + urlencode(history_qs)
        return f"""
        <tr>
          <td>{row["id"]}</td>
          <td><div class='avatar-row'>{avatar_html(row["avatar_url"], row["full_name"])}<div>{esc(row["full_name"])}</div></div></td>
          <td>{esc(row["email"])}</td>
          <td>{'ผู้ดูแลระบบ' if row["role"] == "admin" else "ศิษย์เก่า"}</td>
          <td>{esc(row["student_id"])}</td>
          <td>{esc(row["education_level"])}</td>
          <td>{esc(row["major"])}</td>
          <td>{esc(row["employment_status"])}</td>
          <td>
            <div class='actions actions-table'>
              <a class='btn btn-ghost btn-inline btn-action' href='{history_url}'>ประวัติ</a>
              <a class='btn btn-soft btn-inline btn-action' href='{edit_url}'>แก้ไข</a>
              <form method='post' action='/admin/users/{row["id"]}/delete' onsubmit="return confirm('ต้องการลบผู้ใช้รหัส {row["id"]} ใช่หรือไม่?')">
                <button class='btn btn-danger btn-inline btn-action' type='submit'>ลบ</button>
              </form>
              {status_badge}
            </div>
          </td>
        </tr>
        """

    def admin_edit_form_html(self, row):
        return f"""
        <form method='post' action='/admin/users/{row["id"]}/update'>
          <div class='avatar-row'>
            {avatar_html(row["avatar_url"], row["full_name"])}
            <div class='muted'>รูปประจำตัว</div>
          </div>
          <div class='row'>
            <div><label>ชื่อ - นามสกุล</label><input name='full_name' value='{esc(row["full_name"])}' required /></div>
            <div><label>อีเมล</label><input type='email' name='email' value='{esc(row["email"])}' required /></div>
            <div><label>บทบาท</label><select name='role'>
              <option value='alumni' {"selected" if row["role"] == "alumni" else ""}>ศิษย์เก่า</option>
              <option value='admin' {"selected" if row["role"] == "admin" else ""}>ผู้ดูแลระบบ</option>
            </select></div>
          </div>
          <div class='row'>
            <div><label>ลิงก์รูปประจำตัว (URL)</label><input name='avatar_url' value='{esc(row["avatar_url"])}' placeholder='https://...' /></div>
            <div><label>รหัสนิสิต</label><input name='student_id' value='{esc(row["student_id"])}' /></div>
            <div><label>ระดับการศึกษา</label>{education_level_select("education_level", row["education_level"] or "ปริญญาตรี")}</div>
            <div><label>สาขา</label>{major_select("major", row["major"], level=row["education_level"] or "ปริญญาตรี", css_class="major-select")}</div>
            <div><label>สถานะการทำงาน</label>{employment_select("employment_status", row["employment_status"] or "ไม่สะดวกให้ข้อมูล")}</div>
          </div>
          <div class='row employed-only'>
            <div><label>ตำแหน่งงาน</label><input name='job_title' value='{esc(row["job_title"])}' /></div>
            <div><label>ประเภทหน่วยงาน</label>{org_type_select("organization_type", row["organization_type"])}</div>
            <div><label>เงินเดือน/รายได้เฉลี่ยต่อเดือน</label>{income_select("monthly_income", row["monthly_income"])}</div>
            <div><label>สถานที่ทำงาน</label><input name='company' value='{esc(row["company"])}' /></div>
          </div>
          <div class='row employed-only'>
            <div><label>บ้านเลขที่</label><input name='workplace_house_no' value='{esc(row["workplace_house_no"])}' /></div>
            <div><label>รหัสไปรษณีย์</label>{postal_code_input("workplace_postal_code", row["workplace_postal_code"])}</div>
            <div><label>ตำบล</label>{subdistrict_select("workplace_subdistrict", row["workplace_subdistrict"])}</div>
            <div><label>อำเภอ</label>{postal_locked_input("workplace_district", row["workplace_district"])}</div>
            <div><label>จังหวัด</label>{postal_locked_input("workplace_province", row["workplace_province"])}</div>
          </div>
          <div class='actions'>
            <button type='submit'>บันทึกการแก้ไข</button>
            <a class='btn btn-ghost btn-inline' href='/admin/users'>ยกเลิก</a>
          </div>
        </form>
        """

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/login":
            form = self.parse_form()
            email = form.get("email", "")
            password = form.get("password", "")
            conn = db_conn()
            user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            conn.close()
            if not user or not verify_password(password, user["password_hash"]):
                self.redirect("/login?" + urlencode({"msg": "อีเมลหรือรหัสผ่านไม่ถูกต้อง"}))
                return

            self.send_response(302)
            self.set_session(user["id"])
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path == "/forgot-password":
            form = self.parse_form()
            email = (form.get("email") or "").strip()
            conn = db_conn()
            user = conn.execute("SELECT id, email FROM users WHERE email = ?", (email,)).fetchone()
            if user:
                token = secrets.token_urlsafe(32)
                now_ts = int(time.time())
                expires_ts = now_ts + RESET_TOKEN_TTL_SECONDS
                with conn:
                    conn.execute(
                        "INSERT INTO password_reset_tokens (user_id, token, expires_at, created_at) VALUES (?, ?, ?, ?)",
                        (user["id"], token, expires_ts, now_ts),
                    )
                    conn.execute("DELETE FROM password_reset_tokens WHERE expires_at < ?", (now_ts,))
                reset_link = self.absolute_url("/reset-password?" + urlencode({"token": token}))
                try:
                    send_password_reset_email(user["email"], reset_link)
                except Exception as exc:
                    print(f"[password-reset] failed to send email: {exc}")
            conn.close()
            self.redirect(
                "/forgot-password?"
                + urlencode({"msg": "หากอีเมลมีอยู่ในระบบ เราได้ส่งลิงก์รีเซ็ตรหัสผ่านไปให้แล้ว"})
            )
            return

        if path == "/reset-password":
            form = self.parse_form()
            token = (form.get("token") or "").strip()
            password = form.get("password") or ""
            confirm = form.get("confirm_password") or ""
            if not token:
                self.redirect("/forgot-password?" + urlencode({"msg": "ลิงก์รีเซ็ตรหัสผ่านไม่ถูกต้อง"}))
                return
            if len(password) < 8:
                self.redirect("/reset-password?" + urlencode({"token": token, "msg": "รหัสผ่านต้องมีอย่างน้อย 8 ตัวอักษร"}))
                return
            if password != confirm:
                self.redirect("/reset-password?" + urlencode({"token": token, "msg": "ยืนยันรหัสผ่านไม่ตรงกัน"}))
                return
            now_ts = int(time.time())
            conn = db_conn()
            reset_row = conn.execute(
                """
                SELECT id, user_id
                FROM password_reset_tokens
                WHERE token = ? AND used_at IS NULL AND expires_at >= ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (token, now_ts),
            ).fetchone()
            if not reset_row:
                conn.close()
                self.redirect("/forgot-password?" + urlencode({"msg": "ลิงก์หมดอายุหรือไม่ถูกต้อง กรุณาขอใหม่อีกครั้ง"}))
                return
            with conn:
                conn.execute(
                    "UPDATE users SET password_hash=?, updated_at=? WHERE id=?",
                    (hash_password(password), now_iso(), reset_row["user_id"]),
                )
                conn.execute(
                    "UPDATE password_reset_tokens SET used_at=? WHERE id=?",
                    (now_ts, reset_row["id"]),
                )
                conn.execute(
                    "UPDATE password_reset_tokens SET used_at=? WHERE user_id=? AND used_at IS NULL AND id != ?",
                    (now_ts, reset_row["user_id"], reset_row["id"]),
                )
            conn.close()
            self.redirect("/login?" + urlencode({"msg": "ตั้งรหัสผ่านใหม่เรียบร้อยแล้ว กรุณาเข้าสู่ระบบ"}))
            return

        if path == "/register":
            form = self.parse_form()
            required = ["full_name", "student_id", "education_level", "major", "employment_status", "email", "password"]
            if any(not form.get(k, "").strip() for k in required):
                self.redirect("/register?" + urlencode({"msg": "กรุณากรอกข้อมูลให้ครบถ้วน"}))
                return
            edu_payload, edu_err = parse_education_form(form, allow_blank=False)
            if edu_err:
                self.redirect("/register?" + urlencode({"msg": edu_err}))
                return
            employment_payload, employment_err = parse_employment_form(form)
            if employment_err:
                self.redirect("/register?" + urlencode({"msg": employment_err}))
                return
            conn = db_conn()
            try:
                with conn:
                    cur = conn.execute(
                        """
                        INSERT INTO users (email, password_hash, role, full_name, student_id, education_level, major, employment_status, organization_type, monthly_income, company, job_title, workplace_house_no, workplace_subdistrict, workplace_district, workplace_province, workplace_postal_code, created_at, updated_at)
                        VALUES (?, ?, 'alumni', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            form["email"],
                            hash_password(form["password"]),
                            form["full_name"],
                            form["student_id"],
                            edu_payload["education_level"],
                            edu_payload["major"],
                            employment_payload["employment_status"],
                            employment_payload["organization_type"],
                            employment_payload["monthly_income"],
                            employment_payload["company"],
                            employment_payload["job_title"],
                            employment_payload["workplace_house_no"],
                            employment_payload["workplace_subdistrict"],
                            employment_payload["workplace_district"],
                            employment_payload["workplace_province"],
                            employment_payload["workplace_postal_code"],
                            now_iso(),
                            now_iso(),
                        ),
                    )
                    new_user_id = cur.lastrowid
            except sqlite3.IntegrityError:
                conn.close()
                self.redirect("/register?" + urlencode({"msg": "อีเมลนี้ถูกใช้งานแล้ว"}))
                return
            conn.close()
            self.send_response(302)
            self.set_session(new_user_id)
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path == "/logout":
            self.send_response(302)
            self.clear_session()
            self.send_header("Location", "/login")
            self.end_headers()
            return

        if path == "/profile/avatar":
            user = self.require_auth()
            if not user:
                return

            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0 or content_length > MAX_AVATAR_REQUEST_BYTES:
                self.redirect("/dashboard?" + urlencode({"err": "ขนาดไฟล์เกินที่กำหนดหรือไม่มีไฟล์"}))
                return

            if "multipart/form-data" not in self.headers.get("Content-Type", ""):
                self.redirect("/dashboard?" + urlencode({"err": "รูปแบบคำขอไม่ถูกต้อง"}))
                return

            form = self.parse_multipart()
            file_item = form.get("avatar_file")
            if not file_item or not file_item.get("filename"):
                self.redirect("/dashboard?" + urlencode({"err": "กรุณาเลือกไฟล์รูปภาพก่อนอัปโหลด"}))
                return

            file_type = file_item.get("content_type", "")
            file_ext = Path(file_item.get("filename", "")).suffix.lower()
            if not is_allowed_image_content(file_type) and file_ext not in {".png", ".jpg", ".jpeg", ".gif", ".webp"}:
                self.redirect("/dashboard?" + urlencode({"err": "รองรับเฉพาะไฟล์รูป JPG PNG GIF WEBP"}))
                return

            blob = file_item.get("data", b"")
            if not blob or len(blob) > MAX_AVATAR_UPLOAD_BYTES:
                self.redirect("/dashboard?" + urlencode({"err": "ไฟล์รูปไม่ถูกต้องหรือมีขนาดเกิน 5MB"}))
                return

            filename = build_avatar_filename(user["id"], file_item.get("filename"))
            target = UPLOAD_DIR / filename
            target.write_bytes(blob)

            old_avatar = user["avatar_url"] or ""
            conn = db_conn()
            with conn:
                conn.execute(
                    "UPDATE users SET avatar_url=?, updated_at=? WHERE id=?",
                    (f"/uploads/{filename}", now_iso(), user["id"]),
                )
                log_user_audit(
                    conn,
                    user["id"],
                    user["id"],
                    "avatar_update",
                    {"avatar_url": {"from": old_avatar or None, "to": f"/uploads/{filename}"}},
                )
            conn.close()

            if old_avatar.startswith("/uploads/"):
                old_name = os.path.basename(old_avatar)
                old_path = UPLOAD_DIR / old_name
                if old_path.exists() and old_path.is_file():
                    try:
                        old_path.unlink()
                    except OSError:
                        pass

            self.redirect("/dashboard?" + urlencode({"msg": "อัปโหลดรูปประจำตัวเรียบร้อยแล้ว"}))
            return

        if path == "/profile/update":
            user = self.require_auth()
            if not user:
                return
            form = self.parse_form()
            edu_payload, edu_err = parse_education_form(form, allow_blank=False)
            if edu_err:
                self.redirect("/dashboard?" + urlencode({"err": edu_err}))
                return
            employment_payload, employment_err = parse_employment_form(form)
            if employment_err:
                self.redirect("/dashboard?" + urlencode({"err": employment_err}))
                return
            before = row_snapshot(user)
            conn = db_conn()
            with conn:
                conn.execute(
                    """
                    UPDATE users
                    SET full_name=?, student_id=?, education_level=?, major=?, employment_status=?, organization_type=?, monthly_income=?, company=?, job_title=?, workplace_house_no=?, workplace_subdistrict=?, workplace_district=?, workplace_province=?, workplace_postal_code=?, updated_at=?
                    WHERE id=?
                    """,
                    (
                        form.get("full_name", user["full_name"]),
                        form.get("student_id") or None,
                        edu_payload["education_level"],
                        edu_payload["major"],
                        employment_payload["employment_status"],
                        employment_payload["organization_type"],
                        employment_payload["monthly_income"],
                        employment_payload["company"],
                        employment_payload["job_title"],
                        employment_payload["workplace_house_no"],
                        employment_payload["workplace_subdistrict"],
                        employment_payload["workplace_district"],
                        employment_payload["workplace_province"],
                        employment_payload["workplace_postal_code"],
                        now_iso(),
                        user["id"],
                    ),
                )
                after = conn.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
                changes = diff_snapshots(before, row_snapshot(after))
                if changes:
                    log_user_audit(conn, user["id"], user["id"], "profile_update", changes)
            conn.close()
            self.redirect("/dashboard?" + urlencode({"msg": "บันทึกข้อมูลส่วนตัวเรียบร้อยแล้ว"}))
            return

        if path == "/profile/password":
            user = self.require_auth()
            if not user:
                return
            form = self.parse_form()
            current_password = form.get("current_password") or ""
            new_password = form.get("new_password") or ""
            confirm_new_password = form.get("confirm_new_password") or ""
            if not current_password or not new_password or not confirm_new_password:
                self.redirect("/dashboard?" + urlencode({"err": "กรุณากรอกรหัสผ่านให้ครบทุกช่อง"}))
                return
            if not verify_password(current_password, user["password_hash"]):
                self.redirect("/dashboard?" + urlencode({"err": "รหัสผ่านปัจจุบันไม่ถูกต้อง"}))
                return
            if len(new_password) < 8:
                self.redirect("/dashboard?" + urlencode({"err": "รหัสผ่านใหม่ต้องมีอย่างน้อย 8 ตัวอักษร"}))
                return
            if new_password != confirm_new_password:
                self.redirect("/dashboard?" + urlencode({"err": "ยืนยันรหัสผ่านใหม่ไม่ตรงกัน"}))
                return
            if verify_password(new_password, user["password_hash"]):
                self.redirect("/dashboard?" + urlencode({"err": "รหัสผ่านใหม่ต้องไม่ซ้ำกับรหัสผ่านเดิม"}))
                return
            now_ts = int(time.time())
            conn = db_conn()
            with conn:
                conn.execute(
                    "UPDATE users SET password_hash=?, updated_at=? WHERE id=?",
                    (hash_password(new_password), now_iso(), user["id"]),
                )
                conn.execute(
                    "UPDATE password_reset_tokens SET used_at=? WHERE user_id=? AND used_at IS NULL",
                    (now_ts, user["id"]),
                )
                log_user_audit(
                    conn,
                    user["id"],
                    user["id"],
                    "password_change",
                    {"password": {"from": "[hidden]", "to": "[updated]"}},
                )
            conn.close()
            self.redirect("/dashboard?" + urlencode({"msg": "เปลี่ยนรหัสผ่านเรียบร้อยแล้ว"}))
            return

        if path == "/admin/users/create":
            admin = self.require_admin()
            if not admin:
                return
            form = self.parse_form()
            required = ["full_name", "email", "password", "role"]
            if any(not form.get(k, "").strip() for k in required):
                self.redirect("/admin/users")
                return
            role = "admin" if form.get("role") == "admin" else "alumni"
            edu_payload, edu_err = parse_education_form(form, allow_blank=(role == "admin"))
            if edu_err:
                self.redirect("/admin/users")
                return
            employment_payload, employment_err = parse_employment_form(form)
            if employment_err:
                self.redirect("/admin/users")
                return
            conn = db_conn()
            try:
                with conn:
                    cur = conn.execute(
                        """
                        INSERT INTO users (email, password_hash, role, full_name, avatar_url, student_id, education_level, major, employment_status, organization_type, monthly_income, company, job_title, workplace_house_no, workplace_subdistrict, workplace_district, workplace_province, workplace_postal_code, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            form["email"],
                            hash_password(form["password"]),
                            role,
                            form["full_name"],
                            form.get("avatar_url") or None,
                            form.get("student_id") or None,
                            edu_payload["education_level"],
                            edu_payload["major"],
                            employment_payload["employment_status"],
                            employment_payload["organization_type"],
                            employment_payload["monthly_income"],
                            employment_payload["company"],
                            employment_payload["job_title"],
                            employment_payload["workplace_house_no"],
                            employment_payload["workplace_subdistrict"],
                            employment_payload["workplace_district"],
                            employment_payload["workplace_province"],
                            employment_payload["workplace_postal_code"],
                            now_iso(),
                            now_iso(),
                        ),
                    )
                    created_id = cur.lastrowid
                    created_user = conn.execute("SELECT * FROM users WHERE id = ?", (created_id,)).fetchone()
                    log_user_audit(
                        conn,
                        admin["id"],
                        created_id,
                        "admin_create",
                        {"created": row_snapshot(created_user)},
                    )
            except sqlite3.IntegrityError:
                pass
            finally:
                conn.close()
            self.redirect("/admin/users")
            return

        if path.startswith("/admin/users/") and path.endswith("/update"):
            admin = self.require_admin()
            if not admin:
                return
            form = self.parse_form()
            role = "admin" if form.get("role") == "admin" else "alumni"
            edu_payload, edu_err = parse_education_form(form, allow_blank=(role == "admin"))
            if edu_err:
                self.redirect("/admin/users")
                return
            employment_payload, employment_err = parse_employment_form(form)
            if employment_err:
                self.redirect("/admin/users")
                return
            user_id = path.split("/")[3]
            conn = db_conn()
            with conn:
                before_row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
                conn.execute(
                    """
                    UPDATE users
                    SET email=?, role=?, full_name=?, avatar_url=?, student_id=?, education_level=?, major=?, employment_status=?, organization_type=?, monthly_income=?, company=?, job_title=?, workplace_house_no=?, workplace_subdistrict=?, workplace_district=?, workplace_province=?, workplace_postal_code=?, updated_at=?
                    WHERE id=?
                    """,
                    (
                        form.get("email"),
                        role,
                        form.get("full_name"),
                        form.get("avatar_url") or None,
                        form.get("student_id") or None,
                        edu_payload["education_level"],
                        edu_payload["major"],
                        employment_payload["employment_status"],
                        employment_payload["organization_type"],
                        employment_payload["monthly_income"],
                        employment_payload["company"],
                        employment_payload["job_title"],
                        employment_payload["workplace_house_no"],
                        employment_payload["workplace_subdistrict"],
                        employment_payload["workplace_district"],
                        employment_payload["workplace_province"],
                        employment_payload["workplace_postal_code"],
                        now_iso(),
                        user_id,
                    ),
                )
                after_row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
                changes = diff_snapshots(row_snapshot(before_row), row_snapshot(after_row))
                if changes:
                    log_user_audit(conn, admin["id"], int(user_id), "admin_update", changes)
            conn.close()
            self.redirect("/admin/users")
            return

        if path.startswith("/admin/users/") and path.endswith("/delete"):
            admin = self.require_admin()
            if not admin:
                return
            user_id = int(path.split("/")[3])
            if user_id == admin["id"]:
                self.redirect("/admin/users")
                return
            conn = db_conn()
            with conn:
                target = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
                conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
                if target:
                    log_user_audit(
                        conn,
                        admin["id"],
                        user_id,
                        "admin_delete",
                        {"deleted": row_snapshot(target)},
                    )
            conn.close()
            self.redirect("/admin/users")
            return

        self.send_html(404, "ไม่พบหน้าที่ต้องการ", "<div class='card'><h2>404</h2><p>ไม่พบหน้าที่คุณร้องขอ</p></div>")


def snapshot_py_mtimes():
    mtimes = {}
    for file_path in BASE_DIR.rglob("*.py"):
        if file_path.is_file():
            try:
                mtimes[str(file_path)] = file_path.stat().st_mtime_ns
            except OSError:
                continue
    return mtimes


def start_hot_reload_watcher():
    if not HOT_RELOAD_ENABLED:
        return

    baseline = snapshot_py_mtimes()

    def watch():
        while True:
            time.sleep(HOT_RELOAD_INTERVAL)
            current = snapshot_py_mtimes()
            if current != baseline:
                print("Detected source changes. Restarting server for hot reload...")
                os.execv(sys.executable, [sys.executable] + sys.argv)

    thread = threading.Thread(target=watch, daemon=True)
    thread.start()


def main():
    init_db()
    start_hot_reload_watcher()
    server = HTTPServer((HOST, PORT), AlumniHandler)
    print(f"Math Alumni Phase 1 server running at http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
