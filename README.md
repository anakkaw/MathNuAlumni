# Math Alumni Portal - Phase 1

เว็บต้นแบบสำหรับเก็บฐานข้อมูลศิษย์เก่า พร้อมฟีเจอร์หลักใน Phase 1:

- Login / Logout
- Register (สมัครสมาชิกผู้ใช้ใหม่)
- Alumni profile (ดูและแก้ไขข้อมูลตัวเอง)
- Alumni avatar upload (อัปโหลดรูปประจำตัว)
- Search alumni (เฉพาะ admin: ค้นหาตามชื่อ รหัสนิสิต สาขา)
- Admin CRUD users (เพิ่ม/แก้ไข/ลบผู้ใช้)
- Public homepage dashboard (กราฟสถานะการทำงาน + กราฟประเภทหน่วยงาน พร้อม filter แยกสาขา/ปีรับเข้า โดยไม่ต้อง login)
- Seed ข้อมูลตัวอย่างศิษย์เก่า 15 รายการ (คละสาขา)

ฟิลด์ข้อมูลการทำงานที่รองรับ:
- สถานะการทำงาน
- ประเภทหน่วยงาน (`หน่วยงานของรัฐ/รัฐวิสาหกิจ`, `หน่วยงานเอกชน`, `ธุรกิจส่วนตัว`)
- เงินเดือน/รายได้เฉลี่ยต่อเดือน (dropdown)
- สถานที่ทำงาน + ที่อยู่แยกช่อง (`บ้านเลขที่`, `ตำบล`, `อำเภอ`, `จังหวัด`, `รหัสไปรษณีย์`)
- กรอกรหัสไปรษณีย์แล้วระบบช่วยเลือก `อำเภอ/จังหวัด` อัตโนมัติ และแสดง `ตำบล` เป็น dropdown ให้เลือก

## Tech stack

- Python 3 (standard library only)
- SQLite (`data/alumni.db`)
- Built-in HTTP server

## Run

```bash
python3 app.py
```

เปิดที่:

`http://127.0.0.1:8000`

## ฐานรหัสไปรษณีย์ทั้งประเทศ

ระบบรองรับการโหลดฐานรหัสไปรษณีย์จากไฟล์ภายนอกอัตโนมัติ (แนะนำให้ใช้ข้อมูลทั้งประเทศ):

1. วางไฟล์ไว้ที่ `data/thai_postal_codes.json` หรือ `data/thai_postal_codes.csv`
2. รีสตาร์ตเซิร์ฟเวอร์
3. ระบบจะใช้ฐานข้อมูลนี้แทนชุด fallback ทันที

รูปแบบที่รองรับ:

- `JSON` แบบ list ของ object โดยมีคีย์อย่างน้อย:
  - `postal_code` (หรือ `postcode`, `zip_code`, `zip`)
  - `subdistrict` (หรือ `tambon`, `ตำบล`, `แขวง`)
  - `district` (หรือ `amphoe`, `อำเภอ`, `เขต`)
  - `province` (หรือ `changwat`, `จังหวัด`)
- `CSV` ใช้คอลัมน์เดียวกันตามด้านบน

มีไฟล์ตัวอย่างให้ที่ `thai_postal_codes.template.csv`

## Seed accounts (สำหรับเดโม)

- Admin
  - Email: `admin@mathalumni.local`
  - Password: `Admin123!`

## Notes

- สำหรับ production ควรเปลี่ยน `ALUMNI_SECRET` ผ่าน environment variable
- ควรวางระบบ HTTPS, CSRF protection, และ password policy เพิ่มเติมใน Phase ถัดไป
