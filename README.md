# Ysint - Modular OSINT Reconnaissance Toolkit

Toolkit Open Source Intelligence (OSINT) berbasis Python untuk melakukan footprinting dan reconnaissance terhadap nomor telepon, username, domain, alamat IP, email, dan subdomain secara komprehensif dengan dukungan pencarian database jejak publik dan validasi telekomunikasi.

## Kenapa Ini Dibuat

Investigasi jejak digital (reconnaissance) manual sering membuang waktu operasional: membuka puluhan tab browser satu per satu, mengurai record DNS mentah, menyalin data geolokasi, memetakan prefix nomor telepon internasional secara manual, dan berhadapan dengan false positive akibat respons HTTP soft-404.

Ysint dibangun untuk memberikan ringkasan intelijen yang cepat, akurat, terhubung dengan database telekomunikasi global (Google libphonenumber), dan dapat langsung diintegrasikan ke dalam pipeline keamanan melalui output JSON murni.

## Cara Kerja dan Integrasi Database Publik

- **Smart Auto-Detection**: Subcommand `scan` secara otomatis mengidentifikasi format target (nomor telepon internasional/nasional, IPv4, format email, nama domain, atau handle username) dan menjalankan alur audit yang relevan.
- **Phone Intelligence & Caller / Fraud Database Footprint**:
  - Integrasi database telekomunikasi resmi Google (`libphonenumber`) untuk resolusi operator global, validitas format ITU-T E.164, dan zona waktu.
  - Pencarian jejak database publik realtime dari direktori web, database penipuan (Kredibel.co.id), laporan caller spam (Tellows, ShouldIAnswer, UnknownPhone, Whocallsme), dan rekaman kebocoran data.
  - Dukungan Live HLR API (Numverify) untuk mengecek status kartu SIM aktif di jaringan seluler.
  - Penjanaan pivot link OSINT identitas instan: Truecaller, Getcontact, Sync.ME, Kredibel, WhatsApp Direct, Telegram Direct, Archive.org, dan Google Dorks (dokumen dan kebocoran data).
- **Subdomain Discovery via Certificate Transparency & Passive DNS**:
  - Mengintegrasikan database log Certificate Transparency (crt.sh) global dan HackerTarget HostSearch database untuk memetakan subdomain riil dari sertifikat SSL/TLS yang pernah diterbitkan.
  - Dikombinasikan dengan probing aktif DNS berbasis wordlist bernilai tinggi (120+ entri) dan resolusi konkruen untuk memvalidasi IP aktif.
- **Co-Hosted Domain Database & IP Intelligence**:
  - Database Reverse IP HackerTarget untuk mendeteksi domain-domain lain yang di-hosting pada alamat IP server target yang sama (shared hosting footprint).
  - Geolokasi presisi, ASN, ISP, organisasi pemilik IP, dan tautan pivot intelijen ancaman (Shodan, Censys, AbuseIPDB, GreyNoise, VirusTotal, BGP Route).
- **Live Data Breach & Infostealer Intelligence for Email**:
  - Pemeriksaan kebocoran data langsung secara realtime menggunakan database global XposedOrNot untuk mendeteksi insiden breach riil tanpa memerlukan API key berbayar.
  - Integrasi feed intelijen malware infostealer Hudson Rock untuk mendeteksi apakah email target pernah terinfeksi malware pencuri kredensial (RedLine, Lumma, Raccoon, Vidar), termasuk tanggal kompromi, sistem operasi, dan jumlah akun terdampak.
  - Ekstraksi jejak kebocoran data publik dan pastebin secara otomatis dari mesin pencari.
  - Query ke direktori publik Ubuntu OpenPGP Keyring untuk mengekstraksi PGP Key ID, panjang bit kunci, dan tautan verifikasi identitas pengunggah kunci.
  - Validasi profil identitas Gravatar via hash kriptografis untuk mendeteksi keberadaan avatar dan akun publik terdaftar.
  - Database pengecekan domain disposable/burner email (80+ penyedia throwaway) dan validasi server penampung email (MX records).
- **Domain & RDAP Public Registry Recon**:
  - Penarikan metadata pendaftaran resmi ICANN via RDAP (Registrar, tanggal registrasi, tanggal kedaluwarsa).
  - Record DNS lengkap (A, AAAA, MX, TXT, NS, SOA) via DNS over HTTPS (DoH), inspeksi TLS/SSL cipher, dan audit header keamanan (HSTS, CSP, X-Frame-Options).
- **Multi-Platform Username Reconnaissance**:
  - Memindai target secara konkuren di 23+ platform publik (GitHub, GitLab, DockerHub, Dev.to, HackerNews, Keybase, Steam, Rubygems, Packagist, About.me, Disqus, Bandcamp, Letterboxd, IFTTT, Chess.com, Codeforces, Duolingo, Replit, Gravatar, Pastebin, dll.) dengan validasi isi respons untuk mencegah false positive.

## Quickstart & Contoh Penggunaan

Kloning repositori dan jalankan langsung:

```bash
git clone https://github.com/yanzyuyu/Ysint.git
cd Ysint
pip install -r requirements.txt
python main.py phone +628123456789
```

```text
$ python main.py phone +628123456789

[*] Inspecting phone number '+628123456789'...

--- Phone Intelligence: +628123456789 ---
  International : +628123456789
  National      : 08123456789
  Country       : Indonesia (ID)
  Calling Code  : +62
  Region        : Southeast Asia
  Timezone      : Asia/Jakarta
  Carrier       : Telkomsel (Google libphonenumber)
  Line Type     : Mobile

--- Public Database & Leak Footprint ---
  [+] Found 3 public web / caller record mentions:
    - Ponimen 08123456789 / +628123456789 Jenis Panggilan:Peneror Nama Penelepon:Ponimen...
    - Nomor (+) 628123456789 / 08123456789 statistik Terakhir dilihat...
    - Nomor telepon 08123456789 telah dilaporkan lebih dari 11 kali oleh komunitas kami...

--- OSINT Pivots & Identity Databases ---
  WhatsApp Direct   : https://wa.me/628123456789
  Telegram Direct   : https://t.me/+628123456789
  Truecaller Recon  : https://www.truecaller.com/search/62/8123456789
  Getcontact Lookup : https://www.getcontact.com/en/search?number=628123456789
  Sync.ME Directory : https://sync.me/search/?number=628123456789
```

![Terminal Demo](terminal_demo.png)

### Perintah Utama

1. **Auto-Scan (Deteksi Otomatis Target):**
   ```bash
   python main.py scan +628123456789
   python main.py scan 085712345678
   python main.py scan yanzyuyu
   python main.py scan 8.8.8.8
   python main.py scan github.com
   ```

2. **Phone Number Intelligence (Database & Footprint):**
   ```bash
   python main.py phone +628123456789
   python main.py phone 083123456789
   python main.py phone +1-415-555-2671
   ```

3. **Username Recon:**
   ```bash
   python main.py user yanzyuyu
   ```

4. **Domain Intelligence:**
   ```bash
   python main.py domain github.com
   ```

5. **Subdomain Enumeration:**
   ```bash
   python main.py subdomains github.com
   ```

6. **IP Intelligence:**
   ```bash
   python main.py ip 1.1.1.1
   ```

7. **Email Analysis:**
   ```bash
   python main.py email test@mailinator.com
   ```

8. **Pipeline Automation (Format JSON Murni):**
   ```bash
   python main.py phone +628123456789 --json
   python main.py scan target --json -o report.json
   ```

## Struktur Proyek

```
ysint/
├── .gitignore             # Aturan ignorasi cache dan file sensitif
├── main.py                # Entrypoint eksekusi aplikasi
├── README.md              # Dokumentasi teknis proyek
├── requirements.txt       # Dependensi library
├── terminal_demo.png      # Snapshot visual eksekusi terminal
├── tests/
│   ├── __init__.py
│   └── test_modules.py    # Unit test modul OSINT
└── ysint/
    ├── __init__.py        # Metadata versi paket
    ├── cli.py             # Parser CLI dan formatted reporter
    ├── utils.py           # Utilitas jaringan, SSL context, dan validator
    └── modules/
        ├── __init__.py
        ├── domain.py      # DNS DoH, SSL inspection, security headers
        ├── email.py       # Syntax, MX check, disposable detection
        ├── ip.py          # IP intelligence, ASN, reverse DNS
        ├── phone.py       # Google libphonenumber, database footprint, OSINT pivots
        ├── subdomain.py   # Resolusi konkruen subdomain
        └── username.py    # Multi-platform username hunting
```

## Pengujian Unit

Jalankan rangkaian test otomatis bawaan:

```bash
python -m unittest discover tests
```
