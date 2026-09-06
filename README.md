# Ysint - Modular OSINT Reconnaissance Toolkit

Toolkit Open Source Intelligence (OSINT) berbasis Python Standard Library untuk melakukan footprinting dan reconnaissance terhadap username, domain, alamat IP, email, dan subdomain secara cepat tanpa dependensi pihak ketiga.

## Kenapa Ini Dibuat

Investigasi jejak digital (reconnaissance) manual sering membuang waktu operasional: membuka puluhan tab browser satu per satu, mengurai record DNS mentah, menyalin data geolokasi, dan berhadapan dengan false positive akibat respons HTTP soft-404.

Ysint dibangun untuk memberikan ringkasan intelijen yang cepat, akurat, dan dapat langsung diintegrasikan ke dalam pipeline keamanan atau script otomasi melalui output JSON murni.

## Cara Kerja (Under the Hood)

- **Smart Auto-Detection**: Subcommand `scan` secara otomatis mengidentifikasi format target (IPv4, format email, nama domain, atau handle username) dan menjalankan alur audit yang relevan.
- **Username Enumeration**: Memindai target secara paralel menggunakan `ThreadPoolExecutor` di belasan platform publik dengan validasi isi respons (bukan sekadar status HTTP 200) untuk mencegah false positive.
- **Domain & DNS Intelligence**: Mengambil record DNS (A, AAAA, MX, TXT, NS, SOA) via DNS over HTTPS (DoH), menganalisis header keamanan web (HSTS, CSP, X-Frame-Options, X-Content-Type-Options), serta mengecek konfigurasi cipher suite TLS/SSL.
- **IP Intelligence & ASN**: Mendeteksi rentang IP privat/loopback/reserved secara lokal sebelum memicu jaringan, melakukan Reverse DNS (PTR), serta menarik metadata ASN dan geolokasi publik.
- **Subdomain Discovery**: Enumerasi konkuren terhadap target subdomain bernilai tinggi dengan kecepatan tinggi menggunakan DNS socket resolver.
- **Email Verification**: Memvalidasi sintaks RFC, mengecek keberadaan server penampung email (MX records), dan mendeteksi penggunaan domain email sementara (disposable/burner email).
- **Zero External Dependencies**: Menggunakan pustaka bawaan Python 3 murni sehingga siap dijalankan langsung di server Linux, macOS, maupun Windows tanpa perlu `pip install`.

## Quickstart & Contoh Penggunaan

Kloning repositori dan jalankan langsung dengan Python 3.8+:

```bash
git clone https://github.com/yanzyuyu/Ysint.git
cd Ysint
python main.py scan yanzyuyu
```

![Terminal Demo](terminal_demo.svg)

### Perintah Utama

1. **Auto-Scan (Deteksi Otomatis Target):**
   ```bash
   python main.py scan target_username
   python main.py scan 8.8.8.8
   python main.py scan github.com
   python main.py scan user@example.com
   ```

2. **Username Recon:**
   ```bash
   python main.py user yanzyuyu
   ```

3. **Domain Intelligence:**
   ```bash
   python main.py domain github.com
   ```

4. **Subdomain Enumeration:**
   ```bash
   python main.py subdomains github.com
   ```

5. **IP Intelligence:**
   ```bash
   python main.py ip 1.1.1.1
   ```

6. **Email Analysis:**
   ```bash
   python main.py email test@mailinator.com
   ```

7. **Pipeline Automation (Format JSON Murni):**
   ```bash
   python main.py ip 1.1.1.1 --json
   python main.py scan target --json -o report.json
   ```

## Struktur Proyek

```
ysint/
├── .gitignore             # Aturan ignorasi cache dan file sensitif
├── main.py                # Entrypoint eksekusi aplikasi
├── README.md              # Dokumentasi teknis proyek
├── terminal_demo.svg      # Snapshot visual eksekusi terminal
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
        ├── subdomain.py   # Resolusi konkruen subdomain
        └── username.py    # Multi-platform username hunting
```

## Pengujian Unit

Jalankan rangkaian test otomatis bawaan:

```bash
python -m unittest discover tests
```
