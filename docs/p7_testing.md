# PRD Bagian 7: Hardening, Pengujian, Bukti, dan Kriteria Kelulusan

**Versi:** 4.2  
**Tujuan:** Melaksanakan pengujian beban/stres, analisis statis keamanan kode, pengambilan bukti Wireshark, penyusunan README final, dan verifikasi kriteria kelulusan proyek.

---

## 1. Hardening & Analisis Kode Statis (`tests/test_static_checks.py`)

Analisis statis memakai `ast` dan `tokenize` dari stdlib, bukan pencocokan teks mentah. Seluruh aturan harus deterministik dan dapat dijalankan ulang di clean clone.

1. **Larangan library terlarang:**
   - Pindai seluruh `*.py` di repositori (kecuali `.git/`, `__pycache__/`, `.venv/`) dan tolak `import`/`from ... import` untuk root modul: `cryptography`, `Crypto`, `Cryptodome`, `pycryptodome`, `pyaes`, `hashlib`, `hmac`, `ssl`, `crypt`, `nacl`, `OpenSSL`, `M2Crypto`.
   - Tolak `__import__` dan `importlib.import_module` dengan argumen literal yang menunjuk modul terlarang; impor dinamis dengan argumen non-literal dianggap gagal.
   - `random` dilarang di modul produksi; hanya boleh di `tests/` untuk fixture non-keamanan. `secrets` wajib dipakai untuk key/nonce/IV.
2. **Larangan key hardcoding:**
   - Pindai modul produksi (semua `*.py` di luar `tests/`) untuk literal `str`/`bytes` berukuran 16 yang di-assign ke nama variabel/parameter yang cocok dengan pola `(?i)(key|ka|kb|ks|secret|password|token)`.
   - `config.*.example.json` tidak boleh memiliki field bernilai key atau string 16 karakter yang berfungsi sebagai key.
   - Pengecualian hanya untuk test vector di `tests/` dan literal 16 byte nol yang eksplisit (blok zero untuk KCV). Tidak ada pengecualian untuk kode produksi.
3. **Kebersihan komentar, docstring, dan tipe:**
   - `tokenize` menolak `TODO`, `FIXME`, `XXX`, komentar berisi kode yang dinonaktifkan, dan docstring multi-baris di modul produksi; docstring maksimal satu baris ringkas.
   - Setiap fungsi/metode produksi wajib memiliki type hint lengkap untuk parameter dan return value (dicek dengan `ast`).
   - Impor dikelompokkan dan diurutkan alfabetis; nama konstanta `UPPER_SNAKE_CASE`; panjang baris 88-100 karakter; dua baris kosong antar-fungsi/kelas.
   - Tidak ada komentar narasi langkah-demi-langkah. Komentar hanya boleh satu baris dan menjelaskan alasan non-obvious (“why”, bukan “how”). Pemeriksaan narasi tetap memerlukan review manual di T7.6.
4. **Larangan kebocoran log:**
   - Test runtime menjalankan skenario sukses dan gagal dengan direktori log sementara, lalu memastikan log tidak memuat `Ka`, `Kb`, `Ks`, `N1`, `N2`, KCV, atau isi key.
   - Event `APP_MSG` wajib memuat plaintext dan hex ciphertext lowercase (sesuai T6.18), tetapi tidak boleh memuat key/nonce/KCV.
   - File log wajib mode `0600`; logging tidak boleh menulis ke `stdout` setelah UI aktif.
5. **Larangan dependensi eksternal:**
   - Repositori wajib berjalan dengan Python 3.10+ tanpa `pip install` paket pihak ketiga. `requirements.txt` tidak boleh mendeklarasikan dependensi runtime.

---

## 2. Panduan Bukti Wireshark (`docs/evidence/`)

- **Filter Capture:** `tcp port 5000 or tcp port 5001`
- **Tabel Bukti Analisis Paket Wireshark:**

| Langkah | Arah | Protokol | Isi Terlihat (Plaintext / Hex) | Status Kerahasiaan |
|---|---|---|---|---|
| 1 | Alice → KDC | TCP | JSON: `type: "KDC_REQ"`, `id_a`, `id_b`, `n1` | Plaintext (Sesuai Diagram) |
| 2 | KDC → Alice | TCP | JSON: `type: "KDC_RESP"`, `iv`, `ct` (Hex) | Terenkripsi ($K_a$ & $K_b$) |
| 3 | Alice → Bob | TCP | JSON: `type: "TICKET"`, `iv`, `ct` (Hex) | Terenkripsi ($K_b$) |
| 4 | Bob → Alice | TCP | JSON: `type: "CHALLENGE"`, `iv`, `ct` (Hex) | Terenkripsi ($K_s$) |
| 5 | Alice → Bob | TCP | JSON: `type: "CHALLENGE_RESP"`, `iv`, `ct` (Hex) | Terenkripsi ($K_s$) |
| App | 2 Arah | TCP | JSON: `type: "APP_MSG"`, `iv`, `ct` (Hex) | Terenkripsi ($K_s$) |

- **Struktur direktori bukti:**

```text
docs/evidence/
  README.md
  step1_alice_kdc_YYYYMMDD-HHMMSS.pcapng
  step2_kdc_alice_YYYYMMDD-HHMMSS.pcapng
  step3_alice_bob_YYYYMMDD-HHMMSS.pcapng
  step4_bob_alice_YYYYMMDD-HHMMSS.pcapng
  step5_alice_bob_YYYYMMDD-HHMMSS.pcapng
  app_alice_bob_YYYYMMDD-HHMMSS.pcapng
  app_bob_alice_YYYYMMDD-HHMMSS.pcapng
  screenshots/
    demo-01-menu-kdc.png
    demo-02-auth-ok.png
    demo-03-app-msg.png
```

- **`docs/evidence/README.md` wajib berisi indeks:** ID test manual (T1.15/T4.15/T5.17/T6.19/T6.20), nama file, IP ketiga perangkat, tanggal/jam, interface capture, filter yang dipakai, penguji, dan hasil singkat.
- **Setiap pcapng wajib** memuat handshake TCP lengkap untuk langkah terkait (bukan potongan frame), dapat dibuka di Wireshark, dan konsisten dengan tabel di atas. Sertakan catatan “Follow TCP Stream” untuk membuktikan `KDC_REQ` plaintext dan payload lain berupa hex.
- **Screenshot** memakai PNG/JPG, tidak boleh menampilkan key, prompt `getpass`, isi `config.json`, atau terminal history. Screenshot boleh menampilkan ID, state, KCV, plaintext uji, dan hex ciphertext.
- **Data uji** memakai key dan plaintext dummy. File pcapng/screenshot yang dikomit hanya bukti yang sudah diperiksa; file mentah berisi data sensitif tidak boleh masuk repositori.

---

## 3. Struktur README Final (`README.md`)

README wajib berbahasa Indonesia, menjadi dokumen utama teori/arsitektur/panduan penggunaan (PRD tetap dokumen spesifikasi internal), sesuai `docs/AGENTS.md`, dan mencakup 10 poin berikut:
1. Ringkasan Proyek & Alur 5 Langkah KDC.
2. Prasyarat Lingkungan (Python 3.10+ tanpa library eksternal).
3. Panduan Konfigurasi (`config.alice/bob/kdc.example.json` & IP Address).
4. Tata Cara Menjalankan Aplikasi (KDC → Bob → Alice).
5. Contoh Tangkapan Layar Demo Interaktif.
6. Cara Menjalankan Pengujian Otomatis (`unittest`).
7. Tabel Analisis Wireshark & Panduan Pembuktian.
8. Penjelasan Perilaku Perubahan Key Dinamis (FR-08).
9. **Dokumentasi Keterbatasan Sistem:**
   - CBC tanpa HMAC tidak menjamin integritas ciphertext penuh.
   - Tiket tanpa Timestamp rentan terhadap Replay Attack jika tidak dimitigasi.
   - Ruang key ASCII printable lebih kecil dibandingkan 128-bit acak murni.
10. Referensi Akademis (FIPS-197, NIST SP 800-38A).

**Tambahan wajib di README:**
- Struktur repositori dan tanggung jawab setiap modul (`encoding_utils`, `network`, `manual_aes`, `protocol`, `session`, `ui`, `kdc_server`, `alice_client`, `bob_client`, `tests`).
- Config contoh terpisah untuk KDC/Alice/Bob, cara mengisi IP di 3 perangkat, port yang harus dibuka, dan urutan startup.
- Prosedur provisioning key awal (`Ka`, `Kb`) via `getpass` serta cara mencocokkan key antar-perangkat.
- Perintah persis: `python -m unittest discover -s tests -v` dan cara menjalankan demo 3 perangkat.
- Lokasi log (`logs/`), format, izin `0600`, dan aturan redaksi.
- Non-goal keamanan dari PRD Bagian 1 §2.4 (HMAC/integrity, replay pesan aplikasi, TLS, DoS, memory zeroization, forward secrecy).
- Tautan ke indeks `docs/evidence/README.md` dan pemetaan test manual ke file bukti.
- Troubleshooting umum: key mismatch, `UNKNOWN_ID`, `BUSY`, timeout, port terpakai, dan config invalid.

---

## 4. Matriks Pengujian Akhir & Stres Test

| ID | Skenario | Hasil yang Diharapkan |
|---|---|---|
| T7.1 | `python -m unittest discover -s tests -v` | 100% lulus, tidak ada error/skip tak terduga |
| T7.2 | Injection error/putus koneksi di tiap langkah: connect KDC, setelah respons KDC, kirim tiket, challenge, response, app message | State sesuai tabel PRD Bagian 5; tidak ada crash/thread bocor |
| T7.3 | Stres 20 sesi autentikasi berurutan (masing-masing 1 pesan aplikasi) | Tidak ada unhandled exception; setelah idle 5 detik thread ≤ baseline + 2, FD tidak naik monoton (toleransi transient +4); total ≤ 120 detik |
| T7.4 | Restart listener segera setelah shutdown | Bind ulang berhasil karena `SO_REUSEADDR` |
| T7.5 | Static check AST untuk impor, dynamic import, hardcoded key, dan dependensi | Lulus 100%; pelanggaran menghasilkan pesan file/baris |
| T7.6 | Review comment, docstring, type hint, import order, line length | Sesuai `docs/AGENTS.md`; tidak ada komentar narasi/commented-out code; type hint lengkap |
| T7.7 | Audit git history (`git log -p --all`) | Tidak ada key/nonce/log/config rahasia; hanya test vector di `tests/` yang diizinkan |
| T7.8 | Audit pcapng dan screenshot | Setiap langkah punya bukti lengkap, konsisten dengan tabel, tidak membocorkan key |
| T7.9 | Clean clone ke direktori sementara | `git clone` → copy config contoh → `python -m unittest discover -s tests -v` lulus tanpa instalasi eksternal |
| T7.10 | Audit README 10 poin + tambahan wajib | Lengkap, akurat, dan perintah dapat dijalankan apa adanya |
| T7.11 | **Final Demo Run pada 3 IP Perangkat Fisik** | Seluruh skenario pengujian dosen lulus sempurna |
| T7.12 | Audit log runtime | Tidak ada key/nonce/KCV; APP_MSG mencatat plaintext + ct; mode file `0600` |
| T7.13 | Shutdown KDC/Bob/Alice saat idle dan saat sesi aktif | Thread join ≤ 2 detik, socket tertutup, tidak ada FD/thread menggantung |
| T7.14 | UI non-TTY (pipe) dan input invalid | Tidak ada escape ANSI, tidak crash, prompt tidak ganda |
| T7.15 | Config per-role valid/invalid | Config valid diterima; invalid exit `2` tanpa stack trace/kebocoran |
| T7.16 | Cross-check KCV Alice vs Bob setelah autentikasi | 6 hex lowercase identik; `-` saat belum ada `Ks` |
| T7.17 | Indeks `docs/evidence/README.md` | Semua test manual terpetakan ke file bukti yang ada |

---

## 5. Struktur Repositori dan Perintah Uji

```text
.
├── README.md
├── config.alice.example.json
├── config.bob.example.json
├── config.kdc.example.json
├── docs/
│   ├── AGENTS.md
│   ├── p1_network_foundation.md ... p7_testing.md
│   └── evidence/
│       ├── README.md
│       ├── *.pcapng
│       └── screenshots/
├── encoding_utils.py
├── network.py
├── manual_aes.py
├── protocol.py
├── session.py
├── ui.py
├── kdc_server.py
├── alice_client.py
├── bob_client.py
├── tests/
│   ├── test_p1_network.py ... test_p7_integration.py
│   ├── test_static_checks.py
│   └── test_integration_loopback.py
└── logs/                  # gitignored, dibuat saat runtime
```

- **Perintah wajib:** `python -m unittest discover -s tests -v`; jalankan juga `python -m unittest tests.test_static_checks -v` secara terpisah di CI/lokal.
- **Test loopback** wajib menjalankan KDC/Alice/Bob dalam proses terpisah atau thread dengan port ephemeral, sehingga suite tidak bergantung pada 3 perangkat fisik.
- **Test seam:** test boleh memakai `unittest.mock` untuk mengganti `new_nonce`, `new_session_key`, `generate_iv`, dan waktu/timeout. `seal()` sudah menerima `iv` eksplisit untuk kasus deterministik. Tidak perlu menambahkan parameter test ke API produksi.
- **Tidak ada dependensi runtime pihak ketiga.** Seluruh test memakai `unittest` dan stdlib.
- File `config*.json` (selain `config.*.example.json`), `logs/`, `__pycache__/`, `*.pyc`, dan file sementara tidak boleh di-commit; `docs/evidence/` dan screenshot yang sudah diperiksa boleh di-commit.

---

## 6. Checklist Kriteria Kelulusan Proyek

Centang hanya setelah bukti tersedia dan diverifikasi.

- [ ] Berjalan pada 3 IP address / perangkat fisik terpisah.
- [ ] Implementasi 5 langkah skenario KDC dan komunikasi AES 2 arah berjalan lancar.
- [ ] AES-128-CBC, PKCS#7, dan KDC diimplementasikan secara manual.
- [ ] Key & Plaintext berformat ASCII, Ciphertext berformat Hexadecimal.
- [ ] Program bersifat interaktif (Key dapat diubah tanpa restart).
- [ ] Bebas dari library kriptografi eksternal.
- [ ] Config per-role, provisioning key, dan urutan startup terdokumentasi serta teruji.
- [ ] Logging/redaksi sesuai PRD Bagian 1 §2.3 dan lolos T7.12.
- [ ] Suite otomatis, static check, dan test loopback lulus tanpa skip.
- [ ] Bukti Wireshark, indeks evidence, dan README final lengkap.
- [ ] Clean clone berhasil dijalankan sesuai README.
- [ ] Final demo pada 3 perangkat fisik lulus.