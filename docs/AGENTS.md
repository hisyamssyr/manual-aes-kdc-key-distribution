# AGENT GUIDELINES & STRICT CODING STANDARDS

Dokumen ini berisi instruksi eksekusi utama untuk AI Coding Agent. Semua kode yang dibuat atau diubah wajib mematuhi standar di bawah ini secara mutlak.

---

## 1. Zero-Narrative Comment Policy (Aturan Komentar Ketat)

- DILARANG menulis komentar yang menarasikan alur kode, menceritakan ulang nama fungsi, atau menyerupai catatan modul kuliah (contoh terlarang: `# buat socket`, `# xor dua byte`, `# panggil fungsi encrypt`).
- Tulis kode yang *self-documenting* melalui penamaan variabel dan fungsi yang jelas serta deskriptif.
- Komentar HANYA diperbolehkan maksimal 1 baris jika menjelaskan alasan teknis *non-obvious* (alasan "WHY", bukan "HOW").
- Jika alur fungsi terlalu panjang, pecah menjadi fungsi-fungsi kecil deskriptif daripada memberinya komentar langkah demi langkah.

---

## 2. README-Only Documentation Policy

- DILARANG menaruh penjelasan teori kriptografi, matematika AES, alur diagram Needham-Schroeder, penjelasan struktur berkas, atau panduan penggunaan di dalam berkas `.py` (baik di komentar maupun *docstring*).
- SELURUH penjelasan teori, arsitektur, peta paket Wireshark, dan dokumentasi berkas WAJIB ditaruh di berkas `README.md`.
- *Docstring* pada berkas `.py` hanya diperbolehkan 1 baris ringkas (*one-line summary*) pada level fungsi/kelas jika benar-benar diperlukan.

---

## 3. Uniform Code Layout & Style Rules

Setiap berkas `.py` wajib mengikuti struktur dan tata letak yang seragam dari atas ke bawah:

1. **Imports:**
   - Hanya gunakan Standard Library Python 3.10+.
   - Kelompokkan dan urutkan secara alfabetis.
2. **Constants:**
   - Gunakan format `UPPER_SNAKE_CASE`.
3. **Custom Exceptions / Enums / Dataclasses:**
   - Gunakan format `PascalCase`.
4. **Functions & Classes:**
   - Gunakan `snake_case` untuk nama fungsi/metode dan `PascalCase` untuk kelas.
   - Wajib menggunakan *Type Hints* secara penuh pada setiap parameter dan *return value* (misal: `def process_data(data: bytes) -> dict:`).
5. **PEP 8 Compliance:**
   - Maksimal 88–100 karakter per baris.
   - 2 baris kosong antar-fungsi/kelas.

---

## 4. Contoh Penulisan Kode (Bad vs Good)

**[X] TERLARANG (Banyak komentar narasi & tanpa type hint):**

```python
# Modul ini untuk enkripsi AES CBC
def cbc_enc(k, p):
    # Langkah 1: buat IV acak 16 byte
    iv = os.urandom(16)
    # Langkah 2: tambahkan padding PKCS7
    pad_len = 16 - (len(p) % 16)
    p = p + bytes([pad_len] * pad_len)
    # Langkah 3: loop enkripsi per blok
    ...
```

**[V] WAJIB (Clean, Self-Documenting, Uniform):**

```python
def encrypt_cbc(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    padded_plaintext = apply_pkcs7_padding(plaintext)
    blocks = split_into_blocks(padded_plaintext)
    ciphertext_blocks = []
    previous_block = iv

    for block in blocks:
        xored_block = xor_bytes(block, previous_block)
        encrypted_block = encrypt_block(key, xored_block)
        ciphertext_blocks.append(encrypted_block)
        previous_block = encrypted_block

    return b"".join(ciphertext_blocks)
```

## 5. Automated Static Check Rules

Kode yang ditulis akan diverifikasi oleh suite test statis. Pengerjaan dinyatakan GAGAL jika:

- Ditemukan impor library terlarang (cryptography, Crypto, pyaes, hashlib, dll.).
- Rasio baris komentar melebihi 10% dari total baris kode pada suatu berkas .py.
- Ditemukan pola komentar narasi seperti # langkah, # step, # fungsi, # algoritma.
- Ada parameter atau return value fungsi publik yang tidak memiliki Type Hints.

---

## 2. Pembaharuan K.2 pada `PART_1_FONDASI_NETWORK.md`

```markdown
## K.2 Aturan Wajib untuk Agent

1. Bahasa & Library: Python 3.10+. Tanpa dependensi eksternal. Dilarang memakai library kriptografi apa pun (`cryptography`, `pycryptodome`, `pyaes`, `Crypto`, `hashlib` untuk keperluan protokol, dan sejenisnya), termasuk di folder tes.
2. Library yang Diizinkan: `socket`, `threading`, `queue`, `json`, `struct`, `secrets`, `os`, `argparse`, `getpass`, `logging`, `time`, `enum`, `dataclasses`, `unittest`.
3. Kebijakan Komentar & Dokumentasi Ketat:
   - Zero-Narrative Comment Policy: Dilarang keras menulis komentar yang menarasikan alur kode atau menyerupai catatan. Gunakan nama fungsi/variabel yang deskriptif dan fungsi pendek.
   - README-Only Documentation: Penjelasan teori matematika AES, arsitektur KDC, maupun deskripsi peran berkas WAJIB ditaruh di `README.md`, tidak boleh di dalam kode `.py`.
   - Rasio komentar pada setiap berkas `.py` maksimal 10% dari total baris kode.
4. Uniform Layout & Typing:
   - Wajib menggunakan Type Hints penuh pada setiap argumen dan return value fungsi.
   - Urutan penulisan berkas seragam: Import (sistem) -> Konstanta -> Exception/Enum -> Fungsi/Kelas.
5. Manajemen Key: Key tidak boleh di-hardcode dan tidak boleh ada di repo, log, atau berkas konfigurasi. Key diminta lewat prompt dan bisa diubah saat program berjalan.
6. Kode Sederhana & Modular: Harus mudah dijelaskan secara lisan oleh pemilik proyek tanpa catatan.
7. Setiap bagian harus lulus semua tesnya (termasuk static checks) sebelum bagian berikutnya dimulai.
```

