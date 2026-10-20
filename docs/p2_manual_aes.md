# PRD Bagian 2: Implementasi Manual AES-128, Mode CBC, dan Padding PKCS#7

**Versi:** 4.2  
**Tujuan:** Mengimplementasikan algoritma AES-128, mode operasi CBC, dan padding PKCS#7 secara manual dari dasar tanpa pustaka kriptografi eksternal.

---

## 1. Spesifikasi Teknis AES-128

### 1.1 Aritmetika GF(2^8) & Pembangkitan Tabel
- Polinomial Irredusibel: $x^8 + x^4 + x^3 + x + 1$ (`0x11B`).
- Pembangkitan S-Box secara dinamis saat modul dimuat:
  1. Cari invers perkalian di GF(2^8) (0x00 dipetakan ke 0x00).
  2. Terapkan transformasi afine: $s = inv \oplus rotl8(inv,1) \oplus rotl8(inv,2) \oplus rotl8(inv,3) \oplus rotl8(inv,4) \oplus 0x63$.
- S-Box Invers dibangkitkan langsung dari S-Box.
- Verifikasi internal: `S[0x00] == 0x63`, `S[0x53] == 0xED`.

### 1.2 Operasi Blok & Key Expansion
- State disusun dalam format **Column-Major** (4x4 byte).
- Transformasi Standar FIPS-197: `sub_bytes`, `shift_rows`, `mix_columns`, `add_round_key` beserta fungsi kebalikannya.
- Key Expansion: Menghasilkan 11 Round Keys (176 byte) dari 16 byte cipher key.

### 1.3 Mode CBC & Padding PKCS#7
- Alignment blok: 16 byte (128 bit).
- PKCS#7 Padding: Selalu menambahkan 1-16 byte padding. Jika plaintext kelipatan 16, tambahkan 1 blok baru berisi 16 byte `0x10`.
- Penanganan IV: IV acak 16 byte dibangkitkan menggunakan `secrets.token_bytes(16)`.
- Enkripsi CBC: $C_i = E_K(P_i \oplus C_{i-1})$ dengan $C_0 = IV$.

---

## 2. API Modul `manual_aes.py`

```python
class AESError(Exception):
    """Exception khusus untuk kegagalan internal AES."""
    pass

def encrypt_block(key: bytes, block: bytes) -> bytes: ...
def decrypt_block(key: bytes, block: bytes) -> bytes: ...
def encrypt_cbc(key: bytes, iv: bytes, plaintext: bytes) -> bytes: ...
def decrypt_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> bytes: ...
def generate_iv() -> bytes: ...
```

### 2.1 Semantik API dan Validasi

- **Tipe input:** seluruh parameter biner wajib `bytes`; tipe lain menghasilkan `TypeError`. Kesalahan panjang, padding, atau data internal menghasilkan `AESError` dengan pesan generik (tidak memuat key/plaintext).
- **`encrypt_block`/`decrypt_block`:** `key` tepat 16 byte dan `block` tepat 16 byte. Mengembalikan 16 byte. Panjang lain → `AESError`.
- **`encrypt_cbc`:** `key` dan `iv` tepat 16 byte. `plaintext` boleh kosong dan tidak dibatasi di lapisan AES. Selalu menambahkan padding PKCS#7 1-16 byte, sehingga `len(ct) == (len(pt) // 16 + 1) * 16`. Panjang key/IV salah → `AESError`.
- **`decrypt_cbc`:** `key` dan `iv` tepat 16 byte. `ciphertext` wajib tidak kosong dan kelipatan 16 byte. Validasi padding wajib memeriksa seluruh byte padding: nilai 1-16, jumlah byte konsisten, dan tidak ada byte di luar rentang. Padding `0x00`, nilai > 16, atau tidak konsisten → `AESError`. Hasil bisa `b""` untuk plaintext kosong.
- **Key salah:** CBC tanpa MAC tidak dapat membedakan key salah dari ciphertext acak. `decrypt_cbc` boleh mengembalikan garbage jika kebetulan padding valid; yang diwajibkan adalah tidak crash dan tetap memvalidasi panjang/padding. Ini bukan jaminan integritas.
- **`generate_iv`:** mengembalikan tepat 16 byte dari `secrets.token_bytes(16)`. IV tidak boleh dipakai ulang untuk key yang sama pada pesan berbeda; `seal()` di `protocol.py` membangkitkan IV baru setiap pesan.
- **Pembangkitan tabel:** S-Box dan inverse dibangkitkan saat modul dimuat. Modul wajib memverifikasi `S[0x00] == 0x63` dan `S[0x53] == 0xED`; jika verifikasi gagal, modul gagal cepat dengan `AESError`.
- **Non-goal:** implementasi tidak menjamin constant-time dan tidak menyediakan autentikasi/integritas. Hal itu berada di luar scope PRD ini.

---

## 3. Matriks Pengujian Bagian 2

| ID | Skenario | Hasil yang Diharapkan |
|---|---|---|
| T2.1 | Verifikasi S-Box & Inverse S-Box | S[0x00]=0x63, S[0x53]=0xED, Sinv[S[x]] == x |
| T2.2 | Key Expansion Test Vector FIPS-197 A.1 | Round Key ke-10 cocok tepat |
| T2.3 | AES Single-Block Test Vector FIPS-197 App B | Ciphertext cocok tepat |
| T2.4 | AES Single-Block Test Vector FIPS-197 App C.1 | Ciphertext cocok tepat |
| T2.5 | Uji Fungsi Kebalikan (inv_mix_columns, dll.) | State kembali utuh |
| T2.6 | CBC Test Vector NIST SP 800-38A F.2.1 | Seluruh blok ciphertext cocok |
| T2.7 | CBC Round-Trip Enkripsi/Dekripsi (0-100 byte) | Plaintext pulih 100% identik, termasuk plaintext kosong |
| T2.8 | Verifikasi Ukuran Ciphertext CBC | len(ct) == (len(pt) // 16 + 1) * 16 |
| T2.9 | Plaintext sama dengan IV berbeda | Menghasilkan ciphertext yang berbeda |
| T2.10 | Validation Padding Rusak / Invalid | Lempar AESError untuk padding 0x00, >16, atau tidak konsisten |
| T2.11 | Ciphertext kosong atau tidak kelipatan 16 byte | Lempar AESError |
| T2.12 | Key atau IV berukuran selain 16 byte | Lempar AESError |
| T2.13 | Dekripsi dengan Key yang salah | Tidak crash; boleh AESError atau garbage jika padding kebetulan valid |
| T2.14 | Pemindaian statis repositori terhadap library terlarang | Bersih dari cryptography, Crypto, pyaes, hashlib, hmac, dll. |
| T2.15 | `encrypt_block`/`decrypt_block` dengan key/block selain 16 byte | Lempar AESError |
| T2.16 | `generate_iv` dipanggil berulang | Selalu 16 byte dan tidak identik secara praktis |

---

## 4. Gerbang Selesai

- Pengujian T2.1 - T2.16 lulus 100%.
- Pengembang mampu menjelaskan alur matematika AES secara lisan tanpa alat bantu.

