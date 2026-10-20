# PRD Bagian 3: Spesifikasi Protokol, Serialisasi, dan Validasi

**Versi:** 4.2  
**Tujuan:** Mendefinisikan struktur pesan JSON, aturan serialisasi byte deterministik, dan fungsi validasi protokol murni (tanpa ketergantungan socket).

---

## 1. Spesifikasi Serialisasi Plaintext Terenkripsi

Untuk mencegah ambiguitas pemisahan variabel saat dekripsi, serialisasi byte internal mengikuti aturan deterministik berikut:

1. **`R_A` (Payload untuk Alice di Langkah 2):**  
   `Ks (16B) || len(ID_A) (1B) || ID_A || len(ID_B) (1B) || ID_B || N1 (8B)`
2. **`T_B` (Tiket untuk Bob di Langkah 2 & 3):**  
   `Ks (16B) || len(ID_A) (1B) || ID_A`  
   `T_B` tidak memuat `ID_B`; implementasi mengasumsikan `Kb` unik untuk Bob.
3. **`C` (Challenge Bob di Langkah 4):**  
   `N2 (8B big-endian)`
4. **`R` (Response Alice di Langkah 5):**  
   `f(N2) (8B big-endian)` di mana $f(N2) = (N2 - 1) \pmod{2^{64}}$.

**Aturan encoding dan validasi serialisasi:**
- Panjang ID adalah unsigned 8-bit dan dihitung dari jumlah byte ASCII (ID dijamin ASCII oleh `validate_id`). ID wajib 1-16 byte.
- `N1` dan `N2` direpresentasikan sebagai unsigned 64-bit big-endian, baik di byte internal maupun di field JSON `n1` (16 karakter hex lowercase). Parser menerima hex huruf besar/kecil, tetapi builder selalu menulis lowercase. Tidak ada signed integer.
- `Ks` wajib 16 byte ASCII printable; decoder menolak key yang tidak valid dengan `ProtocolError("BAD_FORMAT")`.
- Decoder wajib mengonsumsi seluruh byte dan menolak byte berlebih/kurang, panjang ID yang tidak cocok, serta ID yang tidak valid dengan `ProtocolError("BAD_FORMAT")`.
- Kegagalan dekripsi/padding pada amplop menghasilkan `ProtocolError("DECRYPT_FAIL")`; kegagalan struktur/schema menghasilkan `ProtocolError("BAD_FORMAT")`. Kedua kelas error tidak boleh saling dipertukarkan.

---

## 2. Skema Amplop Pesan Jaringan (JSON)

Semua objek terenkripsi berbentuk `{"iv": "<32_hex>", "ct": "<hex_kelipatan_32>"}`. Setiap pesan wajib memiliki `v: 1`.

**Aturan amplop dan pesan:**
- `iv` wajib tepat 32 karakter hex (16 byte). `ct` wajib hex dengan panjang minimal 32 karakter (satu blok) dan kelipatan 32 karakter. Output builder selalu lowercase; parser menerima huruf besar/kecil dan menormalkan ke lowercase.
- Amplop hanya boleh memiliki key `iv` dan `ct`; field tambahan ditolak dengan `ProtocolError("BAD_FORMAT")`.
- `v` wajib integer `1` (bukan `true`/`false`). `type` wajib string yang terdaftar. Field wajib per tipe pesan harus ada; field asing pada level pesan ditolak dengan `ProtocolError("BAD_FORMAT")`.
- `msg` pada pesan error bersifat non-normatif, tidak boleh memuat key/nonce/plaintext, dan tidak boleh diandalkan oleh test. Yang normatif adalah `code`.
- Field `from` pada `APP_MSG` wajib sama dengan `peer_id` yang terautentikasi; jika tidak cocok, pesan ditolak dengan `ProtocolError("BAD_FORMAT")`.
- Tidak ada sequence number, MAC, ACK, atau timestamp. Replay pesan aplikasi dalam sesi aktif adalah non-goal (lihat PRD Bagian 1).

**Kode error yang diizinkan:**

| Tipe pesan | Kode | Kondisi |
|---|---|---|
| `KDC_ERR` | `UNKNOWN_ID` | `id_a` atau `id_b` tidak ada di registry KDC |
| `KDC_ERR` | `BAD_FORMAT` | JSON/field/tipe/versi request tidak valid |
| `KDC_ERR` | `INTERNAL` | Kegagalan internal KDC yang tidak diharapkan |
| `AUTH_FAIL` | `DECRYPT_FAIL` | Tiket atau respons challenge gagal didekripsi/divalidasi padding |
| `AUTH_FAIL` | `BAD_RESPONSE` | Nilai `f(N2)` tidak cocok |
| `AUTH_FAIL` | `BAD_FORMAT` | Field/payload challenge rusak |
| `AUTH_FAIL` | `TIMEOUT` | Batas waktu langkah terlampaui |
| `ERROR` | `BAD_STATE` | Tipe pesan tidak legal untuk state saat ini |
| `ERROR` | `BUSY` | Bob sudah memiliki sesi aktif |
| `ERROR` | `DECRYPT_FAIL` | Pesan aplikasi gagal didekripsi |
| `ERROR` | `BAD_FORMAT` | Pesan/field tidak valid |
| `ERROR` | `TIMEOUT` | Timeout saat menunggu peer |
| `ERROR` | `INTERNAL` | Kegagalan internal yang tidak diharapkan |

| Step | Type | Schema Payload JSON |
|---|---|---|
| 1 | `KDC_REQ` | `{"v":1, "type":"KDC_REQ", "id_a":"alice", "id_b":"bob", "n1":"<16_hex>"}` |
| 2 | `KDC_RESP` | `{"v":1, "type":"KDC_RESP", "for_a":{"iv":"..","ct":".."}, "ticket":{"iv":"..","ct":".."}}` |
| 2 | `KDC_ERR` | `{"v":1, "type":"KDC_ERR", "code":"UNKNOWN_ID", "msg":"..."}` |
| 3 | `TICKET` | `{"v":1, "type":"TICKET", "ticket":{"iv":"..","ct":".."}}` |
| 4 | `CHALLENGE` | `{"v":1, "type":"CHALLENGE", "body":{"iv":"..","ct":".."}}` |
| 5 | `CHALLENGE_RESP` | `{"v":1, "type":"CHALLENGE_RESP", "body":{"iv":"..","ct":".."}}` |
| Status | `AUTH_OK` | `{"v":1, "type":"AUTH_OK"}` |
| Status | `AUTH_FAIL` | `{"v":1, "type":"AUTH_FAIL", "code":"DECRYPT_FAIL"}` |
| App | `APP_MSG` | `{"v":1, "type":"APP_MSG", "from":"alice", "body":{"iv":"..","ct":".."}}` |
| Control | `BYE` | `{"v":1, "type":"BYE"}` |
| Control | `ERROR` | `{"v":1, "type":"ERROR", "code":"BAD_STATE", "msg":"..."}` |

### 2.1 Kontrak API `protocol.py`

`protocol.py` murni fungsi/kelas protokol tanpa socket, thread, atau I/O. Seluruh builder mengembalikan `dict` yang JSON-serializable dan tidak pernah memuat `Ka`, `Kb`, atau `Ks` plaintext. Seluruh parser menolak schema yang salah dengan `ProtocolError` dan tidak melakukan logging.

- **Exception:** `class ProtocolError(Exception)` dengan atribut `code: str`; konstruktor `ProtocolError(code: str, msg: str = "")`.
- **`new_session_key() -> bytes`:** 16 byte acak dari `secrets.choice` atas karakter ASCII printable 0x21-0x7E. Tidak memakai whitespace dan tidak pernah dicatat.
- **`new_nonce() -> bytes`:** 8 byte acak dari `secrets.token_bytes(8)`. `N1`/`N2` diinterpretasikan sebagai unsigned 64-bit big-endian.
- **`f(n2: int) -> int`:** `(n2 - 1) % 2**64`; menerima `n2=0`.
- **`seal(key: bytes, plaintext: bytes, *, iv: bytes | None = None) -> dict`:** memvalidasi key 16 byte; jika `iv` diberikan (khusus test) wajib 16 byte, jika tidak memakai `generate_iv()`. Mengembalikan amplop `iv`/`ct` lowercase. Tidak memakai parameter di luar signature ini.
- **`unseal(key: bytes, envelope: dict) -> bytes`:** memvalidasi amplop secara ketat lalu mendekripsi. Schema/hex/panjang salah → `BAD_FORMAT`; kegagalan dekripsi/padding → `DECRYPT_FAIL`. Key salah dapat menghasilkan garbage jika padding kebetulan valid; tidak ada jaminan deteksi.
- **`encode_r_a(ks: bytes, id_a: str, id_b: str, n1: bytes) -> bytes`** dan **`decode_r_a(data: bytes) -> tuple[bytes, str, str, bytes]`**.
- **`encode_t_b(ks: bytes, id_a: str) -> bytes`** dan **`decode_t_b(data: bytes) -> tuple[bytes, str]`**.
- **`build_kdc_request(id_a: str, id_b: str, n1: bytes) -> dict`:** menolak `id_a == id_b`, ID invalid, atau `n1` bukan 8 byte. Field `n1` memakai hex lowercase 16 karakter.
- **`parse_kdc_request(msg: dict) -> tuple[str, str, bytes]`:** mengembalikan `(id_a, id_b, n1)` setelah validasi `v`, `type`, schema, ID, dan nonce.
- **`build_kdc_response(ka: bytes, kb: bytes, ks: bytes, id_a: str, id_b: str, n1: bytes) -> dict`:** membangun `KDC_RESP` dengan `for_a = seal(ka, encode_r_a(...))` dan `ticket = seal(kb, encode_t_b(...))`.
- **`open_kdc_response(msg: dict, ka: bytes, id_a: str, id_b: str, n1: bytes) -> tuple[bytes, dict]`:** memvalidasi tipe, membuka `for_a`, memeriksa `ID_A`, `ID_B`, dan `N1` (perbandingan memakai `secrets.compare_digest`), lalu mengembalikan `(ks, ticket_envelope)`. `N1` tidak cocok atau ID tidak cocok → `BAD_FORMAT`; gagal dekripsi → `DECRYPT_FAIL`.
- **`open_ticket(ticket: dict, kb: bytes, expected_id_a: str) -> tuple[bytes, str]`:** membuka `T_B`, memvalidasi `Ks` dan `ID_A`, dan memastikan `ID_A == expected_id_a`. `T_B` tidak memuat `ID_B`; identitas Bob dijamin oleh `Kb`.
- **`build_challenge(ks: bytes, n2: bytes) -> dict`** dan **`build_challenge_response(ks: bytes, n2: bytes) -> dict`:** masing-masing membungkus `N2` dan `f(N2)` 8 byte big-endian.
- **`check_challenge_response(ks: bytes, n2: bytes, msg: dict) -> bool`:** membuka `CHALLENGE_RESP`, memastikan panjang 8 byte, dan membandingkan `f(N2)` dengan `secrets.compare_digest`. Nilai tidak cocok → `False`; schema/dekripsi gagal → `ProtocolError`.
- **`build_app_msg(from_id: str, ks: bytes, plaintext: str) -> dict`:** memvalidasi `from_id` dan plaintext (1-1.024 ASCII printable), lalu membungkus plaintext dengan `Ks`.
- **`open_app_msg(msg: dict, ks: bytes, expected_from: str | None = None) -> tuple[str, str]`:** memvalidasi tipe/field, membuka body, memvalidasi plaintext, dan mengembalikan `(from_id, plaintext)`. Jika `expected_from` diberikan dan tidak cocok → `BAD_FORMAT`.
- **`compute_kcv(ks: bytes) -> str`:** `encrypt_block(ks, b"\x00" * 16)[:3].hex()`, selalu 6 karakter lowercase. Hanya untuk tampilan, tidak untuk logging.
- **Builder status/kontrol:** `build_auth_ok()`, `build_auth_fail(code)`, `build_error(code, msg="")`, `build_bye()`, dan `build_kdc_error(code, msg="")`. Semua `code` harus berasal dari tabel kode error di atas.
- **Validator umum:** `parse_message(msg: dict, expected_type: str | None = None) -> dict` memvalidasi `v`, `type`, field wajib, dan field asing; fungsi ini dipakai oleh seluruh parser. `bool` tidak diterima sebagai nilai integer.

---

## 3. Matriks Pengujian Bagian 3

| ID | Skenario | Hasil yang Diharapkan |
|---|---|---|
| T3.1 | Serialisasi & Deserialisasi `R_A` | Seluruh field pulih presisi |
| T3.2 | Serialisasi & Deserialisasi `T_B` | Seluruh field pulih presisi |
| T3.3 | Deserialisasi `R_A` dengan byte berlebih/kurang | Ditolak dengan `ProtocolError` |
| T3.4 | Pengujian ID batas 1 byte & 16 byte | Diterima sesuai aturan |
| T3.5 | Evaluasi $f(N2)$ untuk $N2=0$ (underflow) | Menghasilkan $2^{64}-1$ (8 byte big-endian) |
| T3.6 | Pembangkitan `new_session_key()` | 16 byte ASCII printable (0x21-0x7E) acak |
| T3.7 | Pembangkitan `new_nonce()` | 8 byte acak |
| T3.8 | Pengujian `seal()` dengan plaintext identik | IV dan Ciphertext Hex berbeda |
| T3.9 | Pengujian `unseal()` dengan ct rusak/padding invalid | Lempar `ProtocolError("DECRYPT_FAIL")`; key salah tidak dijamin terdeteksi |
| T3.10 | `build_kdc_request` dan `parse_kdc_request` | Data terurai sempurna |
| T3.11 | `parse_kdc_request` dengan `id_a == id_b` | Ditolak `ProtocolError("BAD_FORMAT")` |
| T3.12 | `build_kdc_response` dan `open_kdc_response` | $K_s$ dan Tiket terurai sempurna |
| T3.13 | `open_kdc_response` dengan $N_1$ tidak cocok | Ditolak |
| T3.14 | `open_ticket` dengan $K_b$ salah / ID terlarang | Ditolak |
| T3.15 | Validation Challenge-Response sukses | Mengembalikan `True` |
| T3.16 | Validation Challenge-Response jawaban salah | Mengembalikan `False` (tanpa raise exception) |
| T3.17 | Enkripsi & Dekripsi `APP_MSG` | Plaintext dan sender pulih identik |
| T3.18 | Dekripsi `APP_MSG` menghasilkan non-ASCII | Ditolak |
| T3.19 | Verifikasi JSON Serializability seluruh builder | Bebas dari type error, tidak bocor key |
| T3.20 | Penanganan error jaringan generik | Tidak dipetakan menjadi `DECRYPT_FAIL`; session layer menutup koneksi dan mereset state |
| T3.21 | Eksekusi Ulang Seluruh Tes dengan `manual_aes` | Lulus 100% |
| T3.22 | Amplop dengan field asing / `iv` bukan 16 byte / `v` bukan 1 | Lempar `ProtocolError("BAD_FORMAT")` |
| T3.23 | `decode_r_a` dengan `Ks` non-printable atau ID invalid | Lempar `ProtocolError("BAD_FORMAT")` |
| T3.24 | Round-trip `N1`/`N2` big-endian 8 byte | Byte identik dan nilai unsigned 64-bit benar |
| T3.25 | `open_app_msg` dengan `from` tidak cocok | Lempar `ProtocolError("BAD_FORMAT")` |
| T3.26 | Tipe pesan tidak dikenal / field wajib hilang | Lempar `ProtocolError("BAD_FORMAT")` |
| T3.27 | Pemindaian string builder untuk `Ka`/`Kb`/`Ks` | Tidak ada key plaintext pada output JSON |
| T3.28 | `compute_kcv` untuk `Ks` yang sama | 6 karakter hex lowercase dan identik |

---

## 4. Gerbang Selesai
- Pengujian T3.1 - T3.28 lulus.
- File `protocol.py` murni bebas dari impor modul `socket`.