# PRD Bagian 1: Konteks Umum, Fondasi, Konfigurasi, dan Transport Jaringan

**Versi:** 4.2 (Diselaraskan dengan Ketentuan Dosen & Best Practices)  
**Tujuan:** Menyiapkan struktur repositori, aturan encoding, validasi input, konfigurasi, dan transport TCP dengan framing 4-byte big-endian yang andal.

---

## 1. Konteks Umum Proyek

### 1.1 Ringkasan Ketentuan Dosen
1. **Arsitektur & Key Distribution:** Skenario KDC melibatkan 3 entitas (KDC, Alice, Bob) pada **3 IP Address / perangkat fisik berbeda**. Setelah langkah ke-5 selesai, Alice dan Bob berkomunikasi menggunakan AES terenkripsi.
2. **Komunikasi Dua Arah:** Alice dan Bob dapat bertindak sebagai sender maupun receiver secara interaktif.
3. **Implementasi AES & KDC Manual:** Dilarang keras menggunakan library kriptografi eksternal (`cryptography`, `pycryptodome`, `pyaes`, `Crypto`, `hashlib`, dsb.). Hanya pustaka bawaan Python 3.10+ yang diperbolehkan (`socket`, `threading`, `queue`, `json`, `struct`, `secrets`, `os`, `argparse`, `getpass`, `logging`, `time`, `enum`, `dataclasses`, `unittest`).
4. **Format Data:** Key dan Plaintext berformat ASCII, sedangkan Ciphertext ditampilkan dalam format Hexadecimal. Key tidak di-hardcode.
5. **Interaktivitas:** Key dapat diubah lewat menu tanpa perlu melakukan restart program.

**Kebijakan impor (mengikat):** Daftar pada poin 3 adalah modul yang direkomendasikan, bukan allowlist eksklusif. Seluruh modul stdlib Python 3.10+ non-kriptografi (antara lain `sys`, `typing`, `re`, `pathlib`, `tempfile`, `contextlib`, `signal`, `selectors`, `collections`, `unittest.mock`) boleh digunakan. Yang dilarang adalah seluruh pustaka pihak ketiga dan modul kriptografi/hash (`cryptography`, `Crypto`, `Cryptodome`, `pycryptodome`, `pyaes`, `hashlib`, `hmac`, `ssl`, `crypt`, `nacl`, `OpenSSL`, `M2Crypto`) serta impor dinamis dengan nama modul yang tidak literal. Modul `random` hanya boleh dipakai untuk fixture non-keamanan di `tests/`; seluruh nilai rahasia wajib memakai `secrets`. Pemindaian otomatis aturan ini dijelaskan di PRD Bagian 7.

---

### 1.2 Lima Langkah Protokol KDC
1. Alice → KDC: `ID_A || ID_B || N1` (Plaintext JSON)
2. KDC → Alice: `E(Ka, [Ks || ID_A || ID_B || N1]) || E(Kb, [Ks || ID_A])`
3. Alice → Bob: `E(Kb, [Ks || ID_A])` (Tiket)
4. Bob → Alice: `E(Ks, N2)` (Challenge)
5. Alice → Bob: `E(Ks, f(N2))` di mana `f(N2) = (N2 - 1) mod 2^64` (Response)

---

### 1.3 Kontrak Antarmuka Modul (`K.5`)

#### `encoding_utils.py`
- `bytes_to_hex(b: bytes) -> str`: Mengembalikan string hex huruf kecil tanpa pemisah. `bytes_to_hex(b"") == ""`.
- `hex_to_bytes(s: str) -> bytes`: Mengubah hex ke bytes. Menerima huruf besar maupun kecil, tetapi keluaran selalu lowercase. Lempar `ValueError` jika bukan hex valid atau panjang ganjil. String kosong menghasilkan `b""`.
- `validate_key(s: str) -> bytes`: Validasi tepat 16 karakter ASCII printable (0x20-0x7E), tanpa trimming. Lempar `ValueError` dengan pesan jelas (tanpa menampilkan key) jika tidak valid. Key sesi yang dibangkitkan KDC memakai subset 0x21-0x7E.
- `validate_plaintext(s: str) -> bytes`: Validasi ASCII printable (0x20-0x7E), panjang 1-1.024 karakter. Karakter kontrol, newline, dan karakter non-ASCII ditolak.
- `validate_id(s: str) -> str`: Validasi ID 1-16 karakter regex `[A-Za-z0-9_-]`. ID bersifat case-sensitive dan tidak dinormalisasi.

#### `network.py`
- `make_listener(host: str, port: int) -> socket.socket`: Membuat socket TCP `AF_INET`, menyalakan `SO_REUSEADDR`, melakukan `bind`, lalu `listen(backlog=16)`. Tidak memanggil `accept`. Lempar `NetworkError` dengan rincian host/port jika gagal.
- `connect(host: str, port: int, timeout: float) -> socket.socket`: Membuka koneksi TCP dengan timeout koneksi. Menutup socket parsial saat gagal dan melempar `NetworkError` dengan rincian host/port.
- `send_message(sock: socket.socket, obj: dict) -> None`: Membuat payload JSON UTF-8, memeriksa batas ukuran sebelum menulis, lalu memakai `sendall`. `obj` wajib `dict`. Lempar `FrameTooLarge` jika payload > 65.536 byte, `ValueError` jika objek tidak dapat diserialisasi, dan `NetworkError`/`ConnectionClosed` jika pengiriman gagal. Pemanggil wajib menjamin hanya satu thread yang menulis ke socket pada satu waktu (session layer menyediakan lock).
- `recv_message(sock: socket.socket, timeout: float = None) -> dict`: Batas waktu berlaku untuk keseluruhan frame (deadline), bukan per-`recv`. `timeout=None` berarti blocking; nilai `timeout <= 0` ditolak dengan `ValueError`. Header bernilai 0, payload bukan JSON, payload bukan `dict`, atau JSON memiliki key duplikat menghasilkan `BadFrame`. Panjang diumumkan > 65.536 byte menghasilkan `FrameTooLarge` tanpa membaca payload. EOF di tengah header/body menghasilkan `ConnectionClosed`; deadline terlewati menghasilkan `NetworkTimeout`. Validasi `v`, `type`, dan field protokol dilakukan di lapisan `protocol.py`, bukan di sini.
- **Urutan prioritas error:** `FrameTooLarge`/`BadFrame` (header tidak valid) → `ConnectionClosed` (EOF) → `NetworkTimeout` (deadline) → `BadFrame` (payload invalid). Setelah `recv_message` melempar `FrameTooLarge`, `BadFrame`, atau `NetworkTimeout`, stream dianggap tidak sinkron dan pemanggil wajib menutup socket.
- **Hierarki exception:** `NetworkError` adalah base class; `ConnectionClosed`, `FrameTooLarge`, `BadFrame`, dan `NetworkTimeout` adalah subclass-nya.
- **Penutupan socket:** gunakan `shutdown(SHUT_RDWR)` best-effort lalu `close()`. Error saat penutupan diabaikan. Tidak ada kompresi, delimiter newline, atau TLS pada lapisan ini.

---

## 2. Spesifikasi Bagian 1

### 2.1 Konfigurasi (contoh per-role)
```json
{
  "id": "alice",
  "kdc": {"host": "192.168.1.10", "port": 5000},
  "bob": {"host": "192.168.1.12", "port": 5001},
  "peer_id": "bob",
  "timeouts": {"connect": 5.0, "step": 10.0}
}
```

Catatan: Berkas config.json tidak di-commit dan tidak boleh berisi Encryption Key. Contoh di atas disimpan sebagai `config.alice.example.json`.

**Config Bob (`config.bob.example.json`):**
```json
{
  "id": "bob",
  "peer_id": "alice",
  "listen": {"host": "0.0.0.0", "port": 5001},
  "timeouts": {"step": 10.0},
  "logging": {"file": "logs/bob.log", "level": "INFO"}
}
```

**Config KDC (`config.kdc.example.json`):**
```json
{
  "listen": {"host": "0.0.0.0", "port": 5000},
  "registry_ids": ["alice", "bob"],
  "timeouts": {"step": 10.0},
  "logging": {"file": "logs/kdc.log", "level": "INFO"}
}
```

**Aturan config:**
- `id` dan `peer_id` wajib untuk Alice/Bob, divalidasi dengan `validate_id`, dan bersifat case-sensitive. Alice wajib memiliki `kdc` dan `bob`; Bob wajib memiliki `listen`; KDC wajib memiliki `listen` dan `registry_ids`.
- `port` harus integer 1-65535 (bukan boolean). `host` harus string non-kosong. `timeout` harus float > 0. Nilai default: port KDC 5000, port Bob 5001, `timeouts.connect=5.0`, `timeouts.step=10.0`, dan `logging.level=INFO`.
- `timeouts.connect` hanya dipakai untuk koneksi TCP keluar (Alice → KDC/Bob); `timeouts.step` adalah batas waktu satu langkah protokol (respons KDC, challenge, response, dan BYE handshake).
- `logging.file` opsional; default `logs/<id>.log` untuk Alice/Bob dan `logs/kdc.log` untuk KDC. `logging.level` mengikuti level standar Python (`DEBUG`, `INFO`, `WARNING`, `ERROR`).
- Field asing diabaikan dengan peringatan `WARNING` di log; field wajib yang hilang, tipe salah, atau nilai di luar rentang menyebabkan proses keluar dengan pesan ramah ke `stderr` dan exit code `2`, tanpa stack trace dan tanpa mencetak isi config.
- Config **tidak boleh** memuat `Ka`, `Kb`, atau `Ks`. Key dimasukkan interaktif memakai `getpass`: KDC meminta key untuk setiap ID pada `registry_ids` (dengan konfirmasi ulang), sedangkan Alice/Bob meminta key miliknya sendiri saat startup. Key tidak pernah ditulis ke disk, log, atau histori shell.
- Setiap program dijalankan dengan `--config PATH` (default `config.json`); contoh: `python kdc_server.py --config config.kdc.json`, `python bob_client.py --config config.bob.json`, `python alice_client.py --config config.alice.json`.

### 2.2 Framing Jaringan

- **Header:** 4 byte Unsigned Big-Endian Integer (`!I`) menentukan panjang payload bytes. Nilai `0` tidak valid dan menghasilkan `BadFrame`.
- **Batas Maksimum Payload:** 65.536 byte (64 KiB). Jika melebihi, lempar `FrameTooLarge` tanpa membaca payload; sisi pengirim juga wajib menolak payload > batas sebelum menulis ke socket.
- **Format Payload:** JSON terenkode UTF-8. Sender memakai JSON valid tanpa `NaN`/`Infinity`; receiver menerima whitespace JSON yang valid, tetapi hasil akhirnya wajib `dict`.
- **Batas waktu:** `recv_message` memakai satu deadline total per frame. Timeout tidak boleh di-reset setiap kali potongan data diterima.
- **Sinkronisasi tulis:** satu socket hanya boleh memiliki satu penulis aktif. Session layer wajib memakai lock yang sama untuk seluruh `send_message` pada socket tersebut.
- **Timeout operasi:** operasi handshake/request wajib memakai `settimeout(timeouts.step)` pada socket hasil `accept`/`connect`. Setelah `AUTHENTICATED`, receiver thread memakai `recv_message(sock, timeout=None)` (blocking) dan dihentikan dengan `shutdown`/`close` dari thread lain; idle bukan error sesi. Timeout pengiriman dipetakan ke `NetworkTimeout` atau `NetworkError` dan sesi ditutup.

### 2.3 Logging dan Redaksi Data Sensitif

- **Tujuan log:** file log terpisah dari UI, agar output receiver thread tidak merusak prompt `input()`. Log tidak ditulis ke `stdout`/`stderr` setelah UI aktif; error fatal saat startup boleh ditulis ke `stderr`.
- **Lokasi dan izin:** direktori `logs/` dibuat otomatis. File log memakai mode `0600`, ditambahkan (append), dan di-flush setiap record. `config.json`, direktori `logs/`, `__pycache__`, dan `*.pyc` tidak di-commit.
- **Format:** satu record per baris, minimal berisi timestamp ISO-8601 UTC, level, role, event, dan field `key=value`. Nilai string di-escape (misalnya dengan `repr`/JSON string) agar newline tidak memecah record.
- **Klasifikasi data:**

| Kelas | Data | Aturan |
|---|---|---|
| Rahasia | `Ka`, `Kb`, `Ks`, byte key mentah | Tidak boleh masuk log, UI, pesan JSON plaintext, pesan error, atau nama file. |
| Sensitif | Plaintext aplikasi, `N1`, `N2`, ciphertext | Nonce tidak dicatat. Plaintext dan hex ciphertext hanya boleh dicatat pada event audit `APP_MSG` sesuai T6.18. |
| Publik | ID, tipe pesan, kode error, timestamp, alamat/port | Boleh dicatat. |

- **KCV:** KCV boleh ditampilkan di UI, tetapi tidak dicatat di log karena membocorkan 24 bit turunan `Ks`.
- **Key hygiene:** Python tidak menjamin zeroization karena `bytes` immutable. Implementasi wajib melakukan best-effort: hapus referensi dari objek sesi/registry saat key berubah atau sesi berakhir, jangan menyimpan salinan tambahan, dan jangan pernah memformat key ke string. Jaminan terhadap memory dump, swap, atau debugger berada di luar scope.
- **Audit log aplikasi:** event `APP_MSG` mencatat arah, ID pengirim, plaintext (di-escape), dan hex ciphertext lowercase. Tidak ada key, nonce, atau KCV di record tersebut.

### 2.4 Threat Model dan Non-Goal

- **Aset yang dilindungi:** kerahasiaan `Ka`, `Kb`, dan `Ks`; autentikasi Alice-Bob; kerahasiaan pesan aplikasi.
- **Non-goal yang disepakati:** tidak ada TLS; tidak ada HMAC/MAC sehingga integritas ciphertext tidak dijamin penuh dan malleability CBC diterima; tiket tidak memiliki timestamp/expiry; replay pesan aplikasi di dalam sesi aktif tidak dicegah; tidak ada proteksi terhadap endpoint yang dikompromikan, memory dump, side-channel, DoS, atau traffic analysis; langkah 1 memang mengirim `ID_A`, `ID_B`, dan `N1` sebagai plaintext; tidak ada forward secrecy.
- **Replay tiket:** tiket lama tanpa `Kb` tidak dapat dibuka, dan challenge `N2` yang baru membuat respons lama tidak valid. Ini adalah mitigasi replay untuk autentikasi sesi, bukan jaminan anti-replay untuk pesan aplikasi.
- **Error yang tidak terautentikasi:** `KDC_ERR`, `AUTH_FAIL`, dan `ERROR` tidak dienkripsi; penyerang aktif dapat mengubah/menghapusnya dan menyebabkan DoS. PRD hanya menjamin deteksi kegagalan, bukan pencegahan DoS.
- **Topologi:** implementasi ditargetkan untuk LAN IPv4 dengan 3 perangkat fisik; IPv6 dan NAT traversal tidak diwajibkan.

---

## 3. Matriks Pengujian Bagian 1

| ID | Skenario | Hasil yang Diharapkan |
|---|---|---|
| T1.1 | bytes_to_hex & hex_to_bytes round-trip | Data pulih identik, huruf kecil |
| T1.2 | hex_to_bytes dengan input tidak valid | Lempar ValueError |
| T1.3 | validate_key dengan 15, 16, 17 karakter dan non-ASCII | Hanya 16 karakter ASCII printable yang diterima |
| T1.4 | validate_plaintext batas 0, 1, 1024, 1025 karakter | Menegakkan batas 1-1024 karakter ASCII printable |
| T1.5 | validate_id dengan karakter spesial / >16 karakter | Ditolak |
| T1.6 | Loader konfigurasi file tidak ada / JSON rusak / port invalid | Mengeluarkan pesan error ramah tanpa crash |
| T1.7 | Framing jaringan loopback send & recv dict | Dict terintegrasi penuh |
| T1.8 | Payload terpotong-potong (1 byte per read) | recv_message tetap membaca lengkap hingga utuh |
| T1.9 | Dua pesan berurutan dalam satu segmen TCP | Terbaca terpisah dan presisi |
| T1.10 | Payload diumumkan > 65.536 byte | Lempar FrameTooLarge |
| T1.11 | Socket terputus di tengah transmisi header/body | Lempar ConnectionClosed |
| T1.12 | Payload sanitasinya bukan JSON / bukan dict | Lempar BadFrame |
| T1.13 | Timeout penerimaan tercapai | Lempar NetworkTimeout |
| T1.14 | connect ke port tertutup | Lempar NetworkError dengan rincian host dan port |
| T1.15 | Manual: Echo TCP antar 3 IP perangkat fisik berbeda | Transmisi pesan berhasil 2 arah di semua pasangan |
| T1.16 | Header frame bernilai 0 | Lempar `BadFrame`; socket ditutup pemanggil |
| T1.17 | `send_message` dengan payload > 65.536 byte | Lempar `FrameTooLarge` sebelum ada byte yang ditulis |
| T1.18 | Timeout total saat frame baru terbaca sebagian | Lempar `NetworkTimeout`; tidak ada data parsial yang dikembalikan |
| T1.19 | Config per-role valid / field wajib hilang / tipe salah | Config valid diterima; config invalid keluar dengan exit code `2` dan pesan ramah |
| T1.20 | Restart listener pada port yang sama | Bind ulang berhasil karena `SO_REUSEADDR` |

**Prosedur T1.15:** setiap perangkat menjalankan echo server sementara pada port uji. Uji tiga pasangan (KDC↔Alice, KDC↔Bob, Alice↔Bob) dua arah dengan minimal satu pesan dict per arah, lalu catat IP/port dan hasilnya di `docs/evidence/README.md`. Bukti Wireshark mengikuti PRD Bagian 7.

---

## 4. Gerbang Selesai

- Pengujian T1.1 - T1.14 dan T1.16 - T1.20 lulus otomatis.
- Pengujian T1.15 sukses dilaksanakan di 3 IP perangkat fisik terpisah.