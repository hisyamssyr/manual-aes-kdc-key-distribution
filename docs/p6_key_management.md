# PRD Bagian 6: Komunikasi Dua Arah, Interaktivitas, dan Manajemen Key

**Versi:** 4.2  
**Tujuan:** Mengimplementasikan pertukaran pesan terenkripsi AES dua arah secara interaktif, penanganan konsol UI asynchronous, manajemen key dinamis (FR-08), dan verifikasi KCV.

---

## 1. Komunikasi Dua Arah Terenkripsi AES

- **Thread Receiver:** Begitu mencapai state `AUTHENTICATED`, Alice dan Bob menjalankan background thread yang terus memanggil `recv_message()`.
- **Antrean Pesan (`queue.Queue`):** Pesan `APP_MSG` yang masuk didekripsi dengan `open_app_msg()`, lalu dimasukkan ke antrean dan segera dicetak ke layar konsol.
- **Penanganan Terminal UI Asynchronous:** Untuk mencegah pencetakan pesan masuk merusak input teks yang sedang diketik pengguna pada prompt `input()`, modul `ui.py` wajib menyisipkan karakter `\r` (carriage return), menghapus baris, mencetak pesan masuk, dan mencetak ulang prompt input pengguna.
- **Pesan Kontrol `BYE`:** Pengiriman `BYE` dari salah satu pihak akan membuat kedua belah pihak menutup socket sesi, menghapus $K_s$, dan mengembalikan state ke `IDLE` / `LISTENING`.

### 1.1 Receiver Thread, Queue, dan Riwayat Pesan

- Satu receiver thread dibuat per sesi `AUTHENTICATED` dan hanya melakukan `recv_message` blocking (`timeout=None`). Thread dihentikan dengan `shutdown`/`close` dari thread lain saat `BYE`, error framing, atau shutdown; idle bukan error sesi. Tidak boleh ada dua receiver pada socket yang sama.
- `APP_MSG` yang valid didekripsi dengan `open_app_msg(msg, ks, expected_from=peer_id)`, lalu dicatat ke riwayat in-memory maksimal 100 entri: `(timestamp, from, plaintext, ct_hex)`. Tidak ada key/nonce di riwayat. Riwayat pesan dimiliki `AliceSession` / `BobSession` (`session.py`), bukan variabel global.
- Pesan masuk diteruskan ke callback UI (`ui.print_incoming`) untuk segera dicetak ke layar konsol dan menaikkan `unread_count`. Menu “Lihat Pesan Masuk” menampilkan riwayat (maksimal 100) dan mereset `unread_count` ke 0. Dengan demikian pesan tetap “segera dicetak” sekaligus tersedia di menu.
- Pesan dengan `from` tidak cocok, plaintext invalid, atau gagal didekripsi tidak dimasukkan ke riwayat dan tidak dicetak.
- Setiap `APP_MSG` valid yang diterima juga dicatat ke audit log melalui `app_logging.audit_app_message` dengan arah masuk, `from`, plaintext, dan `ct_hex` lowercase; kegagalan didekripsi dicatat sebagai kode error tanpa plaintext.

### 1.2 Sinkronisasi UI, Pengirim, dan Socket

- Setiap socket sesi memiliki satu `send_lock` yang dimiliki `AliceSession` / `BobSession` (`session.py`, PRD Bagian 5 §2); seluruh pengiriman dari menu, receiver (misalnya `BYE`/`ERROR`), dan handshake memakai lock yang sama. Ini mencegah frame tercampur saat Alice dan Bob mengirim bersamaan.
- `ui.py` memiliki satu `output_lock` global per proses. Semua cetakan (info, error, pesan masuk, prompt) memakai lock ini.
- Saat pengguna sedang mengetik, `ui.py` menyimpan teks prompt aktif. Pesan masuk dicetak dengan `\r\033[K` + pesan + baris baru + prompt + buffer input, lalu di-flush. Escape ANSI hanya dipakai jika `sys.stdout.isatty()` dan `sys.stdin.isatty()` bernilai benar.
- Pada non-TTY (pipe/test), pesan masuk dicetak satu baris tanpa escape dan tanpa mencetak ulang prompt; UI tidak boleh crash atau menggandakan prompt.
- Logging tetap ke file (PRD Bagian 1 §2.3), bukan ke konsol, agar tidak bertabrakan dengan prompt.

### 1.3 Validasi dan Pengiriman Pesan Aplikasi

- Input plaintext dibaca satu baris; hanya newline akhir (`\n`/`\r\n`) yang dihapus. Spasi di awal/akhir dipertahankan. Plaintext wajib 1-1.024 karakter ASCII printable; kosong, karakter kontrol, non-ASCII, atau >1.024 ditolak sebelum enkripsi.
- Pengirim membangun `APP_MSG` dengan `build_app_msg(id, ks, plaintext)`, mengirim di bawah `send_lock`, lalu mencatat/menampilkan plaintext dan `ct` hex lowercase sesuai T6.18.
- Penerima memvalidasi tipe, `from`, amplop, dan plaintext. Kegagalan dekripsi/validasi pesan aplikasi → kirim `ERROR` (`DECRYPT_FAIL`/`BAD_FORMAT`) best-effort, buang pesan, pertahankan sesi `AUTHENTICATED`.
- Tipe pesan tak dikenal, pesan sebelum autentikasi, atau pelanggaran state → `ERROR BAD_STATE`, lalu koneksi ditutup dan state direset sesuai PRD Bagian 5.
- Error framing/socket (`ConnectionClosed`, `FrameTooLarge`, `BadFrame`, `NetworkTimeout`) → tutup sesi, reset state, tanpa mencoba mengirim error.

### 1.4 Handshake `BYE`

- Menutup sesi secara normal: kirim `BYE`, lalu tunggu maksimal `timeouts.step` pada `close_event` yang di-set receiver thread saat menerima `BYE`/EOF (bukan memanggil `recv` kedua), lalu tutup socket. Jika peer mengirim `BYE` lebih dulu, balas `BYE` best-effort (jika socket masih terbuka) dan tutup.
- `BYE` bersifat idempotent: dua pihak boleh mengirim bersamaan; salah satu `BYE` pertama memicu cleanup, duplikat diabaikan. Tidak ada `AUTH_OK` untuk `BYE`.
- Jika handshake timeout atau pengiriman gagal, tetap tutup socket dan cleanup. Perubahan key memakai prosedur yang sama sebelum key baru dipasang.

### 1.5 API `ui.py`

- `print_info(text: str)`, `print_error(text: str)`, `print_incoming(record: dict)`: mencetak dengan `output_lock`; `print_incoming` memakai perilaku TTY/non-TTY di atas.
- `prompt_input(label: str) -> str`: satu-satunya jalur `input()`, menyimpan prompt aktif untuk reprint, dan mengembalikan baris tanpa newline.
- `set_unread(count: int)` / `render_status(...)`: pembantu tampilan menu; tidak menyimpan key.
- `ui.py` tidak melakukan logging file dan tidak membaca config.

---

## 2. Key Confirmation Value (KCV) & Manajemen Key (FR-08)

### 2.1 Formula KCV
Untuk mengonfirmasi kesamaan $K_s$ antara Alice dan Bob tanpa membocorkan key:
$$\text{KCV} = \text{hex}\left(\text{3 byte pertama dari } \text{encrypt\_block}(K_s, \text{16 byte zero } \texttt{0x00})\right)$$

- Implementasi: `compute_kcv(ks: bytes) -> str` di `protocol.py`, yaitu `encrypt_block(ks, b"\x00" * 16)[:3].hex()`.
- Format tampilan: tepat 6 karakter hex lowercase. Jika `Ks` belum ada, tampilkan `-`.
- KCV bukan bukti kriptografis kuat (collision 24-bit); hanya alat bantu demo. KCV tidak dicatat di log.

### 2.2 Aturan Perubahan Key Dinamis
1. Pengguna dapat mengubah $K_a$ (Alice) atau $K_b$ (Bob) kapan saja lewat menu tanpa restart program.
2. Key baru diminta dua kali memakai `getpass`, divalidasi `validate_key`, dan baru dipasang jika kedua input sama. Input invalid/mismatch tidak mengubah key lama.
3. Mengubah Key saat sesi sedang aktif akan **otomatis memutus sesi aktif (mengirim `BYE`), menghapus $K_s$, dan mereset state**. Jika sesi sedang dalam handshake, handshake dibatalkan dan state direset sebelum key dipasang.
4. Perubahan key dan operasi sesi diserialisasi dengan lock state. Key tidak boleh berubah di tengah enkripsi/dekripsi satu pesan.
5. Perubahan Key di KDC tidak memutus sesi lama yang sedang berjalan, namun menyebabkan permintaan autentikasi baru menggunakan key lama akan gagal.
6. Key tidak pernah ditampilkan, dicatat, atau disimpan ke disk. Zeroization fisik tidak dijamin; referensi key lama dihapus best-effort.

---

## 3. Spesifikasi Menu CLI

### Menu Alice
```text
=== MENU ALICE ===
1. Minta Session Key ke KDC (Langkah 1-2)
2. Hubungi Bob dan Autentikasi (Langkah 3-5)
3. Kirim Pesan Aplikasi
4. Lihat Pesan Masuk
5. Ubah Key Ka
6. Lihat Status Sesi & KCV Ks
7. Tutup Sesi (BYE)
0. Keluar
```

### Menu Bob
```text
=== MENU BOB ===
1. Lihat Status Sesi & KCV Ks
2. Kirim Pesan Aplikasi
3. Lihat Pesan Masuk
4. Ubah Key Kb
5. Tutup Sesi (BYE)
0. Keluar
```

### Aturan Menu

- Status sesi minimal menampilkan: role, `id`, `peer_id`, state, alamat peer, KCV `Ks` (atau `-`), jumlah pesan belum dibaca, dan error terakhir (kode saja).
- Aksi yang membutuhkan sesi (`Kirim Pesan`, `Tutup Sesi`) menolak dengan pesan ramah jika state belum `AUTHENTICATED`; `Lihat Status Sesi & KCV` dan `Lihat Pesan Masuk` tetap dapat dibuka dan menampilkan `-`/riwayat yang ada; tidak boleh crash.
- Aksi `Minta Session Key`/`Hubungi Bob` ditolak jika masih ada request/handshake berjalan (`StateError` ditangkap UI). Hanya satu operasi jaringan interaktif pada satu waktu.
- Input menu invalid/kosong menampilkan peringatan dan mengulang menu. EOF (Ctrl-D) diperlakukan seperti `Keluar`.
- `Keluar` (menu `0`) atau SIGINT: jika sesi aktif, minta konfirmasi, jalankan handshake `BYE` §1.4, hentikan receiver thread dengan join ≤ 2 detik, hapus referensi key, lalu exit code `0`.
- Semua input key memakai `getpass`; key tidak pernah muncul di echo, history, log, atau pesan error.

---

## 4. Matriks Pengujian Bagian 6

| ID | Skenario | Hasil yang Diharapkan |
|---|---|---|
| T6.1 | Alice mengirim pesan aplikasi ke Bob | Bob menampilkan plaintext dan Hex ciphertext |
| T6.2 | Bob mengirim pesan aplikasi ke Alice | Alice menampilkan plaintext dan Hex ciphertext |
| T6.3 | Pertukaran pesan bergantian 10 kali | Seluruh pesan sampai utuh dan berurutan |
| T6.4 | Alice dan Bob mengirim bersamaan | Pesan terisolasi rapi, frame tidak tercampur |
| T6.5 | Plaintext sama dikirim dua kali | Menghasilkan Hex ciphertext berbeda (IV acak) |
| T6.6 | Input Plaintext kosong / non-ASCII / >1024 char | Ditolak oleh UI sebelum terkirim |
| T6.7 | Ciphertext dimodifikasi di tengah jalan | Pesan dibuang, `ERROR DECRYPT_FAIL` dikirim; sesi tetap `AUTHENTICATED` |
| T6.8 | Pengiriman BYE dari salah satu pihak | Handshake BYE selesai/timeout, $K_s$ terhapus, state reset |
| T6.9 | Pemutusan Socket mendadak (Unplug Cable) | Pihak sebelah mendeteksi ConnectionClosed, state reset |
| T6.10 | Kirim Pesan sebelum Autentikasi | Ditolak UI dengan alasan belum terautentikasi |
| T6.11 | Ubah $K_a$ di Alice saat sesi aktif | `BYE` dikirim, sesi terputus, key baru dipasang, state reset ke IDLE |
| T6.12 | Ubah $K_b$ di Bob saja | Sesi baru dari Alice ditolak oleh Bob |
| T6.13 | Ubah Key di KDC saja | Sesi aktif lama tetap jalan; sesi baru butuh key baru |
| T6.14 | Ubah Key di kedua belah pihak lalu ulangi protokol | Sesi baru terautentikasi sukses |
| T6.15 | Input Key Baru invalid / konfirmasi tidak cocok | Ditolak UI, key lama tetap dipakai |
| T6.16 | Verifikasi KCV Alice dan Bob | KCV 6 hex lowercase identik saat $K_s$ sama |
| T6.17 | Input Menu tidak valid / kosong | Menampilkan peringatan tanpa crash |
| T6.18 | Pemindaian Log Komunikasi Aplikasi | Plaintext & hex ciphertext tercatat; key/nonce/KCV tidak bocor |
| T6.19 | Manual: Pengujian Komunikasi 2 Arah di 3 IP Perangkat Fisik | Komunikasi interaktif berjalan lancar |
| T6.20 | Manual: Wireshark Capture Pesan Aplikasi | Mengonfirmasi payload terisi Hex ciphertext |
| T6.21 | 3 pesan masuk saat menu idle | Riwayat bertambah, unread=3, menu 4 menampilkan lalu mereset unread |
| T6.22 | UI dijalankan non-TTY (pipe) | Pesan tercetak tanpa escape ANSI; tidak crash/gandakan prompt |
| T6.23 | Kedua pihak mengirim BYE bersamaan | Handshake idempotent, tidak ada error ganda, state reset |
| T6.24 | Peer tidak membalas BYE | Socket ditutup setelah `timeouts.step`, state reset |
| T6.25 | Tampilkan KCV saat belum ada $K_s$ | Menampilkan `-`; tidak ada exception |
| T6.26 | `APP_MSG` dengan `from` salah / plaintext invalid | Pesan dibuang, `ERROR BAD_FORMAT`, sesi tetap stabil |
| T6.27 | Ubah key saat handshake berjalan | Handshake dibatalkan, state reset, key baru dipasang utuh |

---

## 5. Gerbang Selesai

- Pengujian T6.1 - T6.18 dan T6.21 - T6.27 lulus.
- Pengujian T6.19 - T6.20 sukses dilaksanakan pada 3 IP perangkat fisik terpisah.