# PRD Bagian 5: Bob, Tiket, dan Challenge-Response (Langkah 3-5)

**Versi:** 4.2  
**Tujuan:** Menyelesaikan autentikasi Langkah 3, 4, dan 5 antara Alice dan Bob, serta mengimplementasikan Mesin State Sesi yang ketat.

---

## 1. Spesifikasi Bob Client (`bob_client.py`)

- **Socket Management:**
  - `server_sock`: Socket listener permanen di port 5001.
  - `client_sock`: Socket koneksi aktif dengan Alice.
- **Aturan Konkurensi Sesi:** Bob hanya melayani **1 sesi aktif**. Koneksi masuk kedua saat sesi aktif langsung ditolak dengan `ERROR code=BUSY` lalu ditutup.
- **Alur Autentikasi Langkah 3-5:**
  1. Listener menerima koneksi → Terima `TICKET` → Jalankan `open_ticket` menggunakan $K_b$.
  2. Jika valid, transisi ke `TICKET_RECEIVED`, bangkitkan Nonce $N_2$ (8 byte acak).
  3. Kirim `CHALLENGE` terenkripsi $K_s$ → Transisi ke `CHALLENGE_SENT`.
  4. Terima `CHALLENGE_RESP` → Eksekusi `check_challenge_response`.
  5. Jika jawaban tepat $f(N2)$, kirim `AUTH_OK`, transisi ke `AUTHENTICATED`. Sesi siap dipakai.
  6. Jika jawaban salah / dekripsi gagal / timeout: Kirim `AUTH_FAIL`, tutup `client_sock`, hapus $K_s$, kembali ke state `LISTENING`.

### 1.1 Config, Startup, dan Expected ID

- Bob dijalankan dengan `python bob_client.py --config config.bob.json`; config memakai schema PRD Bagian 1 (`id`, `peer_id`, `listen`, `timeouts`, `logging`). `id` wajib `bob` untuk demo, `peer_id` wajib `alice`.
- `Kb` diminta saat startup memakai `getpass` (tidak echo, tidak disimpan ke disk). Key divalidasi dengan `validate_key`; jika invalid, ulangi maksimal 3 kali lalu exit code `2`.
- Tiket wajib memiliki `ID_A == config["peer_id"]`. `T_B` tidak memuat `ID_B`; identitas Bob dijamin oleh `Kb`. ID yang tidak cocok menghasilkan `AUTH_FAIL BAD_FORMAT` setelah tiket berhasil didekripsi.
- Port listen default `0.0.0.0:5001` dan socket memakai `SO_REUSEADDR` melalui `make_listener`.

### 1.2 Arsitektur Listener dan Sesi Tunggal

- Listener dijalankan di daemon thread dengan `accept()` timeout 1 detik agar bisa memeriksa flag shutdown.
- Sebuah lock/flag `active_session` menjaga hanya satu sesi. Jika ada sesi aktif, koneksi baru tetap diterima, dibalas `ERROR BUSY` best-effort, lalu ditutup; sesi aktif tidak terganggu.
- Jika idle, Bob menandai sesi aktif dan menjalankan worker thread untuk koneksi tersebut. Accept loop tetap berjalan untuk menolak koneksi berikutnya.
- Pesan pertama pada koneksi baru wajib `TICKET`. Tipe lain → `ERROR BAD_STATE`, tutup koneksi, reset `LISTENING`.
- Shutdown (menu `0`/SIGINT): set flag, tutup listener, kirim `BYE` best-effort ke sesi aktif, tutup `client_sock`, join worker ≤ 2 detik, hapus referensi `Ks`, lalu keluar exit code `0`.

### 1.3 Perilaku Kegagalan Autentikasi

| Kondisi | Respons Bob | State akhir |
|---|---|---|
| Tiket gagal didekripsi/padding invalid | `AUTH_FAIL DECRYPT_FAIL` best-effort | `LISTENING` |
| Field/tiket rusak atau `ID_A` tidak cocok | `AUTH_FAIL BAD_FORMAT` best-effort | `LISTENING` |
| `f(N2)` salah | `AUTH_FAIL BAD_RESPONSE` | `LISTENING` |
| Timeout menunggu `CHALLENGE_RESP` | `AUTH_FAIL TIMEOUT` best-effort | `LISTENING` |
| Socket putus/frame truncated/oversize | Tutup tanpa respons jika socket tidak aman | `LISTENING` |
| Pesan bukan `TICKET` saat handshake | `ERROR BAD_STATE` lalu tutup | `LISTENING` |

Alice mengikuti aturan PRD Bagian 5 §2: jika koneksi ke Bob gagal **sebelum** tiket terkirim, tetap `KEY_READY`; setelah tiket terkirim, kegagalan apa pun menghapus `Ks`/tiket dan kembali `IDLE`.

---

## 2. Spesifikasi State Machine (`session.py`)

### AliceState
- `IDLE`: Belum ada sesi.
- `REQUESTED`: Menunggu respons KDC.
- `KEY_READY`: Memegang $K_s$ dan Tiket.
- `TICKET_SENT`: Menunggu Challenge dari Bob.
- `AUTHENTICATED`: Sesi terautentikasi (komunikasi 2 arah aktif).
- `CLOSED`: Sesi ditutup.

### BobState
- `LISTENING`: Menunggu koneksi masuk.
- `TICKET_RECEIVED`: Tiket valid, memegang $K_s$.
- `CHALLENGE_SENT`: Challenge $N_2$ dikirim.
- `AUTHENTICATED`: Sesi terautentikasi (komunikasi 2 arah aktif).
- `CLOSED`: Sesi ditutup.

### Aturan Transisi Kegagalan (Best Practice)
1. Jika Alice gagal terhubung ke Bob **sebelum tiket dikirim** (koneksi ditolak/timeout), Alice **tetap pada state `KEY_READY`** (tiket dapat dicoba ulang).
2. Jika kegagalan terjadi **setelah tiket dikirim** (`AUTH_FAIL`, respons tantangan salah, dekripsi gagal), Alice **wajib menghapus $K_s$ dan kembali ke `IDLE`**.
3. Perubahan Key $K_a$ atau $K_b$ saat sesi aktif otomatis memutus sesi dan mengembalikan state ke `IDLE` / `LISTENING`.

### Tabel Transisi Alice

| State | Event | State berikutnya | Aksi |
|---|---|---|---|
| `IDLE` | `REQUEST_START` | `REQUESTED` | Bangkitkan `N1`, buka koneksi KDC |
| `REQUESTED` | `KDC_SUCCESS` | `KEY_READY` | Simpan `Ks` + tiket, hapus `N1` |
| `REQUESTED` | `KDC_ERROR` / timeout / socket error | `IDLE` | Hapus `N1`, tampilkan error |
| `KEY_READY` | `REQUEST_START` | `REQUESTED` | Buang tiket/`Ks` lama, minta session key baru |
| `KEY_READY` | `BOB_CONNECT_FAIL` sebelum tiket terkirim | `KEY_READY` | Tiket tetap disimpan untuk retry |
| `KEY_READY` | `SEND_TICKET` | `TICKET_SENT` | Kirim tiket, tunggu `CHALLENGE` |
| `TICKET_SENT` | `CHALLENGE_VALID` | `AUTHENTICATED` | Kirim respons, mulai receiver thread |
| `TICKET_SENT` | `AUTH_FAIL` / respons salah / timeout / dekripsi gagal | `IDLE` | Tutup socket, hapus `Ks` + tiket |
| `AUTHENTICATED` | `BYE` / socket error / `KEY_CHANGE` | `CLOSED` → `IDLE` | Kirim `BYE` best-effort, bersihkan sesi |
| State mana pun | `SHUTDOWN` | `CLOSED` | Tutup socket, bersihkan referensi key |

### Tabel Transisi Bob

| State | Event | State berikutnya | Aksi |
|---|---|---|---|
| `LISTENING` | `TICKET_VALID` | `TICKET_RECEIVED` | Simpan `Ks`, bangkitkan `N2` |
| `LISTENING` | `TICKET_INVALID` / timeout | `LISTENING` | Kirim `AUTH_FAIL` best-effort, tutup |
| `LISTENING` | `ACCEPT_BUSY` | `LISTENING` | Kirim `ERROR BUSY`, tutup koneksi baru |
| `TICKET_RECEIVED` | `SEND_CHALLENGE` | `CHALLENGE_SENT` | Kirim `CHALLENGE`, mulai deadline |
| `CHALLENGE_SENT` | `RESPONSE_VALID` | `AUTHENTICATED` | Kirim `AUTH_OK`, mulai receiver thread |
| `CHALLENGE_SENT` | `RESPONSE_INVALID` / timeout | `LISTENING` | Kirim `AUTH_FAIL`, hapus `Ks`/`N2`, tutup |
| `AUTHENTICATED` | `BYE` / socket error / `KEY_CHANGE` | `CLOSED` → `LISTENING` | Kirim `BYE` best-effort, bersihkan sesi |
| State mana pun | `SHUTDOWN` | `CLOSED` | Tutup listener/socket, bersihkan referensi key |

### API `session.py`

- `class StateError(Exception)`: dilempar untuk event yang tidak legal pada state saat ini. T5.14 menguji transisi ilegal dan memastikan exception ini muncul.
- `AliceState` dan `BobState` adalah `enum.Enum` dengan nilai persis seperti daftar di atas.
- `assert_transition(current: AliceState | BobState, event: str, allowed: dict) -> None`: memvalidasi transisi; event ilegal → `StateError`. Tidak ada transisi implisit di luar tabel.
- `CLOSED` adalah state terminal sesi. Setelah cleanup selesai, session layer melakukan reset eksplisit ke `IDLE`/`LISTENING`; program tidak boleh menerima pesan aplikasi saat `CLOSED`.
- Setiap transisi keluar dari `AUTHENTICATED` wajib menghentikan receiver thread, menutup socket, menghapus referensi `Ks`, `N1`, `N2`, dan tiket, serta mencatat event tanpa nilai rahasia.

### Key Hygiene dan Logging

- `Ks`, `Kb`, `N2`, tiket, dan `N1` tidak boleh dicatat di log atau pesan error. ID, tipe pesan, state, dan kode error boleh dicatat.
- Zeroization tidak dapat dijamin di Python. Implementasi wajib menghapus referensi dari objek sesi/registry dan tidak menyimpan salinan di closure, cache, atau history. T5.15 menguji tidak adanya referensi yang tersisa, bukan penghapusan fisik memori.
- Format/izin log mengikuti PRD Bagian 1 §2.3.

---

## 3. Matriks Pengujian Bagian 5

| ID | Skenario | Hasil yang Diharapkan |
|---|---|---|
| T5.1 | Alur Lengkap Langkah 1-5 (3 Thread / 3 Perangkat) | Alice & Bob mencapai state `AUTHENTICATED` dengan $K_s$ identik |
| T5.2 | $K_b$ pada Bob berbeda dengan $K_b$ di KDC | Bob gagal membuka tiket; kirim `AUTH_FAIL`; Alice kembali `IDLE` |
| T5.3 | Tiket dimodifikasi di tengah jalan | Bob menolak tiket |
| T5.4 | $ID_A$ pada Tiket bukan ID yang diizinkan | Bob mengirim `AUTH_FAIL BAD_FORMAT`, menolak tiket, reset `LISTENING` |
| T5.5 | Alice menjawab Challenge dengan $f(N2)$ yang salah | Bob membalas `AUTH_FAIL BAD_RESPONSE` dan menutup socket |
| T5.6 | Alice membalas Challenge dengan payload rusak | Bob membalas `AUTH_FAIL BAD_FORMAT` tanpa crash |
| T5.7 | Alice tidak membalas Challenge (Timeout) | Bob mengirim `AUTH_FAIL TIMEOUT` best-effort, reset ke `LISTENING` |
| T5.8 | Bob tidak mengirim Challenge (Timeout) | Alice timeout, reset ke `IDLE` |
| T5.9 | `APP_MSG` dikirim sebelum Autentikasi | Ditolak dengan `ERROR BAD_STATE` lalu koneksi ditutup |
| T5.10 | `TICKET` kedua dikirim saat sesi aktif | Ditolak dengan `ERROR BAD_STATE` lalu sesi ditutup |
| T5.11 | Koneksi kedua saat Bob sibuk | Ditolak dengan `ERROR BUSY`; sesi pertama tidak terganggu |
| T5.12 | Bob Offline saat Alice menghubungkan | Error koneksi ramah; Alice tetap `KEY_READY` |
| T5.13 | Dua sesi autentikasi berurutan | Menghasilkan $K_s$ dan $N_2$ yang berbeda |
| T5.14 | Pengujian Tabel Transisi State Machine | Transisi sah diterima, transisi ilegal melempar `StateError` |
| T5.15 | Kebersihan referensi pasca Kegagalan | Atribut `Ks`/tiket/`N2` menjadi `None` atau tidak ada; zeroization fisik tidak diwajibkan |
| T5.16 | Pemindaian Log Aktivitas | Bersih dari $K_a$, $K_b$, $K_s$, $N_1$, $N_2$ plaintext |
| T5.17 | **Manual:** Pengujian Langkah 1-5 pada 3 IP Perangkat Fisik | Langkah 1-5 sukses sempurna |
| T5.18 | Koneksi kedua saat sesi aktif | `ERROR BUSY` diterima, sesi pertama tetap `AUTHENTICATED` |
| T5.19 | Pesan pertama bukan `TICKET` | `ERROR BAD_STATE` lalu koneksi ditutup |
| T5.20 | Shutdown Bob saat sesi aktif | `BYE` best-effort, worker join ≤ 2 detik, state `LISTENING`/exit `0` |
| T5.21 | Event ilegal pada state machine | `StateError`; tidak ada perubahan state/key |
| T5.22 | Ubah `Ka`/`Kb` saat `AUTHENTICATED` | `BYE` dikirim, socket ditutup, `Ks` dihapus, state reset |

---

## 4. Gerbang Selesai
- Pengujian T5.1 - T5.16 dan T5.18 - T5.22 lulus.
- Pengujian T5.17 sukses dilaksanakan di 3 IP perangkat fisik terpisah.