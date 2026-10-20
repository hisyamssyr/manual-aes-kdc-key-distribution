# PRD Bagian 4: KDC Server dan Alice Langkah 1-2

**Versi:** 4.2  
**Tujuan:** Mengembangkan KDC Server untuk melayani permintaan session key dan antarmuka Alice untuk mengeksekusi Langkah 1 dan Langkah 2 protokol KDC.

---

## 1. Spesifikasi KDC Server (`kdc_server.py`)

- **Networking:** Listen pada IP `0.0.0.0` port 5000 (default).
- **Concurrency:** Thread-per-connection.
- **Key Registry:** Menyimpan pemetaan `ID -> Key` di memori (thread-safe dengan `threading.Lock`). Key dimasukkan secara interaktif lewat prompt terminal saat startup.
- **Menu CLI KDC (Berjalan Paralel):**
  1. Lihat status KDC (ID terdaftar, statistik permintaan).
  2. Ubah Key untuk ID tertentu (`alice` / `bob`).
  3. Lihat log aktivitas terakhir.
  0. Keluar.
- **Aturan Perubahan Key KDC:** Perubahan key di KDC langsung berlaku untuk permintaan `KDC_REQ` berikutnya. Sesi aktif lama antara Alice dan Bob tidak terganggu.

### 1.1 Startup, Config, dan Key Registry

- KDC dijalankan dengan `python kdc_server.py --config config.kdc.json`. Config memakai schema PRD Bagian 1: `listen`, `registry_ids`, `timeouts`, dan `logging`.
- `registry_ids` wajib berisi minimal satu ID valid dan unik. Untuk demo proyek, nilainya `["alice", "bob"]`. Duplikat, ID invalid, atau daftar kosong menyebabkan exit code `2`.
- Saat startup, KDC meminta key untuk setiap ID pada `registry_ids` memakai `getpass` dua kali (input + konfirmasi). Key divalidasi dengan `validate_key`; jika tidak cocok/invalid, ulangi maksimal 3 kali lalu keluar dengan exit code `2`. Key tidak boleh berasal dari CLI argument, environment variable, atau config.
- Registry disimpan hanya di memori sebagai `dict[str, bytes]` dan dilindungi `threading.RLock`. Lookup key mengambil snapshot di bawah lock; operasi kriptografi dilakukan setelah lock dilepas.
- Perubahan key lewat menu meminta konfirmasi key baru dua kali, memvalidasi, lalu mengganti entri secara atomik di bawah lock. Key lama dihapus dari registry (best-effort). Sesi Alice-Bob yang sudah memiliki `Ks` tidak terpengaruh.

### 1.2 Concurrency, Lifecycle, dan Error Matrix

- **Arsitektur thread:** accept loop berjalan di daemon thread; menu berjalan di main thread; setiap koneksi dilayani satu daemon thread. Maksimum 32 koneksi aktif dijaga dengan `threading.Semaphore`; koneksi di atas batas langsung ditutup tanpa respons.
- **Satu request per koneksi:** KDC membaca satu frame `KDC_REQ` dengan timeout `timeouts.step`, mengirim satu respons/error, lalu menutup koneksi. KDC tidak menyimpan state sesi antar-koneksi.
- **Tracking shutdown:** listener dan socket aktif dicatat di bawah lock. Saat menu `0`/SIGINT, KDC berhenti menerima koneksi, menutup listener, menutup socket aktif best-effort, join thread maksimal 2 detik, menghapus referensi key, lalu keluar dengan exit code `0`.
- **Matriks penanganan request:**

| Kondisi | Aksi KDC |
|---|---|
| Frame > 64 KiB, header invalid, timeout, atau EOF | Tutup socket tanpa respons; catat error |
| JSON invalid, bukan `dict`, `v`/`type` salah, schema/field invalid, `id_a == id_b` | Kirim `KDC_ERR BAD_FORMAT` best-effort lalu tutup |
| `id_a` atau `id_b` tidak ada di registry | Kirim `KDC_ERR UNKNOWN_ID` lalu tutup |
| Request valid | Bangkitkan `Ks`, kirim `KDC_RESP`, catat metrik sukses, tutup |
| Exception internal | Kirim `KDC_ERR INTERNAL` best-effort lalu tutup; jangan sertakan detail sensitif |

- KDC tidak melakukan retry otomatis, tidak membaca frame kedua, dan tidak pernah mengirim key/nonce di pesan error.

### 1.3 Menu, Status, dan Logging

- Status KDC menampilkan: uptime, alamat bind, daftar ID terdaftar, jumlah request total/sukses/error, error per kode, dan jumlah koneksi aktif.
- Menu “Lihat log aktivitas terakhir” menampilkan maksimal 20 event terakhir dari ring buffer in-memory (bukan membaca ulang seluruh file log).
- Event minimal yang dicatat: startup, listen, accept, hasil request (sukses/error code), perubahan key (hanya ID), dan shutdown. Tidak ada `Ka`, `Kb`, `Ks`, nonce, tiket ciphertext, atau plaintext aplikasi di log KDC.
- Format, izin file, dan redaksi mengikuti PRD Bagian 1 §2.3.

---

## 2. Spesifikasi Alice Langkah 1-2 (`alice_client.py`)

- **Startup/config:** dijalankan dengan `python alice_client.py --config config.alice.json`; `id` wajib `alice`, `peer_id` wajib `bob`. `Ka` diminta sekali saat startup memakai `getpass`, divalidasi `validate_key`, dan tidak disimpan ke disk; input invalid diulang maksimal 3 kali lalu exit code `2`. Config tidak boleh memuat key.
- **Fungsi Utama:** `request_session_key(config, ka) -> tuple[bytes, dict]`, dengan `config` yang sudah tervalidasi dan `ka: bytes` 16 karakter ASCII printable. Mengembalikan `(ks, ticket_envelope)` dan hanya boleh dipanggil saat state `IDLE` atau `KEY_READY`.
- **Alur Kerja:**
  1. Transisi state dari `IDLE`/`KEY_READY` ke `REQUESTED` (tiket/`Ks` lama dibuang jika ada).
  2. Bangkitkan Nonce $N_1$ baru (8 byte dari `new_nonce()`); nonce lama tidak boleh dipakai ulang.
  3. Buka koneksi TCP ke KDC dengan `timeouts.connect`, kirim `KDC_REQ`.
  4. Terima respons `KDC_RESP` atau `KDC_ERR` dengan deadline `timeouts.step`.
  5. Eksekusi `open_kdc_response`. Jika $N_1$, $ID_A$, dan $ID_B$ valid, dapatkan $K_s$ dan Tiket. Transisi ke `KEY_READY`.
  6. Jika gagal (timeout, dekripsi gagal, `KDC_ERR`, schema invalid), hapus $N_1$/$K_s$/tiket, transisi kembali ke `IDLE`, dan tampilkan pesan kesalahan ke pengguna.
  7. Tutup koneksi ke KDC di blok `finally`, termasuk saat terjadi exception.

### 2.1 Kontrak `request_session_key`

- **Precondition:** state `IDLE` atau `KEY_READY`; `config` dan `ka` valid. Dari `KEY_READY`, tiket/`Ks` lama dibuang sebelum request baru. Pelanggaran state menghasilkan `StateError` (PRD Bagian 5); `ka` invalid menghasilkan `ValueError`.
- **Return:** `ks` 16 byte printable dan `ticket_envelope` (`dict` amplop) persis seperti diterima dari KDC. Tiket tidak boleh dimodifikasi.
- **Exception:** `NetworkError` (dan subclass-nya) untuk kegagalan koneksi/timeout/EOF; `ProtocolError` untuk `KDC_ERR` atau respons tidak valid. `KDC_ERR` diteruskan dengan `code` yang sama. Pemanggil menampilkan pesan ramah dan mereset state ke `IDLE`.
- **Retry:** tidak ada retry otomatis. Pengguna memicu ulang lewat menu, dan setiap percobaan memakai `N1` baru.
- **Concurrency:** hanya satu request in-flight. Menu mengunci aksi selama request berjalan; request kedua saat state `REQUESTED` ditolak dengan `StateError`.
- **Logging:** catat hasil (sukses/`code` error) dan ID tujuan; jangan catat `Ka`, `N1`, `Ks`, atau tiket.
- **Interaksi state:** sukses → `KEY_READY`; semua kegagalan → `IDLE`. Perpindahan setelah `KEY_READY` diatur di PRD Bagian 5.

---

## 3. Matriks Pengujian Bagian 4

| ID | Skenario | Hasil yang Diharapkan |
|---|---|---|
| T4.1 | Permintaan Session Key Alice ke KDC (Success) | Alice memperoleh $K_s$ & Tiket; state `KEY_READY` |
| T4.2 | Dua permintaan berurutan | Menghasilkan $K_s$ dan $N_1$ yang berbeda |
| T4.3 | Tiket hasil KDC diuji dengan $K_b$ yang sesuai | Tiket dapat dibuka dan berisi $K_s$ + $ID_A$; KDC tidak melakukan verifikasi tiket |
| T4.4 | KDC Palsu mengirim $N_1$ salah | Alice menolak respons; state kembali `IDLE` |
| T4.5 | KDC Palsu mengirim $ID_B$ salah | Alice menolak respons; state kembali `IDLE` |
| T4.6 | Alice menggunakan $K_a$ yang salah | Dekripsi gagal; Alice menolak; state kembali `IDLE` |
| T4.7 | Permintaan $ID_B$ tidak terdaftar di KDC | KDC membalas `KDC_ERR UNKNOWN_ID`; Alice tanggap |
| T4.8 | Request JSON/schema rusak | KDC membalas `KDC_ERR BAD_FORMAT` lalu menutup; frame rusak/truncated ditutup tanpa respons |
| T4.9 | Frame Payload > 64 KiB ke KDC | KDC memutuskan socket, KDC tetap stabil |
| T4.10 | KDC tidak aktif / offline | Alice menampilkan pesan koneksi gagal; state `IDLE` |
| T4.11 | KDC hang / tidak membalas | Alice mengalami timeout langkah; state kembali `IDLE` |
| T4.12 | Konkurensi 2 Alice meminta bersamaan | KDC melayani kedua thread dengan $K_s$ independen |
| T4.13 | Ubah $K_a$ di KDC lalu Alice meminta dengan $K_a$ lama | Dekripsi Alice gagal; dengan $K_a$ baru berhasil |
| T4.14 | Pemindaian Log KDC & Alice | Tidak pernah mencetak $K_a$, $K_b$, atau $K_s$ plaintext |
| T4.15 | **Manual:** Pengujian KDC & Alice di 2 IP perangkat fisik terpisah | Langkah 1-2 sukses; Wireshark mengonfirmasi data terenkripsi |
| T4.16 | Input key KDC invalid / konfirmasi tidak cocok | Retry maksimal 3 kali lalu exit code `2`; key tidak muncul di output |
| T4.17 | Ubah key KDC saat request berjalan | Request membaca key lama atau baru secara utuh; tidak ada key “robek” |
| T4.18 | Koneksi KDC timeout / klien putus di tengah request | Koneksi ditutup, thread berhenti, KDC tetap melayani request lain |
| T4.19 | Panggil `request_session_key` saat state `REQUESTED` | Ditolak dengan `StateError`; tidak ada request kedua |
| T4.20 | Shutdown KDC saat ada koneksi aktif | Listener dan socket aktif ditutup, thread join ≤ 2 detik, exit `0` |
| T4.21 | Exception internal saat membangun respons | KDC membalas `KDC_ERR INTERNAL` tanpa detail/key, lalu tetap stabil |
| T4.22 | Minta session key baru saat state `KEY_READY` | Tiket/`Ks` lama dibuang, request baru memakai `N1` baru |

---

## 4. Gerbang Selesai
- Pengujian T4.1 - T4.14 dan T4.16 - T4.22 lulus.
- Pengujian T4.15 sukses dilaksanakan pada 2 perangkat fisik terpisah.