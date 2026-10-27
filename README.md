# manual-aes-kdc-key-distribution

Implementasi manual AES-128-CBC dan distribusi session key berbasis Key Distribution Center (KDC) untuk komunikasi aman antar-perangkat.

## 1. Ringkasan Proyek & Alur 5 Langkah KDC

Proyek ini mengimplementasikan enkripsi simetris AES-128-CBC secara manual tanpa library kriptografi pihak ketiga, serta protokol Needham-Schroeder untuk mendistribusikan session key secara aman antara dua pihak (Alice dan Bob) melalui server tepercaya (KDC).

### Peran Entitas
- KDC: Server tepercaya pihak ketiga yang menyimpan master key dari Alice (Ka) dan Bob (Kb). KDC bertugas membuat session key acak (Ks) serta tiket terenkripsi untuk Bob.
- Alice: Klien yang meminta session key ke KDC, lalu menggunakannya untuk membuka komunikasi dan handshake ke Bob.
- Bob: Server/klien penerima yang memverifikasi tiket dari Alice menggunakan Kb, lalu menguji keaslian Alice lewat challenge-response sebelum memulai sesi chat.

### Alur 5 Langkah Needham-Schroeder
1. Alice -> KDC: Alice mengirim request berisi ID Alice, ID Bob, dan nonce N1 dalam bentuk JSON plaintext.
2. KDC -> Alice: KDC merespons dengan paket yang dienkripsi menggunakan Ka. Isinya mencakup session key Ks, ID Bob, nonce N1, dan sebuah tiket untuk Bob yang sudah dienkripsi dengan Kb.
3. Alice -> Bob: Alice mendekripsi pesan dari KDC, memeriksa nonce N1, lalu meneruskan tiket ke Bob.
4. Bob -> Alice: Bob mendekripsi tiket dengan Kb untuk mendapatkan Ks, lalu mengirim challenge berupa nonce acak N2 yang dienkripsi dengan Ks ke Alice.
5. Alice -> Bob: Alice mendekripsi N2, menghitung respons (N2 - 1), mengenkripsinya dengan Ks, lalu mengirimkannya kembali ke Bob.

Setelah langkah 5 terverifikasi, status sesi berubah menjadi AUTHENTICATED dan kedua pihak bisa saling berkirim pesan chat terenkripsi AES-128-CBC.

## 2. Prasyarat Lingkungan

- Python 3.10 atau versi yang lebih baru.
- Standard Library Only: Hanya menggunakan modul bawaan Python (seperti socket, threading, json, secrets, getpass, dll.).
- Tidak memerlukan instalasi paket tambahan (tanpa pip install).
- Tidak menggunakan library kriptografi eksternal seperti cryptography, pycryptodome, atau hashlib.

## 3. Panduan Konfigurasi

Konfigurasi disimpan dalam file JSON terpisah untuk masing-masing role:
- config.kdc.example.json: Konfigurasi host dan port listener KDC (port 5000) serta daftar ID yang terdaftar (registry_ids).
- config.bob.example.json: Konfigurasi host dan port listener Bob (port 5001) serta peer_id.
- config.alice.example.json: Konfigurasi alamat IP dan port tujuan untuk KDC dan Bob.

### Pengaturan IP untuk 3 Perangkat
1. Salin file template ke file konfigurasi aktif:
   - config.kdc.example.json -> config.kdc.json
   - config.bob.example.json -> config.bob.json
   - config.alice.example.json -> config.alice.json
2. Pada config.alice.json, ubah nilai host pada field "kdc" dan "bob" sesuai alamat IP lokal masing-masing perangkat.
3. Pada config.kdc.json dan config.bob.json, gunakan host "0.0.0.0" agar server dapat diakses dari perangkat lain di jaringan lokal.
4. Pastikan port 5000 dan 5001 tidak diblokir oleh firewall.

Penting: File konfigurasi tidak boleh menyimpan key (Ka, Kb, atau Ks). Semua key dimasukkan secara manual saat aplikasi dijalankan melalui prompt getpass.

## 4. Tata Cara Menjalankan Aplikasi

Jalankan aplikasi dengan urutan berikut: KDC -> Bob -> Alice.

### 1. Menjalankan KDC
```bash
python kdc_server.py --config config.kdc.json
```
Masukkan master key untuk Alice (Ka) dan Bob (Kb) saat diminta. Panjang key harus tepat 16 karakter ASCII printable.

Menu KDC:
- 1: Cek status server dan statistik koneksi.
- 2: Ubah master key entitas secara dinamis.
- 3: Lihat riwayat log audit ring buffer.
- 0: Stop server dan keluar.

### 2. Menjalankan Bob
```bash
python bob_client.py --config config.bob.json
```
Masukkan master key Bob (Kb) saat diminta (harus sama dengan Kb yang diinput di KDC). Bob akan standby mendengarkan koneksi di port 5001.

Menu Bob:
- 1: Status sesi dan KCV session key.
- 2: Kirim pesan chat ke Alice.
- 3: Lihat pesan masuk / riwayat chat.
- 4: Ubah key Kb.
- 5: Tutup sesi (kirim BYE).
- 0: Keluar.

### 3. Menjalankan Alice
```bash
python alice_client.py --config config.alice.json
```
Masukkan master key Alice (Ka) saat diminta (harus sama dengan Ka yang diinput di KDC).

Menu Alice:
- 1: Request session key Ks ke KDC (Langkah 1 & 2).
- 2: Autentikasi ke Bob menggunakan tiket (Langkah 3, 4, & 5).
- 3: Kirim pesan chat ke Bob.
- 4: Lihat pesan masuk / riwayat chat.
- 5: Ubah key Ka.
- 6: Status sesi dan KCV session key.
- 7: Tutup sesi (kirim BYE).
- 0: Keluar.

Setelah memilih menu 1 lalu menu 2 di Alice, status sesi akan menjadi AUTHENTICATED. Kedua pihak dapat langsung saling bertukar pesan chat melalui menu kirim pesan.

## 5. Cara Menjalankan Pengujian Otomatis

Untuk menjalankan seluruh unit test otomatis:
```bash
python -m unittest discover -s tests -v
```

Untuk menjalankan pengujian modul tertentu:
```bash
python -m unittest tests/test_p1_encoding.py -v
python -m unittest tests/test_p1_network.py -v
python -m unittest tests/test_p2_aes.py -v
python -m unittest tests/test_p3_protocol.py -v
python -m unittest tests/test_p4_kdc_alice.py -v
python -m unittest tests/test_p5_bob_session.py -v
python -m unittest tests/test_p6_messaging_ui.py -v
```

Pemeriksaan statis (static check) untuk memastikan tidak ada library kriptografi terlarang dan tidak ada hardcoded key dapat dijalankan melalui test suite terkait.

## 6. Tabel Analisis Wireshark & Panduan Pembuktian

Gunakan filter berikut pada Wireshark untuk menangkap paket pertukaran data:
```text
tcp port 5000 or tcp port 5001
```

### Tabel Ringkasan Paket
| Langkah | Arah | Port | Protokol | Data Terlihat di Stream | Status Enkripsi |
|---|---|---|---|---|---|
| 1 | Alice -> KDC | 5000 | TCP | JSON: type KDC_REQ, id_a, id_b, n1 | Plaintext |
| 2 | KDC -> Alice | 5000 | TCP | JSON: type KDC_RESP, iv, ct | Terenkripsi (Ka & Kb) |
| 3 | Alice -> Bob | 5001 | TCP | JSON: type TICKET, iv, ct | Terenkripsi (Kb) |
| 4 | Bob -> Alice | 5001 | TCP | JSON: type CHALLENGE, iv, ct | Terenkripsi (Ks) |
| 5 | Alice -> Bob | 5001 | TCP | JSON: type CHALLENGE_RESP, iv, ct | Terenkripsi (Ks) |
| Chat | Alice <-> Bob | 5001 | TCP | JSON: type APP_MSG, iv, ct | Terenkripsi (Ks) |

Detail analisis stream dan panduan pengujian manual dapat dilihat pada docs/evidence/README.md.

## 7. Penjelasan Perilaku Perubahan Key Dinamis (FR-08)

Sistem mendukung penggantian master key langsung saat aplikasi sedang berjalan (runtime) tanpa perlu me-restart proses:
- KDC menyediakan menu 2 untuk memperbarui key ID tertentu di memory registry.
- Alice menyediakan menu 5 untuk memperbarui key Ka.
- Bob menyediakan menu 4 untuk memperbarui key Kb.

Jika Alice atau Bob mengganti key saat masih berada dalam sesi aktif:
1. Sesi aktif akan langsung diputus secara otomatis dengan mengirim pesan BYE ke pihak lawan.
2. Status sesi kembali ke IDLE.
3. Untuk berkomunikasi kembali, Alice harus meminta session key baru ke KDC dan mengulang proses autentikasi ke Bob.

Pengecekan KCV (Key Check Value):
KCV dihitung dari enkripsi blok nol menggunakan key yang aktif (diambil 6 karakter heksadesimal pertama). Nilai KCV ini ditampilkan pada status sesi di Alice dan Bob agar user dapat memastikan kedua belah pihak memegang session key yang sama tanpa perlu melihat isi key aslinya.

## 8. Dokumentasi Keterbatasan Sistem

Beberapa keterbatasan teknis dan batasan keamanan sistem ini meliputi:
- CBC tanpa HMAC: Enkripsi AES-CBC dengan padding PKCS#7 menjaga kerahasiaan isi data, namun tidak memiliki mekanisme pengecekan integritas penuh (message authentication code) seperti pada mode AEAD/GCM.
- Replay Tiket: Tiket dari KDC tidak menggunakan timestamp kadaluarsa, sehingga pengamanan replay attack pada handshake mengandalkan nonce challenge-response (N2).
- Ruang Key ASCII: Key dibatasi pada 16 karakter ASCII printable, sehingga variasi kombinasi key lebih kecil dibandingkan key biner acak 128-bit murni.
- Non-goal Keamanan: Sistem ini tidak mencakup enkripsi transport level (seperti TLS), proteksi anti-replay pada pesan chat individual setelah handshake, proteksi terhadap serangan DoS pada soket TCP, dan memory zeroization pada runtime Python.

## 9. Referensi Akademis

1. NIST FIPS PUB 197: Advanced Encryption Standard (AES).
2. NIST Special Publication 800-38A: Recommendation for Block Cipher Modes of Operation.
3. Needham, R. M., & Schroeder, M. D. (1978): Using encryption for authentication in large networks of computers. Communications of the ACM, 21(12), 993-999.
4. RFC 2315: PKCS #7 Cryptographic Message Syntax Version 1.5.

## Struktur Repositori

Tanggung jawab masing-masing file dalam repositori:
- config.py: Membaca dan memvalidasi konfigurasi JSON untuk Alice, Bob, dan KDC.
- app_logging.py: Mengatur log format JSON lines, masking data sensitif, dan ring buffer di memory.
- encoding_utils.py: Helper konversi hex, validasi string ASCII printable, dan validasi ID.
- network.py: Abstraksi koneksi TCP client/server dengan framing length-prefix 4-byte big-endian.
- manual_aes.py: Implementasi murni AES-128 (Key Expansion, SubBytes, ShiftRows, MixColumns, AddRoundKey) dan mode CBC dengan padding PKCS#7.
- protocol.py: Format dan validasi struktur pesan protokol, kalkulasi nonce, dan KCV.
- session.py: State machine sesi, buffer riwayat pesan, dan background thread receiver.
- ui.py: Antarmuka konsol terminal thread-safe dengan warna dasar sederhana (hitam, putih, abu-abu).
- kdc_server.py: Program utama server KDC dan manajemen registry key.
- alice_client.py: Program utama klien Alice dan menu interaktif.
- bob_client.py: Program utama server/klien Bob dan listener koneksi.
- tests/: Direktori unit test dan integrasi untuk setiap modul.

## Troubleshooting

Panduan penanganan kendala yang umum terjadi:
- Key Mismatch atau Error Dekripsi: Pastikan master key Ka (Alice-KDC) dan Kb (Bob-KDC) diinput dengan nilai yang sama persis di kedua sisi. Gunakan nilai KCV untuk memverifikasi kesamaan session key.
- UNKNOWN_ID: Terjadi jika Alice meminta tiket untuk ID yang belum terdaftar di config.kdc.json. Tambahkan ID tersebut ke dalam field "registry_ids".
- BUSY: Bob sedang menangani koneksi lain atau sesi sebelumnya belum ditutup. Pilih menu tutup sesi atau kirim BYE terlebih dahulu.
- Connection Refused: Server target (KDC atau Bob) belum dijalankan atau alamat IP/port yang dituju tidak sesuai. Jalankan server target terlebih dahulu.
- Timeout: Terjadi jika paket terhalang firewall atau IP tidak dapat dijangkau. Pastikan port 5000 dan 5001 diizinkan pada firewall lokal.
- Port Terpakai (Address already in use): Port 5000 atau 5001 masih dipakai proses lama. Hentikan proses tersebut atau ubah konfigurasi port pada file JSON.
- Config Invalid: Format file JSON salah atau ada field wajib yang kurang. Periksa format file JSON sesuai file contoh (.example.json).
