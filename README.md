# manual-aes-kdc-key-distribution

Implementasi manual AES-128-CBC dan distribusi session key berbasis KDC untuk tiga perangkat terpisah.

> Status: scaffold. Marker `TODO` menandai bagian yang belum diimplementasikan.

## 1. Ringkasan Proyek & Alur 5 Langkah KDC

TODO: jelaskan tujuan proyek, peran KDC/Alice/Bob, dan alur lima langkah Needham-Schroeder.

## 2. Prasyarat Lingkungan

TODO: dokumentasikan Python 3.10+, stdlib-only, dan tidak ada `pip install`.

## 3. Panduan Konfigurasi

TODO: dokumentasikan `config.alice.example.json`, `config.bob.example.json`, `config.kdc.example.json`, pengisian IP, port, dan larangan menyimpan key.

## 4. Tata Cara Menjalankan Aplikasi

TODO: dokumentasikan urutan startup KDC, Bob, Alice dan provisioning key melalui `getpass`.

## 5. Contoh Tangkapan Layar Demo Interaktif

TODO: tautkan screenshot final dari `docs/evidence/screenshots/`.

## 6. Cara Menjalankan Pengujian Otomatis

TODO: tulis perintah `python -m unittest discover -s tests -v` dan tes static check.

## 7. Tabel Analisis Wireshark & Panduan Pembuktian

TODO: salin tabel bukti Wireshark dan tautkan `docs/evidence/README.md`.

## 8. Penjelasan Perilaku Perubahan Key Dinamis (FR-08)

TODO: jelaskan perubahan key tanpa restart, pemutusan sesi aktif, dan KCV.

## 9. Dokumentasi Keterbatasan Sistem

TODO: jelaskan CBC tanpa HMAC, replay tiket, ruang key ASCII, dan non-goal keamanan lain.

## 10. Referensi Akademis

TODO: cantumkan FIPS-197 dan NIST SP 800-38A.

## Struktur Repositori

TODO: jelaskan tanggung jawab `config.py`, `app_logging.py`, `encoding_utils.py`, `network.py`, `manual_aes.py`, `protocol.py`, `session.py`, `ui.py`, dan entrypoint.

## Troubleshooting

TODO: dokumentasikan key mismatch, `UNKNOWN_ID`, `BUSY`, timeout, port terpakai, dan config invalid.
