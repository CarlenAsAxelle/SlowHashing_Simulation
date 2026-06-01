# SlowHashing Simulation

Program Python untuk membandingkan biaya hashing PBKDF2-HMAC-SHA256,
bcrypt, scrypt, dan Argon2id, lalu menghitung estimasi waktu brute-force
offline berdasarkan keyspace password.

Program ini hanya menjalankan benchmark dan estimasi. Program tidak melakukan
cracking nyata, tidak memakai akun asli, dan tidak memakai database password
asli.

## Struktur Proyek

```txt
SlowHashing_Simulation/
|-- main.py
|-- benchmark.py
|-- estimasi.py
|-- config.py
|-- requirements.txt
|-- output/
|   |-- hasil_benchmark.csv
|   |-- hasil_estimasi_bruteforce.csv
|   |-- grafik_waktu_hashing.png
|   `-- grafik_estimasi_bruteforce.png
`-- README.md
```

Folder `output/` dibuat otomatis saat program dijalankan.

## Instalasi

Gunakan Python 3.10 atau lebih baru.

```bash
pip install -r requirements.txt
```

## Cara Menjalankan

```bash
python main.py
```

Untuk smoke test yang lebih cepat:

```bash
BENCHMARK_REPEATS=1 python main.py
```

Pada PowerShell:

```powershell
$env:BENCHMARK_REPEATS = "1"
python main.py
```

## Parameter Eksperimen

- Password benchmark utama: `P@ssw0rd2026!`
- Salt: 16 byte, dibuat satu kali per konfigurasi algoritma
- Repetisi default: 5 kali per konfigurasi
- PBKDF2: 100000, 300000, 600000, dan 1000000 iterasi
- bcrypt: cost 10, 12, dan 14
- scrypt: `N=2^14`, `N=2^15`, dan `N=2^16` dengan `r=8`, `p=1`
- Argon2id:
  - `memory_cost=65536 KiB`, `time_cost=2`, `parallelism=1`
  - `memory_cost=131072 KiB`, `time_cost=3`, `parallelism=1`
  - `memory_cost=262144 KiB`, `time_cost=3`, `parallelism=2`

Argon2id konfigurasi ketiga mengubah memory cost dan parallelism sekaligus,
sehingga analisis hasil perlu menyebutkan bahwa dua faktor berubah pada
konfigurasi tersebut.

## Output

Program menghasilkan:

- `output/hasil_benchmark.csv`
- `output/hasil_estimasi_bruteforce.csv`
- `output/grafik_waktu_hashing.png`
- `output/grafik_estimasi_bruteforce.png`

Kolom benchmark:

```csv
algorithm,parameter,status,error,avg_time_sec,median_time_sec,min_time_sec,max_time_sec,local_hash_per_sec
```

Kolom estimasi:

```csv
algorithm,parameter,password_scenario,keyspace,attacker_profile,hash_per_sec,avg_case_seconds,worst_case_seconds,avg_case_human,worst_case_human,source
```

## Estimasi Brute-Force

Keyspace dihitung dengan:

```txt
N = C^L
```

Worst-case brute-force:

```txt
T_worst = N / R
```

Average-case brute-force:

```txt
T_avg = N / (2R)
```

Keterangan:

- `C`: ukuran himpunan karakter
- `L`: panjang password
- `R`: hash rate attacker

Hash rate lokal berasal dari hasil benchmark. Hash rate GPU/FPGA eksternal
belum diisi secara default karena harus memakai angka dari referensi yang jelas.
Jika nanti ditambahkan, nilainya harus disimpan per algoritma dan parameter di
`ATTACKER_HASH_RATES` pada `config.py`.

## Batasan

- Eksperimen dilakukan pada perangkat lokal, bukan GPU/FPGA langsung.
- Estimasi GPU/FPGA harus dianggap asumsi literatur, bukan hasil pengujian
  perangkat keras langsung.
- Hasil benchmark bergantung pada spesifikasi perangkat dan kondisi sistem.
- Estimasi brute-force memakai model exhaustive search. Serangan nyata dapat
  memakai dictionary attack, mask attack, rule-based attack, atau leaked
  password corpus.
- Program hanya mengukur biaya hashing, bukan keseluruhan sistem autentikasi.
- Parameter tinggi dapat gagal karena batas memori atau waktu eksekusi perangkat.
