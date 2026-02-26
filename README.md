# Pencatatan-Log-Linux-untuk-SOC
Jelajahi sumber log Linux utama dan pelajari cara menggunakannya dalam proses triase SOC Anda.

# Perkenalan
Linux telah lama menjadi pemimpin dalam server dan sistem tertanam, dan sekarang penggunaannya semakin meluas seiring dengan pertumbuhan adopsi cloud. Sebagai analis SOC , Anda kemungkinan besar akan menyelidiki peringatan dan insiden Linux , baik dari server on-premises tradisional maupun dari beban kerja berbasis kontainer cloud-native. Di ruangan ini, Anda akan menjelajahi log Linux paling umum yang dikirim ke SIEM dan mempelajari cara melihatnya langsung di host.

Tujuan pembelajaran
Jelajahi otentikasi, runtime, dan log sistem di Linux.
Pelajari perintah dan jebakan saat bekerja dengan log.
Ungkap bagaimana alat seperti auditd memantau dan melaporkan peristiwa-peristiwa tersebut

# Bekerja dengan log text
Format Log
Bertentangan dengan kepercayaan umum, sistem berbasis Linux tidak kebal terhadap malware. Terlebih lagi, intrusi yang menargetkan Linux merupakan masalah yang semakin meningkat. Oleh karena itu, sebagai analis SOC , Anda akan sering perlu menyelidiki peringatan Linux , dan untuk itu, Anda perlu memahami cara kerja pencatatannya. Sekarang, mari kita klarifikasi beberapa hal dan lanjutkan!

Yang dimaksud dengan Linux di sini adalah distribusi Linux seperti Debian, Ubuntu, CentOS, atau RHEL.
Ruangan ini berfokus pada server Linux tanpa GUI dan tidak menjelaskan tentang pencatatan log desktop.
Bekerja dengan Log
Tidak seperti di Windows, Linux mencatat sebagian besar peristiwa ke dalam file teks biasa. Ini berarti Anda dapat membaca log melalui editor teks apa pun tanpa memerlukan alat khusus seperti Event Viewer. Di sisi lain, log Linux default kurang terstruktur karena tidak ada kode peristiwa dan aturan format log yang ketat. Sebagian besar log Linux terletak di  /var/logfolder, jadi mari kita mulai perjalanan dengan memeriksa /var/log/syslogfile tersebut - aliran gabungan dari berbagai peristiwa sistem:

Isi File Syslog
root@thm-vm:~$ cat /var/log/syslog | head
[...]
2025-08-13T13:57:49.388941+00:00 thm-vm systemd-timesyncd[268]: Initial clock synchronization to Wed 2025-08-13 13:57:49.387835 UTC.
2025-08-13T13:59:39.970029+00:00 thm-vm systemd[888]: Starting dbus.socket - D-Bus User Message Bus Socket...
2025-08-13T14:02:22.606216+00:00 thm-vm dbus-daemon[564]: [system] Successfully activated service 'org.freedesktop.timedate1'
2025-08-13T14:05:01.999677+00:00 thm-vm CRON[1027]: (root) CMD (command -v debian-sa1 > /dev/null && debian-sa1 1 1)
[...]
Memfilter Log

Anda akan melihat ribuan kejadian saat membaca file syslog pada VM yang terhubung , tetapi hanya beberapa yang berguna untuk SOC. Itulah mengapa Anda harus memfilter log dan mempersempit pencarian Anda sebanyak mungkin. Misalnya, Anda dapat menggunakan perintah "grep" untuk memfilter kata kunci "CRON" dan hanya melihat log cronjob:

Penyaringan Syslog
# Or "grep -v CRON" to exclude "CRON" from results
root@thm-vm:~$ cat /var/log/syslog | grep CRON
2025-08-13T14:17:01.025846+00:00 thm-vm CRON[1042]: (root) CMD (cd / && run-parts --report /etc/cron.hourly)
2025-08-13T14:25:01.043238+00:00 thm-vm CRON[1046]: (root) CMD (command -v debian-sa1 > /dev/null && debian-sa1 1 1)
2025-08-13T14:30:01.014532+00:00 thm-vm CRON[1048]: (root) CMD (date > mycrondebug.log)
Menemukan Log

Terakhir, misalkan Anda mencari semua login pengguna, tetapi tidak tahu di mana mencarinya. Log sistem Linux disimpan dalam /var/log/folder dalam bentuk teks biasa, jadi Anda cukup menggunakan perintah grep untuk kata kunci terkait seperti "login", "auth", atau "session" di semua file log di sana dan mempersempit pencarian Anda berikutnya:

Menemukan Log
# List what's logged by your system (/var/log folder) 
root@thm-vm:~$ ls -l /var/log
drwxr-xr-x  2 root      root               4096 Aug 12 16:41 apt
drwxr-x---  2 root      adm                4096 Aug 12 12:40 audit
-rw-r-----  1 syslog    adm               45399 Aug 13 15:05 auth.log
-rw-r--r--  1 root      root            1361277 Aug 12 16:41 dpkg.log
drwxr-sr-x+ 3 root      systemd-journal    4096 Oct 22  2024 journal
-rw-r-----  1 syslog    adm              214772 Aug 13 13:57 kern.log
-rw-r-----  1 syslog    adm              315798 Aug 13 15:05 syslog
[...]

# Search for potential logins across all logs (/var/log)
root@thm-vm:~$ grep -R -E "auth|login|session" /var/log
[...]
Peringatan Terkait Penebangan Kayu
Tidak seperti Windows, Linux memungkinkan Anda untuk dengan mudah mengubah format log, detail log, dan lokasi penyimpanan. Dengan ratusan distribusi Linux , yang masing-masing dikenal sedikit menyesuaikan pencatatan log, bersiaplah bahwa log di ruangan ini mungkin terlihat berbeda di sistem Anda, atau mungkin tidak ada sama sekali.

Jawablah pertanyaan-pertanyaan di bawah ini.
Gunakan  file /var/log/syslog pada VM untuk menjawab pertanyaan-pertanyaan tersebut.
Domain server waktu mana yang dihubungi VM untuk menyinkronkan waktunya?




ubuntu@thm-vm:~$ cd /var/log
ubuntu@thm-vm:/var/log$ ls
README            apt       cloud-init-output.log  dmesg.0     dmesg.4.gz  landscape  sysstat               wtmp
alternatives.log  audit     cloud-init.log         dmesg.1.gz  dpkg.log    lastlog    ubuntu-advantage.log
amazon            auth.log  dist-upgrade           dmesg.2.gz  journal     private    unattended-upgrades
apport.log        btmp      dmesg                  dmesg.3.gz  kern.log    syslog     upgrade
ubuntu@thm-vm:/var/log$
ubuntu@thm-vm:/var/log$ :  cat /var/log/syslog | grep "com"
2026-02-26T01:56:08.936305+00:00 thm-vm systemd-timesyncd[281]: Timed out waiting for reply from 91.189.91.157:123 (ntp.ubuntu.com).

jawaban : ntp.ubuntu.com

Jawaban yang Benar

Apa isi pesan kernel dari Yama di /var/log/syslog ?

Becoming mindful.

Jawaban yang Benar

# Log Otentikasi
Log Otentikasi
File log pertama dan seringkali yang paling berguna yang ingin Anda pantau adalah /var/log/auth.log(atau /var/log/securepada sistem berbasis RHEL). Meskipun namanya menunjukkan bahwa file ini berisi peristiwa otentikasi, file ini juga dapat menyimpan peristiwa manajemen pengguna, perintah sudo yang dijalankan, dan banyak lagi! Mari kita mulai dengan format file log:

Contoh peristiwa autentikasi (/var/log/auth.log) yang terdiri dari waktu peristiwa, nama host, dan layanan yang menghasilkan peristiwa, serta pesan sebenarnya dalam format teks yang tidak terstruktur.

Peristiwa Masuk dan Keluar
Ada banyak cara pengguna melakukan autentikasi ke mesin Linux: secara lokal, melalui SSH, menggunakan perintah "sudo" atau "su", atau secara otomatis untuk menjalankan cron job. Setiap proses masuk dan keluar yang berhasil dicatat, dan Anda dapat melihatnya dengan memfilter peristiwa yang berisi kata kunci "session opened" atau "session closed":

Login Lokal dan Jarak Jauh
root@thm-vm:~$ cat /var/log/auth.log | grep -E 'session opened|session closed'
# Local, on-keyboard login and logout of Bob (login:session)
2025-08-02T16:04:43 thm-vm login[1138]: pam_unix(login:session): session opened for user bob(uid=1001) by bob(uid=0)
2025-08-02T19:23:08 thm-vm login[1138]: pam_unix(login:session): session closed for user bob
# Remote login examples of Alice (via SSH and then SMB)
2025-08-04T09:09:06 thm-vm sshd[839]: pam_unix(sshd:session): session opened for user alice(uid=1002) by alice(uid=0)
2025-08-04T12:46:13 thm-vm smbd[1795]: pam_unix(samba:session): session opened for user alice(uid=1002) by alice(uid=0)
Login Cron dan Sudo
root@thm-vm:~$ cat /var/log/auth.log | grep -E 'session opened|session closed'
# Traces of some cron job launch running as root (cron:session)
2025-08-06T19:35:01 thm-vm CRON[41925]: pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)
2025-08-06T19:35:01 thm-vm CRON[3108]: pam_unix(cron:session): session closed for user root
# Carol running "sudo su" to access root (sudo:session)
2025-08-07T09:12:32 thm-vm sudo: pam_unix(sudo:session): session opened for user root(uid=0) by carol(uid=1003)
Selain log sistem, daemon SSH menyimpan lognya sendiri tentang login SSH yang berhasil dan gagal. Log ini dikirim ke file auth.log yang sama, tetapi memiliki format yang sedikit berbeda. Mari kita lihat contoh dua login SSH yang gagal dan satu yang berhasil:

Acara Khusus SSH
root@thm-vm:~$ cat /var/log/auth.log | grep "sshd" | grep -E 'Accepted|Failed'
# Common SSH log format: <is-successful> <auth-method> for <user> from <ip>
2025-08-07T11:21:25 thm-vm sshd[3139]: Failed password for root from 222.124.17.227 port 50293 ssh2
2025-08-07T14:17:40 thm-vm sshd[3139]: Failed password for admin from 138.204.127.54 port 52670 ssh2
2025-08-09T20:30:51 thm-vm sshd[1690]: Accepted publickey for bob from 10.19.92.18 port 55050 ssh2: <key>
Berbagai Acara
Anda juga dapat menggunakan file log yang sama untuk mendeteksi peristiwa manajemen pengguna. Ini mudah jika Anda mengetahui perintah dasar Linux: Jika useradd adalah perintah untuk menambahkan pengguna baru, cukup cari kata kunci "useradd" untuk melihat peristiwa pembuatan pengguna! Berikut adalah contoh apa yang dapat Anda lihat di log: perubahan kata sandi, penghapusan pengguna, dan kemudian pembuatan pengguna dengan hak istimewa.

Acara Manajemen Pengguna
root@thm-vm:~$ cat /var/log/auth.log | grep -E '(passwd|useradd|usermod|userdel)\['
2023-02-01T11:09:55 thm-vm passwd[644]: password for 'ubuntu' changed by 'root'
2025-08-07T22:11:11 thm-vm userdel[1887]: delete user 'oldbackdoor'
2025-08-07T22:11:29 thm-vm useradd[1878]: new user: name=backdoor, UID=1002, GID=1002, shell=/bin/sh
2025-08-07T22:11:54 thm-vm usermod[1906]: add 'backdoor' to group 'sudo'
2025-08-07T22:11:54 thm-vm usermod[1906]: add 'backdoor' to shadow group 'sudo'
Terakhir, tergantung pada konfigurasi sistem dan paket yang terinstal, Anda mungkin menemukan kejadian menarik atau tak terduga. Misalnya, Anda mungkin menemukan perintah yang dijalankan dengan sudo, yang dapat membantu melacak tindakan berbahaya. Dalam contoh di bawah ini, pengguna "ubuntu" menggunakan sudo untuk menghentikan EDR, membaca status firewall, dan akhirnya mengakses root melalui "sudo su":

Perintah yang Dijalankan dengan Sudo
root@thm-vm:~$ cat /var/log/auth.log | grep -E 'COMMAND='
2025-08-07T11:21:49 thm-vm sudo: ubuntu : TTY=pts/0 ; [...] COMMAND=/usr/bin/systemctl stop edr
2025-08-07T11:23:18 thm-vm sudo: ubuntu : TTY=pts/0 ; [...] COMMAND=/usr/bin/ufw status numbered
2025-08-07T11:23:33 thm-vm sudo: ubuntu : TTY=pts/0 ; [...] COMMAND=/usr/bin/su
Jawablah pertanyaan-pertanyaan di bawah ini.
Lanjutkan dengan VM dan gunakan file /var/log/auth.log .
Alamat IP mana yang gagal masuk sebagai beberapa pengguna melalui SSH?

10.14.94.82

Jawaban yang Benar
Pengguna mana yang dibuat dan ditambahkan ke grup "sudo"?

xerxes

Jawaban yang Benar

Log Linux Umum
Log Sistem Umum
Linux mencatat banyak peristiwa lain yang tersebar di berbagai file, seperti /var/log: log kernel, perubahan jaringan, eksekusi layanan atau cron, instalasi paket, dan masih banyak lagi. Isi dan formatnya dapat berbeda tergantung pada sistem operasi, dan file log yang paling umum adalah:

/var/log/kern.logPesan dan kesalahan kernel, berguna untuk investigasi yang lebih lanjut.
/var/log/syslog (or /var/log/messages): Kumpulan berbagai acara Linux yang terpadu
/var/log/dpkg.log (or /var/log/apt)Log pengelola paket pada sistem berbasis Debian
/var/log/dnf.log (or /var/log/yum.log): Log pengelola paket pada sistem berbasis RHEL
Log yang tercantum sangat berharga selama DFIR, tetapi jarang terlihat dalam rutinitas SOC sehari-hari karena seringkali berisik dan sulit diuraikan. Namun, jika Anda ingin mempelajari lebih dalam cara kerja log ini, kunjungi ruang DFIR Investigasi Log Linux .

Log Khusus Aplikasi
Di SOC, Anda mungkin juga memantau program tertentu, dan untuk melakukannya secara efektif, Anda perlu menggunakan log-nya. Misalnya, menganalisis log basis data untuk melihat kueri apa yang dijalankan, log email untuk menyelidiki phishing, log kontainer untuk menangkap anomali, dan log server web untuk mengetahui halaman mana yang dibuka, kapan, dan oleh siapa. Anda akan menjelajahi log-log ini di modul-modul mendatang, tetapi untuk memberikan gambaran umum, berikut adalah contoh dari log server web Nginx yang umum:

Log Akses Web Nginx
root@thm-vm:~$ cat /var/log/nginx/access.log
# Every log line corresponds to a web request to the web server
10.0.1.12 - - [11/08/2025:14:32:10 +0000] "GET / HTTP/1.1" 200 3022
10.0.1.12 - - [11/08/2025:14:32:14 +0000] "GET /login HTTP/1.1" 200 1056
10.0.1.12 - - [11/08/2025:14:33:09 +0000] "POST /login HTTP/1.1" 302 112
10.0.4.99 - - [11/08/2025:17:11:20 +0000] "GET /images/logo.png HTTP/1.1" 200 5432
10.0.5.21 - - [11/08/2025:17:56:23 +0000] "GET /admin HTTP/1.1" 403 104
Sejarah Bash
Sumber log berharga lainnya adalah riwayat Bash - fitur yang merekam setiap perintah yang Anda jalankan setelah menekan Enter. Secara default, perintah pertama kali disimpan dalam memori selama sesi Anda, dan kemudian ditulis ke  ~/.bash_historyfile per pengguna saat Anda keluar. Anda dapat membuka ~/.bash_historyfile untuk meninjau perintah dari sesi sebelumnya atau menggunakan historyperintah untuk melihat perintah dari sesi Anda saat ini dan sebelumnya:

File Riwayat Bash dan Perintah
ubuntu@thm-vm:~$ cat /home/ubuntu/.bash_history
echo "hello" > world.txt
nano /etc/ssh/sshd_config
sudo su
ubuntu@thm-vm:~$ history
1 echo "hello" > world.txt
2 nano /etc/ssh/sshd_config
3 sudo su
4 ls -la /home/ubuntu
5 cat /home/ubuntu/.bash_history
6 history
Meskipun file riwayat Bash tampak seperti sumber log yang vital, file ini jarang digunakan oleh tim SOC dalam rutinitas harian mereka. Hal ini karena file tersebut tidak melacak perintah non-interaktif (seperti yang diinisiasi oleh sistem operasi Anda, cron job, atau server web) dan memiliki beberapa keterbatasan lainnya. Meskipun Anda dapat mengkonfigurasinya agar lebih bermanfaat, masih ada beberapa masalah yang perlu Anda ketahui:

Keterbatasan Riwayat Bash
# Attackers can simply add a leading space to the command to avoid being logged
ubuntu@thm-vm:~$  echo "You will never see me in logs!"

# Attackers can paste their commands in a script to hide them from Bash history
ubuntu@thm-vm:~$ nano legit.sh && ./legit.sh
 
# Attackers can use other shells like /bin/sh that don't save the history like Bash
ubuntu@thm-vm:~$ sh
$ echo "I am no longer tracked by Bash!"
Jawablah pertanyaan-pertanyaan di bawah ini.
Berdasarkan log pengelola paket VM,
versi unzip mana  yang terpasang pada sistem?

6.0-28ubuntu4.1

Jawaban yang Benar
Bendera apa yang Anda lihat di riwayat bash salah satu pengguna?

THM{note_to_remember}

Jawaban yang Benar

# Pemantauan Waktu Eksekusi
Pemantauan Waktu Eksekusi
Sampai saat ini, Anda telah menjelajahi berbagai sumber log Linux , tetapi tidak ada yang dapat menjawab pertanyaan seperti "Program apa saja yang dijalankan Bob hari ini?" atau "Siapa yang menghapus folder beranda saya, dan kapan?". Itu karena, secara default, Linux tidak mencatat pembuatan proses, perubahan file, atau peristiwa terkait jaringan, yang secara kolektif dikenal sebagai peristiwa runtime . Menariknya, Windows menghadapi keterbatasan yang sama, itulah sebabnya di ruang Windows Logging for SOC kami harus menggunakan alat tambahan: Sysmon . Di Linux , kita akan mengambil pendekatan serupa.


Panggilan Sistem
Sebelum melanjutkan, mari kita jelajahi konsep inti sistem operasi yang mungkin membantu Anda memahami banyak topik lain: panggilan sistem. Singkatnya, setiap kali Anda perlu membuka file, membuat proses, mengakses kamera, atau meminta layanan sistem operasi lainnya , Anda melakukan panggilan sistem tertentu. Ada lebih dari 300 panggilan sistem di Linux , seperti execveuntuk menjalankan program. Berikut adalah diagram alur tingkat tinggi tentang cara kerjanya:

<img width="1152" height="213" alt="image" src="https://github.com/user-attachments/assets/e06985d4-92a5-4e98-89c5-b13122898a3a" />

Mengapa Anda perlu mengetahui tentang panggilan sistem? Nah, semua EDR dan alat pencatatan modern bergantung padanya - mereka memantau panggilan sistem utama dan mencatat detailnya dalam format yang mudah dibaca manusia. Karena hampir tidak ada cara bagi penyerang untuk melewati panggilan sistem, yang perlu Anda lakukan hanyalah memilih panggilan sistem yang ingin Anda catat dan pantau. Pada tugas berikutnya, Anda akan mencobanya dalam praktik menggunakan auditd.

Jawablah pertanyaan-pertanyaan di bawah ini.
System call Linux mana yang umum digunakan untuk mengeksekusi program?

execve

Jawaban yang Benar
Bisakah program biasa membuka file atau membuat proses tanpa melalui panggilan sistem? (Ya/Tidak)

Nay

Jawaban yang Benar

# Menggunakan Auditd
Daemon Audit
Auditd (Audit Daemon) adalah solusi audit bawaan yang sering digunakan oleh tim SOC untuk pemantauan runtime. Dalam tugas ini, kita akan melewati bagian konfigurasi dan fokus pada cara membaca aturan auditd dan cara menafsirkan hasilnya. Mari kita mulai dari aturan - instruksi yang terdapat di dalamnya /etc/audit/rules.d/yang mendefinisikan panggilan sistem mana yang akan dipantau dan filter mana yang akan diterapkan:


Memantau setiap proses, file, dan kejadian jaringan dapat dengan cepat menghasilkan gigabyte log setiap hari. Tetapi lebih banyak log tidak selalu berarti deteksi yang lebih baik karena serangan yang terkubur dalam terabyte data yang tidak terdeteksi masih belum terlihat. Itulah mengapa tim SOC sering fokus pada kejadian berisiko tinggi dan membangun aturan yang seimbang, seperti  ini atau contoh yang Anda lihat di atas.

Menggunakan Auditd
Anda dapat melihat log yang dihasilkan secara real-time di /var/log/audit/audit.log, tetapi lebih mudah menggunakan ausearchperintah tersebut, karena perintah ini memformat output agar lebih mudah dibaca dan mendukung opsi pemfilteran. Mari kita lihat contoh berdasarkan aturan dari contoh di atas dengan mencari kejadian yang cocok dengan kunci "proc_wget":

Mencari eksekusi "Wget"
root@thm-vm:~$ ausearch -i -k proc_wget
----
type=PROCTITLE msg=audit(08/12/25 12:48:19.093:2219) : proctitle=wget https://files.tryhackme.thm/report.zip
type=CWD msg=audit(08/12/25 12:48:19.093:2219) : cwd=/root
type=EXECVE msg=audit(08/12/25 12:48:19.093:2219) : argc=2 a0=wget a1=https://files.tryhackme.thm/report.zip
type=SYSCALL msg=audit(08/12/25 12:48:19.093:2219) : arch=x86_64 syscall=execve [...] ppid=3752 pid=3888 auid=ubuntu uid=root tty=pts1 exe=/usr/bin/wget key=proc_wget
Terminal di atas menunjukkan log dari satu perintah "wget". Di sini, auditd membagi kejadian tersebut menjadi empat baris: PROCTITLE menunjukkan baris perintah proses, CWD melaporkan direktori kerja saat ini, dan dua baris sisanya menunjukkan detail panggilan sistem, seperti:

pid=3888, ppid=3752: ID Proses dan ID Proses Induk. Berguna untuk menghubungkan peristiwa dan membangun pohon proses.
auid=ubuntuPengguna audit. Akun yang awalnya digunakan untuk masuk, baik secara lokal (keyboard) maupun jarak jauh (SSH).
uid=root: Pengguna yang menjalankan perintah. Kolom ini dapat berbeda dari auid jika Anda berganti pengguna dengan sudo atau su.
tty=pts1: Pengidentifikasi sesi. Membantu membedakan peristiwa ketika beberapa orang bekerja pada server Linux yang sama.
exe=/usr/bin/wgetJalur absolut ke file biner yang dieksekusi, sering digunakan untuk membangun aturan deteksi SOC.
key=proc_wgetTag opsional yang ditentukan oleh para insinyur dalam aturan auditd yang berguna untuk memfilter peristiwa.
Peristiwa File

Sekarang, mari kita lihat peristiwa file yang cocok dengan kunci "file_sshconf". Seperti yang dapat Anda lihat dari terminal di bawah ini, auditd melacak perubahan pada /etc/ssh/sshd_configfile melalui perintah "nano". Tim SOC sering menetapkan aturan untuk memantau perubahan pada file dan direktori penting (misalnya, file konfigurasi SSH , definisi cronjob, atau pengaturan sistem).

Mencari
SSH
Perubahan Konfigurasi
root@thm-vm:~$ ausearch -i -k file_sshconf
----
type=PROCTITLE msg=audit(08/12/25 13:06:47.656:2240) : proctitle=nano /etc/ssh/sshd_config
type=CWD msg=audit(08/12/25 13:06:47.656:2240) : cwd=/
type=PATH msg=audit(08/12/25 13:06:47.656:2240) : item=0 name=/etc/ssh/sshd_config [...]
type=SYSCALL msg=audit(08/12/25 13:06:47.656:2240) : arch=x86_64 syscall=openat [...] ppid=3752 pid=3899 auid=ubuntu uid=root tty=pts1 exe=/usr/bin/nano key=file_sshconf
Alternatif Audit
Anda mungkin memperhatikan output auditd yang kurang praktis - meskipun menyediakan pencatatan log yang detail, output tersebut sulit dibaca dan diintegrasikan ke dalam SIEM. Itulah mengapa banyak tim SOC menggunakan solusi pencatatan log runtime alternatif, misalnya:

Sysmon untuk Linux : Pilihan sempurna jika Anda sudah terbiasa menggunakan Sysmon dan menyukai XML.
Falco : Solusi modern dan sumber terbuka, ideal untuk memantau sistem berbasis kontainer.
Osquery : Sebuah alat menarik yang dapat digunakan secara luas untuk berbagai tujuan keamanan.
EDR : Sebagian besar solusi EDR dapat melacak dan memantau berbagai peristiwa runtime Linux.
Hal terpenting yang perlu diingat adalah bahwa semua alat yang tercantum bekerja berdasarkan prinsip yang sama - memantau panggilan sistem. Setelah Anda memahami panggilan sistem, Anda akan dengan mudah mempelajari semua alat yang disebutkan. Pengetahuan ini juga membantu Anda menangani skenario tingkat lanjut, seperti memahami mengapa tindakan tertentu dicatat dengan cara tertentu atau tidak dicatat sama sekali.

Sekarang, cobalah untuk mengungkap pelaku ancaman dengan log pembuatan proses! Untuk tugas ini, lanjutkan dengan VM dan gunakan log auditd untuk menjawab pertanyaan.
Anda mungkin perlu menggunakan perintah ausearch -idan untuk tugas ini.grep

Jawablah pertanyaan-pertanyaan di bawah ini.
Kapan  file secret.thm dibuka untuk pertama kalinya? (BB/HH/TTY HH:BB:SS)
Catatan: Akses ke file ini dicatat dengan kunci "file_thmsecret".

08/13/25 18:36:54

Jawaban yang Benar

Apa nama file asli yang diunduh dari GitHub melalui wget?
Catatan: Pembuatan proses wget dicatat dengan kunci "proc_wget".

naabu_2.3.5_linux_amd64.zip

Jawaban yang Benar

Rentang jaringan mana yang dipindai menggunakan alat yang diunduh?
Catatan: Tidak ada kunci khusus untuk kejadian ini, tetapi masih ada di log auditd.

192.168.50.0/24

Jawaban yang Benar

# kesimpulan 
Kerja bagus dalam menjelajahi sumber log Linux ! Di ruangan selanjutnya, Anda akan menerapkan pengetahuan ini untuk melacak dan menyelidiki berbagai ancaman yang menargetkan sistem Linux . Mulai dari Akses Awal hingga langkah-langkah serangan terakhir, Anda mungkin memerlukan semua sumber log yang telah dipelajari untuk mengungkap sepenuhnya pelanggaran tersebut.

Poin-Poin Penting
Pencatatan log Linux bisa jadi kacau, tetapi sering kali menyimpan detail yang cukup untuk mendeteksi ancaman.
Secara default, log disimpan dalam /var/log/folder dan biasanya disimpan dalam format teks biasa.
Tiga sumber log utama untuk SOC adalah auth.log, log khusus aplikasi, dan log runtime.
Riwayat Bash tidak dapat diandalkan untuk SOC ; lebih baik gunakan auditd atau solusi alternatif lainnya.
