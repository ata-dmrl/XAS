XAS – Extended Analysis System v2.0.0
Güvenlik Araçları Yönetim Konsolu (çok araçlı tarama + risk skoru + fix rehberi + raporlama)

XAS, sahip olduğunuz ya da yetkili olduğunuz sistemlerdeki güvenlik açıklarını
birden fazla güvenlik aracını tek bir konsoldan yöneterek bulmanızı ve bunların
nasıl kapatılacağına dair rehber elde etmenizi sağlar. Modüler (adapter tabanlı),
genişletilebilir ve tamamen CLI tabanlıdır. Beyaz şapka güvenlik çalışması içindir.

> ⚠️ Yalnızca sahibi olduğunuz veya açıkça yetki aldığınız sistemleri tarayın.
> İzinsiz tarama çoğu ülkede suçtur.

Özellikler:
✅ Tek komutla tam tarama: `start <hedef>` → uygun tüm araçları çalıştırır
✅ 0–10 risk skoru + A–F harf notu (kural tabanlı, offline, belirleyici)
✅ Toplu kapatma rehberi: `guide`
✅ Adapter tabanlı araç mimarisi — yeni araç = tek dosya
✅ 11 araç: nmap, nbtscan, zap, nikto, sqlmap, gobuster, tshark, msfconsole + GUI (wireshark, burp, armitage)
✅ Araç yönetimi: `tools` (durum), `install` (onaylı apt kurulumu), `launch` (GUI)
✅ 20 zafiyet türü için detaylı fix rehberi
✅ Zafiyet arama, filtreleme, severity bazlı renkli çıktı
✅ TXT, HTML, JSON rapor + CSV/JSON dışa aktarma
✅ Tab completion

------------------------------------------------------------
# 📁 PROJE YAPISI
------------------------------------------------------------

```
xas/
 ├─ package.json
 ├─ reports/
 ├─ src/
 │   ├─ index.js            Ana giriş (REPL + tab completion)
 │   ├─ commands.js         Tüm komut yönetimi
 │   ├─ riskScorer.js       0–10 risk skoru + A–F harf notu (kural tabanlı)
 │   ├─ toolCheck.js        Başlangıç araç durumu
 │   ├─ issue.js            Zafiyet veri modeli
 │   ├─ fixGuides.js        20 zafiyet fix rehberi
 │   ├─ banner.js           Renkli ASCII banner
 │   ├─ parsers/            Nmap XML / ZAP JSON ayrıştırıcıları
 │   ├─ tools/
 │   │   ├─ Adapter.js      Ortak adapter taban sınıfı (isInstalled/install/run/launch)
 │   │   ├─ registry.js     Araç kayıt sistemi (get/byCategory/managedFor/launchable)
 │   │   └─ adapters/       Her araç bir dosya:
 │   │       ├─ nmap.js  nbtscan.js         (keşif)
 │   │       ├─ zap.js  nikto.js  sqlmap.js  gobuster.js  burpsuite.js (web)
 │   │       ├─ tshark.js  wireshark.js      (ağ trafiği)
 │   │       └─ msfconsole.js  armitage.js   (doğrulama / sömürü)
 │   └─ reportGenerator.js  TXT + HTML + JSON rapor
 └─ README.md
```

------------------------------------------------------------
# 🚀 BAŞLANGIÇ
------------------------------------------------------------

```bash
npm install
npm start
```

------------------------------------------------------------
# ⚡ TAM TARAMA (önerilen akış)
------------------------------------------------------------

Tek komutla hedefe uygun tüm araçları çalıştırır, bulguları birleştirir ve
0–10 risk skoru üretir:

```bash
xas> start 192.168.1.10
xas> start https://hedef.com
```

- IP hedefte: nmap, nbtscan, tshark, msfconsole (doğrulama)
- URL hedefte: nmap, zap, nikto, sqlmap, gobuster, tshark

Kurulu olmayan araçlar otomatik atlanır. Tarama sonunda risk kartı basılır:

```
╔══════════════════════════════════════════════════════╗
║  XAS RİSK RAPORU — https://hedef.com
╠══════════════════════════════════════════════════════╣
║  RİSK SKORU: 8.7 / 10   [D - Riskli — kısa sürede müdahale]
╚══════════════════════════════════════════════════════╝

  Dağılım:  CRITICAL 1 │ HIGH 3 │ MEDIUM 2 │ LOW 1 │ INFO 0

  En kritik bulgular:
   #4 [CRITICAL] SQL Injection: id   http://hedef.com/login.php
   #2 [HIGH    ] Erişilebilir yönetim yolu: /admin   http://hedef.com/admin
   ...

  Kapatma rehberi: guide | tüm liste: list | rapor: report
```

## Risk skoru nasıl hesaplanır?
Kural tabanlı ve belirleyicidir (LLM yok). Her bulgu severity'sine göre bir taban
puan alır (critical 9.5 … info 0.5). Hedef skoru "en kötü açık baskındır, ama adet
de sayar" modeliyle hesaplanır: en yüksek bulgu temel puandır, kalan bulgular azalan
ağırlıkla eklenir, tavan 10'dur.

| Skor | Not | Anlam |
|------|-----|-------|
| 0–2 | A | Temiz / düşük risk |
| 2–4 | B | Kabul edilebilir |
| 4–6.5 | C | Dikkat — planlı düzeltme |
| 6.5–8.5 | D | Riskli — kısa sürede müdahale |
| 8.5–10 | F | Kritik — acil müdahale |

------------------------------------------------------------
# 🧰 ARAÇ YÖNETİMİ
------------------------------------------------------------

### Araç durumu (kategorili, kurulu/değil):
```bash
xas> tools
```

### Eksik aracı kur (onaylı; Linux/apt):
```bash
xas> install nikto
```
Onay istenir, ardından `sudo apt install -y <paket>` çalışır. Windows'ta veya apt
paketi yoksa otomatik kurulum yerine indirme bağlantısı gösterilir.

### GUI aracı başlat (Wireshark / Burp Suite / Armitage):
```bash
xas> launch wireshark
```
GUI araçlar yalnızca başlatılır; çıktıları XAS tarafından ayrıştırılmaz.
(Ağ trafiği analizi için terminalden `tshark` adapter'ı kullanılır.)

------------------------------------------------------------
# 🔧 TEK ARAÇ ÇALIŞTIRMA
------------------------------------------------------------

```bash
xas> run nmap -sV 192.168.1.10
xas> run nmap full 192.168.1.10
xas> run zap https://hedef.com
xas> run msfconsole 192.168.1.10
```

`msfconsole` yalnızca DOĞRULAMA modunda çalışır: sabit bir dizi `auxiliary/scanner`
modülüyle (MS17-010, BlueKeep, anonim FTP, VNC no-auth) zafiyetin VAR olup olmadığını
doğrular. Exploit modülü, oturum/shell açma veya post-exploitation yapılmaz.

### Hazır rapor yükleme:
```bash
xas> load nmap scan.xml
xas> load zap zap.json
```

------------------------------------------------------------
# 🧠 AKILLI TARAMA (tek araç, otomatik seçim)
------------------------------------------------------------

```bash
xas> scan 192.168.1.10        # IP → Nmap
xas> scan https://hedef.com   # URL → ZAP
xas> scan full 192.168.1.10   # Nmap + ZAP birlikte
```

------------------------------------------------------------
# 📋 ZAFİYET YÖNETİMİ
------------------------------------------------------------

```bash
xas> list                 # tümü (severity sıralı)
xas> list sev=critical    # filtrele: critical|high|medium|low|info
xas> search sql           # anahtar kelime / CVE ara
xas> detail 3             # bulgu detayı
xas> stats                # severity + kaynak dağılımı
```

------------------------------------------------------------
# 🛡️ KAPATMA REHBERİ
------------------------------------------------------------

### Tek bulgu için:
```bash
xas> fix 3
```

### Tüm bulgular için toplu rehber (tür bazında gruplu):
```bash
xas> guide
```

Rehberi olan türler: SQL/Command Injection, XSS, CSRF, Telnet, FTP, RDP, SMB,
MySQL, MSSQL, VNC, Redis, MongoDB, SSH zayıf yapılandırma, HTTP Proxy,
Directory Listing, Erişilebilir Yönetim Paneli, SSL/TLS, CORS, Open Redirect,
Güvenlik başlıkları eksik, Zayıf parola, DNS Zone Transfer.

------------------------------------------------------------
# 📄 RAPORLAMA
------------------------------------------------------------

```bash
xas> report        # reports/report.txt + .html + .json
xas> export json
xas> export csv
```

------------------------------------------------------------
# 🧩 YENİ ARAÇ EKLEME (adapter mimarisi)
------------------------------------------------------------

1. `src/tools/adapters/<arac>.js` içinde `Adapter`'ı genişleten bir sınıf yazın
   (name, category, binary, aptPackage, mode ve `parse()`/`run()`).
2. `src/tools/registry.js` içine bir satırla kaydedin.

Çekirdek kod değişmez; `tools`, `install`, `start`, `guide` yeni aracı otomatik
tanır. `managed` araçlar çıktısı ayrıştırılıp risk skoruna katılır; `launch`
araçları yalnızca başlatılır.

------------------------------------------------------------
## LİSANS
------------------------------------------------------------

Bu proje geliştiricinin kullanımına özeldir.
