🔍 RoundcubeVulnScanner - Roundcube Webmail RCE Vulnerability Scanner 🔍  
🚀 Professional Edition | 🛠️ Pentest Tool | ⚠️ Ethical Use Only  

📌 GitHub Repo: https://github.com/ebubekirbastama/RoundcubeVulnScanner  

📜 1. GENEL BAKIŞ  
---------------  
Bu araç, Roundcube Webmail'deki kritik güvenlik açıklarını tarar:  
✔️ Uzaktan Kod Çalıştırma (RCE)  
✔️ CSV/HTML Enjeksiyonu  
✔️ Kimlik Doğrulama Atlama  

2. KURULUM
---------
🔹 Python 3.8+ gereklidir.
🔹 Bağımlılıkları yüklemek için:
🔹 pip install -r requirements.txt

---

📸 Ekran Görüntüsü

![Ana Ekran](s11.png)
![Ana Ekran](s12.png)
![Ana Ekran](s13.png)

---

3. KULLANIM
----------
Temel Kullanım:
python scanner.py -u https://webmail.hedefsite.com

Çoklu Tarama:
python scanner.py -f targets.txt -o report.json

Parametreler:
-u URL      : Tek hedef tarama
-f DOSYA    : Hedef listesi içeren dosya
-o RAPOR    : Sonuçları JSON olarak kaydetme
-t THREAD   : Thread sayısı (varsayılan: 5)
-v          : Detaylı mod

⚠️ 4. YASAL UYARI

❗ BU ARAÇ YALNIZCA:
✅ Yazılı izinli sistemlerde
✅ Etik hackleme eğitimlerinde
✅ Sorumlu açık bildirimi için kullanılabilir

🚨 İzinsiz kullanım TCK 243. madde ve GDPR'a göre suçtur!

5. ÖRNEK ÇIKTI
--------------
[+] https://webmail.hedefsite.com:443 - VULNERABLE (CVE-2020-35730)<br>
[-] https://webmail2.hedefsite.com:443 - Secure

----------
Geliştirici: Ebubekir Baştar
GitHub: github.com/ebubekirbastama
