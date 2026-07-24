# Case Study: Analiza wycieku poświadczeń w niezaszyfrowanym ruchu sieciowym 

## 1. Cel mojego projektu
Celem mojego projektu było przeprowadzenie symulacji ataku typu **Credential Sniffing** w izolowanym środowisku laboratoryjnym (Oracle VirtualBox). Eksperyment miał na celu zademonstrowanie przeze mnie podatności przestarzałych protokołów sieciowych (FTP) na podsłuch oraz praktyczne wykorzystanie przeze mnie narzędzi `tcpdump` oraz `Wireshark` do analizy ruchu sieciowego i ekstrakcji danych przesyłanych w otwartym tekście.

## 2. MITRE ATT&CK Mapowanie

| Tactic | Technique | ID | Opis |
| :--- | :--- | :--- | :--- |
| **Credential Access** | Unsecured Credentials | T1552.001 | Przechwytywanie poświadczeń przesyłanych w otwartym tekście. |
| **Discovery** | Network Sniffing | T1040 | Monitorowanie ruchu sieciowego w celu pozyskania informacji. |

*Wyjaśnienie:* Wykorzystałem brak szyfrowania w protokole FTP, co pozwoliło mi na przechwycenie (sniffing) pakietów w sieci lokalnej i ekstrakcję poświadczeń.

## 3. Metodologia mojego ataku

### Faza A: Przygotowanie środowiska (Kali Linux - Atakujący)
Na mojej maszynie atakującego uruchomiłem serwer FTP oraz zainicjowałem przechwytywanie ruchu sieciowego.

**Komendy, których użyłem:**
```bash
# Instalacja i uruchomienie usługi FTP
sudo apt install vsftpd -y
sudo systemctl start vsftpd

# Przechwytywanie ruchu na porcie 21 do pliku .pcap
sudo tcpdump -i eth0 port 21 -w capture.pcap
```
<img width="715" height="483" alt="kali" src="https://github.com/user-attachments/assets/6dceb8f7-c8cb-42a1-b6df-af3bc3ef63b7" />

### Faza B: Generowanie ruchu (Windows 10 - Ofiara)
Z poziomu drugiego systemu (Windows 10) zainicjowałem sesję FTP, generując ruch sieciowy zawierający poświadczenia.

**Procedura, którą wykonałem:**
1. Otworzyłem CMD (jako Administrator).
2. Nawiązałem połączenie z moim serwerem atakującego:
```cmd
ftp 10.0.2.5
```
<img width="630" height="540" alt="cmd" src="https://github.com/user-attachments/assets/04a20a11-b244-4007-b957-ff2bd5a620cd" />

3. Wprowadziłem poświadczenia (w celach symulacji):
   - User: anonymous
   - Password: password

## 4. Moja analiza ruchu sieciowego (Wireshark)
Po przechwyceniu ruchu, poddałem plik `capture.pcap` analizie za pomocą narzędzia Wireshark.

<img width="1889" height="887" alt="tpc" src="https://github.com/user-attachments/assets/61d159fb-3f8d-41bb-8445-3146cb4146db" />

**Mój proces badawczy:**
- **Otwarcie pliku:** Otworzyłem plik `capture.pcap` i zastosowałem filtr `ftp`.
- **Analiza strumienia:** Użyłem funkcji *Follow -> TCP Stream*, która pozwoliła mi na rekonstrukcję pełnej sesji komunikacyjnej między klientem (Windows) a serwerem (Kali).
- **Wynik:** W warstwie aplikacji protokołu FTP zidentyfikowałem pakiety typu `USER` oraz `PASS`, w których poświadczenia były dla mnie widoczne w postaci czystego tekstu (cleartext). Potwierdziło to skuteczność przeprowadzonego przeze mnie pasywnego podsłuchu.
- 
## 5. Wnioski techniczne 
- **Krytyczność:** Podczas moich testów potwierdziłem, że wykorzystanie protokołów typu "legacy" (FTP, Telnet) stanowi poważne zagrożenie. Brak szyfrowania w warstwie transportowej (TLS/SSL) sprawia, że każda próba uwierzytelnienia może zostać przechwycona przez stronę trzecią z dostępem do medium transmisyjnego.
- **Widoczność:** Ruch sieciowy w segmencie lokalnym (L2/L3) jest kluczowym elementem analizy śledczej. W przypadku braku logów EDR/SIEM, przeprowadzona przeze mnie analiza pliku PCAP okazała się jedynym wiarygodnym źródłem prawdy o działaniach w sieci.

## 6. Rekomendacje 
Na podstawie wyników mojego eksperymentu, w celu mitygacji ryzyka przechwycenia poświadczeń, zalecam:
1. **Całkowite wycofanie (Deprecation) protokołu FTP:** Zablokowanie ruchu na porcie 21 na poziomie zapór ogniowych (Firewall/ACL).
2. **Migracja do bezpiecznych protokołów:** Wdrożenie SFTP lub FTPS, które zapewniają szyfrowanie danych w tranzycie.
3. **Wdrożenie Network Monitoring:** W środowiskach produkcyjnych zalecam wdrożenie systemów IDS/IPS, które automatycznie wykrywają użycie niezaszyfrowanych protokołów w sieciach korporacyjnych.
