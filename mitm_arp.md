# Case Study: Analiza ataku Man-in-the-Middle (ARP Spoofing)

## 1. Cel projektu
Celem projektu było przeprowadzenie kontrolowanego ataku typu Man-in-the-Middle (MITM) z wykorzystaniem protokołu ARP, aby zademonstrować podatność sieci lokalnych na przechwytywanie ruchu sieciowego. Badanie skupiło się na weryfikacji możliwości podsłuchu ruchu w formacie niezaszyfrowanym (HTTP) przy użyciu narzędzia Wireshark.

## 2. MITRE ATT&CK Mapowanie

| ID Techniki | Nazwa Techniki | Taktka (Tactic) |
| :--- | :--- | :--- |
| **T1557.002** | Adversary-in-the-Middle: ARP Spoofing | Credential Access |
| **T1040** | Network Sniffing | Discovery |

* **Wyjaśnienie:** Atakujący wykorzystał zatrucie tablic ARP, aby przekierować ruch między ofiarą a bramą sieciową przez system Kali Linux. Następnie użyto sniffera (Wireshark) do ekstrakcji danych z ruchu HTTP.

## 3. Metodologia ataku

### Kroki operacyjne:
1.  **Inicjacja ataku:** Na maszynie Kali Linux uruchomiono narzędzie `arpspoof`, aby zatruć tablice ARP ofiary, wymuszając przesyłanie ruchu przez interfejs `eth0` atakującego.

    ```bash
    sudo arpspoof -i eth0 -t 10.0.2.4 10.0.2.1
    ```
  <img width="687" height="457" alt="kali" src="https://github.com/user-attachments/assets/3f74dbbc-6614-429b-901d-25261d99e71e" />

2.  **Monitorowanie ruchu:** W narzędziu Wireshark przefiltrowano ruch ARP, aby potwierdzić skuteczność zatruwania (widoczne masowe pakiety ARP Reply wysyłane do ofiary).

<img width="1121" height="833" alt="wireshark" src="https://github.com/user-attachments/assets/6abc87a3-f3cd-44e0-bc37-367633309f29" />

3.  **Analiza danych:** Wyszukano żądania HTTP, korzystając z filtra `http.request.method==GET`, aby wyizolować ruch aplikacyjny.

 <img width="1011" height="831" alt="wireshark 1" src="https://github.com/user-attachments/assets/88b958be-ea95-4b34-8143-fe7c769e31c4" />

## 4. Analiza danych (PCAP Analysis)

Po przechwyceniu ruchu, dokonano analizy strumienia TCP (`Follow HTTP Stream`). 

* **Obserwacje:** W strumieniu HTTP udało się odczytać nagłówki żądania w formie *cleartext* (niezaszyfrowanej).
* **Kluczowe znaleziska:**
    * `Host`: innershinybrightspell.neverssl.com
    * `User-Agent`: Widoczna wersja przeglądarki (Chrome/Edge).
    * `Referer`: informacja o źródle żądania.
* Widać wyraźnie, że protokół HTTP nie zapewnia poufności danych, co pozwala atakującemu na pełny wgląd w treść komunikacji między klientem a serwerem.

   <img width="1029" height="825" alt="wireshark 2" src="https://github.com/user-attachments/assets/8d34858b-0246-4c88-86c6-4b1eb46e48a8" />

## 5. Wnioski techniczne

1.  **Brak autentykacji ARP:** Protokół ARP nie posiada wbudowanych mechanizmów weryfikacji nadawcy, co sprawia, że jest podatny na manipulację w sieciach lokalnych.
2.  **Podatność na sniffery:** Wdrożenie techniki MITM pozwala na pełną pasywną analizę ruchu, jeśli protokoły warstwy aplikacji (HTTP) nie wspierają szyfrowania (TLS/SSL).
3.  **Skuteczność filtrów Wireshark:** Zastosowanie filtra `http.request.method==GET` pozwoliło na błyskawiczne wyodrębnienie interesujących danych z szumu sieciowego (tysięcy pakietów ARP).

## 6. Rekomendacja

* **Wdrożenie HTTPS:** Wymuszenie protokołu TLS dla wszystkich usług webowych. Nawet w przypadku udanego ataku MITM, napastnik przechwyci jedynie zaszyfrowany ciąg znaków, uniemożliwiając odczytanie treści (np. haseł czy ciasteczek sesyjnych).
* **Dynamic ARP Inspection (DAI):** W środowiskach klasy enterprise, należy skonfigurować switchy, aby odrzucały nieautoryzowane pakiety ARP (tzw. "ARP Spoofing protection").
* **Wdrożenie IDS/IPS:** Wykorzystanie systemów wykrywania intruzów, które monitorują anomalie w tablicach ARP i automatycznie blokują porty, na których wykryto podejrzany ruch ARP Reply bez zapytania.
