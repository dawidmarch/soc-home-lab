# Case Study: Wykrywanie RCE (Remote Code Execution) poprzez XAMPP

## 1. Cel projektu
Celem projektu jest symulacja ataku typu Remote Code Execution na serwerze XAMPP zainstalowanym na systemie Windows 10. Projekt ma na celu zweryfikowanie skuteczności monitorowania procesów potomnych serwera WWW (Apache) za pomocą Sysmon i ich analizę w systemie Wazuh.

## 2. MITRE ATT&CK Mapowanie

| Takt | ID Techniki | Nazwa Techniki | Opis |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1190 | Exploit Public-Facing Application | Wykorzystanie luki w aplikacji webowej (upload shella). |
| **Execution** | T1059.003 | Command and Scripting Interpreter | Wykonanie komend systemowych przez proces `cmd.exe`. |
| **Persistence** | T1505.003 | Server Software Component: Web Shell | Utrzymanie dostępu poprzez wgrany skrypt `.php`. |

## 3. Metodologia ataku

### Faza 1: Rozpoznanie (Kali Linux)
Identyfikacja usług działających na maszynie ofiary.
* **Komenda:** `nmap -sV 10.0.2.4`
* **Cel:** Potwierdzenie dostępności portu 80 (HTTP).

  <img width="713" height="571" alt="nmap" src="https://github.com/user-attachments/assets/0035aef3-b104-436c-b6c9-ba67cf9f7fc2" />

### Faza 2: Przygotowanie payloadu
Stworzenie web-shella umożliwiającego zdalne wykonywanie komend.
* **Komenda:** `echo '<?php system($_GET["cmd"]); ?>' > shell.php`
* **Cel:** Wstrzyknięcie kodu PHP do katalogu `C:\xampp\htdocs\`.

  <img width="815" height="705" alt="shell" src="https://github.com/user-attachments/assets/efc1ee59-14d0-4512-9693-69af909aede0" />

### Faza 3: Eksploatacja
Uruchomienie komendy systemowej przez HTTP.
* **Akcja:** Wywołanie w przeglądarce: `http://10.0.2.4/shell.php?cmd=whoami`
* **Cel:** Potwierdzenie RCE i eskalacja wykonania kodu do poziomu procesu systemowego.

  <img width="718" height="293" alt="curl" src="https://github.com/user-attachments/assets/e0b2b8cc-da72-45a8-be5f-e56c79d19ae0" />

## 4. Analiza logów 
Po ataku, system Wazuh rejestruje zdarzenie utworzenia procesu (Sysmon Event ID 1). W analizie JSON należy skupić się na polach:

* **`win.eventdata.image`**: `C:\Windows\System32\cmd.exe`.
* **`win.eventdata.commandLine`**: Pole zawierające wykonaną komendę (np. `cmd /c whoami`).

  <img width="1515" height="857" alt="wazuh" src="https://github.com/user-attachments/assets/82353f50-7546-455b-b053-bbec7bddd1b3" />

**Wniosek:** Każde zdarzenie, w którym Apache uruchamia proces `cmd.exe` lub `powershell.exe`, jest uznawane za wysokie ryzyko naruszenia bezpieczeństwa.

## 5. Wnioski techniczne 
Z perspektywy analityka, kluczową obserwacją jest **łańcuch procesów (Parent-Child process lineage)**. 
* Serwer Apache działa jako usługa systemowa. Jeśli proces potomny wykazuje cechy interaktywnego shella, mamy do czynienia z naruszeniem integralności aplikacji.
* **Zagrożenie:** Jeśli nie wykryjemy `cmd.exe` na wczesnym etapie, atakujący może przejść do fazy eskalacji uprawnień lub pobrania dodatkowego malware.
* **Detekcja:** Monitoring samego pliku `shell.php` jest niewystarczający; skuteczna detekcja opiera się na analizie zachowania procesów potomnych.

## 6. Rekomendacja (Reguła detekcji w XML)
Poniższa reguła dla Wazuh Manager wykrywa nieautoryzowane wywołanie interpretera poleceń przez proces Apache.

```xml
<group name="sysmon, webshell,">
  <rule id="100001" level="12">
    <if_sid>61603</if_sid> <field name="win.eventdata.parentImage">.*httpd\.exe</field>
    <field name="win.eventdata.image">.*(cmd\.exe|powershell\.exe)</field>
    <description>Wazuh Alert: Web Server spawning shell - Potential RCE detected</description>
    <mitre>
      <id>T1059.003</id>
      <id>T1505.003</id>
    </mitre>
  </rule>
</group>
