# Case Study: Credential Dumping Detection

## 1. Cel projektu
Celem projektu było przeprowadzenie symulowanego ataku typu "credential dumping" na proces `lsass.exe` oraz implementacja mechanizmu detekcji w środowisku Wazuh SIEM z wykorzystaniem telemetrii Sysmon. Projekt demonstruje pełen cykl życia incydentu: od eksploatacji po wykrywanie i analizę w centrum SOC.

## 2. MITRE ATT&CK Mapowanie

| Taktyka | Technika | ID | Opis |
| :--- | :--- | :--- | :--- |
| Credential Access | OS Credential Dumping | T1003.001 | Uzyskanie dostępu do pamięci LSASS w celu ekstrakcji poświadczeń. |

*   **T1003.001:** Uzyskanie dostępu do pamięci procesu `lsass.exe` w celu ekstrakcji poświadczeń.

## 3. Metodologia ataku

### Lateral Movement (PsExec)
Atak rozpoczęto od nawiązania zdalnej sesji z wykorzystaniem `impacket-psexec`. Narzędzie to wykorzystuje protokół SMB do wgrania usługi serwisowej, co pozwoliło na uzyskanie powłoki z uprawnieniami `SYSTEM`.
* **Komenda:**
  ```bash
   impacket-psexec './Administrator:Haslo123!@10.0.2.4' 
 
* **Cel:** Utworzenie katalogu roboczego dla plików narzędziowych.
  
<img width="749" height="455" alt="kali" src="https://github.com/user-attachments/assets/f7ae3f03-d750-46c2-935c-1f50dbfcfb7a" />

<img width="743" height="781" alt="mimikatz" src="https://github.com/user-attachments/assets/d0d917bc-f306-4081-aed4-5a3f3bb8d8b8" />

### Credential Dumping
Po uzyskaniu uprawnień `SYSTEM`, wykonano polecenie `sekurlsa::logonpasswords` w procesie `mimikatz.exe`. Proces ten otworzył uchwyt (handle) do `lsass.exe` w celu odczytu pamięci zawierającej hashe NTLM oraz bilety Kerberos.

## 4. Analiza logów 
Monitorowanie procesów przez Sysmon (Event ID 10) pozwoliło na rejestrację krytycznego zdarzenia.

<img width="1499" height="841" alt="mimikatzexe" src="https://github.com/user-attachments/assets/aefc0682-df76-4f6d-afb9-d149f078b65c" />

**Kluczowe artefakty w JSON:**

```json
{
  "event_id": 10,
  "win.eventdata.targetImage": "C:\\Windows\\system32\\lsass.exe",
  "win.eventdata.sourceImage": "C:\\Temp\\x64\\mimikatz.exe",
  "win.eventdata.grantedAccess": "0x1010"
}
```

## 5. Wnioski techniczne
* Proces `lsass.exe` jest krytycznym elementem bezpieczeństwa systemu Windows, przechowującym poświadczenia użytkowników. Dostęp do jego pamięci przez procesy nieuprawnione (jak `mimikatz.exe`) jest zachowaniem wysoce anomalnym.

* Zidentyfikowana wartość `GrantedAccess: 0x1010` jednoznacznie wskazuje na próbę odczytu pamięci `(PROCESS_VM_READ)`. W środowisku produkcyjnym takie zachowanie jest niemal zawsze wskaźnikiem (IOC) aktywności napastnika (post-exploitation). Warto zauważyć, że Sysmon pozwolił na precyzyjne wskazanie źródłowego pliku wykonywalnego `(sourceImage)`, co drastycznie skraca czas reakcji (MTTR) zespołu SOC.

## 6. Rekomendacja (Reguła detekcji)
W celu zautomatyzowania detekcji wdrożono regułę w pliku `local_rules.xml` serwera Wazuh. Reguła ta alarmuje, gdy dowolny proces prosi o dostęp do pamięci LSASS z wysokimi uprawnieniami.

```XML
<group name="windows,sysmon,credential_dumping,">
  <rule id="100005" level="12">
    <if_sid>61610</if_sid> 
    <field name="win.eventdata.targetImage">C:\\Windows\\system32\\lsass.exe</field>
    <field name="win.eventdata.grantedAccess">0x1010</field>
    <description>ALARM: Podejrzany dostęp do pamięci LSASS (Credential Dumping)</description>
    <mitre>
      <id>T1003.001</id>
    </mitre>
  </rule>
</group>
