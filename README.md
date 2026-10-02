# Nour Khalil Rash

Cybersikkerhetsstudent på siste året ved Høyskolen Kristiania, med en fullført bachelor i sosiologi og samfunnsanalyse fra før. Jeg arbeider mest med identitet og endepunktsikkerhet i Microsoft 365, og med triage av malware.

Metodefagene fra sosiologien gikk mye ut på å skrive ned fremgangsmåten og ikke bare resultatet, og det er slik jeg har dokumentert prosjektene under. Dokumentasjonen er på engelsk.

## Sertifiseringer

<a href="https://www.credly.com/badges/eb42508d-12f5-462f-9731-c69423676f31/public_url"><img src="https://images.credly.com/images/80d8a06a-c384-42bf-ad36-db81bce5adce/blob" width="110" alt="CompTIA Security+"></a> <a href="https://www.credly.com/badges/4956e62b-3c30-4fac-a988-42f292c06a1a/public_url"><img src="https://images.credly.com/images/242902b5-f527-42ad-865e-977c9e1b5b58/image.png" width="110" alt="Cisco Ethical Hacker"></a> <a href="https://www.credly.com/badges/cc59b6e4-f25e-47f9-85a6-4ca5625aa939/public_url"><img src="https://images.credly.com/images/5bdd6a39-3e03-4444-9510-ecff80c9ce79/image.png" width="110" alt="Cisco Networking Basics"></a>

CompTIA Security+ (SY0-701), bestått september 2026. Cisco Ethical Hacker og Cisco Networking Basics, 2024.

## Prosjekter

**[nordvik-lab](https://github.com/NourKhalil0/nordvik-lab)** — En Microsoft 365-tenant bygget og drevet for et oppdiktet norsk verkstedfirma med 56 ansatte. 57 kontoer, dynamiske grupper, lisensiering gjennom gruppemedlemskap, syv Conditional Access-policyer i report-only, en Windows-klient meldt inn i Intune og målt mot ni compliance-krav, og PIM på administratorrollen. Konfigurasjonen er eksportert til JSON, og hvert steg er dokumentert med skjermbilder mens det ble gjort. Underveis fant jeg at tenanten kom med fire påslåtte Microsoft-policyer som ikke kjente til nødkontoene mine, at Intune markerer enheter uten compliance-policy som grønne, og at en av nødkontoene lå i riktig gruppe uten å ha fått rollen. Alle tre står beskrevet i README.

**[r77-triage](https://github.com/NourKhalil0/r77-triage)** — Full triage av et r77-rootkit-sample, fra herding av analyselaben til statisk og dynamisk analyse. Prosesskjede, injeksjonsmetode, den innebygde krypterte nyttelasten, og full IOC-liste. Loaderen krasjet i laben min før den rakk å pakke ut noe, så familiebekreftelsen bygger på kodelesing og oppstartsanalyse i stedet for en fullført infeksjon. Det forbeholdet står tydelig gjennom hele rapporten.

**[xworm-triage](https://github.com/NourKhalil0/xworm-triage)** — Triage av en XWorm-loader: stadier, prosessinjeksjon, persistens gjennom planlagt oppgave, og C2-trafikk. Sekvensene er tegnet opp som diagrammer, og indikatorene ligger som CSV og blokkeringsliste klare til bruk.

**[pfsense-vlan-lab](https://github.com/NourKhalil0/pfsense-vlan-lab)** — Hjemmenett-lab med pfSense og VLAN-segmentering bygget i et virtualisert labmiljø. Tre adskilte soner (TRUSTED, IOT og GUEST) med brannmurregler for inter-VLAN-ruting, DHCP-oppsett og isolering av upålitelige enheter. Oppsettet er testet og verifisert fra en Kali-klient ved hjelp av nmap, curl og Wireshark-pakkefangst, og inkluderer detaljert dokumentasjon av praktisk feilsøking (som regler som ikke trådte i kraft før aktivering, og DHCP-oppførsel på virtuelle subgrensesnitt).

Profilen inneholder også studiearbeid innen deteksjonsregler i Sigma, KQL og SPL mappet til MITRE ATT&CK, samt en Wazuh-basert deteksjonslab.

## Utdanning

**Bachelor i cybersikkerhet, Høyskolen Kristiania (2024–2027)**
Siste studieår. Sikkerhetsanalyse, etisk hacking, nettverk, kryptografi og sårbarhetsvurdering.

**Bachelor i sosiologi og samfunnsanalyse, Nord universitet (2020–2023)**
Kvalitativ og kvantitativ metode, samfunnsanalyse og organisasjonsteori.

## Arbeidserfaring

**Miljøterapeut, barnevernet (2024–2026)**
Arbeid med ungdom i institusjon, med ansvar for sensitiv dokumentasjon og sporbarhet i saksbehandlingen. Rolig kommunikasjon med stressede parter, også de uten fagbakgrunn.

**Salgsmedarbeider, SATS (2023–2026)**
Salg av medlemskap på senter og stand, med flere lokale salgskonkurranser vunnet.

**Stasjonsbetjent, Circle K (2020–2023)**
Skiftdrift på to stasjoner, med ansvar for stenging, rutiner og opplæring av nyansatte.

## Teknologi

**Microsoft 365 og identitet:** Entra ID, Conditional Access, Intune, PIM, Microsoft Graph, PowerShell
**Deteksjon og analyse:** Sigma, KQL, Wazuh, MITRE ATT&CK, Procmon, dnSpy, FLOSS, Wireshark
**Nettverk og drift:** pfSense, VLAN, WireGuard, Linux, VMware, Git
**Programmering:** Python
**Språk:** Norsk, engelsk, arabisk
