# Nour Khalil Rash

Cybersikkerhetsstudent på siste året ved Høyskolen Kristiania, med en fullført bachelor i sosiologi og samfunnsanalyse fra før. Jeg arbeider mest med identitet og endepunktsikkerhet i Microsoft 365, og med triage av malware.

Sosiologibakgrunnen forklarer hvorfor repoene mine ser ut som de gjør. Metodefagene handlet om å dokumentere hvordan man kom frem til en konklusjon, ikke bare hva konklusjonen ble. Prosjektene under er skrevet slik at en leser kan følge hvert steg, også de stedene der noe gikk galt eller ikke lot seg bevise. Dokumentasjonen er på engelsk.

## Prosjekter

**[nordvik-lab](https://github.com/NourKhalil0/nordvik-lab)** — En Microsoft 365-tenant bygget og drevet for et oppdiktet norsk verkstedfirma med 56 ansatte. 57 kontoer, dynamiske grupper, lisensiering gjennom gruppemedlemskap, syv Conditional Access-policyer i report-only, en Windows-klient meldt inn i Intune og målt mot ni compliance-krav, og PIM på administratorrollen. Konfigurasjonen er eksportert til JSON, og hvert steg er dokumentert med skjermbilder mens det ble gjort. Underveis fant jeg at tenanten kom med fire påslåtte Microsoft-policyer som ikke kjente til nødkontoene mine, at Intune markerer enheter uten compliance-policy som grønne, og at en av nødkontoene lå i riktig gruppe uten å ha fått rollen. Alle tre står beskrevet i README.

**[r77-triage](https://github.com/NourKhalil0/r77-triage)** — Full triage av et r77-rootkit-sample, fra herding av analyselaben til statisk og dynamisk analyse. Prosesskjede, injeksjonsmetode, den innebygde krypterte nyttelasten, og full IOC-liste. Loaderen krasjet i laben min før den rakk å pakke ut noe, så familiebekreftelsen bygger på kodelesing og oppstartsanalyse i stedet for en fullført infeksjon. Det forbeholdet står tydelig gjennom hele rapporten.

**[xworm-triage](https://github.com/NourKhalil0/xworm-triage)** — Triage av en XWorm-loader: stadier, prosessinjeksjon, persistens gjennom planlagt oppgave, og C2-trafikk. Sekvensene er tegnet opp som diagrammer, og indikatorene ligger som CSV og blokkeringsliste klare til bruk.

Profilen inneholder også eldre studiearbeid: deteksjonsregler i Sigma, KQL og SPL mappet til MITRE ATT&CK, en Wazuh-basert hjemmelab, og en hjemmenett-lab med pfSense, VLAN-segmentering og WireGuard.

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
