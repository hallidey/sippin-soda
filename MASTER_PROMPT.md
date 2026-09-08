# Sippin Soda — Master Product & Engineering Specification

Specifica unificata basata su «Product Identity & Desktop Application Specification» e sulle integrazioni funzionali fornite nella conversazione. È la baseline di prodotto: non implica che le funzionalità siano già implementate. La roadmap seguente è una proposta di sequenziamento, non la ricostruzione di una roadmap precedente non disponibile.

## 1. Product Vision

> **Sippin Soda is not an API client with a proxy attached. It is a programmable development network layer that sits between an application and the services it communicates with.**

Sippin Soda è un'applicazione desktop open source, local-first, per osservare, intercettare, modificare, riprodurre, simulare e instradare il traffico delle applicazioni. Serve sviluppatori frontend, backend e full stack, QA e team che devono riprodurre problemi di integrazione senza dipendere dalla disponibilità di tutti i servizi.

Il caso strategico è lo sviluppo ibrido: la stessa applicazione può usare users su DEV, orders su TEST, recommendations su LOCAL e payments su MOCK. Il traffico e le decisioni del motore devono essere comprensibili e riproducibili.

- Nome ufficiale in codice, UI, documentazione e distribuzione: **Sippin Soda**. Sostituire eventuali riferimenti al precedente nome OpenScope.
- Posizionamento: **The programmable network layer for local development.**
- Tagline: **Sip into your app's traffic.**
- Descrizione funzionale: **Observe. Intercept. Modify. Mock. Replay.**
- Piattaforme: Windows, macOS e Linux; interfaccia primaria desktop installabile.
- Utilizzo normale senza account, dashboard ospitata, database cloud o sincronizzazione obbligatoria.
- Interfaccia, motore, persistenza, mock e configurazione devono funzionare offline. Le richieste verso servizi remoti richiedono naturalmente connettività.
- Nessun sito marketing o prodotto SaaS nello scope iniziale. Eventuali funzioni team devono basarsi prima di tutto su file condivisibili via Git.

I riferimenti concettuali sono Proxyman, Charles, Requestly, Postman, Bruno, Swagger/OpenAPI, WireMock e DevTools. Il prodotto deve avere una propria identità e un workflow coerente, senza diventare una copia di uno di essi.

## 2. Complete Feature Specification

### F01 — Osservazione e traffic inspector

Intercettare HTTP e HTTPS per i client configurati per attraversare il proxy; non promettere cattura universale del traffico di sistema. Mostrare request, response, metodo, URL, host, path, query, headers, cookies, body, status, timing, dimensioni, timestamp, ambiente e destinazione effettiva.

La lista deve supportare ricerca, filtri, ordinamento, pausa della registrazione e selezione rapida. Distinguere pausa della cattura, arresto del proxy e breakpoint: sono operazioni diverse. Mostrare errori di rete/TLS, cancellazioni e payload incompleti senza inventare una response.

Nel dettaglio fornire JSON con syntax highlighting, espansione/compressione, ricerca, copia e modalità raw/formattata; gestire anche testo, form e payload binari con anteprima limitata e metadati. Mostrare l'origine della risposta: upstream, mock, regola o intervento manuale.

### F02 — Intercettazione e modifica

Breakpoint prima dell'invio upstream e prima della consegna della response. Il developer può sospendere, modificare, continuare, bloccare o rispondere con un mock. Rendere modificabili URL, metodo, query, headers, cookies, request body, response body e status code.

Filtrare i breakpoint per host/path/metodo e condizioni. Gestire più richieste sospese con timeout, cancellazione e comportamento esplicito alla chiusura della UI. Conservare la distinzione originale/modificato per ispezione e diff, soggetta alla policy di redazione. Ricalcolare correttamente lunghezze e framing dopo le modifiche.

### F03 — Replay singolo e di sessione

Replay, Edit & Replay, duplicazione e replay su un ambiente diverso. Ogni esecuzione deve indicare origine, destinazione risolta e rapporto con la cattura iniziale.

Il replay di sessione deve offrire selezione delle richieste, ordine, temporizzazione originale o accelerata, concorrenza limitata, stop/cancel e resoconto per chiamata. Prevedere variabili per correlare identificativi e token generati durante il flusso. Segnalare dipendenze mancanti; non promettere riproduzione fedele di un sistema remoto il cui stato è cambiato.

Non reinviare silenziosamente credenziali a un nuovo host. Applicare Production Safety Mode anche a replay multipli, CLI e sessioni importate.

### F04 — Rule engine e conditional rules

Regole dichiarative con ID, nome, abilitazione, priorità, fase request/response, condizioni e azioni. Condizioni su ambiente, servizio, host, path, metodo, query, headers, status e contenuto del body, inclusi selettori JSON.

Supportare gruppi AND/OR/NOT, contatori e frequenze: «ogni terza chiamata → 500», «solo se il body contiene X», «solo per questo servizio in DEV». Definire scope e reset dei contatori, anche sotto concorrenza.

Azioni: modifica, delay, fault, mock, blocco e routing nelle fasi appropriate. Ordine deterministico, gestione dei conflitti, azioni terminali e protezione dai loop. Ogni richiesta mostra regole valutate/applicate e motivazione della decisione. Una preview deve spiegare gli effetti prima dell'attivazione quando possibile.

### F05 — Simulazione e Chaos Mode

Simulare 400, 401, 403, 404, 409, 422, 429, 500, 502, 503 e 504; latenza fissa o casuale, timeout, interruzione connessione, risposta malformata, JSON invalido, body troncato e altri errori configurabili.

Chaos Mode aggiunge probabilità/percentuali, distribuzioni, seed riproducibile, durata, scope e arresto immediato. Esempio: 20% di 500, 10% di timeout e latenza casuale fra limiti configurati. Specificare se gli eventi sono esclusivi o combinabili e registrare il fault applicato.

Il requisito packet/drop deve distinguere il drop della connessione o dei dati simulato a livello applicativo dalla perdita reale di pacchetti: quest'ultima richiede un'integrazione di rete dedicata e resta un'estensione futura, senza dichiarare che il proxy HTTP la realizzi da solo.

### F06 — Mock server, Record → Mock e mock condizionali

Mock server locale utilizzabile con o senza UI; creazione di endpoint con metodo/path, status, headers, body, latenza e varianti. Importazione OpenAPI con scelta di operation, example e response; gli esempi generati devono essere modificabili.

Record → Mock converte una cattura o una selezione di sessione in definizioni mock dopo redazione e revisione. I conditional mocks selezionano risposte da query, headers, body, ambiente e condizioni condivise con il rule engine.

Definire precedenze, matching, comportamento quando manca una corrispondenza e fallback espliciti. Nessun fallback implicito verso PROD.

Stateful mocks futuri: stati, transizioni, contatori, sequenze di response, reset, isolamento fra sessioni e comportamento concorrente. Esempio: creare un ordine e poi recuperarne lo stato simulato.

### F07 — Hybrid routing, reverse proxy e CORS

Routing verso LOCAL, DEV, TEST, STAGING, MOCK e opzionalmente PRODUCTION per servizio, host, path, metodo e condizioni. Risoluzione deterministica con priorità, riscrittura di path/query, mapping delle porte e indicazione della destinazione effettiva per ogni chiamata.

Supportare reverse proxy e override CORS per sviluppo, inclusi preflight. Gli override devono essere limitati allo scope configurato. Definire trattamento di Host, SNI, redirect, cookies, headers forwarded e credenziali quando cambia destinazione. Rilevare route cicliche e rendere esplicito il comportamento per upstream non raggiungibile.

### F08 — Ambienti e autenticazione

Ambienti con base URL per servizio, variabili, headers, profili auth e riferimenti a segreti locali. Rendere visibili ambiente selezionato e ambiente effettivo della singola route, anche nelle configurazioni ibride.

API key, Basic, Bearer, cookie/session auth e flussi OAuth 2.0 con gestione di scadenza/refresh e token esclusi dai file Git. JWT inspector per header, claims, scadenza e verifica quando sono disponibili chiavi e parametri adeguati; distinguere chiaramente decodifica da verifica della firma.

Prevedere supporto progressivo a mTLS, DPoP e AWS SigV4: modificare metodo, URL o body può invalidare firme/proof e richiedere una nuova firma esplicitamente configurata. Chiavi e certificati devono restare in storage locale protetto.

Certificate pinning: diagnostica e documentazione dei limiti; offrire pass-through o configurazione del client di sviluppo quando possibile. Non promettere un aggiramento universale del pinning.

### F09 — Diff avanzato

Confrontare request e response fra catture, replay, originale/modificato, DEV/LOCAL e DEV/TEST. Vista testuale e strutturata JSON per aggiunte, rimozioni, valori e tipi; confronto anche di status, headers, cookies, tempi e dimensioni.

Permettere esclusione esplicita di campi volatili e normalizzazioni visibili. La comparazione può usare catture esistenti o esecuzioni autorizzate; non duplicare automaticamente richieste con effetti collaterali per ottenere un diff.

### F10 — OpenAPI contracts, discovery e CI

Importare contratti e validare request/response: operation, parametri richiesti, content type, status, campi mancanti, tipi errati, enum, vincoli, oggetti annidati e campi extra secondo la policy dello schema. Distinguere campi extra consentiti da violazioni effettive.

Mostrare posizione del problema, valore atteso/rilevato e riferimento al contratto. Dichiarare versioni OpenAPI e costrutti effettivamente supportati; segnalare ciò che non è validabile.

Discovery dal traffico reale: aggregare esempi, proporre path parametrizzati e schemi, indicare copertura e incertezza, consentire revisione ed export OpenAPI. Uno schema inferito non è un contratto autorevole e non deve sostituire silenziosamente quello importato.

CI integration tramite CLI headless per contract checking, report leggibili e machine-readable, exit code documentati e policy configurabile per fallire la pipeline. Supportare validazione di fixture/sessioni offline oltre alle esecuzioni esplicitamente configurate.

### F11 — Sessioni, portabilità e sensitive-data redaction

Salvare sessioni con nomi, note e metadati utili alla riproduzione. Import/export versionato per trasferire un bug al PC di un collega, con manifest, catture selezionate e riferimenti/configurazioni necessari. Segnalare dipendenze, segreti e payload esclusi.

Redazione prima della persistenza e prima dell'export: Authorization, cookies, API key e campi sensibili in URL/query, headers e body; regole personalizzabili per pattern e percorsi JSON. Offrire rimozione, mascheramento e pseudonimi coerenti quando servono correlazioni. Anteprima di ciò che sarà esportato, con gestione esplicita dei formati non ispezionabili.

Separare il traffico necessario all'inoltro dalla rappresentazione persistita redatta. Originale/modificato, log, indici, file temporanei e crash report non devono aggirare la policy. Un archivio importato non esegue regole, script o replay automaticamente; validare formato, dimensioni e percorsi.

Retention per età, spazio e numero di sessioni, quote dei payload, cleanup e protezione delle sessioni marcate da conservare. Mostrare spazio usato, troncamenti ed eventuali catture scartate.

### F12 — API Client, collections e azioni contestuali

API Client integrato per comporre ed eseguire richieste senza catturarle prima: tab/editor, metodo/URL, query, headers, auth, cookies, body JSON/testo/form/multipart/file, variabili e ambienti, timeout/cancel, history e visualizzazione response.

Collections con cartelle, richieste salvate, documentazione, variabili, profili auth, esecuzione di sequenze e assertion. Prevedere hook/script di pre-request e test isolati con accessi e limiti espliciti; non eseguire codice importato automaticamente. Documentare la compatibilità dei formati import/export senza promettere parità totale con Postman o Bruno.

Da una richiesta catturata offrire: Replay, Edit & Replay, Create Mock, Create Rule, Add Collection, Generate Test e Copy as cURL/fetch/axios. Le esportazioni di codice devono gestire escaping, payload e redazione delle credenziali.

Generate Test crea assertion modificabili per status, headers, schema e campi selezionati; mostrare anteprima e target supportati. I test generati devono essere utili e riproducibili, senza cristallizzare timestamp o identificativi casuali come valori obbligatori.

### F13 — Scenarios

Uno scenario raggruppa regole, mock, route, fault e variabili per un caso riproducibile: payment outage, auth expired, slow backend. Attivazione/disattivazione coerente, conflitti visibili, reset dello stato e indicazione permanente dello scenario attivo. Esportabile via configurazione Git-native.

### F14 — Protocolli futuri

Prevedere estensioni esplicite per GraphQL (operation, variables, errors e contratti dedicati), WebSocket (handshake, frame e chiusura), SSE (stream eventi), gRPC, Protobuf, HTTP/2 e HTTP/3.

Per ogni protocollo documentare separatamente pass-through, cattura, decoding, modifica, replay e mocking. Non mostrare supporto generico completo quando esiste soltanto trasporto opaco. Streaming, multiplexing e QUIC richiedono decisioni architetturali e test dedicati.

### F15 — CLI e plugin futuri

Motore headless riutilizzabile da CLI per proxy, mock, record, replay, gestione configurazioni e contract checking. GUI e CLI devono usare le stesse semantiche, policy e versioni dei file. Documentare comandi, output, exit code e gestione di più istanze.

Architettura futura a plugin per JWT, OAuth, Stripe, AWS e GraphQL: API versionata, capability esplicite, isolamento, timeout e compatibilità. Nessuna esecuzione automatica di plugin presenti in un progetto non fidato. Non ritardare l'MVP per costruire un marketplace.

### F16 — HTTPS e Production Safety Mode

CA di sviluppo locale, generata per installazione, con chiave privata protetta e strumenti di installazione, verifica, rotazione e rimozione. Richiedere consenso esplicito prima di installarla nel trust store; offrire HTTP e CONNECT pass-through senza decrittazione quando l'utente salta il setup.

Verificare TLS upstream per default. Eventuali eccezioni devono essere esplicite, limitate all'ambiente/host e visibili. Documentare la differenza fra trust store di sistema, browser e runtime applicativi.

Production Safety Mode considera la destinazione effettiva, non solo l'etichetta del selettore. Per host PROD identificati, disabilitare di default modifiche, chaos, override, breakpoint attivi e replay; la modalità iniziale è osservazione con redazione. Eventuali abilitazioni sono specifiche, temporanee e chiaramente visibili, senza rimozione silenziosa delle policy tramite route o redirect.

Bloccare invii pericolosi anche da CLI, collection runner e replay di sessione. Non assumere che una GET sia sempre priva di effetti. Per sbloccare un'operazione mostrare target, metodo, quantità e modifica prevista. Registrare gli eventi di policy senza salvare segreti.

Il proxy ascolta sul loopback per default; esposizione LAN e controllo remoto richiedono configurazione deliberata e protezione dell'accesso. Non cambiare proxy di sistema o trust store senza un'azione esplicita dell'utente.

## 3. Desktop UX/UI & Brand

### Identità visiva e startup

Bicchiere con cannuccia come icona principale, semplice e riconoscibile anche a dimensioni tray. Wordmark «Sippin Soda» accanto al simbolo quando lo spazio lo consente; niente testo minuscolo obbligatorio nell'icona. Asset per app, taskbar, dock, tray, repository e installer; eventuale favicon futura riusa la stessa identità.

Splash leggero: bicchiere appare a 0 ms, cannuccia scende a circa 150 ms, atterra a 400 ms, piccola reazione a 450 ms, wordmark a 550 ms, passaggio all'app entro circa 800–1000 ms. Non attendere la fine dell'animazione se l'app è pronta. Usare SVG/CSS transforms o primitive leggere, senza libreria pesante dedicata. Con reduced motion usare logo statico.

Brand amichevole in onboarding, empty states, icona e repository; UI operativa precisa e professionale. Niente decorazioni a tema soda pervasive.

### Layout e navigazione

Traffic è la schermata iniziale. Barra superiore con progetto, ambiente, stato proxy/cattura e scenario; sidebar con Traffic, Collections, Mocks, Rules, Scenarios, Environments, Sessions e Settings. Contracts, OpenAPI e Plugins possono diventare sezioni dedicate quando necessario. L'API Client può essere integrato in Collections e nell'editor delle richieste.

Lista traffico con METHOD, HOST, PATH, STATUS, DURATION, SIZE, TIME ed ENVIRONMENT, pannelli ridimensionabili e dettaglio della selezione. Tab Request, Response, Headers, Cookies, Timing e Rules; Diff e Contract quando disponibili.

Replay, Edit & Replay, Intercept, Mock, Create Rule e Copy devono essere facilmente accessibili, con scorciatoie per le azioni frequenti. Non nascondere tutto nei menu contestuali. Filtri e selezione devono restare utilizzabili mentre arrivano nuove richieste.

Stati espliciti: Capturing, Paused, Proxy active, Mock active, Certificate required e Production, distinguibili anche senza colore. Ambiente effettivo e route devono rimanere visibili nei casi ibridi. PRODUCTION deve risaltare senza invadere tutta l'interfaccia.

### Qualità dell'interazione

Interfaccia compatta, calma, veloce, tipografia leggibile, spaziatura coerente e alta densità informativa. Riferimenti: qualità d'interazione di Linear/Raycast, densità DevTools/VS Code e cura delle app desktop native, senza copiarne branding o imporre convenzioni macOS alle altre piattaforme.

Temi System, Light e Dark progettati dall'inizio. Accessibilità: navigazione tastiera, focus visibile, contrasto, controlli semantici, etichette screen reader, testo scalabile e reduced motion. Evitare card giganti, gradienti decorativi, controlli eccessivamente arrotondati e linguaggio da dashboard SaaS.

Micro-animazioni brevi per arrivo richieste, breakpoint, scenario, proxy, mock e cambio route. Nessuna animazione deve rallentare la cattura o spostare imprevedibilmente la selezione.

### Onboarding, tray e ciclo di vita

Primo avvio: splash, breve spiegazione, setup proxy, spiegazione HTTPS, consenso CA e possibilità di saltare. Il setup deve mostrare quali applicazioni/client sono configurati e offrire una richiesta di verifica locale. Nessun account obbligatorio.

System tray/menu bar: Open, Start/Pause Capture, Enable/Disable Scenario, Switch Environment e Quit. Chiarire se chiudere la finestra lascia il motore attivo. Quit deve gestire richieste sospese, persistenza e ripristino delle impostazioni proxy modificate dall'app; prevedere recupero dopo crash.

## 4. Engineering Specification & Roadmap

### Architettura e decisione Rust vs C++

Valutare prima di fissare il core un ADR Rust vs C++: memory safety, async/concorrenza, librerie proxy/TLS, supporto protocolli, FFI, integrazione Tauri, toolchain multipiattaforma, packaging, debugging, competenze e manutenzione. Motivare la scelta con un piccolo spike di proxy/TLS e misure riproducibili; non scegliere sulla sola preferenza personale.

Tauri + React + TypeScript è l'ipotesi preferita per la shell/UI. Un core C++ richiederebbe un confine FFI/sidecar esplicito; un core Rust può essere libreria o processo separato. Registrare la decisione di isolamento e crash recovery in un ADR.

Flusso architetturale: Desktop UI → IPC locale tipizzato → Engine → SQLite/filesystem. Il motore include proxy, TLS, routing, rules, interception, replay, mocking, recording e validation; la CLI riusa i moduli del motore senza dipendere dalla UI.

Definire pipeline e fasi: controllo policy/destinazione, condizioni e routing request, breakpoint/modifiche, upstream o mock, elaborazione response, regole/breakpoint response, consegna e registrazione redatta. Ogni nuova destinazione deve essere rivalidata; le policy non possono essere aggirate da trasformazioni successive. Il dettaglio dell'ordine deve essere documentato e coperto da test.

IPC con input validati, capability ristrette, cancellazione, errori strutturati e stream di eventi con limiti. Payload e contenuto HTTP sono dati non fidati: nessuna esecuzione HTML/script nell'inspector e nessuna esposizione incontrollata di filesystem o segreti alla webview.

### Persistenza locale e Git-native config

SQLite per sessioni, indici e stato; filesystem per payload grandi; file dichiarativi leggibili e diffabili per progetto:

```text
.sippin-soda/
  config.yaml
  environments/
  mocks/
  rules/
  scenarios/
  collections/
  contracts/
```

Schemi versionati, validazione, migrazioni, salvataggi atomici e riferimenti stabili. Segreti e CA fuori dai file tracciabili, usando keystore di sistema o storage locale protetto e riferimenti nella configurazione. Fornire .gitignore e configurazioni di esempio prive di credenziali. Le sessioni non entrano automaticamente in Git.

### Performance, streaming e backpressure

Nessuna elaborazione pesante nel thread UI. Liste virtualizzate, ricerca indicizzata, formattazione e diff in background, aggiornamenti UI aggregati. Separare limiti di forwarding, capture e preview.

Payload grandi in streaming/spool su disco, preview limitata e body caricati su richiesta. Le regole che richiedono buffering devono dichiarare limiti e comportamento oltre soglia; preservare gli stream per le operazioni compatibili.

Code limitate, budget di memoria/disco, concorrenza controllata e backpressure. Esplicitare quando si rallenta il flusso, si interrompe una richiesta o si rinuncia alla cattura; non perdere dati silenziosamente. Misurare overhead del proxy, throughput, memoria, startup, filtri e responsività UI con hardware e workload dichiarati prima di fissare target numerici.

### Testing e repository

Test unitari del rule engine, matching, precedenze, contatori e probabilità con seed; test di integrazione per proxy, TLS/trust, pass-through, upstream failure, routing, reverse proxy, CORS, mock e replay. Verificare redazione, safety PROD, credenziali fra host, import ostili e limiti di risorse.

Test end-to-end del workflow desktop su Windows/macOS/Linux, usando servizi e CA di test isolati. Coprire payload grandi, streaming, cancellazioni, timeout, connessioni concorrenti, recovery e arresto con breakpoint attivi. Non usare ambienti PROD reali come fixture di test.

Repository GitHub con README.md, LICENSE, CONTRIBUTING.md, CODE_OF_CONDUCT.md, SECURITY.md, CHANGELOG.md, docs/, examples/, ADR e .github/. La scelta della licenza deve essere esplicita prima della distribuzione pubblica.

GitHub Actions multipiattaforma per lint, typecheck, test, build e packaging; release versionate con artifact, checksum e note. Gestire code signing/notarizzazione con credenziali di release protette e documentare eventuali blocchi; non presentare un installer non firmato come firmato.

Formati previsti: Windows .exe/.msi, macOS .dmg, Linux .AppImage e progressivamente .deb/.rpm. Esempi di asset: Sippin-Soda-0.1.0-Windows-x64.exe, Sippin-Soda-0.1.0-macOS-arm64.dmg, Sippin-Soda-0.1.0-macOS-x64.dmg e Sippin-Soda-0.1.0-Linux-x86_64.AppImage. Homebrew e winget sono canali futuri da registrare e verificare, non comandi già disponibili.

### Roadmap proposta e criteri di uscita

| Release | Scope | Criterio di uscita |
| --- | --- | --- |
| v0.1 | ADR core; shell desktop e brand; onboarding HTTP/HTTPS; traffic inspector; breakpoint request/response; modifica; replay/Edit & Replay; delay e regole base; salvataggio locale; redazione e protezioni PROD di base; packaging iniziale | Un frontend chiama DEV attraverso il proxy; il developer ispeziona, ripete, sospende una response, cambia 200 in 500, aggiunge latenza, salva una regola e la riusa dopo riavvio. Nessun dato fittizio presentato come cattura reale. |
| v0.2 | Hybrid routing LOCAL/DEV/TEST/STAGING/MOCK; ambienti/auth base; reverse proxy/CORS; mock server; conditional mocks; import OpenAPI per mock; Record → Mock; API Client e collections iniziali; Git-native config; tray | Un'app usa contemporaneamente più upstream e mock; route e credenziali sono corrette e lo scenario è riutilizzabile da progetto. |
| v0.3 | Regole condizionali avanzate; scenarios; Chaos Mode; diff; import/export e replay di sessione; redazione avanzata; retention; JWT inspector; client/collections estesi; Generate Test e copie codice | Un collega importa una sessione redatta, risolve le dipendenze e riproduce un guasto locale controllato; fault e diff sono tracciabili. |
| v0.4 | Contract validation dettagliata; OpenAPI discovery/export; CLI pubblica e CI checking; hardening prestazioni/streaming; completamento safety; spike auth avanzata e protocolli | Una pipeline valida fixture e segnala violazioni con exit code affidabili; discovery produce una proposta revisionabile; limiti e benchmark sono documentati. |
| v1 | Stabilità dei workflow principali e API Client; accessibilità; recovery/migrazioni; documentazione; release multipiattaforma; support matrix esplicita | Tutti i requisiti dichiarati stabili hanno verifiche, installer validati e limiti pubblicati. Le funzioni future restano chiaramente separate. |
| Futuro / v1.x+ | Stateful mocks; plugin; supporto progressivo completo GraphQL, WebSocket, SSE, gRPC/Protobuf, HTTP/2 e HTTP/3; auth avanzata mTLS/DPoP/SigV4 secondo spike; packet loss a livello rete; ulteriori canali di distribuzione | Ogni estensione ha ADR, scope per capability e test prima di essere dichiarata supportata. |

Le fondamenta di sicurezza, isolamento e backpressure iniziano in v0.1; le tappe successive ne ampliano le capacità. Nessuna funzione differita deve sparire dalla specifica o essere mostrata come implementata.

### Istruzioni per l'implementazione

Usare questo documento come baseline. Prima di implementare, ispezionare repository e istruzioni locali, produrre l'ADR del core e tradurre F01–F16 in un backlog con milestone e criteri verificabili. Procedere per funzionalità complete attraverso motore, IPC, UI e persistenza, iniziando dal workflow v0.1.

Mantenere una matrice requisito → milestone → stato → verifica. Una demo visiva non equivale a un proxy funzionante. Comunicare dipendenze esterne, limiti di piattaforma e funzioni non ancora supportate. Non costruire un backend SaaS, non sostituire il prodotto con una pagina web e non comprimere la visione globale nello scope dell'MVP.

### Tracciabilità delle integrazioni richieste

| Integrazione | Sezione |
| --- | --- |
| Chaos Mode, percentuali, timeout, drop, latenza casuale, malformed JSON | F05 |
| Diff DEV/LOCAL, DEV/TEST e originale/modificato | F09 |
| Contract validation dettagliata e CI | F10 |
| OpenAPI discovery ed export inferito | F10 |
| Session export/import e replay completo | F03, F11 |
| Sensitive-data redaction avanzata | F11, F16 |
| API Client completo, collections, Generate Test, cURL/fetch/axios | F12 |
| GraphQL, WebSocket, SSE, gRPC, Protobuf, HTTP/2 e HTTP/3 | F14 |
| JWT, mTLS, DPoP, SigV4, certificate pinning | F08 |
| Production Safety Mode dettagliato | F16 |
| Conditional rules e contatori | F04 |
| Conditional mocks e stateful mocks futuri | F06 |
| Routing host/path/service sofisticato | F07 |
| Plugin JWT/OAuth/Stripe/AWS/GraphQL | F15 |
| Tray/menu bar | Desktop UX/UI: onboarding, tray e ciclo di vita |
| Retention e limiti storage | F11 |
| Performance, backpressure e streaming | Engineering: performance |
| Test proxy/TLS/rules/mock/routing e GitHub Actions multipiattaforma | Engineering: testing e repository |
| ADR Rust vs C++ e separazione core/UI | Engineering: architettura |
| Roadmap v0.1 → v0.2 → v0.3 → v0.4 → v1 | Roadmap proposta |
| Definizione strategica originale | Prima frase della Product Vision |
