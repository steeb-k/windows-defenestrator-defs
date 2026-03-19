# PUA Detection Rules

Windows Defenestrator includes custom YARA rules for detecting Potentially Unwanted Applications (PUAs). These are programs that aren't traditional malware but are deceptive, invasive, or installed without informed consent — the kind of junk technicians find on customer machines every day.

All PUA rules require the file to be a Windows PE executable (`MZ` header check) and match against PE version info strings, embedded domains, registry key references, known filenames, and other artifacts unique to each family.

---

## Chromium Junkware Browsers

Ad-injecting, data-harvesting Chromium forks that hijack browser defaults.

| Rule | Target | Detection basis | Threat level |
|------|--------|----------------|-------------|
| `PUA_WaveBrowser` | Wave Browser (Wavesor / iSign / Genimous / Polarity) | Company names, product name, domains (`wavebrowser.co`, `gowavebrowser.com`), updater filenames | Medium |
| `PUA_TorchBrowser` | Torch Browser (Torch Media) | Company name, domain (`torchbrowser.com`), executable names | Medium |
| `PUA_ChedotBrowser` | Chedot Browser | Company name, registry key, domain | Medium |
| `PUA_BoBrowser` | BoBrowser (ClaraLabs) | Company names, product name, executable name — replaces Chrome and copies profile data | Medium |
| `PUA_OrbitumBrowser` | Orbitum Browser | Company name, domain, executable name | Medium |
| `PUA_CoowonBrowser` | Coowon Browser | Product name, domain, executable name | Medium |
| `PUA_CitrioBrowser` | Citrio Browser (Catalina Group) | Company name, product name, domain | Medium |
| `PUA_UCBrowser` | UC Browser (UCWeb) | Company names + product/domain cross-match — flagged for data collection and MITM | Medium |
| `PUA_WebNavigatorBrowser` | WebNavigator Browser (Genimous/Polarity ecosystem) | Product name, "Search Encrypt" string | Medium |

---

## Browser Toolbars & Search Hijackers

Toolbars and extensions that redirect searches, change homepages, and track browsing.

| Rule | Target | Detection basis | Threat level |
|------|--------|----------------|-------------|
| `PUA_Mindspark_Toolbar` | Mindspark / IAC toolbars (dozens of branded variants) | Company names, registry keys, domains (`myway.com`, `mindspark.com`) | Medium |
| `PUA_AskToolbar` | Ask Toolbar (APN LLC) | Company name, product name, installer filenames (`ApnStub.exe`, etc.), registry keys | Medium |
| `PUA_Conduit_Toolbar` | Conduit Toolbar (now Perion) | Company name, DLL names (`ConduitEngine.dll`), registry keys, domains, known CLSID | Medium |
| `PUA_SearchProtect` | Search Protect / Client Connect | Company name, product name, executable names (`cltmng.exe`, `CltMngSvc.exe`), registry key | Medium |
| `PUA_DeltaToolbar` | Delta Toolbar / Delta Search | Company name (Montera), product name, filenames, registry key, domains | Medium |
| `PUA_BabylonToolbar` | Babylon Toolbar / Babylon Search | Company name, product name, DLL names, registry keys, domains | Medium |
| `PUA_MyWebSearch` | MyWebSearch / Fun Web Products (IAC/Mindspark) | Company names, product names, registry keys, domains | Medium |
| `PUA_SafeFinder_Linkury` | SafeFinder / Linkury SmartBar | Company name, product names, domains — requires 2+ matches to avoid false positives | Medium |

---

## Bundleware & Deceptive Installers

Installer wrappers that bundle unwanted software with legitimate downloads using deceptive opt-out UIs.

| Rule | Target | Detection basis | Threat level |
|------|--------|----------------|-------------|
| `PUA_OpenCandy` | OpenCandy / SweetLabs | Company names, product name, DLL name (`OCSetupHlp.dll`), registry key, domain | Medium |
| `PUA_InstallCore` | InstallCore (ironSource) | Company name, product name, registry key, domain — requires 2+ matches | Medium |
| `PUA_Crossrider` | Crossrider (now Kape Technologies) | Company name, PDB paths, registry key, domain, known CLSIDs | Medium |
| `PUA_SoftonicDownloader` | Softonic Downloader | Company name, product name | Medium |
| `PUA_CNETDownloader` | CNET Download.com Installer | Product names ("CNET Download.com Installer", "CBS Interactive Download Manager") | Medium |

---

## Adware

Programs that inject ads, hijack search results, install root certificates for MITM interception, or track browsing activity.

| Rule | Target | Detection basis | Threat level |
|------|--------|----------------|-------------|
| `PUA_Pirrit` | Pirrit adware | Company name + domain (both required) | Medium |
| `PUA_Genieo` | Genieo (Genieo Innovation) | Company name, product + domain cross-match | Medium |
| `PUA_Superfish` | Superfish VisualDiscovery (Lenovo) | Company name, product name, Komodia SDK strings — **installs root CA for MITM** | **High** |
| `PUA_Yontoo` | Yontoo / Sambreel | Company names, product name, domain | Medium |
| `PUA_Wajam` | Wajam / IMALI Media (Social2Search, SearchAwesome) | Company name, 7 unique internal component names, rebrandings, root cert name, registry key, domain — **MITM ad injector with anti-analysis** | **High** |
| `PUA_DealPly` | DealPly | Company name, filenames, `--IsErIk` parameter, C2 domain | Medium |
| `PUA_Adpeak` | Adpeak | Company name | Medium |
| `PUA_OutBrowse` | OutBrowse | Company name | Medium |

---

## Threat Levels

- **Medium**: Standard PUA — unwanted but not actively dangerous. Ad injection, search hijacking, tracking, bundleware.
- **High**: Actively harmful PUA — installs root certificates for MITM interception (Superfish, Wajam), enabling traffic inspection of HTTPS connections. These are security threats beyond typical PUA behavior.

---

## Excluded (Legitimate Software)

The following were evaluated and intentionally **not** included because they are legitimate products, even if sometimes distributed via bundleware:

- **Epic Privacy Browser** (Hidden Reflex / Graham Holdings) — genuine privacy browser
- **Falkon / QupZilla** — KDE project, fully open source
- **SRWare Iron** — legitimate privacy-focused Chromium fork
- **Ghost Browser** — legitimate productivity tool, no adware variant found
- **Polarity Browser** — open-source browser (distinct from Polarity Technologies Ltd the PUP distributor)
- **Yandex Browser**, **Avast/AVG Secure Browser**, **Comodo Dragon** — legitimate products; only the third-party bundler installers are PUPs, not the browser binaries themselves

---

## Adding New Rules

Custom PUA rules live in `rules/pua/` in this repository and are automatically included in the definitions pack during CI builds. To add a new PUA family:

1. Add a rule to the appropriate `.yara` file (or create a new one)
2. Use the `: pua adware` tag on the rule declaration line
3. Include `severity = "medium"` (or `"high"` for MITM/rootkit behavior) in metadata
4. Require `uint16(0) == 0x5A4D` (PE header check) in the condition
5. Use multiple string matches to minimize false positives
6. Update this document
