# ReconRisk v2 — State Machines

Tài liệu mô tả state machine cho từng phase và interactive pipeline.

---

## 1. Pipeline State Machine (Tổng thể + Interactive)

```mermaid
stateDiagram-v2
    [*] --> ParseArgs
    ParseArgs --> ValidateArgs
    ValidateArgs --> InitOutput : valid
    ValidateArgs --> ExitError : invalid

    InitOutput --> PrintBanner
    PrintBanner --> BuildPhaseList
    BuildPhaseList --> RunPhase

    state RunPhase {
        [*] --> PickNextPhase
        PickNextPhase --> CheckDeps : phase available
        PickNextPhase --> AllDone : no more phases

        CheckDeps --> ExecutePhase : deps ok or soft-skip
        ExecutePhase --> PhaseSuccess : ok
        ExecutePhase --> PhaseError : failed

        PhaseSuccess --> StoreResult
        PhaseError --> LogWarning

        StoreResult --> CheckInteractive
        
        state CheckInteractive {
            [*] --> IsFlagSet
            IsFlagSet --> IsPausePhase : -i set
            IsFlagSet --> NoAction : no -i
            IsPausePhase --> ShowTable : prioritize/probe/port
            IsPausePhase --> NoAction : other phase
            ShowTable --> UserSelect
            UserSelect --> FilterResults
            FilterResults --> [*]
            NoAction --> [*]
        }

        CheckInteractive --> PickNextPhase
        LogWarning --> PickNextPhase
        AllDone --> [*]
    }

    RunPhase --> GenerateReport
    GenerateReport --> SaveJSON
    SaveJSON --> PrintTable
    PrintTable --> [*]
    ExitError --> [*]
```

### Interactive Pauses
| Pause | After Phase | Table Shows | User Selects |
|-------|-------------|-------------|-------------|
| 1 | prioritize | Score, subdomain, tags, IPs | By number, tag, or top N |
| 2 | probe | Status, host, title, server, TLS | By number or top N |
| 3 | port | Host, IP, open ports, OS | By number or top N |

---

## 2. Subdomain Phase (`subdomain.py`)

```mermaid
stateDiagram-v2
    [*] --> FindGoTools

    state FindGoTools {
        [*] --> SearchSubfinder : ~/go/bin + GOPATH + PATH
        SearchSubfinder --> SearchAssetfinder
        SearchAssetfinder --> [*]
    }

    FindGoTools --> RunSources

    state RunSources {
        [*] --> CheckSubfinder
        CheckSubfinder --> RunSubfinder : found
        CheckSubfinder --> SkipSubfinder : not found
        
        RunSubfinder --> CheckAssetfinder
        SkipSubfinder --> CheckAssetfinder
        
        CheckAssetfinder --> RunAssetfinder : found
        CheckAssetfinder --> SkipAssetfinder : not found
        
        RunAssetfinder --> RunCrtsh
        SkipAssetfinder --> RunCrtsh
        
        RunCrtsh --> ValidateCrtsh : clean garbage subdomains
        ValidateCrtsh --> CheckDepth
        
        CheckDepth --> RunAmass : deep + amass found
        CheckDepth --> CheckFallback : fast or no amass
        
        RunAmass --> CheckFallback
        CheckFallback --> DNSBruteforce : no tools + few results
        CheckFallback --> [*] : enough results
        DNSBruteforce --> [*]
    }

    RunSources --> Deduplicate
    Deduplicate --> SaveFile
    SaveFile --> [*]
```

### Sources & Fallback
| Source | Mode | Notes |
|--------|------|-------|
| subfinder | fast + deep | Searches ~/go/bin/ directly |
| assetfinder | all | Optional, skipped if missing |
| crt.sh | all | Always available, cleans garbage |
| amass | deep only | Slow, passive enum |
| DNS bruteforce | fallback | 53 prefixes if no tools found |

---

## 3. DNS Resolve Phase (`dns_resolve.py`)

```mermaid
stateDiagram-v2
    [*] --> GetSubdomains
    GetSubdomains --> EnsureRootDomain : always include root

    EnsureRootDomain --> ResolveAll

    state ResolveAll {
        [*] --> PickSubdomain
        PickSubdomain --> TryResolve : thread pool

        state TryResolve {
            [*] --> Attempt1 : timeout=5s
            Attempt1 --> DNSSuccess : resolved
            Attempt1 --> Attempt2 : failed, timeout=10s
            Attempt2 --> DNSSuccess : resolved
            Attempt2 --> Attempt3 : failed, timeout=15s
            Attempt3 --> DNSSuccess : resolved
            Attempt3 --> SocketFallback : all DNS failed
            SocketFallback --> DNSSuccess : socket resolved
            SocketFallback --> MarkDead : all failed
        }

        DNSSuccess --> CheckCNAME
        CheckCNAME --> CheckTakeover : has CNAME → check vuln patterns
        CheckCNAME --> StoreResult : no CNAME
        CheckTakeover --> StoreResult
        MarkDead --> StoreResult

        StoreResult --> MoreSubs
        MoreSubs --> PickSubdomain : yes
        MoreSubs --> [*] : no
    }

    ResolveAll --> BuildIPMap : IP → [subdomains]
    BuildIPMap --> DeduplicateIPs
    DeduplicateIPs --> SaveJSON
    SaveJSON --> [*]
```

---

## 4. Prioritize Phase (`prioritize.py`)

```mermaid
stateDiagram-v2
    [*] --> GetSubdomains
    GetSubdomains --> DetectWildcard : check if >50% same IP

    DetectWildcard --> ScoreAll

    state ScoreAll {
        [*] --> PickSub
        PickSub --> IsRootDomain
        IsRootDomain --> AlwaysKeep : root domain → score ≥ 10
        IsRootDomain --> CheckScore : not root

        CheckScore --> ScorePrefix : dev/admin/api → +30-40
        ScorePrefix --> ScoreCNAME : has CNAME → +25
        ScoreCNAME --> ScoreIPUnique : unique IP → +20
        ScoreIPUnique --> ScoreDepth : deep sub → +20
        ScoreDepth --> CheckDead : not resolved → score -1

        CheckDead --> FilterDead : score < 0, not root
        CheckDead --> FilterWildcard : wildcard IP + low score
        CheckDead --> AddToList : passes all filters
        
        AlwaysKeep --> AddToList
        FilterDead --> IncrementFiltered
        FilterWildcard --> IncrementFiltered
        
        AddToList --> MoreSubs
        IncrementFiltered --> MoreSubs
        MoreSubs --> PickSub : yes
        MoreSubs --> [*] : no
    }

    ScoreAll --> SortByScore
    SortByScore --> [*]
```

---

## 5. HTTP Probe Phase (`http_probe.py`)

```mermaid
stateDiagram-v2
    [*] --> GetInput
    GetInput --> HandlePrioritized : list of dicts
    GetInput --> HandleRaw : list of strings
    HandlePrioritized --> ExtractSubdomains
    HandleRaw --> ExtractSubdomains

    ExtractSubdomains --> FindGoHttpx : ~/go/bin/httpx
    FindGoHttpx --> UseGoHttpx : found
    FindGoHttpx --> UseFallback : not found

    UseGoHttpx --> ParseJSONLines --> BuildProbes
    UseFallback --> ThreadPool --> RequestsGet --> BuildProbes

    BuildProbes --> [*]
```

---

## 6. Tech Detect Phase (`tech_detect.py`)

```mermaid
stateDiagram-v2
    [*] --> GetAliveHosts

    state AnalyzeHost {
        [*] --> RunWhatweb : subprocess
        RunWhatweb --> ParseJSON
        ParseJSON --> AnalyzeHeaders : Server, X-Powered-By, Set-Cookie
        AnalyzeHeaders --> AnalyzeBody : HTML patterns
        AnalyzeBody --> MergeTech
        MergeTech --> [*]
    }

    GetAliveHosts --> AnalyzeHost : per host
    AnalyzeHost --> [*]
```

### Detection Sources
| Source | Detects |
|--------|---------|
| whatweb | CMS, framework, server, language |
| HTTP headers | Server, X-Powered-By, cookies |
| HTML body | WordPress, Next.js, React, Angular |

---

## 7. Port Scan Phase (`port_scan.py`)

```mermaid
stateDiagram-v2
    [*] --> GetTargets
    GetTargets --> UseUniqueIPs : from resolve phase
    GetTargets --> UseSubdomains : fallback

    UseUniqueIPs --> LimitTargets : max 50
    UseSubdomains --> LimitTargets

    LimitTargets --> BuildNmapCmd
    BuildNmapCmd --> NmapFast : fast → top 100, -sV
    BuildNmapCmd --> NmapDeep : deep → top 1000, -sV -O

    NmapFast --> RunNmap
    NmapDeep --> RunNmap
    RunNmap --> ParseXML --> ExtractPorts --> [*]
```

---

## 8. Web Fuzz Phase (`web_fuzz.py`)

```mermaid
stateDiagram-v2
    [*] --> FilterHosts : only 200/301/401/403

    FilterHosts --> LimitHosts : fast=20, deep=50
    LimitHosts --> GetWordlist

    state FuzzHost {
        [*] --> CheckFfuf
        CheckFfuf --> RunFfuf : found
        CheckFfuf --> RunFallback : not found
        RunFfuf --> ParseJSON
        RunFallback --> RequestsBrute
        ParseJSON --> ClassifyPaths
        RequestsBrute --> ClassifyPaths
        ClassifyPaths --> AutoFlag : admin/config/backup
        AutoFlag --> [*]
    }

    GetWordlist --> FuzzHost : per host, max 60s
    FuzzHost --> [*]
```

---

## 9. CVE Lookup Phase (`cve_lookup.py`)

```mermaid
stateDiagram-v2
    [*] --> CollectServices : from port + tech

    state LookupLoop {
        [*] --> PickService
        PickService --> CheckCache
        CheckCache --> CacheHit : return cached
        CheckCache --> CallNVD : query API
        CallNVD --> Success : parse CVEs
        CallNVD --> RateLimited : 429 → retry
        CallNVD --> Error : timeout → skip
        Success --> SaveCache
        SaveCache --> MoreServices
        CacheHit --> MoreServices
        Error --> MoreServices
        MoreServices --> PickService : yes
        MoreServices --> [*] : no
    }

    CollectServices --> LookupLoop
    LookupLoop --> [*]
```

---

## 10. Param Find Phase (`param_find.py`)

```mermaid
stateDiagram-v2
    [*] --> GetAliveHosts

    state ScanHost {
        [*] --> RunArjun : subprocess, timeout
        RunArjun --> ParseOutput
        RunArjun --> Timeout : skip host
        ParseOutput --> ClassifyParams
        ClassifyParams --> FlagDangerous : SSRF/LFI/RCE/IDOR
        FlagDangerous --> [*]
        Timeout --> [*]
    }

    GetAliveHosts --> ScanHost : per host
    ScanHost --> [*]
```

---

## 11. Risk Score Phase (`risk_score.py`)

```mermaid
stateDiagram-v2
    [*] --> CollectAllData : probe + port + cve + fuzz + param + dns

    state ScoreHost {
        [*] --> CVEScore : critical/high/medium
        CVEScore --> PortScore : sensitive + admin ports
        PortScore --> HTTPSCheck : HTTP only → +10
        HTTPSCheck --> FuzzScore : config leak/admin/backup
        FuzzScore --> ParamScore : SSRF/LFI/RCE params
        ParamScore --> TakeoverScore : CNAME takeover
        TakeoverScore --> Clamp : 0-100
        Clamp --> AssignBand : CRITICAL/HIGH/MEDIUM/LOW
        AssignBand --> [*]
    }

    CollectAllData --> ScoreHost : per host
    ScoreHost --> SortByScore
    SortByScore --> [*]
```

---

## 12. Phase Dependencies (v2)

```mermaid
graph LR
    subgraph "Recon Pipeline v2"
        SD["1. Subdomain"]
        RS["2. Resolve"]
        PR["3. Prioritize"]
        PB["4. Probe"]
        TD["5. TechDetect"]
        PS["6. Port"]
        FZ["7. Fuzz"]
        CV["8. CVE"]
        PF["9. ParamFind"]
        RK["10. Risk"]
        DL["11. Delta"]
        RP["12. Report"]
    end

    SD --> RS
    RS --> PR
    PR --> PB
    PB --> TD
    RS --> PS
    PB --> FZ
    PS --> CV
    TD --> CV
    PB --> PF
    PB --> RK
    PS --> RK
    CV --> RK
    FZ --> RK
    PF --> RK
    RK --> DL
    RK --> RP
    DL --> RP

    style PR fill:#ff6,stroke:#333
    style PB fill:#6f6,stroke:#333
    style PS fill:#ff6,stroke:#333
```

> [!IMPORTANT]
> Phases có viền vàng/xanh là **interactive pause points** khi dùng `-i`.
> Dependencies là **soft** — phase vẫn chạy nếu deps thiếu data.
