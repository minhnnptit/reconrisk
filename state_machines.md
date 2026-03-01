# ReconRisk — State Machines

Tài liệu này mô tả state machine cho từng thành phần của ReconRisk, giúp hiểu rõ luồng xử lý trước khi bắt tay vào code.

---

## 1. Pipeline State Machine (Tổng thể)

Điều khiển toàn bộ flow từ CLI → chạy từng phase → output.

```mermaid
stateDiagram-v2
    [*] --> ParseArgs
    ParseArgs --> ValidateArgs
    ValidateArgs --> InitOutput : valid
    ValidateArgs --> ExitError : invalid

    InitOutput --> BuildPhaseList
    BuildPhaseList --> RunPhase

    state RunPhase {
        [*] --> PickNextPhase
        PickNextPhase --> CheckDeps : phase available
        PickNextPhase --> AllDone : no more phases

        CheckDeps --> ExecutePhase : deps satisfied
        CheckDeps --> SkipPhase : deps missing

        ExecutePhase --> PhaseSuccess : ok
        ExecutePhase --> PhaseError : failed

        PhaseSuccess --> StoreResult
        PhaseError --> LogWarning
        SkipPhase --> LogWarning

        StoreResult --> PickNextPhase
        LogWarning --> PickNextPhase

        AllDone --> [*]
    }

    RunPhase --> GenerateReport
    GenerateReport --> SaveJSON
    SaveJSON --> PrintTable
    PrintTable --> [*]

    ExitError --> [*]
```

### Giải thích
- **ParseArgs** → **ValidateArgs**: Kiểm tra domain hợp lệ, steps/depth đúng format
- **BuildPhaseList**: Từ `--steps` hoặc `--all`, xây danh sách phase theo thứ tự
- **CheckDeps**: Ví dụ phase `risk` cần data từ `probe` + `cve`. Nếu user chỉ chạy `--steps risk`, skip vì thiếu input
- **PhaseError → LogWarning**: Graceful degradation — không crash cả pipeline

---

## 2. Subdomain Phase (`subdomain.py`)

```mermaid
stateDiagram-v2
    [*] --> CheckTools

    state CheckTools {
        [*] --> HasSubfinder
        HasSubfinder --> HasAssetfinder : yes
        HasSubfinder --> FallbackDNS : no
        HasAssetfinder --> ToolsReady : yes
        HasAssetfinder --> SubfinderOnly : no
    }

    CheckTools --> RunEnum

    state RunEnum {
        [*] --> CheckDepth
        CheckDepth --> RunFast : depth=fast
        CheckDepth --> RunDeep : depth=deep

        state RunFast {
            [*] --> SubfinderDefault
            SubfinderDefault --> AssetfinderRun
            AssetfinderRun --> [*]
        }

        state RunDeep {
            [*] --> SubfinderLargeWordlist
            SubfinderLargeWordlist --> [*]
        }

        RunFast --> MergeResults
        RunDeep --> MergeResults
    }

    state FallbackDNS {
        [*] --> BruteResolve
        BruteResolve --> [*]
    }

    RunEnum --> Deduplicate
    FallbackDNS --> Deduplicate
    Deduplicate --> SaveFile : subdomains.txt
    SaveFile --> ReturnList
    ReturnList --> [*]
```

### States chính
| State | Mô tả |
|-------|--------|
| `CheckTools` | Kiểm tra subfinder/assetfinder có trong PATH |
| `RunFast` | Chạy cả subfinder + assetfinder mặc định |
| `RunDeep` | Subfinder với wordlist lớn |
| `FallbackDNS` | Dùng dnspython nếu không có tool nào |
| `Deduplicate` | Loại bỏ subdomain trùng lặp |

---

## 3. HTTP Probe Phase (`http_probe.py`)

```mermaid
stateDiagram-v2
    [*] --> CheckInput
    CheckInput --> NoData : subdomains list trống
    CheckInput --> CheckHttpx : có subdomains

    NoData --> [*]

    CheckHttpx --> UseHttpx : httpx available
    CheckHttpx --> UseFallback : httpx missing

    state UseHttpx {
        [*] --> BuildCmd
        BuildCmd --> CheckDepth
        CheckDepth --> CmdFast : fast
        CheckDepth --> CmdDeep : deep
        CmdFast --> RunSubprocess
        CmdDeep --> RunSubprocess
        RunSubprocess --> ParseJSONLines
        ParseJSONLines --> [*]
    }

    state UseFallback {
        [*] --> InitThreadPool
        InitThreadPool --> RequestsGet
        RequestsGet --> CollectResults
        CollectResults --> [*]
    }

    UseHttpx --> BuildProbeData
    UseFallback --> BuildProbeData

    BuildProbeData --> ReturnProbes
    ReturnProbes --> [*]
```

### States chính
| State | Mô tả |
|-------|--------|
| `CmdFast` | httpx: status, title, server |
| `CmdDeep` | + follow redirects, HTTPS check, tech headers |
| `UseFallback` | requests.get() với thread pool nếu thiếu httpx |
| `BuildProbeData` | Chuẩn hóa output thành `{url, status, title, server}` |

---

## 4. Port Scan Phase (`port_scan.py`)

```mermaid
stateDiagram-v2
    [*] --> CheckNmap
    CheckNmap --> NmapMissing : not found
    CheckNmap --> ResolveTargets : found

    NmapMissing --> WarnUser
    WarnUser --> ReturnEmpty
    ReturnEmpty --> [*]

    ResolveTargets --> BuildNmapCmd

    state BuildNmapCmd {
        [*] --> CheckDepth
        CheckDepth --> Fast : fast → top 100, -sV
        CheckDepth --> Deep : deep → top 1000, -sV -O
        Fast --> [*]
        Deep --> [*]
    }

    BuildNmapCmd --> RunNmap
    RunNmap --> NmapTimeout : timeout exceeded
    RunNmap --> NmapSuccess : completed
    RunNmap --> NmapError : error

    NmapTimeout --> WarnUser
    NmapError --> WarnUser

    NmapSuccess --> ParseXML
    ParseXML --> ExtractPorts
    ExtractPorts --> ExtractServices
    ExtractServices --> ExtractOS
    ExtractOS --> ReturnPortData
    ReturnPortData --> [*]
```

### States chính
| State | Mô tả |
|-------|--------|
| `CheckNmap` | Kiểm tra nmap có trong PATH |
| `Fast/Deep` | Top 100 vs top 1000 ports |
| `ParseXML` | Parse nmap `-oX -` XML output |
| `ExtractPorts/Services/OS` | Trích dữ liệu từ XML tree |

---

## 5. CVE Lookup Phase (`cve_lookup.py`)

```mermaid
stateDiagram-v2
    [*] --> CollectServices
    CollectServices --> NoServices : không có service data
    CollectServices --> HasServices : có services

    NoServices --> ReturnEmpty
    ReturnEmpty --> [*]

    state HasServices {
        [*] --> PickService
        PickService --> CheckCache
        CheckCache --> CacheHit : found in cache
        CheckCache --> CacheMiss : not cached

        CacheHit --> AddToResults

        CacheMiss --> BuildQuery
        BuildQuery --> RateLimit
        RateLimit --> CallNVD

        CallNVD --> APISuccess : 200 OK
        CallNVD --> APIError : timeout / error
        CallNVD --> RateLimited : 429

        APISuccess --> ParseCVEs
        ParseCVEs --> SaveToCache
        SaveToCache --> AddToResults

        APIError --> LogWarning
        LogWarning --> AddToResults : empty CVE list

        RateLimited --> WaitRetry
        WaitRetry --> CallNVD

        AddToResults --> MoreServices
        MoreServices --> PickService : yes
        MoreServices --> [*] : no
    }

    HasServices --> ReturnCVEData
    ReturnCVEData --> [*]
```

### States chính
| State | Mô tả |
|-------|--------|
| `CheckCache` | Xem `cve_cache.json`, tránh gọi API lại |
| `RateLimit` | Sleep 0.6s (có key) hoặc 6s (không key) |
| `CallNVD` | Gọi NVD API v2 keywordSearch |
| `RateLimited` | Nhận 429 → chờ rồi retry |
| `SaveToCache` | Lưu kết quả vào disk cache |

---

## 6. Risk Score Phase (`risk_score.py`)

```mermaid
stateDiagram-v2
    [*] --> CollectHostData

    state CollectHostData {
        [*] --> GatherProbe
        GatherProbe --> GatherPorts
        GatherPorts --> GatherCVEs
        GatherCVEs --> [*]
    }

    CollectHostData --> ScoreHosts

    state ScoreHosts {
        [*] --> PickHost
        PickHost --> InitScore : score = 0

        InitScore --> CheckCriticalCVE
        CheckCriticalCVE --> AddCVSS9Plus : CVSS >= 9.0 → +40
        CheckCriticalCVE --> CheckHighCVE

        AddCVSS9Plus --> CheckHighCVE
        CheckHighCVE --> AddCVSS7Plus : CVSS 7-8.9 → +25
        CheckHighCVE --> CheckMedCVE

        AddCVSS7Plus --> CheckMedCVE
        CheckMedCVE --> AddCVSSMed : CVSS 4-6.9 → +10 (max +20)
        CheckMedCVE --> CheckPorts

        AddCVSSMed --> CheckPorts
        CheckPorts --> AddSensitive : 22,3306,5432... → +15
        CheckPorts --> CheckAdminPorts

        AddSensitive --> CheckAdminPorts
        CheckAdminPorts --> AddAdmin : 8080,9000... → +10
        CheckAdminPorts --> CheckHTTPS

        AddAdmin --> CheckHTTPS
        CheckHTTPS --> AddHTTPOnly : HTTP only → +10
        CheckHTTPS --> ClampScore

        AddHTTPOnly --> ClampScore
        ClampScore --> AssignBand : cap 0-100

        AssignBand --> MoreHosts
        MoreHosts --> PickHost : yes
        MoreHosts --> [*] : no
    }

    ScoreHosts --> SortByScore
    SortByScore --> ReturnScored
    ReturnScored --> [*]
```

### Risk Bands
| Score | Band | Emoji |
|-------|------|-------|
| ≥ 70 | CRITICAL | 🔴 |
| 50–69 | HIGH | 🟠 |
| 30–49 | MEDIUM | 🟡 |
| < 30 | LOW | 🟢 |

---

## 7. Delta Phase (`delta.py`)

```mermaid
stateDiagram-v2
    [*] --> CheckCompareFlag
    CheckCompareFlag --> Skip : --compare not set
    CheckCompareFlag --> LoadBaseline : --compare set

    Skip --> [*]

    LoadBaseline --> BaselineExists : file found
    LoadBaseline --> NoBaseline : file not found

    NoBaseline --> SaveAsBaseline : lưu scan hiện tại làm baseline
    SaveAsBaseline --> PrintFirstRun : "Baseline saved, no diff"
    PrintFirstRun --> [*]

    BaselineExists --> ParseBaseline

    state ComputeDiff {
        [*] --> CompareHosts
        CompareHosts --> FindNew : host mới xuất hiện
        CompareHosts --> FindGone : host đã biến mất
        CompareHosts --> FindChanged : cùng host, data khác

        FindNew --> CollectChanges
        FindGone --> CollectChanges
        FindChanged --> CollectChanges

        CollectChanges --> [*]
    }

    ParseBaseline --> ComputeDiff
    ComputeDiff --> UpdateBaseline : ghi đè baseline mới
    UpdateBaseline --> ReturnDelta
    ReturnDelta --> [*]
```

### Delta output types
| Tag | Ý nghĩa |
|-----|---------|
| `[NEW]` | Host/port/CVE mới xuất hiện |
| `[GONE]` | Host/port đã offline |
| `[CHANGED]` | Risk score thay đổi, CVE mới |

---

## 8. Report Phase (`report.py`)

```mermaid
stateDiagram-v2
    [*] --> CollectAllData

    state CollectAllData {
        [*] --> MergePhaseOutputs
        MergePhaseOutputs --> HasDelta : --compare was used
        MergePhaseOutputs --> NoDelta
        HasDelta --> [*]
        NoDelta --> [*]
    }

    CollectAllData --> BuildTable

    state BuildTable {
        [*] --> CreateRichTable
        CreateRichTable --> AddColumns : Host, Status, Ports, CVE, Score, Band
        AddColumns --> SortByRisk
        SortByRisk --> CheckTopN
        CheckTopN --> ApplyTopN : --top N set
        CheckTopN --> ShowAll : no filter
        ApplyTopN --> PopulateRows
        ShowAll --> PopulateRows
        PopulateRows --> ColorCode : band → color
        ColorCode --> [*]
    }

    BuildTable --> PrintToTerminal

    state PrintToTerminal {
        [*] --> PrintScanTable
        PrintScanTable --> CheckDelta
        CheckDelta --> PrintDeltaSection : delta data exists
        CheckDelta --> SkipDelta : no delta
        PrintDeltaSection --> [*]
        SkipDelta --> [*]
    }

    PrintToTerminal --> SaveJSON
    SaveJSON --> [*]
```

---

## 9. CLI Validation Flow (chi tiết `recon.py`)

```mermaid
stateDiagram-v2
    [*] --> ReadArgs : argparse

    ReadArgs --> ValidateDomain
    ValidateDomain --> InvalidDomain : empty / bad format
    ValidateDomain --> ValidateSteps : ok

    InvalidDomain --> PrintHelp
    PrintHelp --> [*]

    ValidateSteps --> InvalidStep : unknown step name
    ValidateSteps --> ValidateDepth : ok

    InvalidStep --> PrintHelp

    ValidateDepth --> InvalidDepth : not fast/deep
    ValidateDepth --> ValidateOutput : ok

    InvalidDepth --> PrintHelp

    ValidateOutput --> CreateOutputDir
    CreateOutputDir --> CheckThreads
    CheckThreads --> CheckTimeout
    CheckTimeout --> CheckNVDKey

    CheckNVDKey --> ConfigReady
    ConfigReady --> [*]
```

---

## Tổng kết Phase Dependencies

```mermaid
graph LR
    subgraph Input
        CLI["CLI Args"]
    end

    subgraph Phases
        SD["1. Subdomain"]
        PR["2. Probe"]
        PS["3. Port Scan"]
        CV["4. CVE Lookup"]
        RS["5. Risk Score"]
        DL["6. Delta"]
        RP["7. Report"]
    end

    CLI --> SD
    SD --> PR
    SD --> PS
    PR --> CV
    PS --> CV
    PR --> RS
    PS --> RS
    CV --> RS
    RS --> DL
    RS --> RP
    DL --> RP
```

> [!IMPORTANT]
> Mỗi phase có thể chạy độc lập nếu user cung cấp `--steps` cụ thể, nhưng nếu thiếu data từ phase trước thì sẽ **skip** thay vì crash.
