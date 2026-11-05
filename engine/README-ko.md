포맷하기 싫어서 눈물을 흘리며 만든 작은 프로그램입니다

# NIKKE Recovery Kit

한국어 | [English](README.md)

버전: `0.3.1-preview`

NIKKE PC 런처 침해에서 알려진 악성 DLL, 사용자 레지스트리 자동 로딩 설정, 런처 캐시를 검사하고 원본을 보존한 뒤 격리하는 Windows용 복구 보조 도구입니다. 설치된 프로그램과 시작 경로도 조사해 후속 확인에 필요한 목록을 만듭니다.

**포맷하기 어려운 환경에서 복구를 돕기 위해 만들었습니다. 다만 포맷이 필요 없다는 보증이나 PC 전체가 안전하다는 인증을 제공하지는 않습니다.** 공식 패치가 아니며, 추가 검증이 필요한 미리보기 버전입니다.

## 사용법

### 준비

64비트 Windows와 Windows PowerShell 5.1 또는 PowerShell 7이 필요합니다. `Run-*.cmd` 실행기는 Windows에 포함된 Windows PowerShell 5.1을 사용합니다. ZIP 전체를 로컬 폴더에 풀고 파일을 따로 빼거나 섞지 마세요.

검사 전에 런처 로그와 캐시를 임의로 지우지 마세요. 감염 여부와 발생 시점을 확인할 자료가 들어 있을 수 있습니다. 복구를 적용하기 전에는 작업을 저장하고 NIKKE 런처를 완전히 종료하세요.

### 검사 → 복구 → 재검사

1. **`Run-Audit.cmd` 실행:** 현재 상태를 읽어 검사하고 결과 폴더를 만듭니다. 이 단계에서는 복구 작업을 적용하지 않습니다.
2. **결과 확인:** `REPORT.txt`, `summary.json`, `plan.json`에서 판정, 오류, 대상 경로와 예정 작업을 확인합니다.
3. **`Run-Repair.cmd` 실행:** Windows 관리자 권한 승인 후 통신 차단, 해당 사용자 레지스트리 정리, 확인된 DLL 격리와 런처 캐시 보존을 적용합니다. 적용 시 현재 상태를 다시 조사하므로 앞서 만든 작업 목록과 차이가 날 수 있습니다.
4. **`Run-Verify.cmd` 실행:** 남은 알려진 흔적, 메모리에 로드된 DLL, 읽지 못한 영역을 확인합니다. 복구 작업을 새로 적용하지는 않습니다.
5. `AffectedApplicationExitRequired`가 나오면 표시된 앱의 작업을 저장하고 앱을 완전히 종료한 뒤 다시 검사합니다. 파일 잠금으로 격리가 실패했다면 앱 종료 후 복구도 다시 실행합니다.

기본 결과 위치는 `%LOCALAPPDATA%\NikkeRecovery\Evidence` 아래의 실행별 폴더입니다. 실행할 때마다 새 폴더를 만들며 이전 증거를 덮어쓰지 않습니다.

| 파일 | 확인할 내용 |
|---|---|
| `REPORT.txt` | 요약 판정과 예정 작업 |
| `summary.json` | 작업별 성공·실패, 남은 흔적, 조사 오류 |
| `plan.json` | 해당 실행에서 만든 복구 작업 목록 |
| `before.json`, `after.json` | 실행 전후 관찰 결과 |
| `post-recovery-inventory.json` | 설치 프로그램, 시작 경로, 참조 파일과 조사 범위 |
| `program-recovery-plan.json` | 프로그램별 추가 확인 사항 |
| `EVIDENCE-SHA256.json` | 결과 파일의 무결성 확인 목록 |
| `preserved` | 보존한 원본과 백업. 악성 파일이 들어 있을 수 있음 |

관리자 승인 창이 보이지 않거나 승인이 끝나지 않았다면 복구가 완료된 것이 아닙니다. 도구가 앱을 강제로 종료하거나 Windows를 재부팅하지는 않습니다.

### 사용자 지정 경로

먼저 기본 검사에서 패키지 무결성을 확인한 뒤, 도구 폴더의 64비트 PowerShell에서 실제 설치 경로를 지정할 수 있습니다.

```powershell
.\Invoke-NikkeRecovery.ps1 -Mode Plan -LauncherRoots 'D:\Games\NIKKE\Launcher'

# 작업 목록을 확인한 뒤 관리자 PowerShell에서 실행
.\Invoke-NikkeRecovery.ps1 -Mode Apply -LauncherRoots 'D:\Games\NIKKE\Launcher'

# 같은 경로를 지정하여 재검사
.\Invoke-NikkeRecovery.ps1 -Mode Verify -LauncherRoots 'D:\Games\NIKKE\Launcher'
```

다른 사용자는 `-TargetProfile 'C:\Users\OtherUser'`로 지정합니다. 해당 사용자의 레지스트리 하이브가 이미 로드되어 있어야 하며 도구가 임의로 불러오지는 않습니다. 다른 관리자 계정으로 승인해도 기본 실행기는 처음 선택한 대상 프로필을 전달합니다.

### 복구 후 변화 비교

앱을 다시 실행하거나 사용자가 직접 재부팅한 뒤 새 검사를 수집하면 이전 결과와 비교할 수 있습니다.

```powershell
.\New-NikkeFollowUp.ps1 -InventoryPath 'C:\Evidence\after\post-recovery-inventory.json' -PreviousInventoryPath 'C:\Evidence\before\post-recovery-inventory.json'
```

생성되는 `snapshot-differences.json`에는 시작 경로와 인수, 참조 파일 해시, 브라우저 정책, 등록된 프로그램 버전의 변화가 기록됩니다. `AbsentFromLaterSnapshot`은 나중 조사에서 보이지 않았다는 뜻입니다. 조사 누락일 수 있으므로 제거 성공으로 단정하지 않습니다. 두 결과가 같아도 감염 전 정상 상태와 같다는 뜻은 아닙니다.

## 사후관리

### 한 번 검사하거나 예약하기

`Run-Aftercare.cmd`를 실행하면 알려진 감염 흔적을 재검사하고 이전 조사와 비교합니다. 기본 결과 폴더는 `%LOCALAPPDATA%\NikkeRecovery\Aftercare`입니다. `STATUS.html`에서 가장 최근 상태를, 실행별 `aftercare.json`에서 변경 내역과 재부팅 후 관찰 결과를 확인합니다.

```powershell
# 예약 내용만 파일로 확인
.\Register-NikkeAftercare.ps1 -Mode Plan -Hours 6 -Notify

# 현재 사용자 로그인 3분 후와 6시간 간격으로 읽기 전용 검사
.\Register-NikkeAftercare.ps1 -Mode Install -Hours 6 -Notify

# 예약 상태 확인 / 도구가 만든 예약만 제거
.\Register-NikkeAftercare.ps1 -Mode Status
.\Register-NikkeAftercare.ps1 -Mode Remove
```

예약 검사는 현재 사용자의 일반 권한으로 로그인 중에 실행합니다. 비밀번호를 저장하거나 `SYSTEM` 권한으로 실행하지 않습니다. 같은 사용자에 대한 중복 실행을 막고, 배터리 사용 중에는 예약 실행을 제한합니다. 최초 시간 예약은 등록 약 5분 뒤입니다. 기존 예약은 덮어쓰지 않으므로 주기 변경 시 내용을 확인하고 제거한 뒤 다시 등록합니다. 도구 폴더를 이동하면 예약도 새 경로로 다시 설정해야 합니다.

`-Notify`를 지정하면 새로운 검토 상태에 대해 Windows 알림 표시를 시도합니다. Windows 알림 설정에 따라 보이지 않을 수 있으므로 `STATUS.html`과 `notification.json`도 확인하세요. 외부 전송은 없습니다. 예약 검사는 자동으로 파일을 복구·삭제하거나 Defender 전체 검사를 시작하지 않습니다.

변경된 시작 경로나 파일은 다음 검사에서 그대로라는 이유로 검토 목록에서 사라지지 않습니다. 확인을 마친 변경 내역만 다음처럼 처리할 수 있습니다. `ExpectedAlertSignature`에는 최신 `aftercare.json`의 값을 넣습니다.

```powershell
.\Invoke-NikkeAftercare.ps1 -AcknowledgeChanges -ExpectedAlertSignature 'REPLACE_WITH_CURRENT_ALERT_SHA256'
```

이 명령은 변경 내역을 확인했다는 기록만 남깁니다. 알려진 악성 흔적이나 공급자 기준 대조의 불일치를 정상으로 처리하지 않습니다. 조사 실패 시 이전 관찰 결과는 보존하고 화면에는 실패 상태를 표시합니다.

### 공급자 패키지를 기준으로 대조하기

현재 지원하는 기준 자료는 **같은 버전과 파일 배치를 가진 공급자의 ZIP 패키지**입니다. 공식 배포 경로에서 파일과 SHA-256을 확인한 뒤 사용하세요. 임의로 받은 ZIP의 해시를 계산하는 것만으로 공식 원본이 되는 것은 아닙니다. 기준 목록의 `OperatorPinnedArchive`는 사용자가 지정한 패키지와 일치한다는 뜻이며, `PublisherAuthenticityVerified=false`는 도구가 공급자 신원을 독립적으로 인증하지 않았다는 뜻입니다.

아래 경로·프로그램 버전·주소·해시는 실제 값으로 바꿉니다. ZIP 안에 최상위 폴더가 있으면 `-ArchivePrefix 'ExampleApp'`처럼 지정합니다.

```powershell
# ZIP을 실행하지 않고 파일별 기준 목록 생성
.\Manage-NikkeIntegrity.ps1 -Mode Baseline -PackagePath 'C:\Downloads\ExampleApp-1.0.zip' -PackageSHA256 'REPLACE_WITH_TRUSTED_PACKAGE_SHA256' -ProgramName 'ExampleApp' -ProgramVersion '1.0' -SourceUri 'https://vendor.example/downloads/ExampleApp-1.0.zip'

# 앞 단계가 출력한 baseline.json 경로와 SHA256 사용
.\Manage-NikkeIntegrity.ps1 -Mode Plan -BaselinePath 'C:\Evidence\baseline.json' -BaselineSHA256 'REPLACE_WITH_BASELINE_SHA256' -TargetRoot 'C:\Tools\ExampleApp'
```

일치, 불일치, 누락, 읽기 실패를 구분하고 패키지에 없는 추가 실행 파일은 검토 대상으로 표시합니다. 정상 업데이트도 불일치로 나타날 수 있으므로 설치 버전을 먼저 확인하세요. ZIP은 압축 상태 2 GiB, 전체 해제 크기 1 GiB, 파일당 128 MiB, 최대 20,000개 항목으로 제한합니다. 경로 이탈·중복 경로·심볼릭 링크가 들어 있는 압축은 거부합니다.

### 검토한 파일만 보존하고 복구하기

기준 목록과 작업 계획의 SHA-256을 함께 지정하고 교체할 상대 경로를 명시해야 합니다. 다음 명령은 `-WhatIf`로 적용 없이 선택 내용을 표시합니다. 검토 후 실제 적용할 때만 `-WhatIf`를 제거하세요. 실제 적용 단계에서 패키지와 대상 파일을 다시 검증합니다.

```powershell
.\Manage-NikkeIntegrity.ps1 -Mode Apply -BaselinePath 'C:\Evidence\baseline.json' -BaselineSHA256 'REPLACE_WITH_BASELINE_SHA256' -PlanPath 'C:\Evidence\integrity-plan.json' -PlanSHA256 'REPLACE_WITH_PLAN_SHA256' -PackagePath 'C:\Downloads\ExampleApp-1.0.zip' -RelativePath 'bin\app.dll' -OutputRoot 'C:\Evidence\NikkeRepair' -WhatIf
```

복구 대상은 명시적으로 선택한 `.exe`, `.dll`, `.ocx`, `.pyd`, `.node` 파일입니다. 설정과 사용자 데이터는 교체하지 않습니다. 원본을 해시 검증한 복사본과 원자적 교체 백업으로 보존하고, 교체 후에도 새 파일 해시를 확인합니다. 복구 증거 폴더는 프로그램과 분리된 같은 볼륨에 두세요. 검사 이후 파일이 바뀌거나 잠겨 있으면 실패로 기록하고 후속 교체를 멈춥니다. 이전 악성 파일을 되살리지 않도록 자동 되돌리기는 하지 않습니다.

Windows 시스템 파일, MSIX 관리 폴더, 임의의 MSI·EXE 설치 프로그램 실행은 이 파일 교체 기능의 대상이 아닙니다. 공급자 설치 방식이나 설정 복구가 필요한 프로그램은 별도로 처리해야 합니다. 복구한 프로그램을 다시 시작한 뒤 같은 기준 목록으로 재대조하고 사후 검사를 수집하세요. 재부팅이 관찰돼도 조사 누락이나 미검토 항목이 있으면 `InconclusiveAfterRestart`로 남깁니다.

### 선택한 프로그램의 기준 대조도 예약 검사에 포함하기

다음과 같은 설정 파일을 만들고 그 파일의 SHA-256을 별도로 보관합니다. 한 번에 최대 5개 프로그램을 각 30초의 반복 처리 예산으로 검사합니다.

```json
{
  "Schema": 1,
  "Checks": [
    {
      "BaselinePath": "C:\\Evidence\\baseline.json",
      "BaselineSHA256": "REPLACE_WITH_BASELINE_SHA256",
      "TargetRoot": "C:\\Tools\\ExampleApp"
    }
  ]
}
```

```powershell
.\Invoke-NikkeAftercare.ps1 -BaselineConfigPath 'C:\Evidence\aftercare-baselines.json' -BaselineConfigSHA256 'REPLACE_WITH_CONFIG_SHA256'
```

같은 두 인수를 `Register-NikkeAftercare.ps1 -Mode Install`에도 지정할 수 있습니다. 이 기능은 선정한 프로그램의 파일 대조이며 모든 설치 프로그램의 정상 원본을 자동 수집하는 기능은 아닙니다. 실시간 파일 감시·자동 업데이트 대신 로그인 후와 지정 주기에 조사합니다.

## 결과와 한계

### 판정 읽기

| 판정 | 의미 |
|---|---|
| `KnownIndicatorsRemain` | 알려진 활성 DLL 또는 해당 레지스트리 자동 로딩 흔적이 남음 |
| `AffectedApplicationExitRequired` | 프로세스에 해당 이름의 DLL이 로드되어 있어 앱 종료 후 확인 필요 |
| `ReviewRequired` | 미확인 후보, 읽기 실패, 조사 누락 또는 보호 상태 문제의 추가 확인 필요 |
| `NoKnownActiveIndicatorsWithinScope` | 검사한 범위에서 알려진 활성 흔적을 찾지 못함. PC 전체의 안전 판정은 아님 |

모든 결과는 `WholeHostCleanClaim: false`를 유지합니다. 종료 코드 `0`도 기록된 복구 작업 실패 없이 실행이 끝났다는 뜻이며 감염이 없다는 뜻이 아닙니다. `2`는 복구 작업 실패 또는 검토한 계획과 달라 조치를 건너뛴 경우, `1`은 시작 또는 보고 오류, `1223`은 관리자 승인 취소를 뜻합니다. 일부 Windows 실행 경로에서는 승인 취소도 `1`로 전달됩니다.

복사본을 보존한 뒤 원래 파일 삭제에 실패하면 양쪽에 파일이 남습니다. 이는 격리 완료가 아닙니다. `summary.json`의 작업별 결과와 원래 경로를 함께 확인하세요.

### 해결할 수 없는 부분

- 공격자는 원격 명령으로 추가 프로그램을 설치하거나 다른 파일을 바꿀 수 있었습니다. 이 도구는 알려진 이번 사건의 흔적에 집중하므로 알려지지 않은 추가 악성코드와 변경 사항을 모두 찾아 되돌리지 못합니다.
- 설치 프로그램 목록과 실행 경로를 수집해도 프로그램 전체 파일을 공급자의 정상 원본과 대조한 것은 아닙니다. 별도 대조가 끝나지 않은 프로그램은 `NotIntegrityVerified`, 일괄 조사에서 확인하지 않은 전자서명은 `NotChecked`로 남습니다.
- 보호된 프로세스, 로드되지 않은 사용자 하이브, 선택하지 않은 사용자 파일, 비표준 설치 경로, 포터블·MSIX 앱, 드라이버, 바로가기의 실제 목적지와 스크립트 인수는 누락될 수 있습니다.
- 파일명, 폴더명, 크기, LuaJIT 헤더만으로 악성 여부를 확정하지 않습니다. 알려진 해시와 다르다는 이유만으로 정상 판정하지도 않습니다. 변종 탐지의 오탐·미탐 비율은 충분한 표본에서 측정되지 않았습니다.
- 감염 당시의 악성 `l.js`와 조사 PC에서 내려받았던 정확한 Lua 본체는 확보되지 않았습니다. 다른 시점의 파일과 분석한 `k2f.lua`가 그 빈칸을 모두 대신하지는 못합니다.
- 탈취된 비밀번호·쿠키·세션·API 토큰·SSH 키를 회수하거나 무효화하지 못합니다. 계정 복구와 세션 종료, 필요한 자격 증명 교체는 신뢰할 수 있는 별도 기기에서 진행해야 합니다.
- 백신 검사나 이 도구의 무탐지 결과만으로 재설치 필요성을 배제할 수 없습니다. 포맷 없이 알려진 흔적을 줄일 수 있어도 침해 전 상태로 완전히 돌아갔다는 보증은 할 수 없습니다.

### 조사 범위와 시간 제한

| 조사 | 기본 제한 |
|---|---|
| Lua 후보 | 선택한 런처 로그·캐시와 사용자 Temp, 파일당 16 MiB, 최대 10,000개 파일·5,000개 디렉터리, 깊이 8, 반복 처리 60초 |
| 참조 실행파일 해시 | 최대 750개, 파일당 64 MiB, 반복 처리 120초 |
| 사후 조사 작업 | 별도 읽기 전용 작업 프로세스, 기본 180초 |

시간 제한은 개별 운영체제 파일 읽기를 즉시 중단하는 보장이 아닙니다. 사후 조사 작업이 제한을 넘으면 그 조사 프로세스만 종료하고 이미 저장한 부분 결과를 회수합니다. `WorkerCompleted=false`와 오류, 생략 항목을 확인하세요. 부분 결과에 없거나 해시가 없는 파일은 미확인입니다.

## 작동 원리

### 1. 실행 전 무결성 확인과 조사

기본 실행기는 `PACKAGE-SHA256.json`의 버전, 필수 파일 목록과 SHA-256을 확인한 뒤 검사를 시작합니다. 이 목록은 파일 손상과 불일치를 찾기 위한 것이며 게시자의 전자서명을 대신하지 않습니다.

DLL·Lua·레지스트리·캐시·메모리에 로드된 모듈·통신 차단 상태를 읽고, 설치 프로그램과 Run/RunOnce, 예약 작업, 서비스, 시작 폴더, 브라우저 정책, WMI 구독 및 참조 실행파일을 조사합니다. 조사와 검토 목록 생성 자체는 임의 프로그램을 복구하거나 제거하지 않습니다.

### 2. DLL 및 Lua 식별

DLL은 직접 분석한 샘플의 SHA-256이 일치하면 `Confirmed`로 분류합니다. 해시가 다르면 PE DLL 형식, 지정된 Chrome 하위 경로, 다음 문자열 다섯 개가 모두 맞는 경우에만 `StrongMatch`로 분류합니다.

```text
analytics.insightjs.com/px/
Debugger.paused
Debugger.scriptParsed
Runtime.callFunctionOn
WinHttpSendRequest
```

`StrongMatch`는 엄격한 조건을 묶은 추정 규칙이며 동일한 악성코드임을 완전히 증명하는 것은 아닙니다. 이름만 같은 DLL이나 정상 `platform_experience_helper.exe`는 이 조건으로 제거하지 않습니다.

LuaJIT 형식과 두 치환 테이블 특징이 함께 맞는 파일은 `SuspectedK2f`로 남겨 추가 분석하게 합니다. `log\tinyget` 위치, 숫자 날짜·시간 형태의 `tinyget.*.log` 이름, 205,135바이트 크기가 함께 맞으면 `OfficialTinygetReview`로 기록합니다. 이는 [공식 수동 점검 안내](https://nikke-en.com/newsdetail.html?content_id=ecdccd40a55a5a46aaa9abda64d436082db7)의 검토 조건이며 악성 내용이나 실행을 확정하는 조건은 아닙니다.

Lua 판정은 읽기 전용입니다. 격리 대상 런처 캐시 안의 파일은 캐시와 함께 보존되지만, 그 밖의 Lua 파일은 자동 삭제하지 않습니다. Lua 인터프리터나 악성 원본은 배포 패키지에 넣지 않습니다.

### 3. 통신 차단과 자동 로딩 설정 정리

`Apply`는 알려진 공격자 IP를 방화벽에서 차단하고 도메인을 `hosts`에 추가합니다. 발견한 NIKKE 런처 실행파일에도 통신 차단을 적용합니다. 기존에 충분한 차단이 있으면 재사용합니다. 이 차단으로 게임 이용도 제한될 수 있으며 도구가 자동 해제하지는 않습니다.

레지스트리는 대상 사용자의 해당 CLSID만 다룹니다. 확인된 DLL을 가리키거나 알려진 빈 사용자 등록이면 백업 후 제거합니다. 예상 밖 대상이나 하위 키는 보존하고 검토 대상으로 남깁니다. 정상 `HKLM` 등록은 수정하지 않습니다.

### 4. 원본 보존과 격리

DLL은 보존 복사본의 SHA-256을 대조하고 원본이 바뀌지 않았는지 다시 확인한 뒤 원래 위치에서 제거합니다. 런처 캐시는 파일별 상대 경로·크기·해시 목록을 만들고 같은 볼륨의 보존 폴더로 이동한 뒤 대조합니다.

결과 폴더는 해당 사용자, `SYSTEM`, `Administrators`가 접근하도록 제한합니다. 경로 이탈, UNC 경로, 재분석 지점과 허용하지 않는 별도 데이터 스트림은 거부하거나 수동 검토로 남깁니다. 보존 실패나 격리 실패를 성공으로 처리하지 않습니다.

### 5. 복구 후 재확인

복구 후 다시 상태를 읽어 남은 흔적과 실패 사항을 보고합니다. 프로그램별 후속 계획은 파일·설정의 추가 조사와 정상 원본 대조를 돕는 목록입니다. 레지스트리에서 읽은 임의 복구 명령을 실행하거나 모든 프로그램을 자동 재설치하지는 않습니다.

## 악성코드 해시와 주요 지표

다음 SHA-256은 파일 식별용입니다. 파일이 있다는 사실과 실제로 실행되거나 정보가 유출되었다는 사실은 구분해야 합니다.

| 파일 | 크기 | SHA-256 | 근거와 도구 반영 |
|---|---:|---|---|
| `platform_experience_helper.dll` | 250,368바이트 | `10e722777685e290e8fd5370d4c5cd1a40d0d7e91b93af0156faefe18467a3f1` | 직접 회수·정적 분석한 DLL. 정확한 해시 탐지에 반영 |
| `insight.bundle` | 205,135바이트 | `cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec` | `MotherSphere`가 공개한 참고 해시. 현재 도구의 정확한 해시 목록에는 미포함 |

공개 샘플 해시와 빌드 차이는 [MotherSphere의 분석](https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5#indicators-of-compromise)에서 확인할 수 있습니다. 같은 크기의 다른 빌드가 있으므로 파일 크기만으로 동일 샘플이라고 판단하면 안 됩니다.

| 지표 | 값과 의미 |
|---|---|
| 사용자 COM 등록 | `HKCU\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}` |
| DLL 위치 | `%LOCALAPPDATA%\Google\Chrome\User Data\PlatformExperienceHelper\<SHA256>\platform_experience_helper.dll`. `<SHA256>`은 64자리 16진수 폴더명 |
| 런처 캐시 | `AppData\Roaming` 및 `AppData\Local` 아래 `nikke_launcher`, `nikke_launcher_hmt`, `nikke_launcher_google`의 `tbs_cache` |
| 조사 참고 로그 | `k2f_chan registered`, `k2f.agent.state`. 이 문자열 목록이 범용 로그·LevelDB 분석기의 구현을 의미하지는 않음 |
| 차단 도메인 | `insightjs.com`, `analytics.insightjs.com`, `insightjs.org` |
| 차단 IP | `89.127.233.127`, `89.126.250.172` |

정상 `PlatformExperienceHelper` 폴더 전체, Chrome 확장 프로그램과 지갑 데이터, 게임 실행파일, Windows 시스템 파일은 일괄 삭제하거나 패치하지 않습니다. 위 주소는 식별과 차단을 위한 정보이며 확인하려고 직접 접속할 필요가 없습니다.

## 검증 상태와 증거 취급

Windows PowerShell 5.1과 PowerShell 7.6.5에서 각각 기본 32개, 확장 31개, 사후관리·기준 대조 39개, 패키지 검사 6개, 합성 CLI 작업 흐름 10개, 작업 프로세스 결과 처리 4개가 통과했습니다. 합계 244건은 합성 자료와 시험용 조사 입력에 대한 실행 결과이며 실제 감염 PC의 복구 횟수가 아닙니다.

Windows 작업 스케줄러가 예약 XML을 유효하다고 확인했으며, 검증 과정에서 작업을 실제 등록하지 않았습니다. Microsoft 서명이 유효한 Procmon64.exe도 보관한 공식 ZIP과 읽기 전용으로 대조했습니다. 실제 예약 실행과 화면 알림 전달은 아직 검증하지 않았습니다.

결과 파일에는 개인 경로와 실행 인수가, `preserved`에는 악성 원본이 포함될 수 있습니다. 공유할 때는 도구 배포 ZIP과 개인 실행 결과를 구분하세요. 보존 파일을 실행하거나 레지스트리 백업을 무작정 복원하면 안 됩니다.

이 도구에는 원격 업로드, 통계 수집, 자동 업데이트, 악성코드 실행 기능이 없습니다. 백신 설정과 제외 항목을 변경하거나 Defender 전체 검사·오프라인 검사를 자동 실행하지도 않습니다. 실행기의 `ExecutionPolicy Bypass`는 해당 자식 PowerShell 프로세스에만 적용됩니다.

## 출처와 기여

- **[MotherSphere](https://github.com/MotherSphere)** — [NIKKE PC 런처 침해 분석 Gist](https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5)의 작성자입니다. 공격 흐름, 감염 지표와 댓글의 후속 조사 내용을 참고했습니다.
- **[MotherSphere / NIKKE-Launcher-Check](https://github.com/MotherSphere/NIKKE-Launcher-Check)** — Gist에서 안내하는 읽기 전용 탐지 도구입니다. 탐지 범위와 보고 방식을 비교할 때 참고했습니다.
- **[NIKKE / Level Infinite](https://nikke-en.com/newsdetail.html?content_id=ecdccd40a55a5a46aaa9abda64d436082db7)** — 공식 수동 점검 안내의 경로와 파일 크기 조건을 대조했습니다.
- **[Microsoft Task Scheduler](https://learn.microsoft.com/en-us/windows/win32/taskschd/taskfolder-registertask)** — 예약 설정의 등록 없는 유효성 검증에 참고했습니다. 파일 교체는 [.NET File.Replace 문서](https://learn.microsoft.com/en-us/dotnet/api/system.io.file.replace)를 참고했습니다.
- **v3s9er_PC** — 직접 확보한 DLL, 런처 캐시·로그, 레지스트리 및 시스템 기록과 이를 대조한 독립 분석의 출처입니다. 개인 조사 기록과 악성 원본은 패키지에 포함하지 않습니다.

출처 표기는 참고와 기여에 대한 표시이며 해당 작성자의 공동 개발, 검수 또는 안전성 보증을 뜻하지 않습니다.

## 라이선스

이 프로젝트의 코드와 문서는 **MIT License**로 배포합니다. 전문은 [LICENSE](LICENSE)에 있습니다.

저작권 및 라이선스 고지를 유지하는 조건으로 사용, 복사, 수정, 배포와 상업적 이용을 허용합니다. 소프트웨어는 별도 보증 없이 제공됩니다. 정확한 조건은 MIT 원문을 따릅니다.

연결한 외부 프로젝트·분석 자료·악성 샘플의 권리와 라이선스는 각각 별개이며, 이 프로젝트의 MIT 표기가 그 자료의 라이선스를 변경하지 않습니다.
