# 검증 범위 / Validation scope

검증일: 2026-11-05. 현재 버전: `0.4.4-preview`.

직접 확보한 DLL과 PC의 이벤트·실행 기록 출처: **v3s9er_PC**.

## 0.4.4 복구 승인과 배포 파일 검증

- REA 6.8.0으로 이전 `NikkeCR.exe`의 .NET 메타데이터와 CIL을 실행 없이 확인했습니다. `MainForm`의 32개 메서드가 완전히 해석됐고 선언된 P/Invoke는 0개였습니다. 이는 실행 중 동작이나 버그 부재의 증명은 아닙니다.
- 탐지 후 복구 전에 같은 경로의 DLL 해시 또는 COM 값이 바뀌면 이전 승인으로 해당 조치를 실행하지 않습니다. 승인 불일치로 조치가 남으면 종료 코드 `2`를 반환합니다. `-WhatIf` 실행은 실제 조치가 없으므로 이 규칙에서 제외합니다.
- 실행 파일의 배포 무결성 검사에서 파일뿐 아니라 상위 폴더의 링크도 거부합니다. 실행 중 로그가 8 MiB를 넘으면 화면 갱신만 멈추고 결과 파일과 복구 작업은 계속 진행합니다.
- 국문·영문 README에서 세부 화면 조작 설명을 제거했습니다.
- Windows PowerShell 5.1·PowerShell 7에서 NikkeCR 검사 각 30개, Windows PowerShell 5.1에서 엔진 기본 36개·확장 31개·사후관리 39개와 패키지 검사를 통과했습니다. 실행 코드가 없는 시험 자료를 사용했으며 새로운 실감염 PC의 전체 복구를 입증한 결과는 아닙니다.
- 새 실행 파일을 REA로 다시 확인해 `MainForm`의 33개 메서드가 완전히 해석되고, `VerifyPackage`에서 상위 경로 검사 호출 2회와 `Poll`에서 스트림 길이 확인 호출이 나타나는 것을 확인했습니다. 네이티브 호출 선언은 없었습니다.

## 0.4.3 실행 기록 구분 검증

- MotherSphere의 [NIKKE Launcher Check 0.5.2 변경](https://github.com/MotherSphere/NIKKE-Launcher-Check/compare/0e09c7c422c48103856a933a3b910b51ba7b83da...b7b7c08ee3ca)을 대조했습니다. `k2f_chan registered`는 채널 등록, 뒤따르는 `startup failed`는 해당 실행의 시작 실패, `adopted`·`resuming`·`agent started as`는 후속 시작 단계로 구분합니다. 관련 없는 시작 실패 문구는 무시합니다.
- 실제 PC의 보존된 런처 로그에는 채널 등록 뒤 `adopted`와 `agent started as`가 이어집니다. 구분 결과는 기록된 실행 단계의 근거이며 공격자 명령이나 유출 내용의 증명이 아닙니다.
- Windows PowerShell 5.1과 PowerShell 7에서 각각 29개 검사를 통과했습니다. 복구 엔진의 조치 범위는 변경하지 않았습니다.

## 0.4.2 결과 표시 검증

- 복구 완료 직후 이전 검사에서 찾은 DLL 경로가 여전히 `추가 확인 필요`로 보이던 문제를 수정했습니다. 승인된 격리 조치의 완료 기록, 보존본의 SHA-256, 원래 경로의 부재를 모두 확인한 경우에만 `복구 후 확인`으로 표시합니다. 하나라도 충족하지 않으면 `추가 확인 필요`로 유지합니다.
- 복구 직후 카드의 `복구 계획 항목` 표기를 `이번 복구 계획`으로 바꿔 완료된 실행의 계획을 새로 해야 할 조치로 오해하지 않게 했습니다. 실행 결과는 `탐지 결과`의 조치별 상태에서 확인합니다.
- Windows PowerShell 5.1과 PowerShell 7에서 각각 28개 검사를 통과했습니다. 복구 엔진의 조치 범위는 바꾸지 않았습니다.

## 0.4.1 화면 변경 검증

- 실행로그를 복구 계획 다음 탭으로 옮기고, 저장된 결과를 열었을 때 해당 실행의 로그를 읽는 동작을 확인했습니다.
- 실제 창을 최대화하고 폭 약 850px로 줄여 표 너비 변경, 두 줄 카드 배치, 입력란 재배치와 스크롤을 확인했습니다.
- 기본 12pt에서 14pt로 글자를 확대하고, 행을 두 번 클릭하여 읽기 전용 상세 창이 열리는 것을 확인했습니다. 글자 크기는 10–20pt 범위에서 조절할 수 있습니다.
- Windows PowerShell 5.1에서 NikkeCR의 기존 27개 검사를 통과했습니다. 이번 변경은 화면·가독성·로그 표시와 배포 버전 정보이며 복구 엔진의 조치 범위를 늘리지 않았습니다.

## 0.4.0에서 수행한 검증

| 항목 | 결과와 범위 |
| --- | --- |
| NikkeCR 테스트 | Windows PowerShell 5.1 및 PowerShell 7에서 각각 27개 통과 |
| 복구 엔진 테스트 | Windows PowerShell 5.1에서 기본 32개, 확장 31개, 사후 관찰 39개 통과 |
| 실제 GUI 탐지 | 일반 사용자 권한으로 탐지 버튼 실행 → 진행 로그 갱신 → 결과 표시까지 완료. 설치 프로그램·실행 연결·복구 계획 탭을 화면에서 확인 |
| 실제 이벤트 기록 파싱 | 보존된 System 기록 65개를 모두 해석. 빈 XML 필드도 처리. 이벤트 번호와 공급자를 함께 구분하여 서비스 설치 64건, 로그 삭제 0건으로 분류 |
| DLL 명령어 교차 검증 | 703개 함수의 명령어 44,738개를 원본 PE 바이트 및 Capstone 명령어 경계와 대조, 불일치 0개 |
| DLL 라이브러리 후보 | Ghidra Function ID가 132개 함수에 후보를 제시. 단일 이름 111개·여러 이름 21개. 후보 일치는 의미 동등성 증명이 아님 |
| Lua 구조 검증 | 277개 프로토타입·명령어 26,978개에서 분기 목적지 1,630개와 클로저 생성 276곳의 참조·범위를 검증, 오류 0개 |

새 테스트는 조작되거나 다른 PC에서 가져온 HAR의 유출 확정 방지, 비밀 값 비출력, 유사 도메인 거부, 파일 읽기 제한, 빈 이벤트 필드, 서비스 명령 인수 제외, 경로 깊이 제한, Unicode JSON, 검토 후 변경된 설정 거부, 실제 임시 레지스트리 값의 백업 및 정확한 값 이름만 제거하는 동작을 포함합니다.

GUI 검증 중 Windows PowerShell 5가 상위 PowerShell 7의 모듈 경로를 상속하여 시작에 실패하는 문제를 발견했습니다. 작업 프로세스에서 기본 모듈 경로를 선택하도록 수정하고 실제 버튼 실행으로 재확인했습니다. 실행 실패는 안전 판정으로 바꾸지 않습니다.

## 완료하지 못한 검증

- 위 명령어·구조 검사는 모든 함수의 의미, 간접 호출 대상, 예외 경로 또는 실행 성공을 완전히 증명하지 않습니다.
- 정확한 로컬 Lua와 당시 악성 `l.js`가 없어 전체 감염 경로의 동일성은 입증하지 못했습니다.
- 확보한 과거 로그에는 전송 본문이 없습니다. SRUM 통신량은 탈취 항목·목적지·서버 보관을 증명하지 않습니다. 실제 유출 목록과 전체 호스트 복구 성공은 입증되지 않았습니다.
- 모든 사용자·보호 프로세스·커널·펌웨어·미지의 추가 페이로드에 대한 검증이 아닙니다.

테스트에 사용하는 가짜 DLL 및 레지스트리 값은 실행 불가능하거나 비활성인 합성 자료입니다. 합성 테스트를 실제 악성코드 동적 분석으로 표현하지 않습니다. 개인 경로·이벤트·원본 샘플·자격증명은 이 저장소에 포함하지 않습니다.

## English

For 0.4.3, launcher history distinguishes channel registration, startup failure after registration, and subsequent agent startup. Unrelated startup-failure lines are ignored. This follows the newer MotherSphere detection logic and does not infer attacker commands or exfiltration. All 29 NikkeCR checks passed on Windows PowerShell 5.1 and PowerShell 7. The engine's action scope is unchanged.

For 0.4.2, a completed DLL quarantine is reported as repaired only when the approved action succeeded, the preserved copy still matches SHA-256, and the original path is absent. Otherwise the finding remains for review. The repair card now labels the plan as belonging to this run. All 28 NikkeCR checks passed on Windows PowerShell 5.1 and PowerShell 7. The engine's action scope is unchanged.

For 0.4.1, the execution-log tab, saved progress logs, maximized and narrow-window layouts, 12-to-14 pt text resizing, and the row-detail dialog were verified in the Windows UI. All 27 NikkeCR checks passed on Windows PowerShell 5.1. The recovery engine's action scope is unchanged.

On 2026-11-05, 27 NikkeCR checks passed on each of Windows PowerShell 5.1 and PowerShell 7. The embedded engine passed 32 core, 31 extended and 39 aftercare checks on Windows PowerShell 5.1. A real standard-user GUI detection completed with visible progress and populated result tabs.

Static verification cross-checked 44,738 native instructions across 703 functions against preserved PE bytes and an independent decoder. Lua operand/branch/closure checks covered 277 prototypes and 26,978 original instructions. These are structural checks, not complete semantic proof. FID matches remain candidates.

Exact historical exfiltration contents and complete host eradication remain unproven. Synthetic fixtures are never counted as live-malware tests.
