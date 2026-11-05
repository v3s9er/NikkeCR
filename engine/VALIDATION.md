# 복구 엔진 검증 / Recovery engine validation

## 현재 포함된 엔진

2026-11-05, NikkeCR 0.4.4-preview에 포함된 엔진을 Windows PowerShell 5.1에서 다시 검사했습니다.

| 시험 | 통과 수 |
| --- | ---: |
| 기본 탐지·경계·보존 및 복구 승인 대조 | 36 |
| Lua 식별·추가 조사·범위 제한 | 31 |
| 사후 관찰·기준 대조·선택 파일 복구 | 39 |
| 합계 | 106 |

이 수치는 시험 사례의 수이며 복구한 PC 대수가 아닙니다. 실행 코드가 없는 합성 파일과 시험용 조사 입력을 사용합니다. 실제 DLL 식별 및 PC 기록 대조의 출처는 **v3s9er_PC**입니다.

검증에는 원본 바이트 보존, 경로 경계·재분석 지점·대체 스트림 거부, 예상하지 않은 레지스트리 대상 거부, 해시 변경 시 복구 거부, 접근 실패 시 보존본 유지, 불완전한 조사 범위 표시, 기준 패키지 대조 및 선택 파일 복원 등이 포함됩니다.

0.3.1 엔진에서는 탐지 결과와 복구 직전의 DLL 해시·COM 설정 값을 대조합니다. 값이 바뀌어 조치를 건너뛰면 성공 종료로 표시하지 않는 경계를 합성 시험으로 확인했습니다.

이전 0.3.0 검증에서는 PowerShell 5.1·7 각각 기본 32개, 확장 31개, 사후관리 39개, 패키지 사전 검사 6개, 합성 CLI 작업 흐름 10개, 작업 프로세스 결과 처리 4개가 통과했습니다. 당시의 총 244회 실행과 이번 102회 재검증을 구분합니다.

Windows Task Scheduler의 TASK_VALIDATE_ONLY로 예약 XML을 검증했으며 실제 예약 작업은 등록하지 않았습니다. 실제 예약 실행과 화면 알림 전달은 별도 확인이 필요합니다. Microsoft 서명이 유효한 Procmon64.exe를 보관한 공식 ZIP과 읽기 전용으로 대조한 결과도 전체 프로그램의 무결성 보증으로 해석하지 않습니다.

## 실제 PC 근거와 한계

- 출처 **v3s9er_PC**의 정확한 해시 DLL에 대해 단일 파일 보존·격리 분기가 수행됐습니다. 보존본 해시가 일치하고 선택한 원래 경로가 사라진 것을 확인했습니다. 모든 복구 분기나 전체 PC의 복구 성공을 뜻하지 않습니다.
- 앞선 접근 거부 사례에서는 파일이 적재된 앱이 남아 있었으며, 실패한 조치를 성공으로 처리하지 않고 보존본·실패 상태·종료 코드를 남겼습니다.
- 모듈 접근 실패, 시간·개수 한도, 미검토 변경은 검사 누락으로 표시합니다. 조사 결과가 0개라는 이유만으로 전체 안전 판정을 내리지 않습니다.
- 공급자 원본과 감염 전 기준점이 없는 모든 프로그램을 자동으로 복원하거나, 이미 탈취된 계정·토큰·세션을 복구하는 기능은 아닙니다.

GUI 및 상위 모듈의 검증은 [NikkeCR 검증 기록](../docs/VALIDATION.md)을 참고하세요.

## English

The currently embedded engine passed 32 core, 31 extended, and 39 aftercare checks on Windows PowerShell 5.1 on 2026-11-05. These 102 checks use inert fixtures and controlled inputs. The earlier 244 executions across PowerShell 5.1 and 7 are a separate historical result.

Direct DLL and host-record evidence is attributed to **v3s9er_PC**. The exact-hash single-file preservation/quarantine branch was observed, including matching preserved bytes and removal from the selected original path. This does not establish success for every repair branch or complete host remediation. Coverage gaps, failed actions, and unresolved changes remain visible.
