# NetChecker — 시그널부스터

팀원: 유지흠 · 정수원 · 전병복 · 김기웅

PC·Windows 서버에 설치한 수집 Agent가 장비 상태와 통신 자료를 중앙 서버에 전송합니다. 대시보드와 일일 보고서로 이상 징후, 성능 점검 대상, 트래픽 원인과 조치 후 변화 확인을 지원합니다.

## 기능과 AI 역할
- 통신량·접속량·서버 포트 관측과 실시간 대시보드
- 일일 운영 보고서: 분석 → 근거 검증 → 우선 점검 목록. CrewAI는 별도 작업 환경에서 실행합니다.
- AI 디펜더: 별도 보안 수집 경로, 약 1시간마다 보안 상태·이벤트·업데이트 후보를 전송하고 일일 보고서에 포함합니다.
- 보안 AI는 관측 자료와 불확실성을 검토합니다. 침입 확정이나 AI 공격 차단 성능을 보증하지 않습니다.
- 패치·일시 차단은 관리자 승인과 대상 검증을 거쳐 실행하며 결과를 재검증합니다. 자동 재부팅하지 않습니다.
- 공공데이터 공휴일·기상 참고 자료, 카카오 알림. 각 외부 서비스 인증·권한은 사용자가 별도로 설정합니다.

## 서버 실행 준비
Python 3.11+ 권장. 아래 명령은 프로젝트 폴더에서 실행합니다.

```sh
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python setup_config.py
python -m uvicorn server:app --host 127.0.0.1 --port 8003
```

운영 웹 로그인은 Secure 쿠키를 사용하므로 HTTPS 역방향 프록시가 필요합니다. 예제 주소 `netchecker.example.com`을 본인 도메인으로 교체하고 프록시에서 `/netchecker/` 경로를 맞추세요. 실제 인증키는 로컬 `config.json` 또는 관리자 연동 설정에 입력하며 Git에 넣지 않습니다. `NETCHECKER_STATE`와 `NETCHECKER_CONFIG` 환경변수로 상태·설정 경로를 지정할 수 있습니다.

CrewAI 작업 환경은 메인 서버와 분리하여 `requirements-crew.txt`로 설치하고 `crewai_python`을 해당 Python 경로로 설정합니다. Linux 예제 경로를 Windows에 맞게 조정해야 합니다. AI 기능은 별도의 모델 제공자 API 키와 사용 요금이 필요합니다.

## Windows Agent 빌드
수집기 PowerShell 원본과 C# UI·설치기 원본을 제공합니다. Windows 관리자 권한 및 .NET Framework 빌드 도구가 필요합니다. `flow/NetChecker.Flow.csproj`에 TraceEvent 의존성 버전이 선언되어 있습니다. 기존 `flow/Build-Flow.ps1`은 `flow/packages`의 NuGet 패키지 구조를 사용하므로 패키지를 복원·준비한 후 실행하세요. 그 뒤 `installer/Build.ps1`, `Build-Server.ps1`, `Build-Defender.ps1`로 EXE를 생성합니다. 공개용 EXE 재빌드는 아직 검증하지 않았습니다. 예제 서버 주소를 먼저 수정해야 합니다.

## 검증과 공개 범위
원본 기능 테스트를 포함합니다. 공개본은 비공개 값 치환 후 Python 구문 검사와 정적 검토를 수행했습니다. 외부 API 실연동, 새 도메인 배포와 공개본 설치 EXE 재빌드는 별도 검증이 필요합니다. 운영 DB·로그·실제 보고서·화면 캡처·SSH 키·기존 실행 파일은 포함하지 않습니다. 기존 Git 이력도 포함하지 않습니다.

네트워크 수집과 디펜더는 목적과 수집 경로가 분리됩니다. 백신 자체 엔진은 구현하지 않으며 악성코드 검사는 Windows Defender 기능을 호출합니다. 타사 백신이나 권한 부족으로 확인하지 못한 항목을 정상으로 간주하지 않습니다.

## 라이선스
팀 소유 소스는 MIT License로 공개합니다. 사용·수정·재배포가 가능하며 저작권 및 라이선스 고지를 유지해야 합니다. 외부 라이브러리는 각각의 라이선스를 따릅니다. `THIRD_PARTY.md`와 `PUBLIC_RELEASE_CHECKLIST.md`를 확인하세요.

PDF 한글 출력은 NanumGothic/NanumGothicBold 시스템 글꼴이 필요합니다. Linux에서는 배포판의 나눔 글꼴 패키지를 설치하세요. 글꼴 바이너리는 포함하지 않았습니다.
