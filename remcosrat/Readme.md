# Remcos RAT Config Extractor

Remcos RAT 7.2.0 Pro의 `SETTINGS` 리소스에서 암호화된 설정을 복호화하고
필드 단위로 파싱한다.

## 사용법

```bash

python extractor.py sample.exe              # 기본 출력
python extractor.py sample.exe --json       # JSON 형태로 출력
python extractor.py sample.exe -o ./output_sample.json     # JSON 파일로 저장
```

## Config 구조

`SETTINGS` (RCDATA) 리소스에 구분자를 기준으로 필드 형식으로 저장된다.
## Field Map
분석 후 필드가 어디에 쓰이는지 기록
