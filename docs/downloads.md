# croakcode 내려받기

게이트는 `/download/`에서 파일을 로그인 없이 제공한다. 서버의 `~/croak/downloads/`에 파일을 둔다. Caddy는 이 폴더를 읽기 전용으로 사용한다.

게이트 배포 뒤 관리자의 PC에서 다음 명령을 실행한다. 묶음은 croakcode의 `scripts/package-release.py`로 만든다. CA 인증서는 공개 인증서만 지정한다. 개인 키는 올리지 않는다.

```sh
CROAK_GATE_HOST=서버접속대상 ./upload-release.sh RELEASE_DIR CA_CERT [INSTALLER_DIR]
```

`RELEASE_DIR`에는 다섯 운영체제 대상의 묶음과 `manifest.json`, `SHA256SUMS`가 필요하다. 서버에서 묶음 크기와 SHA-256을 다시 확인한다. 확인이 끝나면 파일을 공개하고 목록을 마지막에 바꾼다. 같은 버전은 다시 올릴 수 없다.

`INSTALLER_DIR`을 지정하면 `install.sh`와 `install.ps1`도 함께 올린다. 설치 스크립트는 Phase 6의 다음 작업에서 만든다. 새 버전 외에 이전 버전 두 개를 보관한다. 업로드에는 서버의 Python 3와 `flock`이 필요하다. 파일 업로드와 게이트 배포는 관리자가 실행한다.
