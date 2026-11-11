# croakcode 내려받기

게이트는 `/download/`에서 파일을 로그인 없이 제공한다. 서버의 `~/croak/downloads/`에 파일을 둔다. Caddy는 이 폴더를 읽기 전용으로 사용한다.

게이트 배포 뒤 관리자의 PC에서 다음 명령을 실행한다. 묶음은 croakcode의 `scripts/package-release.py`로 만든다. CA 인증서는 공개 인증서만 지정한다. 개인 키는 올리지 않는다.

```sh
CROAK_GATE_HOST=서버접속대상 ./upload-release.sh RELEASE_DIR CA_CERT [INSTALLER_DIR]
```

`RELEASE_DIR`에는 다섯 운영체제 대상의 묶음과 `manifest.json`, `SHA256SUMS`가 필요하다. 서버에서 묶음 크기와 SHA-256을 다시 확인한다. 확인이 끝나면 파일을 공개하고 목록을 마지막에 바꾼다. 같은 버전은 다시 올릴 수 없다.

`INSTALLER_DIR`은 croakcode의 `scripts/`다. 지정하면 설치 스크립트(`install.sh`, `install.ps1`)와 더블클릭 설치 파일(`croakcode-setup.sh`, `croakcode-setup-windows.cmd`)도 함께 올린다.

## 게이트 주소와 내려받기 페이지

공개할 때 서버 `.env`의 `CROAK_PUBLIC_URL`을 읽어 설치 파일의 `__CROAK_GATE__` 자리에 넣는다. 그래서 사용자는 게이트 주소를 따로 넣지 않는다. 값이 없으면 설치 파일을 그대로 두고, 사용자가 주소를 넣어야 한다.

같은 단계에서 다음을 만든다.

| 파일 | 내용 |
|---|---|
| `index.html` | `/download/`의 안내 페이지. 운영체제별 설치 파일 링크와 터미널 명령, 인증서 지문을 보인다 |
| `croakcode-setup-windows.cmd` | Windows용. 더블클릭하면 설치한다 |
| `croakcode-setup-macos.zip` | macOS용. 안의 `croakcode-setup.command`는 실행 권한을 유지한다 |
| `croakcode-setup-linux.sh` | Linux와 WSL용. `bash`로 실행한다 | 새 버전 외에 이전 버전 두 개를 보관한다. 업로드에는 서버의 Python 3와 `flock`이 필요하다. 파일 업로드와 게이트 배포는 관리자가 실행한다.
