@echo off
echo build vault gmsm plugin ......
del ..\plugin\vault-gmsm-plugin.exe /s /f /q
del ..\plugin\pki-gmsm.exe /s /f /q
go build -o ..\plugin\vault-gmsm-plugin.exe ..\main.go
go build -o ..\plugin\pki-gmsm.exe ..\cmd\pki-gmsm\main.go
CertUtil -hashfile ..\plugin\vault-gmsm-plugin.exe SHA256 | findstr /v "hash" > ..\plugin\plugin.sha256sum
CertUtil -hashfile ..\plugin\pki-gmsm.exe SHA256 | findstr /v "hash" > ..\plugin\pki-gmsm.sha256sum
echo Done!
