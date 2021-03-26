@echo off
echo build vault gmsm plugin ......
del ..\plugin\vault-gmsm-plugin.exe /s /f /q
go build -o ..\plugin\vault-gmsm-plugin.exe ..\main.go
CertUtil -hashfile ..\plugin\vault-gmsm-plugin.exe SHA256 | findstr /v "hash" > ..\plugin\plugin.sha256sum
echo Done!