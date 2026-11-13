@echo off
setlocal EnableExtensions
title NukeIt  -  force delete
cd /d "%~dp0"
cls

set "PYEXE="
set "PYARG="

py -3 -c "import sys" >nul 2>&1
if not errorlevel 1 goto use_py

python -c "import sys;raise SystemExit(0 if sys.version_info[0]==3 else 1)" >nul 2>&1
if not errorlevel 1 goto use_python

if exist "C:\Program Files\ArcGIS\Pro\bin\Python\envs\arcgispro-py3\python.exe" goto use_arcgis

goto no_python

:use_py
set "PYEXE=py"
set "PYARG=-3"
goto run

:use_python
set "PYEXE=python"
goto run

:use_arcgis
set "PYEXE=C:\Program Files\ArcGIS\Pro\bin\Python\envs\arcgispro-py3\python.exe"
echo   [NukeIt] using ArcGIS Pro python runtime
goto run

:run
"%PYEXE%" %PYARG% "%~dp0nuke.py" %*
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" goto failed
goto done

:failed
echo.
echo   [NukeIt] 有目标没删掉，仔细看上面的提示。
echo.
pause
goto done

:no_python
echo.
echo   [NukeIt] Python 3 not found on this machine.
echo   Falling back to minimal mode (cmd rd / del).
echo   Limits: no locker detection, no reboot-delete, no long path.
echo.
set "TGT="
set /p "TGT=Drop the file or folder here, then press Enter: "
if not defined TGT goto done
set "TGT=%TGT:"=%"
if not exist "%TGT%" goto no_python_missing
echo.
echo   Target : %TGT%
echo   Notice : permanent delete, cannot be undone.
echo.
set "OK="
set /p "OK=Type Y to continue: "
if /i not "%OK%"=="Y" goto done
rem rd does not follow junctions or symlinks, unlike Remove-Item -Recurse
if exist "%TGT%\" (rd /s /q "%TGT%") else (del /f /q /a "%TGT%")
echo.
echo   Finished.
echo.
pause
goto done

:no_python_missing
echo.
echo   Path not found: %TGT%
echo.
pause
goto done

:done
set "FINAL=%RC%"
endlocal & exit /b %FINAL%
