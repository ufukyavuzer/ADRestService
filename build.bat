@echo off
echo Building AD Rest Service executable...
python -m PyInstaller adRestService.py -F --windowed --add-data "favicon.ico;ico" --icon "favicon.ico" --distpath Output\dist --workpath Output\build
echo Build completed!
pause
