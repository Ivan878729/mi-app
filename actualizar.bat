@echo off
cls
echo 🔍 Verificando cambios en Git...
git status
echo.

set /p mensaje=📦 Escribe un mensaje para el commit: 

if "%mensaje%"=="" (
    set mensaje=Actualizacion automatica
)

echo.
echo ✅ Agregando archivos...
git add .

echo 📝 Haciendo commit...
git commit -m "%mensaje%"

echo 📤 Haciendo push a GitHub...
git push origin main

echo.
echo 🚀 ¡Repositorio actualizado con éxito!
pause
