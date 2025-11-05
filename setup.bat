@echo off
REM Create Python virtual environment and install requirements

REM Set the name of the virtual environment folder
set VENV_DIR=.venv

REM Check if virtual environment exists
if exist %VENV_DIR%\Scripts\activate.bat (
    echo Virtual environment already exists.
) else (
    echo Creating virtual environment...
    python -m venv %VENV_DIR%
)

REM Activate the virtual environment
call %VENV_DIR%\Scripts\activate.bat

REM Upgrade pip
python -m pip install --upgrade pip

REM Install requirements if requirements.txt exists
if exist requirements.txt (
    if exist %VENV_DIR%\Scripts\activate.bat (
        pip install -r requirements.txt
    ) else (
        pip install --no-cache-dir -r requirements.txt
    )
) else (
    echo No requirements.txt found.
)

echo Virtual environment setup complete.