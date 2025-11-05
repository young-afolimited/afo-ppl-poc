@REM @echo off
@REM REM Set variables
@REM set IMAGE_NAME=afo-ppl-poc_image
@REM set CONTAINER_NAME=afo-ppl-poc_container
@REM set DOCKERFILE_PATH=.

@REM REM Build the image if it doesn't exist
@REM docker image inspect %IMAGE_NAME% >nul 2>&1
@REM if errorlevel 1 (
@REM     echo Building Docker image %IMAGE_NAME%...
@REM     docker build -t %IMAGE_NAME% %DOCKERFILE_PATH%
@REM )

@REM REM Check if the container is already running
@REM docker ps -a --format "{{.Names}}" | findstr /i "^%CONTAINER_NAME%$" >nul
@REM if %errorlevel%==0 (
@REM     echo Stopping and removing existing container %CONTAINER_NAME%...
@REM     docker stop %CONTAINER_NAME%
@REM     docker rm %CONTAINER_NAME%
@REM )

@REM REM Start the container
@REM echo Starting container %CONTAINER_NAME%...
@REM docker run -d --name %CONTAINER_NAME% %IMAGE_NAME%

docker compose up --build -d