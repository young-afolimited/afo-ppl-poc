@REM @echo off
@REM REM Remove containers and images created by docker-compose
@REM docker-compose down --rmi all

@REM REM Remove manually created container and image (if they exist)
@REM set CONTAINER_NAME=afo-ppl-poc_container
@REM set IMAGE_NAME=afo-ppl-poc_image

@REM docker ps -a --format "{{.Names}}" | findstr /i "^%CONTAINER_NAME%$" >nul
@REM if %errorlevel%==0 (
@REM     echo Stopping and removing container %CONTAINER_NAME%...
@REM     docker stop %CONTAINER_NAME%
@REM     docker rm -f %CONTAINER_NAME%
@REM )

@REM docker images -q %IMAGE_NAME% >nul 2>&1
@REM if %errorlevel%==0 (
@REM     echo Removing image %IMAGE_NAME%...
@REM     docker rmi -f %IMAGE_NAME%
@REM )

@REM remove all containers and images created by docker-compose
docker compose down --rmi all
