#!/bin/bash
docker build -t tipsweb .
docker run -d -p 8080:8080 --env-file .env tipsweb 