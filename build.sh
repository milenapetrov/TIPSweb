#!/bin/bash
docker build -t tipsweb .
docker run -d -p 3000:3000 --env-file .env tipsweb