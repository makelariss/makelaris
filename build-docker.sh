#!/bin/bash
docker build --tag=web_cached_web .
docker run -p 1337:1337 --restart=on-failure --name=web_cached_web --detach web_cached_web