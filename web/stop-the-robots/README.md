# Stop the Robots

[![Try in PWD](https://raw.githubusercontent.com/play-with-docker/stacks/master/assets/images/button.png)](https://labs.play-with-docker.com/?stack=https://raw.githubusercontent.com/cybermouflons/CCSC-CTF-2023/master/web/stop-the-robots/docker-compose.yml)


**Category**: web

**Author**: sAINT_barber

## Description

Where do humans go to hide from robots?



## Run locally

Launch challenge:
```
curl -sSL https://raw.githubusercontent.com/cybermouflons/CCSC-CTF-2023/master/web/stop-the-robots/docker-compose.yml | docker compose -f - up -d
```

Shutdown challenge:
```
curl -sSL https://raw.githubusercontent.com/cybermouflons/CCSC-CTF-2023/master/web/stop-the-robots/docker-compose.yml | docker compose -f - down
```
