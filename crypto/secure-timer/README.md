# Secure Timer

[![Try in PWD](https://raw.githubusercontent.com/play-with-docker/stacks/master/assets/images/button.png)](https://labs.play-with-docker.com/?stack=https://raw.githubusercontent.com/cybermouflons/CCSC-CTF-2023/master/crypto/secure-timer/docker-compose.yml)


**Category**: crypto

**Author**: feltf

## Description

I asked ChatCheapLeakD to implement a deterministic ECDSA scheme following
the specifications outlined in RFC 6979. As always, its implementation surpassed
my expectations.

After examining the intricate generated masterpiece, I made the decision to deploy
an online timer that utilizes the generated ECDSA implementation to sign its responses.

Feeling a bit too confident, I went ahead and added a flag command, which returns
the flag if provided with a valid signature. I'm willing to bet you won't be able to
obtain the flag... or perhaps you can?



## Run locally

Launch challenge:
```
curl -sSL https://raw.githubusercontent.com/cybermouflons/CCSC-CTF-2023/master/crypto/secure-timer/docker-compose.yml | docker compose -f - up -d
```

Shutdown challenge:
```
curl -sSL https://raw.githubusercontent.com/cybermouflons/CCSC-CTF-2023/master/crypto/secure-timer/docker-compose.yml | docker compose -f - down
```
