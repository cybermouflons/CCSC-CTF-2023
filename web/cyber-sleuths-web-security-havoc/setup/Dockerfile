FROM node:16

WORKDIR /app

RUN apt-get update && apt-get install chromium -y

# RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ./server.key -out /server.key

COPY package*.json ./
RUN npm install

COPY . .

# RUN openssl rand -base64 48 > passphrase.txt
# RUN openssl genrsa -aes128 -passout file:passphrase.txt -out server.key 2048
# RUN openssl req -new -passin file:passphrase.txt -key server.key -out server.csr \
#     -subj "/C=CY/O=kokos/OU=Domain Control Validated/CN=*.cybermouflons.com"

# RUN cp server.key server.key.org
# RUN openssl rsa -in server.key.org -passin file:passphrase.txt -out server.key
# RUN openssl x509 -req -days 36500 -in server.csr -signkey server.key -out server.crt


CMD ["npm", "run", "dev"] # Develpment only

# CMD ["npm", "run", "start"] # prod
