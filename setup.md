# Setup

* Make sure the server is updated

1. Go to `dodekasecrets`, ensure all passwords are updated
   * Add the correct passwords to `secretdb.env` and `secretserver.env`
   * But the passphrase in a file (e.g. `secret/.env.pass`), MAKE SURE YOU DON'T PUSH THIS TO GIT
   * Load it as an env variable in bash (`. ./secret/.env.pass)
   * Run `./encrypt_all.sh`
   * Push to GitHub
2. 