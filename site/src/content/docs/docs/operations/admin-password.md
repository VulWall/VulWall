---
title: Reset the admin password
description: Recover access when you have lost the admin password.
---

If you know the current password, change it in **Settings**. Changing the password signs out
every other session.

If you lost it: VulWall has one admin account. To replace it, delete it and run the first-run
setup again. Your assets, scans and findings stay. Run these commands in the install directory:

```sh
docker compose stop web
docker compose exec mongo mongosh vulwall --quiet --eval 'db.users.deleteOne({_id:"admin"})'
docker compose start web
grep SETUP_TOKEN .env
```

Open `http://localhost:8080/setup?token=<token>` with that token and create the admin account
again. If you changed `VULWALL_PORT`, replace 8080 with your port.

If `.env` has no `SETUP_TOKEN`, the web container prints a new setup link at each start. Print it
with:

```sh
docker compose logs --no-log-prefix web | grep -a '^ *First-run setup: open http://localhost:[0-9]*/setup?token=[0-9a-f]* ' | tail -1 | tr -cd '[:print:]\n'
```
