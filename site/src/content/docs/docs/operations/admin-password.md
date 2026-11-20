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
docker compose logs web | grep "First-run setup" | tail -1
```

Open the new setup link and create the admin account again. If you changed `VULWALL_PORT`, replace
8080 in the link with your port.
