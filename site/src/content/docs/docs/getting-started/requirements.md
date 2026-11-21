---
title: Requirements
description: What a host needs to run VulWall.
---

## Software

- **Docker** with the **Compose v2** plugin (`docker compose`, not `docker-compose`): Docker
  Engine on Linux, or Docker Desktop on macOS. The commands in these docs are for a Linux or
  macOS shell. On Windows, use WSL 2.
- For the [install script](/docs/getting-started/install/): a POSIX shell, `curl`, and
  `sha256sum` or `shasum`. On Linux, the script can install Docker for you.

## CPU

The images are published for `linux/amd64` and `linux/arm64`. 32-bit systems are not supported.

VulWall's database, MongoDB 9, needs a recent enough CPU. On x86-64 the CPU must support AVX,
which most CPUs made since 2011 do; some Celeron, Pentium and Atom models do not. On ARM the CPU
must implement ARMv8.2-A. A Raspberry Pi 5 and AWS Graviton2 or later work. A Raspberry Pi 4 or
older does not, because its Cortex-A72 is ARMv8.0.

In a virtual machine, the hypervisor must pass these CPU features through, and many hide AVX with
their default CPU model. In Proxmox, set the VM's CPU type to `host` (Hardware > Processors), then
stop and start the VM. In VirtualBox, Hyper-V, VMware and others, use the host CPU model or host
passthrough.

The install script checks the CPU before it changes anything. On a CPU without these features,
MongoDB stops at start with "Illegal instruction".

## Linux kernel

MongoDB 9 can crash on Linux kernels 6.19 to 7.0.13. Use a kernel older than 6.19 or 7.0.14 and
later. See MongoDB's
[production notes](https://www.mongodb.com/docs/manual/administration/production-notes/).

## Memory and disk

Plan for **4 GB of RAM**; 2 GB is the minimum. In a test scan of one domain with the default
settings, the whole stack used up to 1.5 GB, of which the scanner used 1.2 GB. More domains and a
higher `NUCLEI_WORKERS` use more memory: each nuclei process can use several hundred MB.

Plan for at least **5 GB of free disk space** for the images, the nuclei templates and your data.
The install script warns you when the host has less memory or disk space than this.

## Network

The scanner needs outbound internet access. Besides the traffic to your targets, it downloads the
nuclei templates, the DB-IP Lite geolocation databases and the published IP ranges of some cloud
providers. The first start takes a few minutes because of these downloads.

On a host without internet access, set `GEO_DOWNLOAD=false`, `CLOUD_DETECTOR_ENABLED=false`,
`DNS_RECHECK_RESOLVERS=off` and `UPDATE_CHECK=false`. Scans of internet targets need
internet access in any case.

The web UI needs no inbound port open to the internet. It listens on `127.0.0.1` only. See
[Reverse proxy and HTTPS](/docs/configuration/reverse-proxy/) to reach it from other machines.

## Permission to scan

Add only domains and IP addresses that you own or that you have written permission to test.
Some hosting providers also require you to tell them before you scan. Check your provider's
terms.
