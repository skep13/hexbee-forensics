# Getting started with HexBee

No prior forensics experience assumed. This takes about ten minutes.

## What HexBee is

HexBee collects digital evidence — from computers, USB sticks, disk images and
networks — and keeps it in a log that cannot be quietly edited. Every record is
sealed with a fingerprint of the record before it, so if anyone changes
anything after the fact, it shows.

That is the difference between notes and evidence.

## Install it

```bash
git clone https://github.com/skep13/hexbee-forensics
cd hexbee-forensics
./install.sh
```

Works on macOS and Linux. It explains each thing it installs and why, skips
anything already present, and is safe to run again. Use `./install.sh --check`
to see what it would do without changing anything.

## Set it up

```bash
hexbee-hive setup
```

A guided walkthrough. It creates the evidence log, generates the key your
collection tools will use, and makes your login — explaining what each of
those is as it goes. Press Enter to accept every suggestion if you want.

## Start using it

```bash
hexbee-hive web
```

Open <http://localhost:8080>, log in, and click **Start Here**. It lists
common situations rather than features:

- Someone handed me a USB stick and I need to know what's on it
- I think this computer has been hacked
- I'm doing an authorised security test for a client
- I want to watch a network for suspicious activity
- I want to check whether a computer is healthy
- I need to hand this evidence to somebody else

Each one walks through the whole job step by step, and every step explains
*why* it exists — not just what to type.

## Three words worth knowing

| Word | What it means |
|---|---|
| **Event** | One thing that was observed. A USB stick plugged in, a file found, someone logging in. |
| **Incident** | Related events grouped together, so you see a sequence rather than a pile. HexBee does this for you. |
| **Case** | The folder for one job. Make one *before* you start looking at anything — then everything you find is filed against it automatically, and the report comes out of it at the end. |

The full [glossary](http://localhost:8080/glossary) is in the dashboard.

## When something isn't working

```bash
hexbee-hive doctor
```

Checks everything on this machine and tells you, in plain English, what works,
what doesn't, and the exact command to fix each gap. It distinguishes between
things that are broken and things that are simply optional — most of HexBee
works without most of its extras.

## When you don't know how to do something

```bash
hexbee-hive howto "how do I seal a case in front of a witness"
```

Answers come from HexBee's own built-in manual, so you get real commands
rather than plausible-looking ones. It works whether or not you have a local
AI model running — without one, you get the manual entry itself.

The same thing is available in the dashboard under **Hive Mind**.

## A note on doing this properly

If what you find might ever matter legally, two habits are worth forming from
the start:

1. **Create the case before you look at anything.** The timestamps then show
   when you started, not when you got round to writing it down.
2. **Do not plug evidence into your everyday computer.** Operating systems
   write to drives just by mounting them. Use a hardware write blocker, or
   make an image and work from that — `hexbee-comb extract` reads an image
   without mounting it at all.

If you cannot do either, write that in your case notes. Being honest about a
limitation is far better than quietly compromising the evidence.

## Where things run

| Machine | Role |
|---|---|
| Your laptop | The analyst side — examining evidence, writing reports |
| A Raspberry Pi (optional) | The Hive — collects and stores evidence on the network |
| ESP32 boards (optional) | Field sensors and wireless red-team tooling |

You do not need any of the hardware to start. Everything runs on one laptop.
