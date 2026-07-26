"""Guided jobs, written for someone who has never done digital forensics.

These are phrased as situations rather than features. A beginner does not
think "I need the Comb inventory module"; they think "someone handed me a USB
stick and I don't know what's on it". The naming follows that.

Defined once and used twice: the dashboard's Start Here page renders them, and
`knowledge.py` folds them into the assistant's manual so asking produces the
same guidance as clicking.

Every step carries a `why`. A tool that tells you what to type teaches you
nothing; a beginner needs to know why hashing matters before they will bother
to do it under time pressure.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Step:
    title: str
    why: str                                   # why this step exists
    commands: list[str] = field(default_factory=list)
    where: str = ""                            # dashboard path, if it's clickable
    note: str = ""


@dataclass
class Workflow:
    id: str
    situation: str                             # how a beginner would say it
    summary: str
    mode: str                                  # ir | pentest | diagnostics
    time: str                                  # rough duration
    steps: list[Step] = field(default_factory=list)
    needs: list[str] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)


WORKFLOWS: list[Workflow] = [
    Workflow(
        id="wf-usb",
        situation="Someone handed me a USB stick and I need to know what's on it",
        summary=("Examine a USB stick or disk image safely, record everything "
                 "you find, and end up with a report you could hand to "
                 "somebody else."),
        mode="ir",
        time="10-30 minutes, depending on size",
        needs=["Sleuth Kit (for disk images)", "the stick or an image of it"],
        keywords=["usb stick", "found a usb", "what's on this drive",
                  "examine a usb", "someone gave me a usb"],
        steps=[
            Step(
                "Open a case first",
                "A case is the folder everything about this job goes in. "
                "Create it before you look at anything, so every finding is "
                "recorded against it automatically and you can prove when you "
                "started.",
                ['hexbee-queen case new "USB stick from reception"'],
                where="/cases",
            ),
            Step(
                "Do not plug it into your own computer casually",
                "Plugging a stick into a normal computer changes it — the "
                "operating system writes to it and updates timestamps. If "
                "this might ever matter legally, use a hardware write blocker "
                "or make an image first and work from that.",
                ["hexbee-comb extract /evidence/stick.dd /cases/extracted"],
                note="If you only have the stick and no write blocker, say so "
                     "in your case notes. Being honest about it is better than "
                     "quietly compromising the evidence.",
            ),
            Step(
                "Scan it",
                "This lists every file, fingerprints each one so you can prove "
                "later it hasn't changed, spots files pretending to be a "
                "different type, pulls GPS coordinates out of photos, and "
                "reads any browser history it finds.",
                ["hexbee-comb scan /cases/extracted -o report.html "
                 "--hive http://localhost:8080 --key $HEXBEE_INGEST_KEY"],
                where="/collect",
            ),
            Step(
                "Look at what came back",
                "Anything suspicious raises an incident automatically. Files "
                "with the wrong extension and known-bad signatures are the "
                "usual first things to look at.",
                [],
                where="/incidents",
            ),
            Step(
                "Write it up",
                "The report includes the file list, the fingerprints, and the "
                "integrity check proving nothing was altered while you worked.",
                ["hexbee-queen report 1 -f html -o usb-findings.html"],
                where="/cases",
            ),
        ],
    ),
    Workflow(
        id="wf-infected",
        situation="I think this computer has been hacked",
        summary=("Collect what's happening on a live computer before it's "
                 "lost, so you can work out what happened."),
        mode="ir",
        time="5-15 minutes to collect",
        needs=["access to the computer while it is switched on"],
        keywords=["computer is infected", "been hacked", "compromised",
                  "malware on a pc", "suspicious computer", "incident"],
        steps=[
            Step(
                "Do not switch it off",
                "Turning it off destroys everything that only exists in "
                "memory — running programs, network connections, and often "
                "the malware itself. Collect first.",
                [],
            ),
            Step(
                "Open a case",
                "So everything collected is tied together and timestamped.",
                ['hexbee-queen case new "Suspected compromise - front desk PC"'],
                where="/cases",
            ),
            Step(
                "Collect what's running",
                "This records running programs, network connections, who is "
                "logged in, what starts automatically at boot, USB devices "
                "that have been plugged in, and recently changed files. It "
                "only reads — it changes nothing on the computer.",
                ["hexbee-forager collect --hive http://hive.local:8080 "
                 "--key $HEXBEE_INGEST_KEY"],
                where="/collect",
                note="No network on that machine? Use a USB stick: "
                     "`hexbee-forager collect -o findings.json`, then "
                     "`hexbee-forager submit findings.json` later.",
            ),
            Step(
                "Consider capturing memory",
                "Memory holds what is actually running right now. It is the "
                "richest evidence available and it disappears at shutdown. "
                "This is the one step that loads something onto the target, "
                "so decide deliberately.",
                ["hexbee-forager memory /mnt/evidence --case 1"],
            ),
            Step(
                "Read the timeline",
                "HexBee groups related events into incidents and lays them "
                "out in order, so you can see the sequence rather than a pile "
                "of records.",
                [],
                where="/incidents",
            ),
            Step(
                "Ask for a second opinion",
                "The triage button gives you a severity assessment and "
                "suggested next steps based on what was actually collected.",
                [],
                where="/incidents",
            ),
        ],
    ),
    Workflow(
        id="wf-pentest",
        situation="I'm doing an authorised security test for a client",
        summary=("Set up the authorisation boundary first, then test inside "
                 "it, and produce a report at the end."),
        mode="pentest",
        time="setup 5 minutes; engagement varies",
        needs=["written authorisation from the client", "nmap"],
        keywords=["pentest", "penetration test", "security assessment",
                  "authorised test", "engagement", "client test"],
        steps=[
            Step(
                "Write down what you are allowed to touch",
                "This is the most important step and the easiest to skip. "
                "HexBee refuses to run its active tools against anything not "
                "on this list — including by accident, at 2am, against the "
                "wrong subnet. Put the client's authorisation reference on "
                "each rule so the report can prove you had permission.",
                ["hexbee-queen scope add cidr 10.10.0.0/24 --auth-ref SOW-2026-14",
                 "hexbee-queen scope list"],
                where="/admin#scope",
                note="With nothing listed, every active tool refuses. That is "
                     "deliberate — an empty list is not permission.",
            ),
            Step(
                "Create the case and set it to pentest mode",
                "Mode changes what the dashboard highlights and which report "
                "template you get at the end.",
                ['hexbee-queen case new "CLIENT.TEST engagement"',
                 "hexbee-queen mode 1 pentest"],
                where="/cases",
            ),
            Step(
                "Find out what is there",
                "Scans the authorised range for machines and services. Every "
                "host is checked against your scope before it is touched, so "
                "a partly-authorised range scans only the authorised part.",
                ["hexbee-queen recon quick 10.10.0.0/24 --case 1"],
            ),
            Step(
                "Test, and let findings record themselves",
                "Whatever you use, point its output at HexBee so the evidence "
                "trail builds itself instead of living in scratch files.",
                ["hexbee-queen responder --watch --case 1",
                 "hexbee-queen bloodhound ./collection.zip --case 1"],
            ),
            Step(
                "Produce the report",
                "Groups findings, maps them to the MITRE ATT&CK framework "
                "clients expect to see, and produces a document you can send.",
                ["hexbee-queen engagement report 1 -o report.html --pdf"],
                where="/cases",
            ),
        ],
    ),
    Workflow(
        id="wf-monitor",
        situation="I want to watch a network for suspicious activity",
        summary=("Put a sensor on the network that detects scanning, spoofing "
                 "and other common attacks, and records them as evidence."),
        mode="ir",
        time="10 minutes to set up",
        needs=["a Linux machine on the network (the Raspberry Pi is ideal)"],
        keywords=["monitor the network", "detect attacks", "watch traffic",
                  "ids", "intrusion detection", "network monitoring"],
        steps=[
            Step(
                "Understand what it can and cannot see",
                "A sensor only sees traffic that reaches it. On a normal "
                "switched network that means broadcast traffic and its own — "
                "enough to catch scanning and spoofing, but not enough to see "
                "two other machines talking privately. For that you need a "
                "mirror port on the switch.",
                [],
            ),
            Step(
                "Give it permission to listen",
                "Reading raw network traffic is privileged. This grants just "
                "that one capability rather than running everything as root.",
                ['sudo setcap cap_net_raw,cap_net_admin=eip '
                 '"$(readlink -f "$(which python3)")"'],
            ),
            Step(
                "Start it",
                "It listens only — it never sends anything. Detections become "
                "evidence records automatically.",
                ["hexbee-netmon run --mode ids --iface eth0"],
            ),
            Step(
                "Watch the dashboard",
                "New detections appear in the live feed the moment they are "
                "recorded.",
                [],
                where="/",
            ),
        ],
    ),
    Workflow(
        id="wf-health",
        situation="I want to check whether a computer is healthy",
        summary=("Check disk health, temperature, memory pressure and failed "
                 "services — no forensics involved."),
        mode="diagnostics",
        time="2 minutes",
        needs=[],
        keywords=["computer running slow", "check health", "diagnostics",
                  "is this machine ok", "it support", "troubleshooting"],
        steps=[
            Step(
                "Take a health reading",
                "Reports disk health from the drive's own self-monitoring, "
                "temperature, memory and swap pressure, disk space, failed "
                "services, and what is using the most memory.",
                ["hexbee-forager collect --mode diagnostics"],
            ),
            Step(
                "Or keep watching",
                "Samples every five minutes and raises an alert when "
                "something crosses a threshold — a disk filling up, a drive "
                "reporting bad sectors, a service that keeps dying.",
                ["hexbee-forager watch --mode diagnostics --interval 300"],
            ),
            Step(
                "Check the network too",
                "Gateway reachability and latency, DNS health, and ARP table "
                "anomalies.",
                ["hexbee-netmon check"],
            ),
        ],
    ),
    Workflow(
        id="wf-handover",
        situation="I need to hand this evidence to somebody else",
        summary=("Package a case so the recipient can verify for themselves "
                 "that nothing was altered."),
        mode="ir",
        time="2 minutes",
        needs=[],
        keywords=["hand over evidence", "give evidence to", "court",
                  "chain of custody", "package evidence", "handover"],
        steps=[
            Step(
                "Check the evidence log is intact",
                "Confirms every record still matches its seal. Do this before "
                "packaging, not after — if something is wrong you want to know "
                "now.",
                ["hexbee-queen verify"],
            ),
            Step(
                "Seal the case",
                "Records that you declared it complete at a stated moment "
                "before a stated witness, and takes a signed anchor over the "
                "evidence log as it stood. Keep that anchor somewhere other "
                "than the Hive — an anchor stored beside the thing it "
                "protects proves nothing.",
                ["hexbee-queen seal 1 --operator you --witness 'their name' "
                 "-o seal.json"],
            ),
            Step(
                "Export a signed bundle",
                "Contains the evidence, the full audit trail of who did what, "
                "a fingerprint of every file, and a signature over the whole "
                "package.",
                ["hexbee-queen export 1"],
                where="/cases",
            ),
            Step(
                "Tell them how to check it",
                "The recipient runs one command and gets a yes or no. That is "
                "the point of the whole exercise.",
                ["hexbee-hive verify-bundle /path/to/bundle"],
            ),
        ],
    ),
]


def by_id(workflow_id: str) -> Workflow | None:
    return next((w for w in WORKFLOWS if w.id == workflow_id), None)


def as_knowledge_docs():
    """Fold the workflows into the assistant's manual.

    Same guidance whether the operator clicks Start Here or asks the
    assistant — there is one source, so they cannot disagree.
    """
    from .knowledge import Doc

    docs = []
    for wf in WORKFLOWS:
        lines = [wf.summary, ""]
        if wf.needs:
            lines.append("You need: " + ", ".join(wf.needs))
            lines.append("")
        lines.append(f"Roughly {wf.time}.")
        lines.append("")
        commands: list[str] = []
        for index, step in enumerate(wf.steps, 1):
            lines.append(f"{index}. {step.title}")
            lines.append(f"   Why: {step.why}")
            if step.note:
                lines.append(f"   Note: {step.note}")
            commands.extend(step.commands)
        docs.append(Doc(
            id=wf.id,
            title=wf.situation,
            body="\n".join(lines),
            kind="workflow",
            source="workflow",
            commands=commands,
            keywords=wf.keywords,
        ))
    return docs
