"""--sched-deadline outside the unit. Taken, the loop runs SCHED_DEADLINE and
CAP_SYS_NICE is gone; refused, here for want of CAP_SYS_NICE, the engine says
so and runs on its inherited policy.
"""

import time

from conftest import (
    NS_A,
    NS_B,
    STATS,
    STATS_B,
    sh,
    setup,
    teardown,
    ns_pids,
    start_engine,
    wait_both_up,
    engine_log,
)

CAP_SYS_NICE = 23


def _has_sys_nice(pid):
    for line in open("/proc/%d/status" % pid):
        if line.split(":")[0] in ("CapEff", "CapPrm", "CapAmb"):
            if int(line.split()[1], 16) >> CAP_SYS_NICE & 1:
                return True
    return False


def _run(binary, wrap=""):
    setup()
    # Appended to across tests.
    sh("sudo truncate -s 0 %s" % engine_log(NS_A), check=False)
    try:
        start_engine(
            (wrap + " " + binary).strip(),
            4,
            ns=NS_A,
            stats=STATS,
            extra=("--sched-deadline", "1000/10000"),
        )
        start_engine(binary, 4, ns=NS_B, stats=STATS_B)
        wait_both_up()
        pid = ns_pids(NS_A)[0]
        cls = sh("ps -o cls= -p %d" % pid).strip()
        nice = _has_sys_nice(pid)
        time.sleep(0.5)
        return cls, nice, sh("sudo cat %s" % engine_log(NS_A), check=False)
    finally:
        teardown()


def test_taken_and_the_capability_dropped(request):
    cls, nice, log = _run(str(request.config.rootpath / "bfd_tx"))
    assert cls == "DLN", "engine runs %s, not SCHED_DEADLINE\n%s" % (cls, log)
    assert "SCHED_DEADLINE, 1000us every 10000us" in log, log
    assert not nice, "the engine kept CAP_SYS_NICE"


def test_refused_the_engine_runs_on(request):
    cls, _, log = _run(
        str(request.config.rootpath / "bfd_tx"),
        "setpriv --inh-caps=-sys_nice --bounding-set=-sys_nice",
    )
    assert cls == "TS", "engine runs %s, not its inherited policy\n%s" % (cls, log)
    assert "keeping the inherited policy" in log, log
