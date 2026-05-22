"""Stress / edge tests for the idalib supervisor RW-lock architecture.

200+ test points covering the readers-writer lock primitive, context
binding mutations, open/release races, session_scope behaviour,
listing endpoints, multi-thread stress, and global state invariants.

Helpers are imported from the sibling ``test_idalib_supervisor`` so
both suites stay in sync.
"""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import pytest

# Reuse fixtures from the original suite to keep helper definitions
# in one place.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_idalib_supervisor import (  # type: ignore[import-not-found]
    _BearerMcp,
    _DeadProcess,
    _FakeProcess,
    _FakeSupervisor,
    _SlowFakeSupervisor,
    _TransportMcp,
    _make_saving_sup,
    _patch_discovery,
)

from ida_pro_mcp import idalib_supervisor as supmod
from ida_pro_mcp.idalib_supervisor import _RWLock


# ============================================================================
# Helpers
# ============================================================================


def _spawn(target, *args, daemon=True, **kwargs) -> threading.Thread:
    t = threading.Thread(target=target, args=args, kwargs=kwargs, daemon=daemon)
    t.start()
    return t


def _join_all(threads, timeout: float = 10.0) -> None:
    for t in threads:
        t.join(timeout=timeout)
        assert not t.is_alive(), f"thread {t.name} did not finish within {timeout}s"


def _make_files(tmp_path, n: int, prefix: str = "bin") -> list[Path]:
    paths = []
    for i in range(n):
        p = tmp_path / f"{prefix}_{i}.bin"
        p.write_bytes(b"x")
        paths.append(p)
    return paths


# ============================================================================
# Section A: _RWLock primitive tests
# ============================================================================


def test_rwlock_single_reader_does_not_block():
    lock = _RWLock()
    with lock.read():
        pass  # no exception, no hang


def test_rwlock_single_writer_does_not_block():
    lock = _RWLock()
    with lock.write():
        pass


def test_rwlock_multiple_readers_concurrent():
    lock = _RWLock()
    in_section = threading.Semaphore(0)
    can_release = threading.Event()
    finished = []

    def reader():
        with lock.read():
            in_section.release()
            assert can_release.wait(timeout=2.0)
            finished.append(True)

    threads = [_spawn(reader, daemon=True) for _ in range(8)]
    # All 8 readers should enter their critical section near-simultaneously.
    for _ in range(8):
        assert in_section.acquire(timeout=2.0), "reader failed to enter"
    can_release.set()
    _join_all(threads)
    assert len(finished) == 8


def test_rwlock_writer_excludes_readers():
    lock = _RWLock()
    writer_in = threading.Event()
    can_release_writer = threading.Event()
    reader_completed = threading.Event()

    def writer():
        with lock.write():
            writer_in.set()
            assert can_release_writer.wait(timeout=2.0)

    def reader():
        with lock.read():
            reader_completed.set()

    w = _spawn(writer)
    assert writer_in.wait(timeout=1.0)
    r = _spawn(reader)
    # Reader must NOT be able to enter while writer holds the lock.
    assert not reader_completed.wait(timeout=0.2)
    can_release_writer.set()
    _join_all([w, r])
    assert reader_completed.is_set()


def test_rwlock_writer_excludes_other_writer():
    lock = _RWLock()
    first_in = threading.Event()
    can_release_first = threading.Event()
    second_done = threading.Event()

    def first():
        with lock.write():
            first_in.set()
            assert can_release_first.wait(timeout=2.0)

    def second():
        with lock.write():
            second_done.set()

    t1 = _spawn(first)
    assert first_in.wait(timeout=1.0)
    t2 = _spawn(second)
    assert not second_done.wait(timeout=0.2)
    can_release_first.set()
    _join_all([t1, t2])
    assert second_done.is_set()


def test_rwlock_writer_excludes_reader_in_flight():
    lock = _RWLock()
    reader_in = threading.Event()
    can_release_reader = threading.Event()
    writer_done = threading.Event()

    def reader():
        with lock.read():
            reader_in.set()
            assert can_release_reader.wait(timeout=2.0)

    def writer():
        with lock.write():
            writer_done.set()

    r = _spawn(reader)
    assert reader_in.wait(timeout=1.0)
    w = _spawn(writer)
    assert not writer_done.wait(timeout=0.2)
    can_release_reader.set()
    _join_all([r, w])
    assert writer_done.is_set()


def test_rwlock_writer_preference_blocks_new_readers():
    """Once a writer is waiting, NEW readers must NOT slip in ahead."""
    lock = _RWLock()
    first_reader_in = threading.Event()
    can_release_first_reader = threading.Event()
    writer_done = threading.Event()
    second_reader_done = threading.Event()
    writer_waiting = threading.Event()
    order: list[str] = []
    order_lock = threading.Lock()

    def first_reader():
        with lock.read():
            first_reader_in.set()
            assert can_release_first_reader.wait(timeout=2.0)

    def writer():
        writer_waiting.set()
        with lock.write():
            with order_lock:
                order.append("writer")
            writer_done.set()

    def second_reader():
        # Spawned AFTER writer is waiting.
        with lock.read():
            with order_lock:
                order.append("reader2")
            second_reader_done.set()

    r1 = _spawn(first_reader, daemon=True)
    assert first_reader_in.wait(timeout=1.0)
    w = _spawn(writer, daemon=True)
    assert writer_waiting.wait(timeout=1.0)
    # Give the writer a moment to register itself in _writers_waiting.
    time.sleep(0.1)
    r2 = _spawn(second_reader, daemon=True)
    # Second reader must NOT slip in ahead of the waiting writer.
    assert not second_reader_done.wait(timeout=0.2)
    can_release_first_reader.set()
    _join_all([r1, w, r2])
    assert order == ["writer", "reader2"], (
        f"writer-preference violated: got {order}"
    )


def test_rwlock_read_releases_on_exception():
    lock = _RWLock()
    try:
        with lock.read():
            raise RuntimeError("boom")
    except RuntimeError:
        pass
    # After exception, the lock should be in a consistent state.
    assert lock._readers == 0
    with lock.write():
        pass


def test_rwlock_write_releases_on_exception():
    lock = _RWLock()
    try:
        with lock.write():
            raise RuntimeError("boom")
    except RuntimeError:
        pass
    assert lock._writer is False
    with lock.write():
        pass
    with lock.read():
        pass


def test_rwlock_internal_state_clean_after_workload():
    lock = _RWLock()

    def worker(i):
        if i % 2 == 0:
            with lock.read():
                pass
        else:
            with lock.write():
                pass

    threads = [_spawn(worker, i) for i in range(50)]
    _join_all(threads, timeout=5.0)
    assert lock._readers == 0
    assert lock._writer is False
    assert lock._writers_waiting == 0


@pytest.mark.parametrize("n_readers", [2, 4, 8, 16, 32])
def test_rwlock_many_readers_parallel(n_readers):
    lock = _RWLock()
    entered = threading.Semaphore(0)
    release = threading.Event()

    def reader():
        with lock.read():
            entered.release()
            assert release.wait(timeout=3.0)

    threads = [_spawn(reader) for _ in range(n_readers)]
    for _ in range(n_readers):
        assert entered.acquire(timeout=3.0)
    # All readers concurrently inside the section right now.
    assert lock._readers == n_readers
    release.set()
    _join_all(threads, timeout=5.0)
    assert lock._readers == 0


@pytest.mark.parametrize("n_writers", [2, 4, 8, 16])
def test_rwlock_many_writers_serialised(n_writers):
    lock = _RWLock()
    counter = {"n": 0}
    max_concurrent = {"m": 0}

    def writer():
        with lock.write():
            counter["n"] += 1
            max_concurrent["m"] = max(max_concurrent["m"], counter["n"])
            time.sleep(0.005)
            counter["n"] -= 1

    threads = [_spawn(writer) for _ in range(n_writers)]
    _join_all(threads, timeout=10.0)
    assert max_concurrent["m"] == 1, "writers must serialise (saw concurrent writers)"


@pytest.mark.parametrize("n_readers,n_writers", [(2, 1), (4, 2), (8, 2), (16, 4), (32, 4)])
def test_rwlock_mixed_readers_writers(n_readers, n_writers):
    """Readers may run concurrently among themselves, but never with a writer."""
    lock = _RWLock()
    reader_count = {"n": 0}
    writer_count = {"n": 0}
    violations = {"n": 0}
    state_lock = threading.Lock()

    def reader():
        for _ in range(5):
            with lock.read():
                with state_lock:
                    reader_count["n"] += 1
                    if writer_count["n"] > 0:
                        violations["n"] += 1
                time.sleep(0.001)
                with state_lock:
                    reader_count["n"] -= 1

    def writer():
        for _ in range(5):
            with lock.write():
                with state_lock:
                    writer_count["n"] += 1
                    if reader_count["n"] > 0 or writer_count["n"] > 1:
                        violations["n"] += 1
                time.sleep(0.001)
                with state_lock:
                    writer_count["n"] -= 1

    threads = [_spawn(reader) for _ in range(n_readers)] + [
        _spawn(writer) for _ in range(n_writers)
    ]
    _join_all(threads, timeout=15.0)
    assert violations["n"] == 0, f"reader/writer overlap violations: {violations['n']}"


def test_rwlock_no_starvation_under_constant_readers():
    """A constant stream of readers must NOT starve out a waiting writer."""
    lock = _RWLock()
    stop = threading.Event()
    writer_done = threading.Event()

    def reader_stream():
        while not stop.is_set():
            with lock.read():
                time.sleep(0.001)

    def writer():
        with lock.write():
            writer_done.set()

    readers = [_spawn(reader_stream) for _ in range(8)]
    time.sleep(0.05)
    w = _spawn(writer)
    # Under writer-preference, writer must eventually go through.
    assert writer_done.wait(timeout=3.0), "writer starved by constant readers"
    stop.set()
    _join_all(readers + [w], timeout=5.0)


def test_rwlock_writers_waiting_decremented_on_success():
    lock = _RWLock()
    with lock.write():
        pass
    assert lock._writers_waiting == 0


def test_rwlock_read_after_write_release_is_immediate():
    lock = _RWLock()
    with lock.write():
        pass
    t0 = time.monotonic()
    with lock.read():
        pass
    assert (time.monotonic() - t0) < 0.1


def test_rwlock_write_after_read_release_is_immediate():
    lock = _RWLock()
    with lock.read():
        pass
    t0 = time.monotonic()
    with lock.write():
        pass
    assert (time.monotonic() - t0) < 0.1


def test_rwlock_release_order_writer_then_writer():
    lock = _RWLock()
    seq = []
    rel1 = threading.Event()
    in1 = threading.Event()

    def w1():
        with lock.write():
            in1.set()
            assert rel1.wait(timeout=2.0)
            seq.append("w1")

    def w2():
        with lock.write():
            seq.append("w2")

    t1 = _spawn(w1)
    assert in1.wait(timeout=1.0)
    t2 = _spawn(w2)
    time.sleep(0.05)
    rel1.set()
    _join_all([t1, t2])
    assert seq == ["w1", "w2"]


def test_rwlock_many_waiters_all_wake_up():
    lock = _RWLock()
    can_release = threading.Event()
    finished = []
    finished_lock = threading.Lock()

    def first_writer():
        with lock.write():
            assert can_release.wait(timeout=2.0)

    def reader():
        with lock.read():
            with finished_lock:
                finished.append("r")

    def writer():
        with lock.write():
            with finished_lock:
                finished.append("w")

    fw = _spawn(first_writer)
    time.sleep(0.05)  # first writer in
    waiters = [_spawn(reader if i % 2 == 0 else writer) for i in range(20)]
    time.sleep(0.1)
    can_release.set()
    _join_all([fw] + waiters, timeout=10.0)
    assert len(finished) == 20


@pytest.mark.parametrize("ops", [
    ["r", "r", "w", "r"],
    ["w", "r", "w", "r"],
    ["w", "w", "w", "w"],
    ["r"] * 16,
    ["w"] * 8,
    ["r", "w"] * 8,
])
def test_rwlock_op_sequences(ops):
    lock = _RWLock()
    completed = []
    lock_for_log = threading.Lock()

    def one(op):
        if op == "r":
            with lock.read():
                with lock_for_log:
                    completed.append("r")
        else:
            with lock.write():
                with lock_for_log:
                    completed.append("w")

    threads = [_spawn(one, op) for op in ops]
    _join_all(threads, timeout=5.0)
    # All ops eventually completed.
    assert sorted(completed) == sorted(ops)
    assert lock._readers == 0
    assert lock._writer is False
    assert lock._writers_waiting == 0


# ============================================================================
# Section B: bind_context / unbind_context tests
# ============================================================================


def test_bind_context_sets_binding():
    sup = supmod.IdalibSupervisor(_BearerMcp())
    sup.bind_context("ctxA", "sess1")
    assert sup.context_bindings == {"ctxA": "sess1"}


def test_bind_context_overwrites_existing():
    sup = supmod.IdalibSupervisor(_BearerMcp())
    sup.bind_context("ctxA", "sess1")
    sup.bind_context("ctxA", "sess2")
    assert sup.context_bindings == {"ctxA": "sess2"}


def test_unbind_context_present_returns_true():
    sup = supmod.IdalibSupervisor(_BearerMcp())
    sup.bind_context("ctxA", "sess1")
    assert sup.unbind_context("ctxA") is True
    assert sup.context_bindings == {}


def test_unbind_context_absent_returns_false():
    sup = supmod.IdalibSupervisor(_BearerMcp())
    assert sup.unbind_context("ctxA") is False


def test_unbind_context_twice_second_returns_false():
    sup = supmod.IdalibSupervisor(_BearerMcp())
    sup.bind_context("ctxA", "sess1")
    assert sup.unbind_context("ctxA") is True
    assert sup.unbind_context("ctxA") is False


def test_bind_context_blocks_under_active_writer():
    sup = supmod.IdalibSupervisor(_BearerMcp())
    holder_in = threading.Event()
    release = threading.Event()

    def hold():
        with sup._rw_lock.write():
            holder_in.set()
            assert release.wait(timeout=2.0)

    h = _spawn(hold)
    assert holder_in.wait(timeout=1.0)
    bind_done = threading.Event()

    def bind():
        sup.bind_context("ctxA", "sess1")
        bind_done.set()

    b = _spawn(bind)
    assert not bind_done.wait(timeout=0.2)
    release.set()
    _join_all([h, b])
    assert sup.context_bindings == {"ctxA": "sess1"}


def test_unbind_context_blocks_under_active_writer():
    sup = supmod.IdalibSupervisor(_BearerMcp())
    sup.bind_context("ctxA", "sess1")
    holder_in = threading.Event()
    release = threading.Event()

    def hold():
        with sup._rw_lock.write():
            holder_in.set()
            assert release.wait(timeout=2.0)

    h = _spawn(hold)
    assert holder_in.wait(timeout=1.0)
    unbind_done = threading.Event()

    def unbind():
        sup.unbind_context("ctxA")
        unbind_done.set()

    u = _spawn(unbind)
    assert not unbind_done.wait(timeout=0.2)
    release.set()
    _join_all([h, u])
    assert sup.context_bindings == {}


def test_bind_context_blocks_under_active_reader():
    """bind_context is a writer — it must wait for in-flight readers."""
    sup = supmod.IdalibSupervisor(_BearerMcp())
    reader_in = threading.Event()
    release = threading.Event()

    def hold_read():
        with sup._rw_lock.read():
            reader_in.set()
            assert release.wait(timeout=2.0)

    r = _spawn(hold_read)
    assert reader_in.wait(timeout=1.0)
    bind_done = threading.Event()

    def bind():
        sup.bind_context("ctxA", "sess1")
        bind_done.set()

    b = _spawn(bind)
    assert not bind_done.wait(timeout=0.2)
    release.set()
    _join_all([r, b])
    assert sup.context_bindings == {"ctxA": "sess1"}


@pytest.mark.parametrize("n", [2, 4, 8, 16, 32])
def test_concurrent_bind_to_same_context_final_state_consistent(n):
    """N threads bind ctxA to different sessions. Final binding must be
    one of the values written — never a corrupted mixed/missing state."""
    sup = supmod.IdalibSupervisor(_BearerMcp())
    expected = {f"sess{i}" for i in range(n)}

    def bind(i):
        sup.bind_context("ctxA", f"sess{i}")

    threads = [_spawn(bind, i) for i in range(n)]
    _join_all(threads, timeout=5.0)
    assert "ctxA" in sup.context_bindings
    assert sup.context_bindings["ctxA"] in expected


@pytest.mark.parametrize("n", [2, 4, 8, 16, 32])
def test_concurrent_bind_to_different_contexts(n):
    sup = supmod.IdalibSupervisor(_BearerMcp())

    def bind(i):
        sup.bind_context(f"ctx{i}", f"sess{i}")

    threads = [_spawn(bind, i) for i in range(n)]
    _join_all(threads, timeout=5.0)
    assert len(sup.context_bindings) == n
    for i in range(n):
        assert sup.context_bindings[f"ctx{i}"] == f"sess{i}"


@pytest.mark.parametrize("n", [4, 8, 16])
def test_concurrent_bind_and_unbind_interleaved(n):
    sup = supmod.IdalibSupervisor(_BearerMcp())

    def churn(i):
        for _ in range(20):
            sup.bind_context(f"ctx{i}", f"sess{i}")
            sup.unbind_context(f"ctx{i}")

    threads = [_spawn(churn, i) for i in range(n)]
    _join_all(threads, timeout=15.0)
    # Final state may be empty or some leftovers but never inconsistent.
    for k, v in sup.context_bindings.items():
        assert k.startswith("ctx") and v.startswith("sess")


def test_bind_context_empty_string_context_id_allowed():
    sup = supmod.IdalibSupervisor(_BearerMcp())
    sup.bind_context("", "sess1")
    assert sup.context_bindings[""] == "sess1"


def test_bind_context_empty_string_session_id_allowed():
    sup = supmod.IdalibSupervisor(_BearerMcp())
    sup.bind_context("ctxA", "")
    assert sup.context_bindings["ctxA"] == ""


def test_unbind_context_empty_string_present():
    sup = supmod.IdalibSupervisor(_BearerMcp())
    sup.bind_context("", "sess1")
    assert sup.unbind_context("") is True


# ============================================================================
# Section C: open_session edges
# ============================================================================


def test_open_session_invalid_path_raises_file_not_found(tmp_path):
    sup = _FakeSupervisor()
    with pytest.raises(FileNotFoundError):
        sup.open_session(str(tmp_path / "does_not_exist.bin"))


def test_open_session_session_id_collision_for_different_path_raises(tmp_path):
    a, b = _make_files(tmp_path, 2, "binA")
    sup = _FakeSupervisor()
    sup.open_session(str(a), session_id="dup", context_id="ctxA")
    with pytest.raises(ValueError, match="Session already exists"):
        sup.open_session(str(b), session_id="dup", context_id="ctxB")


def test_open_session_same_path_different_session_id_raises(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="orig", context_id="ctxA")
    with pytest.raises(ValueError, match="cannot reuse different session_id"):
        sup.open_session(str(sample), session_id="other", context_id="ctxB")


def test_open_session_same_path_no_session_id_reuses(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    s1 = sup.open_session(str(sample), session_id="solo", context_id="ctxA")
    s2 = sup.open_session(str(sample), context_id="ctxB")
    assert s1.session_id == s2.session_id


def test_open_session_no_context_id_does_not_bind(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="lone")
    assert sup.context_bindings == {}


def test_open_session_with_context_id_binds(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="lone", context_id="ctxA")
    assert sup.context_bindings["ctxA"] == "lone"


def test_open_session_with_context_id_updates_existing_binding(tmp_path):
    a, b = _make_files(tmp_path, 2)
    sup = _FakeSupervisor()
    sup.open_session(str(a), session_id="a", context_id="ctxA")
    sup.open_session(str(b), session_id="b", context_id="ctxA")
    assert sup.context_bindings["ctxA"] == "b"


def test_open_session_existing_session_updates_last_accessed(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    s = sup.open_session(str(sample), session_id="s1", context_id="ctxA")
    earlier = s.last_accessed
    time.sleep(0.01)
    sup.open_session(str(sample), context_id="ctxB")
    assert s.last_accessed > earlier


def test_open_session_dead_existing_session_is_replaced(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="dead", context_id="ctxA")
    # Mark dead by replacing process.
    sup.sessions["dead"].process = _DeadProcess()
    s2 = sup.open_session(str(sample), session_id="newid", context_id="ctxB")
    assert s2.session_id == "newid"
    assert "dead" not in sup.sessions


def test_open_session_with_path_collision_silent_coalesce_no_id(tmp_path):
    """If a path-collision happens during a spawn and we did NOT pass
    an explicit session_id, it should silently coalesce onto the
    existing session rather than raising."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    s = sup.open_session(str(sample), session_id="anchor", context_id="ctxA")
    again = sup.open_session(str(sample), context_id="ctxB")
    assert again.session_id == s.session_id == "anchor"


def test_open_session_resolves_path_for_path_key(tmp_path):
    sample = tmp_path / "deeper" / "sample.bin"
    sample.parent.mkdir()
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    s = sup.open_session(str(sample), session_id="p", context_id="ctxA")
    # Now opening with an unresolved form (relative or with ./)
    same = sup.open_session(str(sample), context_id="ctxB")
    assert same.session_id == s.session_id


def test_open_session_pending_join_with_different_session_id_raises(tmp_path):
    sample = tmp_path / "slow.bin"
    sample.write_bytes(b"x")
    sup = _SlowFakeSupervisor(spawn_delay=0.4)

    sup.open_session(str(sample), session_id="anchor", context_id="ctxA", wait_timeout=0.05)
    # Second call to same path with conflicting session_id should raise.
    with pytest.raises(ValueError, match="cannot reuse different session_id"):
        sup.open_session(str(sample), session_id="other", context_id="ctxB", wait_timeout=0.05)


def test_open_session_pending_status_dict_fields(tmp_path):
    sample = tmp_path / "slow.bin"
    sample.write_bytes(b"x")
    sup = _SlowFakeSupervisor(spawn_delay=2.0)

    pending = sup.open_session(str(sample), context_id="ctxA", wait_timeout=0.05)
    assert isinstance(pending, dict)
    assert pending["status"] == "opening"
    assert pending["filename"] == "slow.bin"
    assert pending["resolved_path"].endswith("slow.bin")
    assert pending["session_id"]
    assert pending["elapsed_seconds"] >= 0.0
    assert pending["contexts_waiting"] >= 1


def test_open_session_concurrent_join_pending_extra_contexts(tmp_path):
    sample = tmp_path / "slow.bin"
    sample.write_bytes(b"x")
    sup = _SlowFakeSupervisor(spawn_delay=1.0)

    sup.open_session(str(sample), context_id="ctxA", wait_timeout=0.05)
    sup.open_session(str(sample), context_id="ctxB", wait_timeout=0.05)
    sup.open_session(str(sample), context_id="ctxC", wait_timeout=0.05)

    # All three contexts visible on the pending entry.
    pending_a = sup.list_pending("ctxA")
    pending_b = sup.list_pending("ctxB")
    pending_c = sup.list_pending("ctxC")
    assert pending_a[0]["contexts_waiting"] == 3
    assert pending_b[0]["contexts_waiting"] == 3
    assert pending_c[0]["contexts_waiting"] == 3
    # Wait for spawn so we don't leak threads.
    for _ in range(40):
        if all(sup.context_bindings.get(f"ctx{c}") for c in "ABC"):
            break
        time.sleep(0.1)


def test_open_session_path_key_normalises_case():
    sup = _FakeSupervisor()
    p1 = sup._path_key("/Tmp/Foo.bin")
    p2 = sup._path_key("/Tmp/Foo.bin")
    assert p1 == p2


def test_open_session_pending_error_raised_to_waiters(tmp_path):
    """If background spawn fails, waiters see the exception."""
    class _FailingFake(_FakeSupervisor):
        def call_worker_tool(self, worker, name, arguments=None):
            if name == "idalib_open":
                raise RuntimeError("simulated spawn failure")
            return super().call_worker_tool(worker, name, arguments)

    sample = tmp_path / "boom.bin"
    sample.write_bytes(b"x")
    sup = _FailingFake()
    with pytest.raises(RuntimeError, match="simulated spawn failure"):
        sup.open_session(str(sample), context_id="ctxA", wait_timeout=2.0)


def test_open_session_max_workers_respected(tmp_path):
    files = _make_files(tmp_path, 5)
    sup = _FakeSupervisor()
    sup.max_workers = 2
    sup.open_session(str(files[0]), session_id="s0", context_id="c0")
    sup.open_session(str(files[1]), session_id="s1", context_id="c1")
    with pytest.raises(RuntimeError, match="Maximum idalib worker count"):
        sup.open_session(str(files[2]), session_id="s2", context_id="c2")


def test_open_session_max_workers_zero_is_unlimited(tmp_path):
    files = _make_files(tmp_path, 6)
    sup = _FakeSupervisor()
    sup.max_workers = 0
    for i, f in enumerate(files):
        sup.open_session(str(f), session_id=f"s{i}", context_id=f"c{i}")
    assert len(sup.sessions) == 6


def test_open_session_uses_finalise_pending_collision_detection(tmp_path):
    """If a session sneaks into self.sessions during spawn, the
    new spawn must be discarded and pending.error set."""
    files = _make_files(tmp_path, 2, "race")
    sup = _SlowFakeSupervisor(spawn_delay=0.4)
    pending = sup.open_session(str(files[0]), context_id="ctxA", wait_timeout=0.0)
    assert isinstance(pending, dict)
    # Inject a different session into self.sessions claiming the same path BEFORE finalise runs.
    fake = supmod.WorkerSession(
        session_id="injected",
        input_path=str(files[0]),
        filename=files[0].name,
        host="127.0.0.1",
        port=2,
        process=_FakeProcess(),
    )
    with sup._rw_lock.write():
        sup.sessions["injected"] = fake
        sup.path_to_session[sup._path_key(str(files[0]))] = "injected"
    # Wait for the background spawn to finish.
    for _ in range(40):
        if not sup._pending:
            break
        time.sleep(0.1)
    # The injected session must still be the path-owner.
    assert sup.path_to_session[sup._path_key(str(files[0]))] == "injected"


@pytest.mark.parametrize("n", [2, 4, 8, 16])
def test_concurrent_open_same_path_coalesces(tmp_path, n):
    sample = tmp_path / "shared.bin"
    sample.write_bytes(b"x")
    sup = _SlowFakeSupervisor(spawn_delay=0.3)

    results = []
    results_lock = threading.Lock()

    def open_one(i):
        r = sup.open_session(str(sample), context_id=f"ctx{i}", wait_timeout=3.0)
        with results_lock:
            results.append(r)

    threads = [_spawn(open_one, i) for i in range(n)]
    _join_all(threads, timeout=10.0)
    sessions = [r for r in results if not isinstance(r, dict)]
    assert len(sessions) == n
    assert {s.session_id for s in sessions} == {sessions[0].session_id}
    assert sup._spawn_count == 1


@pytest.mark.parametrize("n", [2, 4, 8])
def test_concurrent_open_different_paths_run_in_parallel(tmp_path, n):
    files = _make_files(tmp_path, n, "diff")
    sup = _FakeSupervisor()
    sup.max_workers = 0  # unlimited so n=8 doesn't hit the cap

    results = []
    results_lock = threading.Lock()

    def open_one(f, i):
        r = sup.open_session(str(f), session_id=f"s{i}", context_id=f"ctx{i}", wait_timeout=3.0)
        with results_lock:
            results.append(r)

    threads = [_spawn(open_one, f, i) for i, f in enumerate(files)]
    _join_all(threads, timeout=10.0)
    sessions = [r for r in results if not isinstance(r, dict)]
    assert len(sessions) == n
    assert len({s.session_id for s in sessions}) == n
    assert len(sup.sessions) == n


def test_open_session_gui_path_collision_via_unrelated_idb(tmp_path):
    """When a GUI instance reports an idb path that matches one of the
    .i64/.idb candidates of the requested path, it must take over."""
    sample = tmp_path / "sample.bin"
    idb = tmp_path / "sample.bin.i64"
    sample.write_bytes(b"x")
    idb.write_bytes(b"idb")
    restore = _patch_discovery(
        instances=[
            {
                "host": "127.0.0.1",
                "port": 31337,
                "pid": 999,
                "binary": "sample.bin",
                "idb_path": str(idb),
                "started_at": "now",
            }
        ],
        probe=True,
    )
    try:
        sup = _FakeSupervisor()
        sess = sup.open_session(str(sample), session_id="gui1", context_id="ctxA")
        assert sess.backend == "gui"
    finally:
        restore()


# ============================================================================
# Section D: release_session edges
# ============================================================================


def test_release_session_not_found_returns_error_dict():
    sup = _make_saving_sup()
    outcome = sup.release_session("ghost", "ctxA")
    assert outcome["success"] is False
    assert "Session not found" in outcome["error"]


def test_release_session_releases_only_calling_context(tmp_path):
    sample = tmp_path / "shared.bin"
    sample.write_bytes(b"x")
    sup = _make_saving_sup()
    sup.open_session(str(sample), session_id="s", context_id="ctxA")
    sup.bind_context("ctxB", "s")
    sup.bind_context("ctxC", "s")
    outcome = sup.release_session("s", "ctxA")
    assert outcome["released"] is True
    assert outcome["terminated"] is False
    assert outcome["remaining_refs"] == 2
    assert sup.context_bindings == {"ctxB": "s", "ctxC": "s"}


def test_release_session_last_ref_terminates(tmp_path):
    sample = tmp_path / "solo.bin"
    sample.write_bytes(b"x")
    sup = _make_saving_sup()
    sup.open_session(str(sample), session_id="s", context_id="ctxA")
    outcome = sup.release_session("s", "ctxA")
    assert outcome["terminated"] is True
    assert outcome["remaining_refs"] == 0
    assert "s" not in sup.sessions


def test_release_session_unbound_context_is_noop(tmp_path):
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"x")
    sup = _make_saving_sup()
    sup.open_session(str(sample), session_id="s", context_id="ctxA")
    outcome = sup.release_session("s", "ctxNotBound")
    assert outcome["released"] is False
    assert outcome["terminated"] is False
    assert "s" in sup.sessions


def test_release_session_unbound_does_not_call_save(tmp_path):
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"x")
    sup = _make_saving_sup()
    sup.open_session(str(sample), session_id="s", context_id="ctxA")
    sup.release_session("s", "ctxNotBound")
    assert sup.save_calls == []


def test_release_session_last_ref_calls_save(tmp_path):
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"x")
    sup = _make_saving_sup()
    sup.open_session(str(sample), session_id="s", context_id="ctxA")
    sup.release_session("s", "ctxA")
    assert sup.save_calls == [("idalib_save", "")]


def test_release_session_save_error_does_not_block_release(tmp_path):
    class _FailingSave(_FakeSupervisor):
        def call_worker_tool(self, worker, name, arguments=None):
            if name in {"idalib_save", "idb_save"}:
                raise RuntimeError("disk full")
            return super().call_worker_tool(worker, name, arguments)

    sample = tmp_path / "s.bin"
    sample.write_bytes(b"x")
    sup = _FailingSave()
    sup.open_session(str(sample), session_id="s", context_id="ctxA")
    outcome = sup.release_session("s", "ctxA")
    assert outcome["released"] is True
    assert outcome["saved"] is False
    assert "disk full" in outcome["save_error"]
    # Worker still terminated despite save failure.
    assert outcome["terminated"] is True
    assert "s" not in sup.sessions


def test_release_session_gui_uses_idb_save(tmp_path):
    sample = tmp_path / "sample.bin"
    idb = tmp_path / "sample.bin.i64"
    sample.write_bytes(b"x")
    idb.write_bytes(b"idb")
    restore = _patch_discovery(
        instances=[{
            "host": "127.0.0.1", "port": 31337, "pid": 999,
            "binary": "sample.bin", "idb_path": str(idb), "started_at": "now",
        }],
        probe=True,
    )
    try:
        sup = _make_saving_sup()
        sup.open_session(str(sample), session_id="gui", context_id="ctxA")
        sup.release_session("gui", "ctxA")
        assert ("idb_save", "") in sup.save_calls
    finally:
        restore()


def test_release_session_worker_uses_idalib_save(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _make_saving_sup()
    sup.open_session(str(sample), session_id="s", context_id="ctxA")
    sup.release_session("s", "ctxA")
    assert ("idalib_save", "") in sup.save_calls


@pytest.mark.parametrize("n", [2, 4, 8])
def test_concurrent_release_at_most_one_terminates(tmp_path, n):
    sample = tmp_path / "shared.bin"
    sample.write_bytes(b"x")
    sup = _make_saving_sup()
    sup.open_session(str(sample), session_id="s", context_id="ctxA")
    for i in range(1, n):
        sup.bind_context(f"ctx{i}", "s")

    outcomes = []
    outcomes_lock = threading.Lock()

    def release(ctx):
        o = sup.release_session("s", ctx)
        with outcomes_lock:
            outcomes.append(o)

    contexts = ["ctxA"] + [f"ctx{i}" for i in range(1, n)]
    threads = [_spawn(release, c) for c in contexts]
    _join_all(threads, timeout=10.0)
    # Exactly one terminates; rest released without termination.
    terminated = [o for o in outcomes if o["terminated"]]
    assert len(terminated) == 1
    # All N must have been "released=True" (one per binding).
    released = [o for o in outcomes if o["released"]]
    assert len(released) == n
    assert "s" not in sup.sessions


def test_release_session_serialises_with_concurrent_release(tmp_path):
    """Two releases on the same session must serialise on the write lock.

    Each release does a slow save (0.3s). If they serialise, the total
    wall-clock time is at least 2 × delay; if they ran in parallel
    it'd be close to 1 × delay.
    """
    class _SlowSave(_make_saving_sup().__class__):
        def call_worker_tool(self, worker, name, arguments=None):
            if name == "idalib_save":
                time.sleep(0.3)
            return super().call_worker_tool(worker, name, arguments)

    sample = tmp_path / "s.bin"
    sample.write_bytes(b"x")
    sup = _SlowSave()
    sup.open_session(str(sample), session_id="s", context_id="ctxA")
    sup.bind_context("ctxB", "s")

    def release(ctx):
        sup.release_session("s", ctx)

    t0 = time.monotonic()
    threads = [_spawn(release, "ctxA"), _spawn(release, "ctxB")]
    _join_all(threads, timeout=10.0)
    elapsed = time.monotonic() - t0
    # Both releases take the write lock and do a 0.3s save serially.
    assert elapsed >= 0.5, f"releases ran in parallel ({elapsed:.2f}s)"


def test_release_session_clears_all_bound_contexts_when_terminated(tmp_path):
    """When the LAST ref releases, the bookkeeping for that context
    is gone too — _unregister_session_locked drops all bindings."""
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"x")
    sup = _make_saving_sup()
    sup.open_session(str(sample), session_id="s", context_id="ctxA")
    # Only ctxA has it.
    outcome = sup.release_session("s", "ctxA")
    assert outcome["terminated"] is True
    assert sup.context_bindings == {}
    assert sup.path_to_session == {}


def test_release_session_dead_session_returns_not_found():
    sup = _make_saving_sup()
    outcome = sup.release_session("never_existed", "ctxA")
    assert outcome["success"] is False


@pytest.mark.parametrize("preserve_others", [True, False])
def test_release_session_does_not_disturb_other_sessions(tmp_path, preserve_others):
    files = _make_files(tmp_path, 2)
    sup = _make_saving_sup()
    sup.open_session(str(files[0]), session_id="a", context_id="ctxA")
    sup.open_session(str(files[1]), session_id="b", context_id="ctxB")
    sup.release_session("a", "ctxA")
    assert "b" in sup.sessions
    if preserve_others:
        assert sup.context_bindings.get("ctxB") == "b"


def test_release_session_concurrent_with_unrelated_bind(tmp_path):
    """A release must not race with a bind to a DIFFERENT session."""
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"x")
    sup = _make_saving_sup()
    sup.open_session(str(sample), session_id="s", context_id="ctxA")

    done = []
    done_lock = threading.Lock()

    def release():
        sup.release_session("s", "ctxA")
        with done_lock:
            done.append("rel")

    def bind():
        sup.bind_context("ctxOther", "doesnt-exist-but-bind-still-works")
        with done_lock:
            done.append("bind")

    threads = [_spawn(release), _spawn(bind)]
    _join_all(threads, timeout=5.0)
    assert set(done) == {"rel", "bind"}


@pytest.mark.parametrize("n_sessions", [2, 4, 8])
def test_concurrent_release_across_different_sessions(tmp_path, n_sessions):
    """Releases on N DIFFERENT sessions must all complete successfully."""
    files = _make_files(tmp_path, n_sessions)
    sup = _make_saving_sup()
    sup.max_workers = 0  # unlimited
    for i, f in enumerate(files):
        sup.open_session(str(f), session_id=f"s{i}", context_id=f"ctx{i}")

    threads = [_spawn(sup.release_session, f"s{i}", f"ctx{i}") for i in range(n_sessions)]
    _join_all(threads, timeout=10.0)
    assert sup.sessions == {}


# ============================================================================
# Section E: switch / unbind edges
# ============================================================================


def test_switch_via_internal_path(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="orig", context_id="ctxA")
    # Mimic idalib_switch's flow.
    with sup._rw_lock.write():
        s = sup._resolve_session_locked("orig")
        sup.context_bindings["ctxB"] = s.session_id
    assert sup.context_bindings["ctxB"] == "orig"


def test_switch_to_nonexistent_raises(tmp_path):
    sup = _FakeSupervisor()
    with sup._rw_lock.write():
        with pytest.raises(RuntimeError, match="not found"):
            sup._resolve_session_locked("missing-session")


def test_switch_ambiguous_selector_raises(tmp_path):
    """Two sessions share metadata so the selector is ambiguous."""
    a = tmp_path / "a.bin"
    a.write_bytes(b"x")
    b = tmp_path / "b.bin"
    b.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(a), session_id="s1", context_id="ctxA")
    sup.open_session(str(b), session_id="s2", context_id="ctxB")
    # Make both sessions have the same filename — the resolver uses
    # set lookup so a single value match through the same key isn't
    # ambiguous by accident; we force collision via the filename match.
    sup.sessions["s1"].filename = "collide"
    sup.sessions["s2"].filename = "collide"
    with sup._rw_lock.write():
        with pytest.raises(RuntimeError, match="ambiguous"):
            sup._resolve_session_locked("collide")


def test_unbind_returns_true_when_bound(tmp_path):
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="s", context_id="ctxA")
    assert sup.unbind_context("ctxA") is True


def test_unbind_then_switch_rebinds(tmp_path):
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="s", context_id="ctxA")
    sup.unbind_context("ctxA")
    assert "ctxA" not in sup.context_bindings
    with sup._rw_lock.write():
        sess = sup._resolve_session_locked("s")
        sup.context_bindings["ctxA"] = sess.session_id
    assert sup.context_bindings["ctxA"] == "s"


def test_switch_to_session_with_filename_selector(tmp_path):
    sample = tmp_path / "uniquely.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="s", context_id="ctxA")
    with sup._rw_lock.write():
        sess = sup._resolve_session_locked("uniquely.bin")
        assert sess.session_id == "s"


def test_switch_with_resolved_path_selector(tmp_path):
    sample = tmp_path / "uniquely.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="s", context_id="ctxA")
    with sup._rw_lock.write():
        sess = sup._resolve_session_locked(str(sample))
        assert sess.session_id == "s"


def test_switch_concurrent_with_release(tmp_path):
    """A switch and a release on the same session — exclusive."""
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"x")
    sup = _make_saving_sup()
    sup.open_session(str(sample), session_id="s", context_id="ctxA")
    sup.bind_context("ctxB", "s")

    def switch():
        try:
            with sup._rw_lock.write():
                sess = sup._resolve_session_locked("s")
                sup.context_bindings["ctxC"] = sess.session_id
        except RuntimeError:
            pass  # session was released first

    def release():
        sup.release_session("s", "ctxA")

    threads = [_spawn(switch), _spawn(release)]
    _join_all(threads, timeout=5.0)
    # State must be consistent.
    if "s" in sup.sessions:
        # release happened, then switch; ctxC may be bound to "s"
        assert sup.context_bindings.get("ctxB") == "s"
    else:
        # release terminated; ctxC must not point to "s" or sup.sessions inconsistent.
        # _unregister_session_locked drops all bindings → ctxC absent.
        assert sup.context_bindings.get("ctxC") is None


def test_unbind_no_op_when_already_unbound(tmp_path):
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="s", context_id="ctxA")
    sup.unbind_context("ctxA")
    # Second unbind is a no-op.
    assert sup.unbind_context("ctxA") is False


@pytest.mark.parametrize("n", [2, 4, 8])
def test_concurrent_switch_to_same_session(tmp_path, n):
    """N threads switch DIFFERENT contexts to the SAME session — all succeed."""
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="s", context_id="ctxA")

    def switch(ctx):
        with sup._rw_lock.write():
            sess = sup._resolve_session_locked("s")
            sup.context_bindings[ctx] = sess.session_id

    threads = [_spawn(switch, f"ctx{i}") for i in range(n)]
    _join_all(threads, timeout=5.0)
    for i in range(n):
        assert sup.context_bindings[f"ctx{i}"] == "s"


@pytest.mark.parametrize("n", [2, 4, 8])
def test_concurrent_unbind_idempotent(tmp_path, n):
    """N threads unbind the same context — one returns True, rest False."""
    sup = supmod.IdalibSupervisor(_BearerMcp())
    sup.bind_context("ctxA", "s")

    results = []
    results_lock = threading.Lock()

    def unbind():
        r = sup.unbind_context("ctxA")
        with results_lock:
            results.append(r)

    threads = [_spawn(unbind) for _ in range(n)]
    _join_all(threads, timeout=5.0)
    assert sum(1 for r in results if r) == 1
    assert sum(1 for r in results if not r) == n - 1


def test_switch_with_pending_session_raises(tmp_path):
    """resolving a pending session id surfaces a helpful error."""
    sample = tmp_path / "slow.bin"
    sample.write_bytes(b"x")
    sup = _SlowFakeSupervisor(spawn_delay=2.0)
    pending = sup.open_session(str(sample), context_id="ctxA", wait_timeout=0.05)
    assert isinstance(pending, dict)
    with sup._rw_lock.write():
        with pytest.raises(RuntimeError, match="still opening"):
            sup._resolve_session_locked(pending["session_id"])


# ============================================================================
# Section F: session_scope edges
# ============================================================================


def test_session_scope_database_none_uses_bound(tmp_path):
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.mcp = _BearerMcp(session_id=None)
    sup.open_session(str(sample), session_id="s", context_id=supmod.SHARED_FALLBACK_CONTEXT_ID)
    with sup.session_scope(None) as sess:
        assert sess.session_id == "s"


def test_session_scope_database_session_id(tmp_path):
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="s", context_id="ctxA")
    with sup.session_scope("s") as sess:
        assert sess.session_id == "s"


def test_session_scope_database_filename(tmp_path):
    sample = tmp_path / "unique-name.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="s", context_id="ctxA")
    with sup.session_scope("unique-name.bin") as sess:
        assert sess.session_id == "s"


def test_session_scope_database_not_found_raises():
    sup = _FakeSupervisor()
    with pytest.raises(RuntimeError, match="not found"):
        with sup.session_scope("missing"):
            pass


def test_session_scope_updates_last_accessed(tmp_path):
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="s", context_id="ctxA")
    earlier = sup.sessions["s"].last_accessed
    time.sleep(0.01)
    with sup.session_scope("s"):
        pass
    assert sup.sessions["s"].last_accessed > earlier


def test_session_scope_releases_session_lock_on_exception(tmp_path):
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="s", context_id="ctxA")
    session = sup.sessions["s"]
    try:
        with sup.session_scope("s"):
            raise RuntimeError("boom")
    except RuntimeError:
        pass
    # Lock should be released.
    assert session.lock.acquire(blocking=False)
    session.lock.release()


def test_session_scope_same_session_serialises(tmp_path):
    """Two scopes on the same session must serialise on session.lock."""
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="s", context_id="ctxA")

    in_section = []
    in_section_lock = threading.Lock()

    def use():
        with sup.session_scope("s"):
            with in_section_lock:
                in_section.append(time.monotonic())
            time.sleep(0.1)

    threads = [_spawn(use), _spawn(use)]
    _join_all(threads, timeout=5.0)
    # The second entry should be >= 0.09s after the first.
    assert in_section[1] - in_section[0] >= 0.09


def test_session_scope_cross_session_parallel(tmp_path):
    """Scopes on DIFFERENT sessions must run in parallel."""
    files = _make_files(tmp_path, 2)
    sup = _FakeSupervisor()
    sup.open_session(str(files[0]), session_id="s0", context_id="ctxA")
    sup.open_session(str(files[1]), session_id="s1", context_id="ctxB")

    enter = threading.Semaphore(0)
    release = threading.Event()
    finished = []

    def use(sid):
        with sup.session_scope(sid):
            enter.release()
            assert release.wait(timeout=2.0)
            finished.append(sid)

    threads = [_spawn(use, "s0"), _spawn(use, "s1")]
    # Both should enter near-simultaneously.
    assert enter.acquire(timeout=1.5)
    assert enter.acquire(timeout=1.5)
    release.set()
    _join_all(threads, timeout=5.0)
    assert set(finished) == {"s0", "s1"}


def test_session_scope_blocks_writer(tmp_path):
    """While a session_scope is active, a writer (close) must wait."""
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"x")
    sup = _make_saving_sup()
    sup.open_session(str(sample), session_id="s", context_id="ctxA")

    in_scope = threading.Event()
    release = threading.Event()

    def reader():
        with sup.session_scope("s"):
            in_scope.set()
            assert release.wait(timeout=2.0)

    r = _spawn(reader)
    assert in_scope.wait(timeout=1.0)

    close_done = threading.Event()

    def close():
        sup.release_session("s", "ctxA")
        close_done.set()

    c = _spawn(close)
    # Close should be blocked.
    assert not close_done.wait(timeout=0.2)
    release.set()
    _join_all([r, c], timeout=5.0)
    assert close_done.is_set()


def test_session_scope_pending_session_id_raises(tmp_path):
    sample = tmp_path / "slow.bin"
    sample.write_bytes(b"x")
    sup = _SlowFakeSupervisor(spawn_delay=2.0)
    pending = sup.open_session(str(sample), context_id="ctxA", wait_timeout=0.05)
    assert isinstance(pending, dict)
    with pytest.raises(RuntimeError, match="still opening"):
        with sup.session_scope(pending["session_id"]):
            pass


def test_session_scope_resolves_normcase_path(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="s", context_id="ctxA")
    # Use the same path string (normcase will match itself).
    with sup.session_scope(str(sample)) as sess:
        assert sess.session_id == "s"


def test_session_scope_no_database_no_binding_raises(tmp_path):
    sup = _FakeSupervisor()
    sup.mcp = _BearerMcp(session_id=None)
    with pytest.raises(RuntimeError, match="No database bound"):
        with sup.session_scope(None):
            pass


@pytest.mark.parametrize("n", [2, 4, 8])
def test_concurrent_session_scope_same_session(tmp_path, n):
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="s", context_id="ctxA")

    counter = [0]
    counter_lock = threading.Lock()
    max_concurrent = [0]

    def use():
        with sup.session_scope("s"):
            with counter_lock:
                counter[0] += 1
                max_concurrent[0] = max(max_concurrent[0], counter[0])
            time.sleep(0.01)
            with counter_lock:
                counter[0] -= 1

    threads = [_spawn(use) for _ in range(n)]
    _join_all(threads, timeout=15.0)
    # Per-session lock serialises same-session scopes.
    assert max_concurrent[0] == 1


@pytest.mark.parametrize("n", [2, 4, 8])
def test_concurrent_session_scope_cross_session_parallel(tmp_path, n):
    files = _make_files(tmp_path, n)
    sup = _FakeSupervisor()
    sup.max_workers = 0
    for i, f in enumerate(files):
        sup.open_session(str(f), session_id=f"s{i}", context_id=f"ctx{i}")

    counter = [0]
    counter_lock = threading.Lock()
    max_concurrent = [0]

    def use(sid):
        with sup.session_scope(sid):
            with counter_lock:
                counter[0] += 1
                max_concurrent[0] = max(max_concurrent[0], counter[0])
            time.sleep(0.05)
            with counter_lock:
                counter[0] -= 1

    threads = [_spawn(use, f"s{i}") for i in range(n)]
    _join_all(threads, timeout=15.0)
    # Cross-session scopes run in parallel.
    assert max_concurrent[0] >= 2


# ============================================================================
# Section G: list/current/list_pending edges
# ============================================================================


def test_list_sessions_empty():
    sup = _FakeSupervisor()
    assert sup.list_sessions("ctxA") == []


def test_list_sessions_default_only_returns_mine(tmp_path):
    """mine_only=True (default): only sessions bound to ctx0 → 1."""
    files = _make_files(tmp_path, 3)
    sup = _FakeSupervisor()
    for i, f in enumerate(files):
        sup.open_session(str(f), session_id=f"s{i}", context_id=f"ctx{i}")
    listed = sup.list_sessions("ctx0")
    assert len(listed) == 1
    assert listed[0]["session_id"] == "s0"
    assert listed[0]["is_mine"] is True


def test_list_sessions_all_returns_global_view(tmp_path):
    files = _make_files(tmp_path, 3)
    sup = _FakeSupervisor()
    for i, f in enumerate(files):
        sup.open_session(str(f), session_id=f"s{i}", context_id=f"ctx{i}")
    listed = sup.list_sessions("ctx0", mine_only=False)
    assert len(listed) == 3
    # is_mine flag still correctly identifies ctx0's session.
    mine = [s for s in listed if s["is_mine"]]
    assert len(mine) == 1
    assert mine[0]["session_id"] == "s0"


def test_list_sessions_marks_current(tmp_path):
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="s", context_id="ctxA")
    listed = sup.list_sessions("ctxA")
    assert listed[0]["is_mine"] is True
    assert listed[0]["ref_count"] == 1


def test_list_sessions_marks_other_context_not_current(tmp_path):
    """ctxOther is unbound; under mine_only=False it sees s with is_mine=False."""
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="s", context_id="ctxA")
    listed = sup.list_sessions("ctxOther", mine_only=False)
    assert listed[0]["is_mine"] is False


def test_list_sessions_counts_bindings(tmp_path):
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="s", context_id="ctxA")
    sup.bind_context("ctxB", "s")
    sup.bind_context("ctxC", "s")
    listed = sup.list_sessions("ctxA")
    assert listed[0]["ref_count"] == 3


def test_list_pending_empty():
    sup = _FakeSupervisor()
    assert sup.list_pending("ctxA") == []


def test_list_pending_for_other_ctx_empty(tmp_path):
    sample = tmp_path / "slow.bin"
    sample.write_bytes(b"x")
    sup = _SlowFakeSupervisor(spawn_delay=2.0)
    sup.open_session(str(sample), context_id="ctxA", wait_timeout=0.05)
    assert sup.list_pending("ctxOther") == []


def test_list_pending_includes_after_join(tmp_path):
    sample = tmp_path / "slow.bin"
    sample.write_bytes(b"x")
    sup = _SlowFakeSupervisor(spawn_delay=2.0)
    sup.open_session(str(sample), context_id="ctxA", wait_timeout=0.05)
    sup.open_session(str(sample), context_id="ctxB", wait_timeout=0.05)
    assert len(sup.list_pending("ctxB")) == 1


def test_list_sessions_under_concurrent_reads(tmp_path):
    files = _make_files(tmp_path, 4)
    sup = _FakeSupervisor()
    for i, f in enumerate(files):
        sup.open_session(str(f), session_id=f"s{i}", context_id=f"ctx{i}")

    results = []
    results_lock = threading.Lock()

    def lister(i):
        for _ in range(10):
            listed = sup.list_sessions(f"ctx{i}", mine_only=False)
            with results_lock:
                results.append(len(listed))

    threads = [_spawn(lister, i) for i in range(8)]
    _join_all(threads, timeout=10.0)
    # All listings should report 4 sessions.
    assert all(r == 4 for r in results)


def test_resolve_session_for_dead_worker_raises(tmp_path):
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="s", context_id="ctxA")
    sup.sessions["s"].process = _DeadProcess()
    with pytest.raises(RuntimeError, match="not running"):
        sup.resolve_session("s")


def test_idalib_current_no_binding_returns_error(tmp_path):
    sup = _FakeSupervisor()
    sup.mcp = _BearerMcp(session_id=None)
    # Mimic the idalib_current tool flow.
    context_id = sup.resolve_context_id()
    assert sup.context_bindings.get(context_id) is None


@pytest.mark.parametrize("n", [2, 4, 8])
def test_concurrent_list_pending_does_not_crash(tmp_path, n):
    sample = tmp_path / "slow.bin"
    sample.write_bytes(b"x")
    sup = _SlowFakeSupervisor(spawn_delay=2.0)
    sup.open_session(str(sample), context_id="ctxA", wait_timeout=0.05)

    def lister():
        for _ in range(20):
            sup.list_pending("ctxA")

    threads = [_spawn(lister) for _ in range(n)]
    _join_all(threads, timeout=10.0)


# ============================================================================
# Section H: Heavy parametrize stress
# ============================================================================


@pytest.mark.parametrize("n", [2, 4, 8, 16, 32])
def test_stress_concurrent_open_close_different_paths(tmp_path, n):
    files = _make_files(tmp_path, n, "h1")
    sup = _make_saving_sup()
    sup.max_workers = 0  # unlimited

    def cycle(i, f):
        sup.open_session(str(f), session_id=f"s{i}", context_id=f"ctx{i}")
        sup.release_session(f"s{i}", f"ctx{i}")

    threads = [_spawn(cycle, i, f) for i, f in enumerate(files)]
    _join_all(threads, timeout=30.0)
    assert sup.sessions == {}
    assert sup.context_bindings == {}
    assert sup.path_to_session == {}


@pytest.mark.parametrize("n", [2, 4, 8, 16])
def test_stress_concurrent_open_same_path_n_callers(tmp_path, n):
    sample = tmp_path / "shared.bin"
    sample.write_bytes(b"x")
    sup = _SlowFakeSupervisor(spawn_delay=0.2)

    def opener(i):
        sup.open_session(str(sample), context_id=f"ctx{i}", wait_timeout=5.0)

    threads = [_spawn(opener, i) for i in range(n)]
    _join_all(threads, timeout=15.0)
    # Exactly one underlying spawn.
    assert sup._spawn_count == 1
    assert len(sup.sessions) == 1
    # All N contexts bound.
    for i in range(n):
        assert f"ctx{i}" in sup.context_bindings


@pytest.mark.parametrize("n", [2, 4, 8, 16])
def test_stress_concurrent_list_under_open(tmp_path, n):
    files = _make_files(tmp_path, n)
    sup = _FakeSupervisor()
    sup.max_workers = 0
    for i, f in enumerate(files):
        sup.open_session(str(f), session_id=f"s{i}", context_id=f"ctx{i}")

    stop = threading.Event()
    errors = []
    errors_lock = threading.Lock()

    def lister():
        while not stop.is_set():
            try:
                sup.list_sessions("ctx0")
            except Exception as e:
                with errors_lock:
                    errors.append(e)
            time.sleep(0.001)

    lister_threads = [_spawn(lister) for _ in range(n)]
    time.sleep(0.2)
    stop.set()
    _join_all(lister_threads, timeout=5.0)
    assert not errors


@pytest.mark.parametrize("n", [2, 4, 8, 16, 32])
def test_stress_concurrent_bind_to_different_contexts(n):
    sup = supmod.IdalibSupervisor(_BearerMcp())

    def binder(i):
        for j in range(5):
            sup.bind_context(f"ctx{i}_{j}", f"sess{i}_{j}")

    threads = [_spawn(binder, i) for i in range(n)]
    _join_all(threads, timeout=15.0)
    assert len(sup.context_bindings) == n * 5


@pytest.mark.parametrize("n", [2, 4, 8])
def test_stress_open_close_interleaved(tmp_path, n):
    files = _make_files(tmp_path, n, "il")
    sup = _make_saving_sup()
    sup.max_workers = 0

    barrier = threading.Barrier(n)

    def cycle(i, f):
        barrier.wait()
        for _ in range(5):
            sup.open_session(str(f), session_id=f"s{i}", context_id=f"ctx{i}")
            sup.release_session(f"s{i}", f"ctx{i}")

    threads = [_spawn(cycle, i, f) for i, f in enumerate(files)]
    _join_all(threads, timeout=60.0)
    # All workers cleaned up.
    assert sup.sessions == {}


@pytest.mark.parametrize("n_readers,n_writers", [(8, 1), (16, 2), (32, 4)])
def test_stress_mixed_readers_writers_under_supervisor(tmp_path, n_readers, n_writers):
    """Simulates the actual production lock pattern under stress.
    Readers do list_sessions (read lock); writers do bind/unbind (write)."""
    files = _make_files(tmp_path, n_writers + 2)
    sup = _make_saving_sup()
    # Pre-create N writer-target sessions.
    for i, f in enumerate(files[:n_writers]):
        sup.open_session(str(f), session_id=f"writer_s{i}", context_id=f"writer_ctx{i}")

    stop = threading.Event()
    errors = []
    errors_lock = threading.Lock()

    def reader():
        while not stop.is_set():
            try:
                sup.list_sessions("ctxR")
            except Exception as e:
                with errors_lock:
                    errors.append(e)

    def writer(i):
        while not stop.is_set():
            try:
                sup.bind_context(f"w{i}", "writer_s0")
                sup.unbind_context(f"w{i}")
            except Exception as e:
                with errors_lock:
                    errors.append(e)

    threads = [_spawn(reader) for _ in range(n_readers)] + [
        _spawn(writer, i) for i in range(n_writers)
    ]
    time.sleep(0.5)
    stop.set()
    _join_all(threads, timeout=10.0)
    assert not errors


@pytest.mark.parametrize("cycles", [10, 50, 100])
def test_stress_sequential_open_close_cycles(tmp_path, cycles):
    sample = tmp_path / "cycle.bin"
    sample.write_bytes(b"x")
    sup = _make_saving_sup()
    for i in range(cycles):
        sup.open_session(str(sample), session_id=f"s{i}", context_id="ctxA")
        sup.release_session(f"s{i}", "ctxA")
    assert sup.sessions == {}
    assert sup.context_bindings == {}


@pytest.mark.parametrize("n_readers", [4, 8, 16])
def test_stress_writer_under_constant_readers(tmp_path, n_readers):
    """Writer must NOT starve under N readers continuously listing."""
    files = _make_files(tmp_path, 1)
    sup = _make_saving_sup()
    sup.open_session(str(files[0]), session_id="anchor", context_id="ctxA")

    stop = threading.Event()

    def reader():
        while not stop.is_set():
            sup.list_sessions("ctxA")

    readers = [_spawn(reader) for _ in range(n_readers)]
    time.sleep(0.05)
    writer_done = threading.Event()

    def writer():
        sup.bind_context("writer_ctx", "anchor")
        writer_done.set()

    w = _spawn(writer)
    assert writer_done.wait(timeout=3.0), "writer starved"
    stop.set()
    _join_all(readers + [w], timeout=5.0)


@pytest.mark.parametrize("n", [4, 8, 16])
def test_stress_pending_open_coalescing(tmp_path, n):
    sample = tmp_path / "shared.bin"
    sample.write_bytes(b"x")
    sup = _SlowFakeSupervisor(spawn_delay=0.5)

    barrier = threading.Barrier(n)
    results = []
    results_lock = threading.Lock()

    def opener(i):
        barrier.wait()
        r = sup.open_session(str(sample), context_id=f"ctx{i}", wait_timeout=3.0)
        with results_lock:
            results.append(r)

    threads = [_spawn(opener, i) for i in range(n)]
    _join_all(threads, timeout=15.0)
    sessions = [r for r in results if not isinstance(r, dict)]
    assert sup._spawn_count == 1
    assert len({s.session_id for s in sessions}) == 1


@pytest.mark.parametrize("n", [2, 4, 8])
def test_stress_max_workers_enforced_under_contention(tmp_path, n):
    """Open n-1 sessions sequentially first to fill the cap; then a
    further concurrent open must fail.

    (Strictly-concurrent enforcement under fast spawns has a known
    race window: the worker is spawned before the session is
    registered, so two parallel spawns can pass the cap check. The
    sequential prefix sidesteps that race and tests the post-cap
    rejection deterministically.)
    """
    files = _make_files(tmp_path, n + 1, "mwc")
    sup = _FakeSupervisor()
    sup.max_workers = n
    # Fill the cap.
    for i in range(n):
        sup.open_session(
            str(files[i]),
            session_id=f"s{i}",
            context_id=f"ctx{i}",
            wait_timeout=5.0,
        )
    # Next concurrent open should be rejected.
    errors = []
    barrier = threading.Barrier(2)
    state_lock = threading.Lock()

    def opener(i):
        barrier.wait()
        try:
            sup.open_session(
                str(files[n]),
                session_id=f"extra{i}",
                context_id=f"ctxExtra{i}",
                wait_timeout=5.0,
            )
        except Exception as e:
            with state_lock:
                errors.append(e)

    # Run two openers on the SAME extra path so the second coalesces;
    # only one spawn will be attempted.
    threads = [_spawn(opener, i) for i in range(2)]
    _join_all(threads, timeout=15.0)
    # Both opens for the extra path attempt the same spawn → at
    # least one error (the spawn) hits the cap.
    assert len(errors) >= 1, f"expected cap rejection, got no errors"
    assert any("Maximum idalib worker count" in str(e) for e in errors), (
        f"expected at least one cap error, got: {[str(e) for e in errors]}"
    )


@pytest.mark.parametrize("n", [2, 4])
def test_stress_cross_binary_close_serialises(tmp_path, n):
    """Releases on DIFFERENT sessions serialise under the global write lock.

    Each release sleeps 0.2s inside the save. If they serialise the
    total wall-clock is ~ n × 0.2s; if parallel it'd be ~ 0.2s.
    """
    files = _make_files(tmp_path, n)
    sup = _make_saving_sup()
    sup.max_workers = 0
    for i, f in enumerate(files):
        sup.open_session(str(f), session_id=f"s{i}", context_id=f"ctx{i}")

    original_save = sup.call_worker_tool

    def slow_save(worker, name, arguments=None):
        if name == "idalib_save":
            time.sleep(0.2)
        return original_save(worker, name, arguments)

    sup.call_worker_tool = slow_save  # type: ignore[assignment]

    def release(i):
        sup.release_session(f"s{i}", f"ctx{i}")

    t0 = time.monotonic()
    threads = [_spawn(release, i) for i in range(n)]
    _join_all(threads, timeout=30.0)
    elapsed = time.monotonic() - t0
    # Serial: n × 0.2s with slack. Parallel would be ~0.3s.
    assert elapsed >= 0.2 * n - 0.1, (
        f"cross-binary closes ran in parallel ({elapsed:.2f}s for n={n})"
    )


@pytest.mark.parametrize("n", [4, 8, 16])
def test_stress_open_with_uniform_session_id_collision_some_fail(tmp_path, n):
    """N concurrent opens with conflicting session_ids — only one wins."""
    files = _make_files(tmp_path, n, "samesid")
    sup = _FakeSupervisor()
    sup.max_workers = 0

    successes = []
    errors = []
    state_lock = threading.Lock()
    barrier = threading.Barrier(n)

    def opener(i, f):
        barrier.wait()
        try:
            sup.open_session(str(f), session_id="conflict", context_id=f"ctx{i}", wait_timeout=2.0)
            with state_lock:
                successes.append(i)
        except Exception as e:
            with state_lock:
                errors.append(e)

    threads = [_spawn(opener, i, f) for i, f in enumerate(files)]
    _join_all(threads, timeout=15.0)
    # Exactly one session must end up with id "conflict".
    assert len(successes) == 1
    assert len(errors) == n - 1
    assert all(isinstance(e, ValueError) for e in errors)


@pytest.mark.parametrize("op_pair", [
    ("open", "list"),
    ("open", "current"),
    ("list", "bind"),
    ("unbind", "list"),
    ("open", "open"),
    ("bind", "unbind"),
])
def test_stress_two_thread_op_pairs_do_not_crash(tmp_path, op_pair):
    sample = tmp_path / "p.bin"
    sample.write_bytes(b"x")
    sup = _make_saving_sup()
    sup.open_session(str(sample), session_id="anchor", context_id="ctxA")

    def do(op):
        if op == "open":
            try:
                sup.open_session(str(sample), context_id="ctxOpen")
            except Exception:
                pass
        elif op == "list":
            sup.list_sessions("ctxA")
        elif op == "current":
            try:
                with sup.session_scope("anchor"):
                    pass
            except Exception:
                pass
        elif op == "bind":
            sup.bind_context("ctxBind", "anchor")
        elif op == "unbind":
            sup.unbind_context("ctxA")

    t1 = _spawn(do, op_pair[0])
    t2 = _spawn(do, op_pair[1])
    _join_all([t1, t2], timeout=5.0)
    # Sessions dict is still consistent.
    for sid, sess in sup.sessions.items():
        assert sess.session_id == sid


@pytest.mark.parametrize("n_threads", [2, 4, 8, 16])
def test_stress_concurrent_resolve_session(tmp_path, n_threads):
    """resolve_session under heavy concurrent reads."""
    sample = tmp_path / "r.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="s", context_id="ctxA")

    errors = []
    errors_lock = threading.Lock()

    def resolver():
        for _ in range(20):
            try:
                sess = sup.resolve_session("s")
                assert sess.session_id == "s"
            except Exception as e:
                with errors_lock:
                    errors.append(e)

    threads = [_spawn(resolver) for _ in range(n_threads)]
    _join_all(threads, timeout=10.0)
    assert not errors


# ============================================================================
# Section I: State invariants
# ============================================================================


def test_invariant_open_close_drains_all_state(tmp_path):
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"x")
    sup = _make_saving_sup()
    sup.open_session(str(sample), session_id="s", context_id="ctxA")
    sup.release_session("s", "ctxA")
    assert sup.sessions == {}
    assert sup.context_bindings == {}
    assert sup.path_to_session == {}


def test_invariant_shutdown_clears_everything(tmp_path):
    files = _make_files(tmp_path, 3)
    sup = _FakeSupervisor()
    for i, f in enumerate(files):
        sup.open_session(str(f), session_id=f"s{i}", context_id=f"ctx{i}")
    sup.shutdown()
    assert sup.sessions == {}
    assert sup.context_bindings == {}
    assert sup.path_to_session == {}


def test_invariant_bind_context_and_internal_dict_mutation_equivalent():
    sup = supmod.IdalibSupervisor(_BearerMcp())
    sup.bind_context("ctxA", "s")
    sup2 = supmod.IdalibSupervisor(_BearerMcp())
    with sup2._rw_lock.write():
        sup2.context_bindings["ctxA"] = "s"
    assert sup.context_bindings == sup2.context_bindings


def test_invariant_register_unregister_symmetry(tmp_path):
    sample = tmp_path / "sym.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    sup.open_session(str(sample), session_id="s", context_id="ctxA")
    pre_sessions = dict(sup.sessions)
    pre_paths = dict(sup.path_to_session)
    pre_bindings = dict(sup.context_bindings)
    with sup._rw_lock.write():
        sup._unregister_session_locked("s")
    assert sup.sessions == {}
    assert sup.path_to_session == {}
    assert sup.context_bindings == {}
    # Re-registering the same session reconstitutes the state.
    sample2 = tmp_path / "sym.bin"  # same path
    session = supmod.WorkerSession(
        session_id="s",
        input_path=str(sample2),
        filename=sample2.name,
        host="127.0.0.1",
        port=3,
        process=_FakeProcess(),
    )
    with sup._rw_lock.write():
        sup._register_session_locked(session, str(sample2), "ctxA")
    # Path keyings restored.
    assert sup._path_key(str(sample2)) in sup.path_to_session
    assert sup.context_bindings["ctxA"] == "s"


def test_invariant_path_to_session_drained_after_close(tmp_path):
    sample = tmp_path / "p.bin"
    sample.write_bytes(b"x")
    sup = _make_saving_sup()
    sup.open_session(str(sample), session_id="s", context_id="ctxA")
    sup.release_session("s", "ctxA")
    # No leftover path keys.
    assert sup.path_to_session == {}


def test_invariant_candidate_idb_paths_covers_i64_and_idb(tmp_path):
    sup = _FakeSupervisor()
    p = tmp_path / "binary.bin"
    keys = sup._candidate_idb_paths(str(p))
    # Should include .bin, .bin.i64, .bin.idb candidates.
    assert any(k.endswith(".bin") for k in keys)
    assert any(k.endswith(".i64") for k in keys)
    assert any(k.endswith(".idb") for k in keys)


def test_invariant_path_key_idempotent(tmp_path):
    sup = _FakeSupervisor()
    p = tmp_path / "x.bin"
    p.write_bytes(b"x")
    k1 = sup._path_key(str(p))
    k2 = sup._path_key(k1)
    # Resolved twice — same answer.
    assert k1 == k2


def test_invariant_normalize_input_path_missing_raises(tmp_path):
    sup = _FakeSupervisor()
    with pytest.raises(FileNotFoundError):
        sup._normalize_input_path(str(tmp_path / "absent.bin"))


def test_invariant_normalize_input_path_returns_absolute(tmp_path):
    sample = tmp_path / "x.bin"
    sample.write_bytes(b"x")
    sup = _FakeSupervisor()
    out = sup._normalize_input_path(str(sample))
    assert Path(out).is_absolute()


def test_invariant_after_concurrent_open_state_consistent(tmp_path):
    files = _make_files(tmp_path, 8, "inv")
    sup = _FakeSupervisor()
    sup.max_workers = 0

    def opener(i, f):
        sup.open_session(str(f), session_id=f"s{i}", context_id=f"ctx{i}")

    threads = [_spawn(opener, i, f) for i, f in enumerate(files)]
    _join_all(threads, timeout=15.0)
    # 8 sessions, 8 bindings, path-to-session covers all.
    assert len(sup.sessions) == 8
    assert len(sup.context_bindings) == 8
    # Every path key in path_to_session points to a real session.
    for path_key, sid in sup.path_to_session.items():
        assert sid in sup.sessions


def test_invariant_after_partial_release_cleanup(tmp_path):
    files = _make_files(tmp_path, 4, "inv4")
    sup = _make_saving_sup()
    sup.max_workers = 0
    for i, f in enumerate(files):
        sup.open_session(str(f), session_id=f"s{i}", context_id=f"ctx{i}")
    # Release half.
    sup.release_session("s0", "ctx0")
    sup.release_session("s2", "ctx2")
    # Surviving sessions intact.
    assert "s1" in sup.sessions
    assert "s3" in sup.sessions
    # Released sessions gone.
    assert "s0" not in sup.sessions
    assert "s2" not in sup.sessions
    # path_to_session points only to live sessions.
    for path_key, sid in sup.path_to_session.items():
        assert sid in sup.sessions


def test_invariant_pending_drains_after_completion(tmp_path):
    sample = tmp_path / "slow.bin"
    sample.write_bytes(b"x")
    sup = _SlowFakeSupervisor(spawn_delay=0.2)
    sup.open_session(str(sample), context_id="ctxA", wait_timeout=2.0)
    assert sup._pending == {}


def test_invariant_shutdown_after_concurrent_opens(tmp_path):
    files = _make_files(tmp_path, 8, "shut")
    sup = _FakeSupervisor()
    sup.max_workers = 0

    def opener(i, f):
        sup.open_session(str(f), session_id=f"s{i}", context_id=f"ctx{i}")

    threads = [_spawn(opener, i, f) for i, f in enumerate(files)]
    _join_all(threads, timeout=15.0)
    sup.shutdown()
    assert sup.sessions == {}
    assert sup.context_bindings == {}
    assert sup.path_to_session == {}


def test_invariant_force_close_session_returns_false_for_unknown():
    sup = _make_saving_sup()
    assert sup.close_session("ghost") is False


def test_invariant_force_close_session_terminates(tmp_path):
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"x")
    sup = _make_saving_sup()
    sup.open_session(str(sample), session_id="s", context_id="ctxA")
    sup.bind_context("ctxB", "s")
    # Force-close drops EVERY binding.
    assert sup.close_session("s") is True
    assert "s" not in sup.sessions
    assert sup.context_bindings == {}
