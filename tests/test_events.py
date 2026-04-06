from src.core.events import EventBus, EntryCreated


def test_event_bus_publish_calls_handler():
    bus = EventBus()
    called = {"n": 0}

    def handler(e):
        called["n"] += 1

    bus.subscribe(EntryCreated, handler)
    bus.publish(EntryCreated(entry_id=1))

    assert called["n"] == 1
