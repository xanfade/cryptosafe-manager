from src.core.events import EventBus, EntryAdded


def test_event_bus_publish_calls_handler():
    bus = EventBus()
    called = {"n": 0}

    def handler(e):
        called["n"] += 1

    bus.subscribe(EntryAdded, handler)
    bus.publish(EntryAdded(entry_id=1))

    assert called["n"] == 1
