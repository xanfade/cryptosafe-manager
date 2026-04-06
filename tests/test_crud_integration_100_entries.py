from tests.conftest import make_entry_payload


def test_crud_integration_100_entries(vault_service):
    created_entries = []

    # CREATE 100
    for i in range(100):
        entry = vault_service.create_entry(make_entry_payload(i))
        created_entries.append(entry)

    all_entries = vault_service.list_entries()
    assert len(all_entries) == 100

    # UPDATE 20
    updated_ids = []
    for i in range(20):
        entry_id = created_entries[i].id
        updated = vault_service.update_entry(
            entry_id,
            make_entry_payload(
                i,
                title=f"Updated Title {i}",
                username=f"updated{i}@example.com",
                password=f"UpdatedStrong{i}!Aa9",
                url=f"https://updated{i}.example.com",
                notes=f"Updated notes {i}",
                category="updated",
                tags="updated,checked",
            ),
        )
        updated_ids.append(entry_id)

        assert updated.id == entry_id
        assert updated.title == f"Updated Title {i}"
        assert updated.username == f"updated{i}@example.com"
        assert updated.password == f"UpdatedStrong{i}!Aa9"
        assert updated.url == f"https://updated{i}.example.com"
        assert updated.notes == f"Updated notes {i}"
        assert updated.category == "updated"
        assert updated.tags == "updated,checked"

    # DELETE 15
    deleted_ids = []
    for i in range(20, 35):
        entry_id = created_entries[i].id
        vault_service.delete_entry(entry_id)
        deleted_ids.append(entry_id)

    remaining_entries = vault_service.list_entries()
    assert len(remaining_entries) == 85

    remaining_by_id = {entry.id: entry for entry in remaining_entries}

    # deleted absent
    for entry_id in deleted_ids:
        assert entry_id not in remaining_by_id
        assert vault_service.get_entry(entry_id) is None

    # updated intact
    for i in range(20):
        entry_id = created_entries[i].id
        entry = remaining_by_id[entry_id]
        assert entry.title == f"Updated Title {i}"
        assert entry.username == f"updated{i}@example.com"
        assert entry.password == f"UpdatedStrong{i}!Aa9"
        assert entry.url == f"https://updated{i}.example.com"
        assert entry.notes == f"Updated notes {i}"
        assert entry.category == "updated"
        assert entry.tags == "updated,checked"

    # untouched intact
    for i in range(35, 100):
        entry_id = created_entries[i].id
        entry = remaining_by_id[entry_id]
        original = make_entry_payload(i)

        assert entry.title == original["title"]
        assert entry.username == original["username"]
        assert entry.password == original["password"]
        assert entry.url == original["url"]
        assert entry.notes == original["notes"]
        assert entry.category == original["category"]
        assert entry.tags == original["tags"]