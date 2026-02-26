from src.core.config import ConfigManager


def test_config_save_load(tmp_path):
    path = tmp_path / "config.json"
    cfg = ConfigManager(str(path))
    cfg.set("db_path", "app.db")
    cfg.save()

    cfg2 = ConfigManager(str(path))
    cfg2.load()
    assert cfg2.get("db_path") == "app.db"
