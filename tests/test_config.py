from scanner_core.config import ScanConfig


def test_default_config_has_all_modules():
    cfg = ScanConfig()
    # 20 modül var
    assert len(cfg.modules) >= 20
    assert cfg.modules.get("credential_scanner") == True
    assert cfg.modules.get("browser_scanner") == True


def test_config_loads_missing_file():
    cfg = ScanConfig()
    cfg.load("/nonexistent/path/config.json")
    # Hata vermeden default'lara fallback etmeli
    assert cfg.scan["max_file_size_mb"] == 50
