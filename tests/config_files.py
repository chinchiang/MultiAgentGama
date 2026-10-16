"""測試用的設定檔：讀出內建的 `agents_config.yaml`、修改後寫到測試的暫存目錄。不是測試模組（檔名不以 `test_`
開頭，pytest 不會收集它）。
Config files for tests: read the bundled `agents_config.yaml`, then write an edited copy to the test's temporary
directory. Not a test module (the name does not start with `test_`, so pytest does not collect it)."""
import os

import yaml

CONFIG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "vibeharness", "config",
                      "agents_config.yaml")


def load_config() -> dict:
    """內建設定的一份新副本，可以任意修改 ／ A fresh copy of the bundled config, free to edit."""
    with open(CONFIG, encoding="utf-8") as f:
        return yaml.safe_load(f)


def write_config(tmp_path, cfg: dict, name: str = "cfg.yaml") -> str:
    """把 `cfg` 寫成 `tmp_path / name`，回傳路徑字串 ／ Writes `cfg` to `tmp_path / name` and returns the path as a string."""
    path = tmp_path / name
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    return str(path)
