"""讓 `python -m vibeharness ...` 等同於 `vibeharness ...`：缺少相依套件時同樣以 exit 5 結束（由 cli.main 處理）。
Makes `python -m vibeharness ...` the same as `vibeharness ...`: a missing dependency also exits 5 (cli.main handles it)."""
from vibeharness.cli import main

if __name__ == "__main__":
    main()
