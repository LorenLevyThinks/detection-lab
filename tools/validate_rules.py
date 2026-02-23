import sys
import re
from pathlib import Path

import yaml


REQUIRED_KEYS = {"title", "id", "logsource", "detection", "level"}
ID_PATTERN = re.compile(r"^D-\d{4}$")  # e.g., D-0001


def find_sigma_files(repo_root: Path) -> list[Path]:
    # Look for files named rule.sigma.yml anywhere under detections/
    return sorted(repo_root.glob("detections/**/rule.sigma.yml"))


def load_yaml(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError("YAML root must be a mapping/object")
    return data


def validate_rule(rule: dict, path: Path) -> list[str]:
    errors: list[str] = []

    missing = REQUIRED_KEYS - set(rule.keys())
    if missing:
        errors.append(f"Missing required keys: {sorted(missing)}")

    rule_id = rule.get("id")
    if not isinstance(rule_id, str) or not ID_PATTERN.match(rule_id):
        errors.append("Invalid id format. Expected like D-0001")

    tags = rule.get("tags", [])
    if not isinstance(tags, list):
        errors.append("tags must be a list")
    else:
        if not any(isinstance(t, str) and t.startswith("attack.") for t in tags):
            errors.append("tags should include at least one attack.* tag (MITRE mapping)")

    logsource = rule.get("logsource")
    if isinstance(logsource, dict):
        if not logsource.get("product"):
            errors.append("logsource.product is missing/empty")
        if not (logsource.get("category") or logsource.get("service")):
            errors.append("logsource should include category or service")
    else:
        errors.append("logsource must be a mapping/object")

    detection = rule.get("detection")
    if isinstance(detection, dict):
        if "condition" not in detection:
            errors.append("detection.condition is missing")
    else:
        errors.append("detection must be a mapping/object")

    return errors


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    sigma_files = find_sigma_files(repo_root)

    if not sigma_files:
        print("No Sigma files found at detections/**/rule.sigma.yml")
        return 2

    all_ids: dict[str, Path] = {}
    had_errors = False

    for path in sigma_files:
        try:
            rule = load_yaml(path)
        except Exception as e:
            had_errors = True
            print(f"[FAIL] {path.as_posix()}: YAML parse error: {e}")
            continue

        errors = validate_rule(rule, path)
        rule_id = rule.get("id")

        if isinstance(rule_id, str):
            if rule_id in all_ids:
                had_errors = True
                print(f"[FAIL] Duplicate id {rule_id}: {path.as_posix()} and {all_ids[rule_id].as_posix()}")
            else:
                all_ids[rule_id] = path

        if errors:
            had_errors = True
            print(f"[FAIL] {path.as_posix()}")
            for err in errors:
                print(f"  - {err}")
        else:
            print(f"[OK]   {path.as_posix()}  ({rule_id})")

    return 1 if had_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())