from __future__ import annotations

from pathlib import Path
import xml.etree.ElementTree as ET


REPORT_DIR = Path(__file__).resolve().parent
JUNIT_PATH = REPORT_DIR / "junit.xml"
COVERAGE_PATH = REPORT_DIR / "coverage.xml"
SUMMARY_PATH = REPORT_DIR / "summary.md"


def parse_junit(path: Path) -> dict[str, str]:
    root = ET.parse(path).getroot()
    suite = root if root.tag == "testsuite" else root.find("testsuite")
    if suite is None:
        raise RuntimeError("testsuite not found in junit.xml")

    tests = int(suite.attrib.get("tests", "0"))
    failures = int(suite.attrib.get("failures", "0"))
    errors = int(suite.attrib.get("errors", "0"))
    skipped = int(suite.attrib.get("skipped", "0"))
    passed = tests - failures - errors - skipped
    return {
        "tests": str(tests),
        "passed": str(passed),
        "failures": str(failures),
        "errors": str(errors),
        "skipped": str(skipped),
        "time": suite.attrib.get("time", "0"),
    }


def parse_coverage(path: Path) -> tuple[str, list[tuple[str, str]]]:
    root = ET.parse(path).getroot()
    line_rate = float(root.attrib.get("line-rate", "0")) * 100
    rows: list[tuple[str, str]] = []

    for package in root.findall(".//package"):
        for cls in package.findall("./classes/class"):
            filename = cls.attrib.get("filename", "")
            percent = float(cls.attrib.get("line-rate", "0")) * 100
            rows.append((filename.replace("\\", "/"), f"{percent:.0f}%"))

    rows.sort(key=lambda item: item[0])
    return f"{line_rate:.0f}%", rows


def build_summary() -> str:
    junit = parse_junit(JUNIT_PATH)
    overall_coverage, module_rows = parse_coverage(COVERAGE_PATH)

    lines = [
        "# Test Report",
        "",
        "## Summary",
        "",
        f"- Total tests: {junit['tests']}",
        f"- Passed: {junit['passed']}",
        f"- Failed: {junit['failures']}",
        f"- Errors: {junit['errors']}",
        f"- Skipped: {junit['skipped']}",
        f"- Duration (s): {junit['time']}",
        f"- Overall coverage: {overall_coverage}",
        "",
        "## Module Coverage",
        "",
        "| Module | Coverage |",
        "|---|---:|",
    ]

    for module, coverage in module_rows:
        lines.append(f"| `{module}` | {coverage} |")

    lines.extend(
        [
            "",
            "## Artifacts",
            "",
            "- `junit.xml`: test execution summary",
            "- `coverage.xml`: machine-readable coverage report",
            "- `htmlcov/`: HTML coverage details",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> None:
    if not JUNIT_PATH.exists():
        raise FileNotFoundError(JUNIT_PATH)
    if not COVERAGE_PATH.exists():
        raise FileNotFoundError(COVERAGE_PATH)

    SUMMARY_PATH.write_text(build_summary(), encoding="utf-8")


if __name__ == "__main__":
    main()
