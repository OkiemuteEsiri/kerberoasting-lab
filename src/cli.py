import argparse
from pathlib import Path

from .assessor import assess, load_accounts
from .report import render


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline Kerberos service-account exposure assessment")
    parser.add_argument("input", help="Path to synthetic/exported JSON inventory")
    parser.add_argument("--report", default="assessment.md", help="Markdown output path")
    args = parser.parse_args()

    findings = assess(load_accounts(args.input))
    output = render(findings)
    Path(args.report).write_text(output, encoding="utf-8")
    print(f"wrote {len(findings)} findings to {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
