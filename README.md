# FieldSpider

FieldSpider is a **passive** Python crawler that maps text fields and file upload opportunities on a target site so authorized testers can prioritize manual review.

## What it does
- Crawls pages on the same host as your starting URL.
- Finds HTML forms and extracts:
  - text-like input fields
  - password fields
  - textareas
  - file upload fields
- Adds simple review notes (heuristics) for areas that commonly need security validation.

> ⚠️ This tool does **not** send attack payloads and should be used only on systems you own or are explicitly authorized to test.

## Usage
```bash
python3 field_spider.py https://example.com --max-pages 25 --timeout 10
```

JSON output:
```bash
python3 field_spider.py https://example.com --json
```
