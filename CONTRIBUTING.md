# Contributing

Thank you for your interest in Zero Project! We welcome suggestions, data corrections, and contributions.

## Issues

### Suggest a tool or source to track

Open an issue using the **[Suggestion template](https://github.com/sirbennyy88/zero-project/issues/new?template=suggestion.yml).**

Include:
- What you'd like Zero Project to track (vendor, ecosystem, tool, data feed)
- A primary source URL (feed, API endpoint, advisory page)
- Why it matters (who would find it useful?)

### Report a data error

Open an issue using the **[Data error template](https://github.com/sirbennyy88/zero-project/issues/new?template=data-error.yml).**

Include:
- Where on the page the error is (section name, date, CVE, vendor)
- What's wrong and what the correct value should be
- A primary source URL proving the correct value

## Pull requests

### For `manual.json` changes

`manual.json` contains curated facts: events, timelines, ecosystem/framework lists, and fallback data.

**Before submitting a PR:**
- Cite every fact with a primary URL (vendor advisory, CISA entry, cve.org record, etc.)
- Keep citations brief but specific

**Example:**
```json
{
  "date": "2026-03-15",
  "label": "Example CVE disclosed",
  "source": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-1234"
}
```

### For `data-src/refresh.py` changes

The refresh pipeline is the heart of the project. Before submitting:

1. **Test locally:**
   ```bash
   python data-src/refresh.py --offline
   ```

2. **Ensure it runs with or without GITHUB_TOKEN:**
   - Without: uses cached data, skips per-ecosystem counts
   - With: enables detailed GitHub Advisory Database breakdown

3. **Keep it stdlib-only** (Python 3.10+, no pip dependencies)

4. **Follow the pattern:** Each data source is a `@cached()` function with its own error handling

### For `index.html` changes

Keep it single-file with no build step. All CSS and JavaScript inline.

- Test in a modern browser (Chrome, Firefox, Safari)
- Keep the page responsive
- Respect the existing color scheme and typography

## Development workflow

1. **Fork** the repo
2. **Create a branch** (`git checkout -b feature/my-idea`)
3. **Make changes** and test locally
4. **Commit with clear messages** (`git commit -am "Add support for X"`)
5. **Push** and open a PR with a description of what and why

## Questions?

Open an issue or start a discussion. We're happy to help!

---

Licensed under MIT (code) and CC BY 4.0 (data).
