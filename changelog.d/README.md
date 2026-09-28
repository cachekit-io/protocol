# Changelog fragments

Each unreleased change gets its own file in this directory. Pull requests do not edit
[`CHANGELOG.md`](../CHANGELOG.md): when every PR adds its entry under the same
`## [Unreleased]` heading, any two open PRs conflict. Separate files never do. CI fails a
PR that edits `CHANGELOG.md`, unless the PR is a release (see below).

## Adding an entry

Create `changelog.d/<YYYYMMDD>_<ticket-id>.md`, for example
`changelog.d/20260929_lab-6153.md`, using the date you write it. The file holds the entry
exactly as it will appear in the changelog: a `###` heading naming the area and the change,
then bullets.

```markdown
### Wire format — short statement of the change (LAB-1234)

- What changed, with a link to the spec section.
- **Breaking for …:** who is affected and how to migrate, when it applies.
```

Files are collected in filename order, so entries appear in the order they were written,
not the order they merged. Never let one entry's meaning depend on appearing before or
after another.

A change that needs no changelog entry does not add a file.

## Releasing

Releases are cut from a branch named `release/<version>`. That prefix is the CI exemption.

```bash
git checkout -b release/1.1.0 origin/main
python3 tools/changelog-collect.py 1.1.0
```

`tools/changelog-collect.py` writes a `## [1.1.0] - <date>` section at the
`<!-- changelog-insert-here -->` marker in `CHANGELOG.md`, holding every fragment verbatim
in filename order, and deletes the collected fragments. It never regroups or rewrites
entries. This README stays, and so does the marker. Everything merged between 1.0.0 and
this directory's introduction is in `20260328_unreleased-since-1.0.0.md`, which sorts
first, so the first release's section contains it.
