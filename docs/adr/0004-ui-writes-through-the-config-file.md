# UI writes go through the config file, never around it

The management UI gained full editing (image settings, Overrides, menu,
alerts, auth, answer files). ADR-0002 rejected UI-owned opaque state, and
that still holds: every write the UI makes is a mutation of `emberboot.yaml`
itself (or a file in `answers/`), applied atomically only after the whole
resulting document passes the same strict validation as a hand edit, then
picked up by the normal hot-reload path. A rejected edit changes nothing.
The file remains the single source of truth: hand edits, git diffs, and
server rebuilds keep working exactly as before, and the UI is just another
editor of the same file.

**Consequences**: programmatic saves rewrite the YAML, so hand-written
comments in edited sections do not survive a UI save; network/listener
settings can be edited but only apply on restart (listeners bind at
startup), and the UI labels them so.
