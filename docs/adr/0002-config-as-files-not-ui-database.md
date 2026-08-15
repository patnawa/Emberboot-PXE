# Config as files with Last-Known-Good, not an opaque UI database

iVentoy-style tools keep configuration in an opaque internal database, which
makes servers unrebuildable and changes unauditable — the opposite of our
24x7 goal. We decided the source of truth is a YAML config file plus the image
and answer-file folders: diffable, backupable, restorable in minutes. The
config hot-reloads with Last-Known-Good semantics — an invalid config is
rejected (logged, alerted, shown in dashboard) while the previous valid config
keeps serving; a bad 2am edit never stops Clients booting. The Web UI and REST
API may edit this source of truth only through the same validation and atomic
file-replacement path described by ADR-0004. They must never introduce a
second config database.

**Consequences**: the SQLite boot-session store must remain a disposable cache — if any state ever becomes config-like and unrebuildable from files, this decision has been silently reversed.
