# Config as files with Last-Known-Good, not a UI-edited database

iVentoy-style tools keep configuration in an opaque internal database edited through the UI, which makes servers unrebuildable and changes unauditable — the opposite of our 24x7 goal. We decided the source of truth is a YAML config file plus the image folder: diffable, backupable, restorable in minutes. The config hot-reloads with Last-Known-Good semantics — an invalid config is rejected (logged, alerted, shown in dashboard) while the previous valid config keeps serving; a bad 2am edit never stops Clients booting. The web dashboard is read-mostly operations (Boot Sessions, Image states, health), and the REST API exists for automation, not as a second write path around the file.

**Consequences**: the SQLite boot-session store must remain a disposable cache — if any state ever becomes config-like and unrebuildable from files, this decision has been silently reversed.
