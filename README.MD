# wxl-races-patcher

WarcraftXL module that expands the client limit to 64 playable races, using
race IDs from `0` through `63`.

The original module was created by [Furioz420](https://github.com/Furioz420/)
and patched the client to support up to 32 races. This version has been modified
to support up to 64 races by expanding the internal tables, their initialization
and cleanup logic, and the validation of extended race IDs.
