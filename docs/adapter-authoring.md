# Adapter Authoring

Create an adapter under `dnsintel/sources/`, implement `collect()`, return
`SourceResult`, and normalize data into `Evidence`. Add fixture tests for normal,
empty, malformed, disabled, and authorization-required cases.

