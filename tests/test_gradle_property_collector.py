import base64
from security_agent.application.gradle_property_collector import GradlePropertyCollector, GradlePropertyRequest


def encode(value):
    return base64.b64encode(value.encode()).decode("ascii")


def record(module, name, scope, status, value="", error=""):
    return "MENDER_GRADLE_PROPERTY\t" + "\t".join(
        encode(item) for item in (module, name, scope, status, value, error)
    )


def test_parses_resolved_value():
    result = GradlePropertyCollector.parse_output(
        record(":service", "jacksonVersion", "CURRENT_PROJECT", "RESOLVED", "2.13.4")
    )[0]
    assert result.status == "RESOLVED"
    assert result.value == "2.13.4"


def test_parses_missing_value():
    result = GradlePropertyCollector.parse_output(
        record(":service", "jacksonVersion", "CURRENT_PROJECT", "MISSING")
    )[0]
    assert result.status == "MISSING"
    assert result.value is None


def test_parses_lookup_error():
    result = GradlePropertyCollector.parse_output(
        record(":service", "jacksonVersion", "CURRENT_PROJECT", "ERROR", error="lookup failed")
    )[0]
    assert result.status == "ERROR"
    assert result.error == "lookup failed"


def test_ignores_malformed_records():
    assert GradlePropertyCollector.parse_output("MENDER_GRADLE_PROPERTY\tbad") == ()


def test_rejects_unknown_lookup_scope():
    try:
        GradlePropertyRequest(":service", "jacksonVersion", "ANY")
    except ValueError:
        return
    raise AssertionError("Expected ValueError")


def test_script_uses_project_scoped_find_property():
    script = GradlePropertyCollector._create_init_script()
    assert "lookupProject.findProperty(propertyName)" in script
    assert "scope == \"ROOT_PROJECT\" ? gradle.rootProject : module" in script
