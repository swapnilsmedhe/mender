
from security_agent.application.gradle_dependency_report import (
    GradleDependencyReportParser,
)


DIRECT_CONSUMER_OUTPUT = """
> Task :direct-consumer:dependencyInsight
com.fasterxml.jackson.core:jackson-databind:2.13.4 (by constraint)
  Variant runtimeElements:
    | Attribute Name                     | Provided     | Requested    |

com.fasterxml.jackson.core:jackson-databind:2.13.4
+--- runtimeClasspath
\\--- com.fasterxml.jackson:jackson-bom:2.13.4
     +--- com.fasterxml.jackson.core:jackson-annotations:2.13.4
     |    +--- com.fasterxml.jackson:jackson-bom:2.13.4 (*)
     |    \\--- com.fasterxml.jackson.core:jackson-databind:2.13.4 (*)
     +--- com.fasterxml.jackson.core:jackson-core:2.13.4
     |    +--- com.fasterxml.jackson:jackson-bom:2.13.4 (*)
     |    \\--- com.fasterxml.jackson.core:jackson-databind:2.13.4 (*)
     \\--- com.fasterxml.jackson.core:jackson-databind:2.13.4 (*)
"""


BOM_CONSUMER_OUTPUT = """
> Task :bom-consumer:dependencyInsight
com.fasterxml.jackson.core:jackson-databind:2.13.4 (by constraint)
  Variant runtimeElements:
    | Attribute Name                     | Provided     | Requested    |

com.fasterxml.jackson.core:jackson-databind:2.13.4
+--- com.fasterxml.jackson:jackson-bom:2.13.4
|    +--- runtimeClasspath
|    +--- com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.13.4
|    |    +--- runtimeClasspath (requested com.fasterxml.jackson.datatype:jackson-datatype-jsr310)
|    |    \\--- com.fasterxml.jackson:jackson-bom:2.13.4 (*)
|    +--- com.fasterxml.jackson.core:jackson-databind:2.13.4 (*)
|    +--- com.fasterxml.jackson.core:jackson-annotations:2.13.4
|    |    +--- com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.13.4 (*)
|    |    +--- com.fasterxml.jackson.core:jackson-databind:2.13.4 (*)
|    |    \\--- com.fasterxml.jackson:jackson-bom:2.13.4 (*)
|    \\--- com.fasterxml.jackson.core:jackson-core:2.13.4
|         +--- com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.13.4 (*)
|         +--- com.fasterxml.jackson.core:jackson-databind:2.13.4 (*)
|         \\--- com.fasterxml.jackson:jackson-bom:2.13.4 (*)
\\--- com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.13.4 (*)

com.fasterxml.jackson.core:jackson-databind -> 2.13.4
\\--- runtimeClasspath
"""


def test_parses_direct_consumer_report():
    report = GradleDependencyReportParser().parse(
        DIRECT_CONSUMER_OUTPUT
    )

    assert report.selected_dependency == (
        "com.fasterxml.jackson.core:jackson-databind:2.13.4"
    )

    assert report.is_selected_by_constraint
    assert report.runtime_classpath_entry_count == 1
    assert report.repeated_entry_count > 0


def test_parses_bom_consumer_report():
    report = GradleDependencyReportParser().parse(
        BOM_CONSUMER_OUTPUT
    )

    assert report.selected_dependency == (
        "com.fasterxml.jackson.core:jackson-databind:2.13.4"
    )

    assert report.is_selected_by_constraint
    assert report.runtime_classpath_entry_count == 3
    assert report.repeated_entry_count > 0


def test_repeated_subtrees_are_not_expanded():
    report = GradleDependencyReportParser().parse(
        DIRECT_CONSUMER_OUTPUT
    )

    repeated_entries = [
        entry
        for entry in report.entries
        if entry.is_repeated
    ]

    assert repeated_entries
    assert all(entry.notation for entry in repeated_entries)


def test_parser_handles_empty_output():
    report = GradleDependencyReportParser().parse("")

    assert report.selected_dependency is None
    assert report.entries == ()
    assert not report.is_selected_by_constraint
