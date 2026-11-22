from dataclasses import dataclass
from types import SimpleNamespace
from security_agent.application.effective_property_inspector import EffectiveGradlePropertyInspector
from security_agent.application.gradle_property_collector import GradlePropertyResult
from security_agent.application.constraint_aware_repository_inspector import SourceDeclaration
from security_agent.domain.ai_recommendation_context import DependencyRelationship


@dataclass(frozen=True)
class FakeInspection:
    source_declarations: tuple


def declaration():
    return SourceDeclaration(
        module_path=":service", manifest_file="service/build.gradle.kts",
        dependency="com.fasterxml.jackson.core:jackson-databind",
        declaration='implementation("com.fasterxml.jackson.core:jackson-databind:$jacksonVersion")',
        declaration_kind="DEPENDENCY", declaration_relationship=DependencyRelationship.DIRECT,
        vulnerable_dependency_relationship=DependencyRelationship.DIRECT,
        source_type="GRADLE_PROJECT_PROPERTY", property_name="jacksonVersion",
        lookup_scope="CURRENT_PROJECT", source_resolved=False,
        candidate_source_file="gradle.properties", candidate_value="2.13.4",
    )


class FakeInspector:
    def inspect(self, finding):
        return FakeInspection((declaration(),))


class FakeCollector:
    def __init__(self, results):
        self.results = results
        self.requests = ()

    def collect(self, requests):
        self.requests = requests
        return self.results


def test_attaches_effective_value_and_preserves_candidate():
    collector = FakeCollector((GradlePropertyResult(
        ":service", "jacksonVersion", "CURRENT_PROJECT", "RESOLVED", "2.13.4"),))
    result = EffectiveGradlePropertyInspector(FakeInspector(), collector).inspect(None)
    item = result.source_declarations[0]
    assert item.effective_property_value == "2.13.4"
    assert item.effective_property_status == "RESOLVED"
    assert item.candidate_value == "2.13.4"
    assert item.source_resolved is False
    assert len(collector.requests) == 1


def test_missing_value_is_not_inferred_from_candidate():
    collector = FakeCollector((GradlePropertyResult(
        ":service", "jacksonVersion", "CURRENT_PROJECT", "MISSING"),))
    result = EffectiveGradlePropertyInspector(FakeInspector(), collector).inspect(None)
    item = result.source_declarations[0]
    assert item.effective_property_status == "MISSING"
    assert item.effective_property_value is None
    assert item.candidate_value == "2.13.4"


def test_collection_failure_preserves_inspection():
    class BrokenCollector:
        def collect(self, requests):
            raise RuntimeError("gradle failed")
    result = EffectiveGradlePropertyInspector(FakeInspector(), BrokenCollector()).inspect(None)
    assert result.source_declarations[0].effective_property_status == "COLLECTION_FAILED"
