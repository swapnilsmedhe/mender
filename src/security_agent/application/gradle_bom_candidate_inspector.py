import base64
import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass

from security_agent.application.constraint_aware_repository_inspector import (
    ConstraintAwareRepositoryInspection,
)


@dataclass(frozen=True)
class GradleBomCandidateRequest:
    module_path: str
    configuration: str
    bom_group: str
    bom_artifact: str
    candidate_selector: str
    target_group: str
    target_artifact: str
    scanner_fixed_versions: tuple[str, ...] = ()


@dataclass(frozen=True)
class GradleBomCandidateEvidence:
    module_path: str
    configuration: str
    bom_coordinate: str
    candidate_selector: str
    status: str
    selected_bom_version: str | None = None
    target_component: str | None = None
    target_selected_version: str | None = None
    related_module_versions: tuple[str, ...] = ()
    scanner_fixed_versions: tuple[str, ...] = ()
    error: str | None = None

    @property
    def exact_scanner_fixed_match(self) -> bool:
        return (
            self.target_selected_version is not None
            and self.target_selected_version in self.scanner_fixed_versions
        )


@dataclass(frozen=True)
class BomCandidateRepositoryInspection(ConstraintAwareRepositoryInspection):
    bom_candidate_evidence: tuple[GradleBomCandidateEvidence, ...] = ()


class GradleBomCandidateCollector:
    MARKER = "MENDER_BOM_CANDIDATE"
    MAX_REQUESTS = 40

    def __init__(self, tools, timeout_seconds: int = 180) -> None:
        if timeout_seconds < 1:
            raise ValueError("Timeout must be at least one second.")
        self.tools = tools
        self.timeout_seconds = timeout_seconds

    def collect(self, requests):
        requests = tuple(dict.fromkeys(requests))
        if not requests:
            return ()
        if len(requests) > self.MAX_REQUESTS:
            raise ValueError("Too many BOM candidate investigation requests.")

        grouped = {}
        for request in requests:
            key = (request.bom_group, request.bom_artifact, request.candidate_selector)
            grouped.setdefault(key, []).append(request)

        results = []
        for (group, artifact, selector), group_requests in grouped.items():
            results.extend(self._collect_selector(
                group, artifact, selector, tuple(group_requests)
            ))
        return tuple(results)

    def _collect_selector(self, bom_group, bom_artifact, selector, requests):
        import base64
        import json
        import os
        import subprocess
        import tempfile
        from pathlib import Path

        root = self.tools.root.resolve()
        wrapper_name = "gradlew.bat" if os.name == "nt" else "gradlew"
        wrapper = root / wrapper_name
        if not wrapper.is_file():
            raise FileNotFoundError(f"Gradle wrapper not found: {wrapper}")

        payload = [
            {
                "module_path": item.module_path,
                "configuration": item.configuration,
                "bom_group": item.bom_group,
                "bom_artifact": item.bom_artifact,
                "candidate_selector": item.candidate_selector,
                "target_group": item.target_group,
                "target_artifact": item.target_artifact,
            }
            for item in requests
        ]
        encoded = base64.b64encode(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")

        with tempfile.TemporaryDirectory() as temp_dir:
            script_path = Path(temp_dir) / "mender-bom-candidates.init.gradle"
            script_path.write_text(self._create_init_script(), encoding="utf-8")
            command = [
                str(wrapper), "--init-script", str(script_path),
                f"-Pmender.bom.requests={encoded}", "help", "--console=plain",
            ]
            try:
                process = subprocess.run(
                    command, cwd=root, capture_output=True, text=True,
                    timeout=self.timeout_seconds, check=False, shell=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(
                    "Gradle BOM candidate investigation timed out."
                ) from exc

        parsed = self.parse_output(f"{process.stdout}\n{process.stderr}")
        if process.returncode != 0:
            raise RuntimeError("Gradle BOM candidate investigation failed.")

        by_key = {
            (item.module_path, item.configuration, item.bom_coordinate,
             item.candidate_selector): item
            for item in parsed
        }
        results = []
        for request in requests:
            key = (
                request.module_path, request.configuration,
                f"{request.bom_group}:{request.bom_artifact}",
                request.candidate_selector,
            )
            evidence = by_key.get(key)
            if evidence is None:
                evidence = GradleBomCandidateEvidence(
                    module_path=request.module_path,
                    configuration=request.configuration,
                    bom_coordinate=f"{request.bom_group}:{request.bom_artifact}",
                    candidate_selector=request.candidate_selector,
                    status="MISSING_RESULT",
                    scanner_fixed_versions=request.scanner_fixed_versions,
                    error="Gradle did not return a result for this module.",
                )
            else:
                evidence = GradleBomCandidateEvidence(
                    **{
                        **evidence.__dict__,
                        "scanner_fixed_versions": request.scanner_fixed_versions,
                    }
                )
            results.append(evidence)
        return tuple(results)

    @classmethod
    def parse_output(cls, output):
        results = []
        for line in output.splitlines():
            if not line.startswith(cls.MARKER + "\t"):
                continue
            parts = line.split("\t")
            if len(parts) != 11:
                continue
            try:
                values = [
                    base64.b64decode(part, validate=True).decode("utf-8")
                    for part in parts[1:]
                ]
                (module, configuration, selector, bom, status, bom_version,
                 target, target_version, related_json, error) = values
                related = json.loads(related_json or "[]")
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
                continue
            if status not in (
                "RESOLVED", "BOM_NOT_RESOLVED", "TARGET_NOT_RESOLVED",
                "CONFIGURATION_NOT_FOUND", "ERROR",
            ):
                continue
            if not isinstance(related, list) or not all(
                isinstance(item, str) for item in related
            ):
                continue
            results.append(GradleBomCandidateEvidence(
                module_path=module,
                configuration=configuration,
                bom_coordinate=bom,
                candidate_selector=selector,
                status=status,
                selected_bom_version=bom_version or None,
                target_component=target or None,
                target_selected_version=target_version or None,
                related_module_versions=tuple(related),
                error=error or None,
            ))
        return tuple(results)

    @staticmethod
    def _create_init_script():
        return r'''
import java.util.Base64
import groovy.json.JsonSlurper
import groovy.json.JsonOutput
import org.gradle.api.artifacts.component.ModuleComponentIdentifier

def enc = { value ->
    Base64.encoder.encodeToString(value.toString().getBytes("UTF-8"))
}
def emit = { request, status, bomVersion, targetComponent,
             targetVersion, relatedVersions, error ->
    def bomCoordinate = request.bom_group + ":" + request.bom_artifact
    println(
        "MENDER_BOM_CANDIDATE\t" +
        enc(request.module_path) + "\t" +
        enc(request.configuration) + "\t" +
        enc(request.candidate_selector) + "\t" +
        enc(bomCoordinate) + "\t" +
        enc(status) + "\t" +
        enc(bomVersion ?: "") + "\t" +
        enc(targetComponent ?: "") + "\t" +
        enc(targetVersion ?: "") + "\t" +
        enc(JsonOutput.toJson(relatedVersions ?: [])) + "\t" +
        enc(error ?: "")
    )
}

gradle.projectsEvaluated {
    def encoded = gradle.startParameter.projectProperties["mender.bom.requests"]
    if (!encoded) return
    def requests = new JsonSlurper().parseText(
        new String(Base64.decoder.decode(encoded), "UTF-8")
    )

    requests.each { request ->
        try {
            def project = gradle.rootProject.findProject(request.module_path.toString())
            if (project == null) {
                emit(request, "ERROR", "", "", "", [], "Gradle project was not found")
                return
            }
            def configuration = project.configurations.findByName(
                request.configuration.toString()
            )
            if (configuration == null) {
                emit(request, "CONFIGURATION_NOT_FOUND", "", "", "", [],
                    "Configuration was not found")
                return
            }

            def notation = request.bom_group + ":" + request.bom_artifact + ":" +
                request.candidate_selector
            def platform = project.dependencies.platform(notation)
            configuration.dependencies.add(platform)

            def result = configuration.incoming.resolutionResult
            def moduleIds = result.allComponents.collect { it.id }.findAll {
                it instanceof ModuleComponentIdentifier
            }
            def bomIds = moduleIds.findAll {
                it.group == request.bom_group && it.module == request.bom_artifact
            }
            def targetIds = moduleIds.findAll {
                it.group == request.target_group && it.module == request.target_artifact
            }
            def related = moduleIds.findAll {
                it.group.startsWith(request.bom_group)
            }.collect {
                it.group + ":" + it.module + ":" + it.version
            }.unique().sort()

            def bomVersion = bomIds ? bomIds.last().version : ""
            def targetVersion = targetIds ? targetIds.last().version : ""
            def targetComponent = request.target_group + ":" + request.target_artifact

            if (!bomVersion) {
                emit(request, "BOM_NOT_RESOLVED", "", targetComponent,
                    targetVersion, related, "")
            } else if (!targetVersion) {
                emit(request, "TARGET_NOT_RESOLVED", bomVersion,
                    targetComponent, "", related, "")
            } else {
                emit(request, "RESOLVED", bomVersion, targetComponent,
                    targetVersion, related, "")
            }
        } catch (Exception exception) {
            emit(request, "ERROR", "", "", "", [],
                exception.class.simpleName + ": " +
                (exception.message ?: "Unknown resolution error"))
        }
    }
}
'''

class GradleBomCandidateInspector:
    def __init__(self, inspector, collector):
        self.inspector = inspector
        self.collector = collector

    def inspect(self, finding):
        inspection = self.inspector.inspect(finding)
        requests = self._build_requests(finding, inspection)
        evidence = ()
        if requests:
            try:
                evidence = self.collector.collect(requests)
            except (RuntimeError, OSError, ValueError, FileNotFoundError) as exc:
                evidence = tuple(GradleBomCandidateEvidence(
                    module_path=item.module_path,
                    configuration=item.configuration,
                    bom_coordinate=f"{item.bom_group}:{item.bom_artifact}",
                    candidate_selector=item.candidate_selector,
                    status="COLLECTION_FAILED",
                    scanner_fixed_versions=item.scanner_fixed_versions,
                    error=str(exc),
                ) for item in requests)

        return BomCandidateRepositoryInspection(
            finding_id=inspection.finding_id,
            configuration=inspection.configuration,
            command_output=inspection.command_output,
            is_consistent=inspection.is_consistent,
            matches=inspection.matches,
            errors=inspection.errors,
            transitive_matches=inspection.transitive_matches,
            constraints=inspection.constraints,
            source_declarations=inspection.source_declarations,
            bom_candidate_evidence=evidence,
        )

    @classmethod
    def _build_requests(cls, finding, inspection):
        target_parts = finding.component.split(":")
        if len(target_parts) < 2:
            return ()
        target_group, target_artifact = target_parts[:2]

        platforms = {}
        for declaration in getattr(inspection, "source_declarations", ()):
            if declaration.declaration_kind != "PLATFORM":
                continue
            parts = declaration.dependency.split(":")
            if len(parts) == 2:
                platforms[(parts[0], parts[1])] = declaration.declared_version

        # A resolved constraint may expose a BOM that arrives transitively.
        # Include it for a hypothetical candidate experiment, but do not
        # represent it as a direct source declaration.
        for constraint in getattr(inspection, "constraints", ()):
            parts = constraint.source_component.split(":")
            if len(parts) < 3:
                continue
            artifact = parts[1].lower()
            if not artifact.endswith(("-bom", "-platform", "-dependencies")):
                continue
            platforms.setdefault((parts[0], parts[1]), parts[2])

        modules = {
            match.project_path
            for match in (*inspection.matches, *inspection.transitive_matches)
        }
        modules.update(
            item.module_path for item in getattr(inspection, "constraints", ())
        )

        requests = []
        for (group, artifact), current_version in platforms.items():
            for selector in cls._candidate_selectors(current_version):
                for module_path in sorted(modules):
                    requests.append(GradleBomCandidateRequest(
                        module_path=module_path,
                        configuration=inspection.configuration,
                        bom_group=group,
                        bom_artifact=artifact,
                        candidate_selector=selector,
                        target_group=target_group,
                        target_artifact=target_artifact,
                        scanner_fixed_versions=tuple(finding.fixed_versions),
                    ))
        return tuple(requests)

    @staticmethod
    def _candidate_selectors(current_version):
        match = re.match(r"^(\d+)\.(\d+)\.", current_version)
        if not match:
            return ()
        major, minor = match.groups()
        return tuple(dict.fromkeys((f"{major}.{minor}.+", f"{major}.+")))
