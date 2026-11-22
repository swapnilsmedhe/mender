import base64
import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from security_agent.tools.repository import RepositoryTools


@dataclass(frozen=True)
class GradlePropertyRequest:
    module_path: str
    property_name: str
    lookup_scope: str

    def __post_init__(self) -> None:
        if not self.module_path.strip() or not self.property_name.strip():
            raise ValueError("Module path and property name cannot be empty.")
        if self.lookup_scope not in ("CURRENT_PROJECT", "ROOT_PROJECT"):
            raise ValueError("Unsupported Gradle property lookup scope.")


@dataclass(frozen=True)
class GradlePropertyResult:
    module_path: str
    property_name: str
    lookup_scope: str
    status: str
    value: str | None = None
    error: str | None = None


class GradlePropertyCollector:
    """Resolve only explicitly requested Gradle properties in affected modules."""

    MARKER = "MENDER_GRADLE_PROPERTY"

    def __init__(self, tools: RepositoryTools, timeout_seconds: int = 120) -> None:
        if timeout_seconds < 1:
            raise ValueError("Timeout must be at least one second.")
        self.tools = tools
        self.timeout_seconds = timeout_seconds

    def collect(self, requests: tuple[GradlePropertyRequest, ...]) -> tuple[GradlePropertyResult, ...]:
        requests = tuple(dict.fromkeys(requests))
        if not requests:
            return ()
        if len(requests) > 30:
            raise ValueError("Too many Gradle property requests.")

        root = self.tools.root.resolve()
        wrapper_name = "gradlew.bat" if os.name == "nt" else "gradlew"
        wrapper = root / wrapper_name
        if not wrapper.is_file():
            raise FileNotFoundError(f"Gradle wrapper not found: {wrapper}")

        payload = [
            {"module_path": item.module_path, "property_name": item.property_name,
             "lookup_scope": item.lookup_scope}
            for item in requests
        ]
        encoded = base64.b64encode(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")

        with tempfile.TemporaryDirectory() as temp_dir:
            script = Path(temp_dir) / "mender-gradle-properties.init.gradle"
            script.write_text(self._create_init_script(), encoding="utf-8")
            command = [str(wrapper), "--init-script", str(script),
                       f"-Pmender.property.requests={encoded}", "help", "--console=plain"]
            try:
                process = subprocess.run(command, cwd=root, capture_output=True,
                                         text=True, timeout=self.timeout_seconds,
                                         check=False, shell=False)
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError("Gradle property collection timed out.") from exc

        results = self.parse_output(f"{process.stdout}\n{process.stderr}")
        if process.returncode != 0:
            raise RuntimeError("Gradle property collection failed; inspect Gradle output.")
        returned = {(r.module_path, r.property_name, r.lookup_scope) for r in results}
        if any((r.module_path, r.property_name, r.lookup_scope) not in returned for r in requests):
            raise RuntimeError("Gradle did not return all requested property results.")
        return results

    @classmethod
    def parse_output(cls, output: str) -> tuple[GradlePropertyResult, ...]:
        results = []
        for line in output.splitlines():
            if not line.startswith(cls.MARKER + "\t"):
                continue
            parts = line.split("\t")
            if len(parts) != 7:
                continue
            try:
                values = [base64.b64decode(part, validate=True).decode("utf-8")
                          for part in parts[1:]]
            except (ValueError, UnicodeDecodeError):
                continue
            module, name, scope, status, value, error = values
            if status not in ("RESOLVED", "MISSING", "ERROR"):
                continue
            results.append(GradlePropertyResult(
                module_path=module, property_name=name, lookup_scope=scope,
                status=status, value=value if status == "RESOLVED" else None,
                error=error if status == "ERROR" else None,
            ))
        return tuple(results)

    @classmethod
    def _create_init_script(cls) -> str:
        return r'''
import java.util.Base64
import groovy.json.JsonSlurper

def enc = { value -> Base64.encoder.encodeToString(value.toString().getBytes("UTF-8")) }
def emit = { module, name, scope, status, value, error ->
    println("MENDER_GRADLE_PROPERTY\t" + enc(module) + "\t" + enc(name) + "\t" +
        enc(scope) + "\t" + enc(status) + "\t" + enc(value ?: "") + "\t" + enc(error ?: ""))
}

gradle.projectsEvaluated {
    def encoded = gradle.startParameter.projectProperties["mender.property.requests"]
    if (!encoded) return
    def requests = new JsonSlurper().parseText(
        new String(Base64.decoder.decode(encoded), "UTF-8"))
    requests.each { request ->
        def modulePath = request.module_path.toString()
        def propertyName = request.property_name.toString()
        def scope = request.lookup_scope.toString()
        try {
            def module = gradle.rootProject.findProject(modulePath)
            if (module == null) {
                emit(modulePath, propertyName, scope, "ERROR", "", "Gradle project not found")
                return
            }
            def lookupProject = scope == "ROOT_PROJECT" ? gradle.rootProject : module
            def value = lookupProject.findProperty(propertyName)
            if (value == null) emit(modulePath, propertyName, scope, "MISSING", "", "")
            else emit(modulePath, propertyName, scope, "RESOLVED", value.toString(), "")
        } catch (Exception exception) {
            emit(modulePath, propertyName, scope, "ERROR", "",
                exception.class.simpleName + ": " + (exception.message ?: "Property lookup failed"))
        }
    }
}
'''
