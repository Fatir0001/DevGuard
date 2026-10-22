"""Safe, local-only project inventory and security checks for DevGuard."""

from __future__ import annotations

import ast
import configparser
import json
import os
import re
import stat
import threading
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

import httpx
from cvss import CVSS2, CVSS3, CVSS4

MAX_FILES = 5_000
MAX_FILE_BYTES = 2_000_000
MAX_TOTAL_BYTES = 50_000_000
MAX_ZIP_ENTRIES = 5_000
OSV_BATCH_SIZE = 100
SKIP_DIRS = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "dist",
    "build",
    "__pycache__",
    ".next",
}
SUPPORTED_SUFFIXES = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".json",
    ".ini",
    ".cfg",
    ".yaml",
    ".yml",
    ".toml",
    ".txt",
    ".pem",
    ".key",
}
PLACEHOLDERS = {
    "changeme",
    "change-me",
    "example",
    "your_key",
    "your-key",
    "placeholder",
    "dummy",
    "fake",
    "test",
    "none",
    "null",
}
SECRET_ASSIGNMENT = re.compile(
    r"(?i)([A-Z0-9_-]*(?:api[_-]?key|client[_-]?secret|password|passwd|private[_-]?key|secret[_-]?access[_-]?key|secret[_-]?key|secret|access[_-]?token|auth[_-]?token|token)[A-Z0-9_-]*)"
    r"\s*[:=]\s*['\"]?([A-Za-z0-9._+/=-]{8,})"
)
PRIVATE_KEY_MARKER = re.compile(
    r"-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY-----",
    re.IGNORECASE,
)
_OSV_CACHE: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
_OSV_LOCK = threading.Lock()


def safe_extract(upload: str | Path, target: str | Path) -> int:
    """Extract regular files beneath target with actual-byte limits and ZIP-slip checks."""
    root = Path(target).resolve()
    root.mkdir(parents=True, exist_ok=True)
    entry_count = 0
    total_bytes = 0
    seen: set[str] = set()

    with zipfile.ZipFile(upload) as archive:
        entries = archive.infolist()
        if len(entries) > MAX_ZIP_ENTRIES:
            raise ValueError("Archive contains too many entries")

        for info in entries:
            name = info.filename.replace("\\", "/")
            relative = PurePosixPath(name)
            if (
                relative.is_absolute()
                or ".." in relative.parts
                or any(":" in part for part in relative.parts)
            ):
                raise ValueError("ZIP contains an unsafe path")
            if info.flag_bits & 0x1:
                raise ValueError("Encrypted ZIP entries are not supported")
            mode = (info.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                raise ValueError("ZIP symlinks are not accepted")
            if mode not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise ValueError("ZIP contains an unsupported special file")
            if info.is_dir():
                continue

            entry_count += 1
            if entry_count > MAX_FILES or info.file_size > MAX_FILE_BYTES:
                raise ValueError("Project exceeds scan file or size limits")
            normalized = relative.as_posix().casefold()
            if normalized in seen:
                raise ValueError("ZIP contains duplicate file paths")
            seen.add(normalized)

            destination = root.joinpath(*relative.parts)
            if not destination.resolve().is_relative_to(root):
                raise ValueError("ZIP contains an unsafe path")
            destination.parent.mkdir(parents=True, exist_ok=True)
            actual_file_bytes = 0
            with archive.open(info) as source, destination.open("wb") as output:
                while chunk := source.read(64 * 1024):
                    actual_file_bytes += len(chunk)
                    total_bytes += len(chunk)
                    if (
                        actual_file_bytes > MAX_FILE_BYTES
                        or total_bytes > MAX_TOTAL_BYTES
                    ):
                        raise ValueError("Project exceeds scan file or size limits")
                    output.write(chunk)
            if actual_file_bytes != info.file_size:
                raise ValueError("ZIP entry size does not match its directory record")
    return entry_count


def inventory(root: str | Path) -> list[Path]:
    """List supported regular files without following symlinks or generated trees."""
    root = Path(root).resolve()
    files: list[Path] = []
    total_bytes = 0
    for base, dirs, names in os.walk(root, followlinks=False):
        base_path = Path(base)
        dirs[:] = [
            d for d in dirs if d not in SKIP_DIRS and not (base_path / d).is_symlink()
        ]
        for name in names:
            path = base_path / name
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                size = path.stat().st_size
            except OSError:
                continue
            total_bytes += size
            if total_bytes > MAX_TOTAL_BYTES or len(files) >= MAX_FILES:
                raise ValueError("Project exceeds scan file or size limits")
            if size > MAX_FILE_BYTES:
                continue
            if path.suffix.lower() in SUPPORTED_SUFFIXES or name.lower() in {
                "dockerfile",
                "requirements.txt",
                "package-lock.json",
            }:
                files.append(path)
    return files


def _evidence_line(line: str) -> str:
    """Redact every recognized credential on a line before it can be persisted."""
    return SECRET_ASSIGNMENT.sub(lambda match: f"{match.group(1)}=[REDACTED]", line)[
        :240
    ]


def _secret_is_placeholder(value: str) -> bool:
    lowered = value.lower().replace(" ", "")
    return lowered in PLACEHOLDERS | {
        "password",
        "secret",
        "token",
        "apikey",
        "api_key",
        "1234567890",
        "abcdefgh",
        "xxxxxxxx",
    } or bool(
        re.match(r"^(?:test|fake|dummy|example|placeholder)[_-]", lowered)
        or lowered.startswith("your_")
        or lowered.startswith("your-")
    )


def _finding(
    root: Path,
    path: Path | None,
    rule_id: str,
    title: str,
    description: str,
    severity: str,
    confidence: str,
    line: int | None,
    evidence: str,
    remediation: str,
    category: str = "Static analysis",
    **extra: Any,
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "title": title,
        "description": description,
        "severity": severity,
        "confidence": confidence,
        "file_path": path.relative_to(root).as_posix() if path else None,
        "line": line,
        "evidence": evidence[:240],
        "remediation": remediation,
        "category": category,
        **extra,
    }


def _source_findings(root: Path, path: Path, text: str) -> list[dict[str, Any]]:
    """Conservative source checks; rule hits are potential issues, not proof of exploitability."""
    found: list[dict[str, Any]] = []
    lines = text.splitlines()

    for number, line in enumerate(lines, 1):
        private_key_marker = PRIVATE_KEY_MARKER.search(line)
        for match in SECRET_ASSIGNMENT.finditer(line):
            if not line.lstrip().startswith(
                ("#", "//", "*")
            ) and not private_key_marker and not _secret_is_placeholder(
                match.group(2)
            ):
                found.append(
                    _finding(
                        root,
                        path,
                        "DG-SECRET",
                        "Possible hardcoded secret",
                        "A credential-like assignment was found. Pattern matching can miss secrets or flag non-production values.",
                        "High",
                        "Medium",
                        number,
                        _evidence_line(line),
                        "Move credentials to a secret manager or environment configuration, then rotate any exposed credential.",
                        "Secrets",
                    )
                )
        if private_key_marker:
            found.append(
                _finding(
                    root,
                    path,
                    "DG-SECRET",
                    "Possible private key material",
                    "A private key marker appears in this file. The key content is never copied into finding evidence.",
                    "Critical",
                    "High",
                    number,
                    "[REDACTED private-key marker]",
                    "Remove private key material from source control and rotate the key.",
                    "Secrets",
                )
            )

        # This focused pattern catches a common Node TLS option without matching comments.
        if path.suffix.lower() in {".js", ".jsx", ".ts", ".tsx"} and re.search(
            r"\brejectUnauthorized\s*:\s*false\b", line
        ):
            if not line.lstrip().startswith(("//", "*")):
                found.append(
                    _finding(
                        root,
                        path,
                        "DG-TLS-VERIFY",
                        "TLS certificate verification disabled",
                        "Node TLS certificate validation appears disabled in this configuration.",
                        "High",
                        "Medium",
                        number,
                        "rejectUnauthorized: false",
                        "Enable certificate verification and configure a trusted CA when needed.",
                    )
                )

    if path.suffix.lower() != ".py":
        return found
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return found

    # A literal True in a module-level setting is an explicit configuration choice.
    # Do not infer debug mode from names, strings, environment labels, or truthy values.
    for statement in tree.body:
        targets: list[ast.expr] = []
        value: ast.expr | None = None
        if isinstance(statement, ast.Assign):
            targets = statement.targets
            value = statement.value
        elif isinstance(statement, ast.AnnAssign):
            targets = [statement.target]
            value = statement.value
        if not isinstance(value, ast.Constant) or value.value is not True:
            continue
        for target in targets:
            if not isinstance(target, ast.Name) or target.id.lower() not in {
                "debug",
                "app_debug",
            }:
                continue
            setting = target.id
            found.append(
                _finding(
                    root,
                    path,
                    "DG-CONFIG-DEBUG",
                    "Debug mode enabled",
                    f"The Python setting `{setting}` is explicitly assigned True. Confirm this file is not used for a production deployment.",
                    "Medium",
                    "Medium",
                    statement.lineno,
                    f"{setting} = True",
                    "Disable debug mode in production-oriented configuration and keep detailed errors private.",
                    "Configuration",
                )
            )

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        try:
            function_name = ast.unparse(node.func)
        except Exception:
            continue

        if function_name == "eval" and node.args:
            # Literal-only evaluation is not reported; dynamic expressions remain heuristic hits.
            if not isinstance(node.args[0], ast.Constant) or not isinstance(
                node.args[0].value, str
            ):
                found.append(
                    _finding(
                        root,
                        path,
                        "DG-PY-EVAL",
                        "Dynamic evaluation",
                        "eval() receives a non-literal expression and can execute attacker-controlled input if that value is untrusted.",
                        "High",
                        "Medium",
                        node.lineno,
                        "eval(<dynamic expression>)",
                        "Avoid eval; parse input with a constrained parser or explicit mapping.",
                    )
                )

        if (
            function_name.endswith(".execute")
            and node.args
            and isinstance(node.args[0], ast.JoinedStr)
        ):
            if any(
                isinstance(part, ast.FormattedValue) for part in node.args[0].values
            ):
                found.append(
                    _finding(
                        root,
                        path,
                        "DG-PY-SQL-FSTRING",
                        "Potential SQL injection",
                        "An interpolated f-string is passed directly to a database execute method. This can mix data and SQL syntax.",
                        "High",
                        "Medium",
                        node.lineno,
                        'execute(f"...{value}...")',
                        "Use parameterized queries and bind values separately.",
                    )
                )

        if function_name in {
            "subprocess.run",
            "subprocess.Popen",
            "subprocess.call",
            "subprocess.check_output",
        }:
            if any(
                keyword.arg == "shell"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
                for keyword in node.keywords
            ):
                found.append(
                    _finding(
                        root,
                        path,
                        "DG-CMD-SHELL",
                        "Shell execution enabled",
                        "A subprocess call enables shell parsing. Risk increases when command data can include untrusted input.",
                        "High",
                        "Medium",
                        node.lineno,
                        f"{function_name}(..., shell=True)",
                        "Pass an argument array with shell=False and validate any externally supplied arguments.",
                    )
                )

        if function_name in {
            "requests.get",
            "requests.post",
            "requests.put",
            "requests.delete",
            "httpx.get",
            "httpx.post",
            "httpx.Client",
        }:
            if any(
                keyword.arg == "verify"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is False
                for keyword in node.keywords
            ):
                found.append(
                    _finding(
                        root,
                        path,
                        "DG-TLS-VERIFY",
                        "TLS certificate verification disabled",
                        "A common HTTP client is configured to skip TLS peer verification.",
                        "High",
                        "High",
                        node.lineno,
                        f"{function_name}(..., verify=False)",
                        "Enable certificate verification and use a trusted CA bundle.",
                    )
                )
    return found


def _configuration_findings(root: Path, path: Path, text: str) -> list[dict[str, Any]]:
    suffix = path.suffix.lower()
    if suffix in {".ini", ".cfg"}:
        return _ini_debug_findings(root, path, text)
    if suffix != ".json":
        return []
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    findings: list[dict[str, Any]] = []
    debug_lines = iter(_json_debug_true_lines(text))

    def inspect(value: Any, location: str = "") -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                child_location = f"{location}.{key}" if location else key
                if key.lower() == "debug" and child is True:
                    findings.append(
                        _finding(
                            root,
                            path,
                            "DG-CONFIG-DEBUG",
                            "Debug mode enabled",
                            f"The recognized JSON setting `{child_location}` is true. Confirm this file is not used for a production deployment.",
                            "Medium",
                            "Medium",
                            next(debug_lines, None),
                            f'"{key}": true',
                            "Disable debug mode in production-oriented configuration and keep detailed errors private.",
                            "Configuration",
                        )
                    )
                inspect(child, child_location)
        elif isinstance(value, list):
            for child in value:
                inspect(child, location)

    inspect(data)
    return findings


def _json_debug_true_lines(text: str) -> list[int]:
    """Return source lines for JSON object keys whose value token is true."""
    tokens: list[tuple[str, Any, int]] = []
    index = 0
    line = 1
    while index < len(text):
        char = text[index]
        if char.isspace():
            if char == "\n":
                line += 1
            index += 1
            continue
        token_line = line
        if char == '"':
            start = index
            index += 1
            escaped = False
            while index < len(text):
                current = text[index]
                if current == "\n":
                    line += 1
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == '"':
                    index += 1
                    break
                index += 1
            tokens.append(("string", json.loads(text[start:index]), token_line))
            continue
        if char in "{}[]:,":
            tokens.append((char, char, token_line))
            index += 1
            continue
        start = index
        while index < len(text) and not text[index].isspace() and text[index] not in "{}[]:,":
            index += 1
        tokens.append(("literal", text[start:index], token_line))

    return [
        tokens[position][2]
        for position in range(len(tokens) - 2)
        if tokens[position][0] == "string"
        and str(tokens[position][1]).lower() == "debug"
        and tokens[position + 1][0] == ":"
        and tokens[position + 2][0] == "literal"
        and tokens[position + 2][1] == "true"
    ]


def _ini_debug_findings(root: Path, path: Path, text: str) -> list[dict[str, Any]]:
    """Report explicit true debug options in valid INI/CFG files with source lines."""
    parser = configparser.ConfigParser(
        interpolation=None,
        strict=False,
        inline_comment_prefixes=("#", ";"),
    )
    try:
        parser.read_string(text)
    except configparser.MissingSectionHeaderError:
        # Permit the common sectionless `debug=true` config form as implicit DEFAULT.
        parser = configparser.ConfigParser(
            interpolation=None,
            strict=False,
            inline_comment_prefixes=("#", ";"),
        )
        try:
            parser.read_string("[DEFAULT]\n" + text)
        except configparser.Error:
            return []
    except configparser.Error:
        return []

    # ConfigParser applies the last value for repeated options. Retain that exact line.
    locations: dict[tuple[str, str], int] = {}
    section = "DEFAULT"
    section_header = re.compile(r"^\s*\[([^]]+)\]\s*(?:[;#].*)?$")
    option = re.compile(r"^\s*([^=:#\s][^=:]*?)\s*[=:]")
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        header = section_header.match(line)
        if header:
            section = header.group(1).strip()
            continue
        match = option.match(line)
        if match and match.group(1).strip().lower() in {"debug", "app_debug"}:
            locations[(section, match.group(1).strip().lower())] = number

    findings: list[dict[str, Any]] = []
    for (section_name, setting), number in locations.items():
        try:
            if section_name == "DEFAULT":
                raw_value = parser.defaults().get(setting)
                if raw_value is None:
                    continue
                value = parser.BOOLEAN_STATES[raw_value.lower()]
            else:
                value = parser.getboolean(section_name, setting)
        except (configparser.Error, ValueError):
            continue
        except KeyError:
            continue
        if not value:
            continue
        section_label = f"[{section_name}] " if section_name != "DEFAULT" else ""
        findings.append(
            _finding(
                root,
                path,
                "DG-CONFIG-DEBUG",
                "Debug mode enabled",
                f"The INI setting `{section_label}{setting}` is explicitly true. Confirm this file is not used for a production deployment.",
                "Medium",
                "Medium",
                number,
                f"{setting} = true",
                "Disable debug mode in production-oriented configuration and keep detailed errors private.",
                "Configuration",
            )
        )
    return findings


def _normalize_package_name(name: str, ecosystem: str) -> str:
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower() if not name.startswith("@") else "@" + name[1:].lower()


def _unresolved_dependency(
    root: Path, path: Path, name: str, line: int | None, version: str | None = None
) -> dict[str, Any]:
    ecosystem = "PyPI" if path.name.lower() == "requirements.txt" else "npm"
    normalized_name = _normalize_package_name(name, ecosystem)
    declared = f"{name}{' '+version if version else ''}"
    return _finding(
        root,
        path,
        "DG-DEP-UNRESOLVED",
        "Dependency version is not exact",
        "This manifest does not provide an exact resolved version, so DevGuard did not submit it to OSV. This is not a vulnerability finding.",
        "Informational",
        "High",
        line,
        declared,
        "Use a lockfile or pin an exact version so advisory matching can check the resolved package version.",
        "Dependency",
        dependency_name=normalized_name,
        declared_version=version,
    )


def _parse_dependencies(
    root: Path, path: Path, text: str, errors: list[str]
) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    dependencies: list[dict[str, str]] = []
    unresolved: list[dict[str, Any]] = []
    if path.name.lower() == "requirements.txt":
        for number, line in enumerate(text.splitlines(), 1):
            if (
                not line.strip()
                or line.lstrip().startswith(("#", "-"))
                or "://" in line
            ):
                continue
            match = re.match(
                r"\s*([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*==\s*([^;\s]+)", line
            )
            if match:
                dependencies.append(
                    {
                        "name": _normalize_package_name(match.group(1), "PyPI"),
                        "version": match.group(2),
                        "ecosystem": "PyPI",
                    }
                )
            else:
                declared = re.match(r"\s*([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?(.*)$", line)
                if declared and not declared.group(2).strip().startswith(";"):
                    unresolved.append(
                        _unresolved_dependency(
                            root,
                            path,
                            declared.group(1),
                            number,
                            declared.group(2).strip() or None,
                        )
                    )
    elif path.name == "package.json":
        try:
            data = json.loads(text)
            for group in (
                "dependencies",
                "devDependencies",
                "optionalDependencies",
                "peerDependencies",
            ):
                packages = data.get(group, {})
                if not isinstance(packages, dict):
                    continue
                for name, version in packages.items():
                    if not isinstance(name, str) or not isinstance(version, str):
                        continue
                    exact = re.fullmatch(
                        r"[v=]?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)",
                        version,
                    )
                    if exact:
                        dependencies.append(
                            {
                                "name": _normalize_package_name(name, "npm"),
                                "version": exact.group(1),
                                "ecosystem": "npm",
                            }
                        )
                    else:
                        unresolved.append(
                            _unresolved_dependency(root, path, name, None, version)
                        )
        except (ValueError, TypeError):
            errors.append("Malformed package.json")
    elif path.name == "package-lock.json":
        try:
            data = json.loads(text)
            packages = data.get("packages")
            if isinstance(packages, dict):
                for package_path, entry in packages.items():
                    if (
                        package_path.startswith("node_modules/")
                        and isinstance(entry, dict)
                        and isinstance(entry.get("version"), str)
                    ):
                        package_name = package_path.rsplit("node_modules/", 1)[-1]
                        dependencies.append(
                            {
                                "name": _normalize_package_name(package_name, "npm"),
                                "version": entry["version"],
                                "ecosystem": "npm",
                            }
                        )
            elif isinstance(data.get("dependencies"), dict):

                def walk_v1(entries: dict[str, Any]) -> None:
                    for package_name, entry in entries.items():
                        if isinstance(entry, dict):
                            if isinstance(entry.get("version"), str):
                                dependencies.append(
                                    {
                                        "name": _normalize_package_name(
                                            package_name, "npm"
                                        ),
                                        "version": entry["version"],
                                        "ecosystem": "npm",
                                    }
                                )
                            nested = entry.get("dependencies")
                            if isinstance(nested, dict):
                                walk_v1(nested)

                walk_v1(data["dependencies"])
            else:
                raise ValueError("lockfile has no supported package map")
        except (ValueError, AttributeError, TypeError):
            errors.append("Malformed package-lock.json")
    return dependencies, unresolved


_SEVERITY_LABELS = {
    "critical": "Critical",
    "high": "High",
    "moderate": "Medium",
    "medium": "Medium",
    "low": "Low",
}


def _severity_label(value: Any) -> str | None:
    return _SEVERITY_LABELS.get(value.strip().lower()) if isinstance(value, str) else None


def _affected_package_matches(
    affected: dict[str, Any], dependency: dict[str, str] | None
) -> bool:
    if dependency is None:
        return True
    package = affected.get("package")
    if not isinstance(package, dict):
        return False
    name = package.get("name")
    ecosystem = package.get("ecosystem")
    return (
        isinstance(name, str)
        and isinstance(ecosystem, str)
        and ecosystem.casefold() == dependency["ecosystem"].casefold()
        and _normalize_package_name(name, dependency["ecosystem"])
        == dependency["name"]
    )


def _osv_severity_info(
    advisory: dict[str, Any], dependency: dict[str, str] | None = None
) -> tuple[str, str | None]:
    """Normalize supported OSV labels and CVSS vectors without guessing unknown values."""
    metadata: list[Any] = []
    for field in ("database_specific", "ecosystem_specific"):
        value = advisory.get(field)
        if isinstance(value, dict):
            metadata.append(value.get("severity"))

    affected = advisory.get("affected")
    if isinstance(affected, list):
        for package in affected:
            if not isinstance(package, dict) or not _affected_package_matches(
                package, dependency
            ):
                continue
            for field in ("database_specific", "ecosystem_specific"):
                value = package.get(field)
                if isinstance(value, dict):
                    metadata.append(value.get("severity"))

    first_unrecognized: str | None = None
    for raw in metadata:
        label = _severity_label(raw)
        if label:
            return label, raw
        if isinstance(raw, str) and raw.strip() and first_unrecognized is None:
            first_unrecognized = raw

    severity_entries = advisory.get("severity")
    if isinstance(severity_entries, list):
        parsers = {"CVSS_V2": CVSS2, "CVSS_V3": CVSS3, "CVSS_V4": CVSS4}
        # Prefer the most recent CVSS version if a producer includes more than one.
        ordered = sorted(
            (entry for entry in severity_entries if isinstance(entry, dict)),
            key=lambda entry: {"CVSS_V4": 0, "CVSS_V3": 1, "CVSS_V2": 2}.get(
                str(entry.get("type", "")).upper(), 3
            ),
        )
        for entry in ordered:
            kind = str(entry.get("type", "")).upper()
            score = entry.get("score")
            parser = parsers.get(kind)
            if parser is None or not isinstance(score, str):
                if first_unrecognized is None and isinstance(score, str):
                    first_unrecognized = f"{kind or 'Unknown severity type'}: {score}"
                continue
            try:
                calculated = parser(score).severities()[0]
            except Exception:
                # OSV data is external; malformed vectors are unusable metadata.
                if first_unrecognized is None:
                    first_unrecognized = f"{kind}: {score}"
                continue
            label = _severity_label(calculated)
            if label:
                return label, f"{kind}: {score}"
            if first_unrecognized is None:
                first_unrecognized = f"{kind}: {score}"

    return "Informational", first_unrecognized


def _osv_severity(advisory: dict[str, Any]) -> str:
    """Compatibility wrapper for tests and callers that only need the normalized label."""
    return _osv_severity_info(advisory)[0]


def _advisory_ranges(
    advisory: dict[str, Any], dependency: dict[str, str] | None = None
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    affected = advisory.get("affected")
    if not isinstance(affected, list):
        return result
    for package in affected:
        if not isinstance(package, dict) or not _affected_package_matches(
            package, dependency
        ):
            continue
        ranges = package.get("ranges")
        if not isinstance(ranges, list):
            continue
        for item in ranges:
            if not isinstance(item, dict):
                continue
            events = item.get("events")
            result.append(
                {
                    "type": item.get("type"),
                    "events": events if isinstance(events, list) else [],
                }
            )
    return result


def _advisory_remediation(
    advisory: dict[str, Any], dependency: dict[str, str]
) -> str:
    fixed_versions = [
        event["fixed"]
        for item in _advisory_ranges(advisory, dependency)
        for event in item["events"]
        if isinstance(event, dict)
        and isinstance(event.get("fixed"), str)
        and event["fixed"]
    ]
    if fixed_versions:
        return (
            f"Upgrade {dependency['name']} to a fixed release such as "
            f"{fixed_versions[0]}, then confirm the selected version is not affected; "
            "consult the linked advisory."
        )
    return "Upgrade to a version outside the affected range; consult the linked advisory."


def _query_osv(
    dependencies: list[dict[str, str]],
) -> tuple[list[dict[str, Any]], list[str]]:
    if not dependencies:
        return [], []
    unique = {
        (d["ecosystem"], d["name"].lower(), d["version"]): d for d in dependencies
    }
    results: list[dict[str, Any]] = []
    errors: list[str] = []
    for ecosystem in ("PyPI", "npm"):
        items = [d for d in unique.values() if d["ecosystem"] == ecosystem]
        for offset in range(0, len(items), OSV_BATCH_SIZE):
            batch = items[offset : offset + OSV_BATCH_SIZE]
            uncached = []
            cached_indices: dict[int, list[dict[str, Any]]] = {}
            with _OSV_LOCK:
                for index, dependency in enumerate(batch):
                    key = (ecosystem, dependency["name"].lower(), dependency["version"])
                    if key in _OSV_CACHE:
                        cached_indices[index] = _OSV_CACHE[key]
                    else:
                        uncached.append((index, dependency, key))
            if uncached:
                try:
                    response = httpx.post(
                        "https://api.osv.dev/v1/querybatch",
                        json={
                            "queries": [
                                {
                                    "package": {
                                        "name": dep["name"],
                                        "ecosystem": ecosystem,
                                    },
                                    "version": dep["version"],
                                }
                                for _, dep, _ in uncached
                            ]
                        },
                        timeout=httpx.Timeout(8.0, connect=3.0),
                    )
                    response.raise_for_status()
                    payload = response.json()
                    if not isinstance(payload, dict):
                        raise ValueError("OSV response was not an object")
                    advisory_results = payload.get("results")
                    if not isinstance(advisory_results, list) or len(
                        advisory_results
                    ) != len(uncached):
                        raise ValueError("OSV response did not match the query batch")
                    parsed_batch: list[tuple[int, tuple[str, str, str], list[dict[str, Any]]]] = []
                    for (index, dependency, key), result in zip(uncached, advisory_results):
                        if not isinstance(result, dict):
                            raise ValueError("OSV result was not an object")
                        advisories = result.get("vulns", [])
                        if not isinstance(advisories, list) or any(
                            not isinstance(advisory, dict) for advisory in advisories
                        ):
                            raise ValueError("OSV result contained malformed advisories")
                        parsed_batch.append((index, key, advisories))
                    for index, key, advisories in parsed_batch:
                        cached_indices[index] = advisories
                        with _OSV_LOCK:
                            _OSV_CACHE[key] = advisories
                except (httpx.HTTPError, ValueError, TypeError, AttributeError) as error:
                    errors.append(f"OSV lookup unavailable ({type(error).__name__})")
            for index, dependency in enumerate(batch):
                advisories = cached_indices.get(index)
                if advisories is None:
                    continue
                for advisory in advisories:
                    if not isinstance(advisory, dict):
                        continue
                    raw_references = advisory.get("references")
                    references = (
                        [
                            reference["url"]
                            for reference in raw_references
                            if isinstance(reference, dict)
                            and isinstance(reference.get("url"), str)
                            and reference["url"].startswith("https://")
                        ]
                        if isinstance(raw_references, list)
                        else []
                    )
                    aliases = advisory.get("aliases")
                    if not isinstance(aliases, list):
                        aliases = []
                    alias = next(
                        (
                            value
                            for value in aliases
                            if isinstance(value, str) and value.startswith("CVE-")
                        ),
                        None,
                    )
                    severity, source_severity = _osv_severity_info(
                        advisory, dependency
                    )
                    affected_ranges = _advisory_ranges(advisory)
                    results.append(
                        _finding(
                            Path("."),
                            None,
                            "OSV",
                            advisory.get("summary")
                            or advisory.get("id", "Known dependency advisory"),
                            advisory.get("details")
                            or "OSV reports an advisory affecting this exact package version.",
                            severity,
                            "High",
                            None,
                            f"{dependency['name']}@{dependency['version']}",
                            _advisory_remediation(advisory, dependency),
                            "Dependency",
                            dependency_name=dependency["name"],
                            dependency_version=dependency["version"],
                            advisory_id=advisory.get("id"),
                            cve=alias,
                            references=references,
                            affected_ranges=affected_ranges,
                            source_severity=source_severity,
                        )
                    )
    return results, list(dict.fromkeys(errors))


def scan(
    root: str | Path, osv: bool = True
) -> tuple[
    list[Path], list[dict[str, Any]], dict[tuple[str, str], dict[str, str]], list[str]
]:
    """Run local static checks and exact-version advisory lookups; never execute source files."""
    project_root = Path(root).resolve()
    files = inventory(project_root)
    findings: list[dict[str, Any]] = []
    dependency_list: list[dict[str, str]] = []
    unresolved_dependencies: list[dict[str, Any]] = []
    errors: list[str] = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(_source_findings(project_root, path, text))
        findings.extend(_configuration_findings(project_root, path, text))
        parsed, unresolved = _parse_dependencies(project_root, path, text, errors)
        dependency_list.extend(parsed)
        unresolved_dependencies.extend(unresolved)

    # Keep ecosystem, normalized package name, and exact version together. Different
    # versions in separate manifests must not overwrite each other before OSV matching.
    dependencies: dict[tuple[str, str], dict[str, str]] = {
        (dep["ecosystem"], f"{dep['name'].lower()}@{dep['version']}"): dep
        for dep in dependency_list
    }
    resolved_names = {
        (dep["ecosystem"], dep["name"].lower()) for dep in dependency_list
    }
    findings.extend(
        item
        for item in unresolved_dependencies
        if ("npm", str(item.get("dependency_name", "")).lower()) not in resolved_names
        and ("PyPI", str(item.get("dependency_name", "")).lower()) not in resolved_names
    )
    if osv:
        advisory_findings, osv_errors = _query_osv(dependency_list)
        findings.extend(advisory_findings)
        errors.extend(osv_errors)
    return files, findings, dependencies, list(dict.fromkeys(errors))
