"""AgentSec - Knowledge graph for findings using Neo4j.

Stores attack findings as a graph for attack path analysis, blast radius calculation,
and cross-specialist insights. Inspired by Decepticon's Neo4j knowledge graph.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

try:
    from neo4j import GraphDatabase
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False
    GraphDatabase = None


@dataclass
class FindingNode:
    """A finding node in the knowledge graph."""
    attack_id: str
    attack_name: str
    category: str
    severity: str
    impact_score: float
    target_name: str
    timestamp: str
    evidence: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


@dataclass
class ToolNode:
    """A tool node in the knowledge graph."""
    name: str
    description: str
    parameters: dict[str, Any] = field(default_factory=dict)


@dataclass
class DataNode:
    """A data asset node in the knowledge graph."""
    name: str
    type: str  # pii, credential, config, system, financial
    sensitivity: str  # low, medium, high, critical
    location: str = ""


@dataclass
class AttackPath:
    """An attack path in the knowledge graph."""
    start_finding: str
    end_finding: str
    path_length: int
    techniques: list[str]
    blast_radius: list[str]


class KnowledgeGraph:
    """Neo4j-backed knowledge graph for AgentSec findings."""

    def __init__(
        self,
        uri: str = "bolt://localhost:7687",
        user: str = "neo4j",
        password: str = "password",
    ):
        if not NEO4J_AVAILABLE:
            raise ImportError("neo4j package not installed. Run: pip install neo4j")
        
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self._init_schema()

    def _init_schema(self):
        """Create constraints and indexes."""
        with self.driver.session() as session:
            # Constraints
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (f:Finding) REQUIRE f.attack_id IS UNIQUE")
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (t:Tool) REQUIRE t.name IS UNIQUE")
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (d:Data) REQUIRE d.name IS UNIQUE")
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (a:Attack) REQUIRE a.id IS UNIQUE")
            
            # Indexes
            session.run("CREATE INDEX IF NOT EXISTS FOR (f:Finding) ON (f.category)")
            session.run("CREATE INDEX IF NOT EXISTS FOR (f:Finding) ON (f.severity)")
            session.run("CREATE INDEX IF NOT EXISTS FOR (f:Finding) ON (f.target_name)")

    def close(self):
        """Close the driver connection."""
        self.driver.close()

    def add_finding(self, finding: FindingNode) -> None:
        """Add a finding to the graph."""
        with self.driver.session() as session:
            session.run(
                """
                MERGE (f:Finding {attack_id: $attack_id})
                SET f.attack_name = $attack_name,
                    f.category = $category,
                    f.severity = $severity,
                    f.impact_score = $impact_score,
                    f.target_name = $target_name,
                    f.timestamp = $timestamp,
                    f.evidence = $evidence,
                    f.mitre_techniques = $mitre_techniques,
                    f.tags = $tags
                """,
                attack_id=finding.attack_id,
                attack_name=finding.attack_name,
                category=finding.category,
                severity=finding.severity,
                impact_score=finding.impact_score,
                target_name=finding.target_name,
                timestamp=finding.timestamp,
                evidence=finding.evidence,
                mitre_techniques=finding.mitre_techniques,
                tags=finding.tags,
            )

    def add_tool(self, tool: ToolNode) -> None:
        """Add a tool to the graph."""
        with self.driver.session() as session:
            session.run(
                """
                MERGE (t:Tool {name: $name})
                SET t.description = $description,
                    t.parameters = $parameters
                """,
                name=tool.name,
                description=tool.description,
                parameters=tool.parameters,
            )

    def add_data(self, data: DataNode) -> None:
        """Add a data asset to the graph."""
        with self.driver.session() as session:
            session.run(
                """
                MERGE (d:Data {name: $name})
                SET d.type = $type,
                    d.sensitivity = $sensitivity,
                    d.location = $location
                """,
                name=data.name,
                type=data.type,
                sensitivity=data.sensitivity,
                location=data.location,
            )

    def link_finding_to_tool(self, finding_id: str, tool_name: str, action: str = "CALLS") -> None:
        """Link a finding to a tool it uses."""
        with self.driver.session() as session:
            session.run(
                """
                MATCH (f:Finding {attack_id: $finding_id})
                MATCH (t:Tool {name: $tool_name})
                MERGE (f)-[r:USES_TOOL {action: $action}]->(t)
                """,
                finding_id=finding_id,
                tool_name=tool_name,
                action=action,
            )

    def link_finding_to_data(self, finding_id: str, data_name: str, action: str = "ACCESSES") -> None:
        """Link a finding to data it accesses/exfiltrates."""
        with self.driver.session() as session:
            session.run(
                """
                MATCH (f:Finding {attack_id: $finding_id})
                MATCH (d:Data {name: $data_name})
                MERGE (f)-[r:ACCESSES_DATA {action: $action}]->(d)
                """,
                finding_id=finding_id,
                data_name=data_name,
                action=action,
            )

    def link_finding_to_technique(self, finding_id: str, technique_id: str) -> None:
        """Link a finding to a MITRE ATT&CK technique."""
        with self.driver.session() as session:
            session.run(
                """
                MATCH (f:Finding {attack_id: $finding_id})
                MERGE (t:Technique {id: $technique_id})
                MERGE (f)-[r:USES_TECHNIQUE]->(t)
                """,
                finding_id=finding_id,
                technique_id=technique_id,
            )

    def link_findings(self, from_finding: str, to_finding: str, relationship: str = "ENABLES") -> None:
        """Link two findings (attack chain)."""
        with self.driver.session() as session:
            session.run(
                """
                MATCH (f1:Finding {attack_id: $from_finding})
                MATCH (f2:Finding {attack_id: $to_finding})
                MERGE (f1)-[r:ENABLES {relationship: $relationship}]->(f2)
                """,
                from_finding=from_finding,
                to_finding=to_finding,
                relationship=relationship,
            )

    def get_attack_paths(
        self,
        target_name: str | None = None,
        max_depth: int = 5,
    ) -> list[AttackPath]:
        """Find attack paths in the graph."""
        with self.driver.session() as session:
            where_clause = ""
            params = {"max_depth": max_depth}
            if target_name:
                where_clause = "WHERE f.target_name = $target_name"
                params["target_name"] = target_name

            result = session.run(
                f"""
                MATCH path = (f1:Finding)-[:ENABLES*1..{max_depth}]->(f2:Finding)
                {where_clause}
                RETURN f1.attack_id as start, f2.attack_id as end,
                       length(path) as path_length,
                       [r in relationships(path) | r.relationship] as relationships,
                       [n in nodes(path) | n.attack_id] as findings
                """,
                params,
            )

            paths = []
            for record in result:
                paths.append(AttackPath(
                    start_finding=record["start"],
                    end_finding=record["end"],
                    path_length=record["path_length"],
                    techniques=record["relationships"],
                    blast_radius=record["findings"],
                ))
            return paths

    def get_blast_radius(self, finding_id: str) -> list[str]:
        """Get all findings reachable from a finding (blast radius)."""
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (f:Finding {attack_id: $finding_id})-[:ENABLES*]->(f2:Finding)
                RETURN collect(f2.attack_id) as blast_radius
                """,
                finding_id=finding_id,
            )
            record = result.single()
            return record["blast_radius"] if record else []

    def get_findings_by_technique(self, technique_id: str) -> list[dict[str, Any]]:
        """Get all findings using a specific MITRE technique."""
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (f:Finding)-[:USES_TECHNIQUE]->(t:Technique {id: $technique_id})
                RETURN f.attack_id, f.attack_name, f.category, f.severity, f.impact_score
                """,
                technique_id=technique_id,
            )
            return [dict(r) for r in result]

    def get_tool_usage_stats(self, target_name: str | None = None) -> list[dict[str, Any]]:
        """Get tool usage statistics."""
        with self.driver.session() as session:
            where = "WHERE f.target_name = $target_name" if target_name else ""
            params = {"target_name": target_name} if target_name else {}
            result = session.run(
                f"""
                MATCH (f:Finding)-[:USES_TOOL]->(t:Tool)
                {where}
                RETURN t.name as tool, count(f) as usage_count,
                       collect(f.attack_id) as findings
                ORDER BY usage_count DESC
                """,
                params,
            )
            return [dict(r) for r in result]

    def get_severity_distribution(self, target_name: str | None = None) -> dict[str, int]:
        """Get severity distribution for a target."""
        with self.driver.session() as session:
            where = "WHERE f.target_name = $target_name" if target_name else ""
            params = {"target_name": target_name} if target_name else {}
            result = session.run(
                f"""
                MATCH (f:Finding)
                {where}
                RETURN f.severity as severity, count(f) as count
                """,
                params,
            )
            return {r["severity"]: r["count"] for r in result}

    def import_scan_report(self, scan_report: dict[str, Any]) -> None:
        """Import a full scan report into the graph."""
        target_name = scan_report.get("metadata", {}).get("target", "unknown")
        timestamp = scan_report.get("metadata", {}).get("timestamp", datetime.utcnow().isoformat())
        results = scan_report.get("results", [])

        for r in results:
            finding = FindingNode(
                attack_id=r.get("attack_id", "unknown"),
                attack_name=r.get("name", "unknown"),
                category=r.get("category", "unknown"),
                severity=r.get("severity", "unknown"),
                impact_score=r.get("impact", {}).get("score", 0),
                target_name=target_name,
                timestamp=timestamp,
                evidence=r.get("evidence", []),
                mitre_techniques=[],
                tags=r.get("tags", []),
            )

            # Extract MITRE techniques from attack definition
            # This would need the original attack definition
            self.add_finding(finding)

            # Link to tools and data from evidence
            for evidence in finding.evidence:
                # Parse evidence for tools and data
                pass  # Would need more sophisticated parsing

    def clear(self) -> None:
        """Clear all data from the graph."""
        with self.driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n")


# ──────────────────────────────────────────────────────────────────────────────
# In-Memory Fallback (for testing without Neo4j)
# ──────────────────────────────────────────────────────────────────────────────

class InMemoryKnowledgeGraph:
    """In-memory fallback when Neo4j is not available."""

    def __init__(self):
        self.findings: dict[str, FindingNode] = {}
        self.tools: dict[str, ToolNode] = {}
        self.data: dict[str, DataNode] = {}
        self.edges: list[tuple[str, str, str]] = []  # (from, to, relationship)

    def add_finding(self, finding: FindingNode) -> None:
        self.findings[finding.attack_id] = finding

    def add_tool(self, tool: ToolNode) -> None:
        self.tools[tool.name] = tool

    def add_data(self, data: DataNode) -> None:
        self.data[data.name] = data

    def link_finding_to_tool(self, finding_id: str, tool_name: str, action: str = "CALLS") -> None:
        self.edges.append((finding_id, tool_name, f"USES_TOOL:{action}"))

    def link_finding_to_data(self, finding_id: str, data_name: str, action: str = "ACCESSES") -> None:
        self.edges.append((finding_id, data_name, f"ACCESSES_DATA:{action}"))

    def link_finding_to_technique(self, finding_id: str, technique_id: str) -> None:
        self.edges.append((finding_id, technique_id, "USES_TECHNIQUE"))

    def link_findings(self, from_finding: str, to_finding: str, relationship: str = "ENABLES") -> None:
        self.edges.append((from_finding, to_finding, f"ENABLES:{relationship}"))

    def get_attack_paths(self, target_name: str | None = None, max_depth: int = 5) -> list[AttackPath]:
        # Simple in-memory path finding
        paths = []
        # Build adjacency list
        adj: dict[str, list[str]] = {}
        for from_id, to_id, rel in self.edges:
            if rel.startswith("ENABLES"):
                if from_id not in adj:
                    adj[from_id] = []
                adj[from_id].append(to_id)

        # Find all paths up to max_depth
        for start in self.findings:
            if target_name and self.findings[start].target_name != target_name:
                continue
            self._dfs_paths(start, adj, max_depth, paths, [start])
        return paths

    def _dfs_paths(self, current: str, adj: dict, max_depth: int, paths: list, path: list):
        if len(path) > max_depth:
            return
        if current in adj:
            for next_node in adj[current]:
                if next_node not in path:
                    new_path = path + [next_node]
                    paths.append(AttackPath(
                        start_finding=path[0],
                        end_finding=next_node,
                        path_length=len(new_path) - 1,
                        techniques=[],
                        blast_radius=new_path[1:],
                    ))
                    self._dfs_paths(next_node, adj, max_depth, paths, new_path)

    def get_blast_radius(self, finding_id: str) -> list[str]:
        radius = []
        adj: dict[str, list[str]] = {}
        for from_id, to_id, rel in self.edges:
            if rel.startswith("ENABLES"):
                if from_id not in adj:
                    adj[from_id] = []
                adj[from_id].append(to_id)
        
        visited = set()
        def dfs(node):
            if node in visited:
                return
            visited.add(node)
            if node != finding_id:
                radius.append(node)
            if node in adj:
                for n in adj[node]:
                    dfs(n)
        dfs(finding_id)
        return radius

    def get_findings_by_technique(self, technique_id: str) -> list[dict[str, Any]]:
        results = []
        for finding in self.findings.values():
            if technique_id in finding.mitre_techniques:
                results.append({
                    "attack_id": finding.attack_id,
                    "attack_name": finding.attack_name,
                    "category": finding.category,
                    "severity": finding.severity,
                    "impact_score": finding.impact_score,
                })
        return results

    def get_tool_usage_stats(self, target_name: str | None = None) -> list[dict[str, Any]]:
        stats: dict[str, list[str]] = {}
        for from_id, to_id, rel in self.edges:
            if rel.startswith("USES_TOOL"):
                finding = self.findings.get(from_id)
                if finding and (not target_name or finding.target_name == target_name):
                    if to_id not in stats:
                        stats[to_id] = []
                    stats[to_id].append(from_id)
        
        return [
            {"tool": tool, "usage_count": len(findings), "findings": findings}
            for tool, findings in stats.items()
        ]

    def get_severity_distribution(self, target_name: str | None = None) -> dict[str, int]:
        dist: dict[str, int] = {}
        for finding in self.findings.values():
            if not target_name or finding.target_name == target_name:
                dist[finding.severity] = dist.get(finding.severity, 0) + 1
        return dist

    def import_scan_report(self, scan_report: dict[str, Any]) -> None:
        target_name = scan_report.get("metadata", {}).get("target", "unknown")
        timestamp = scan_report.get("metadata", {}).get("timestamp", datetime.utcnow().isoformat())
        results = scan_report.get("results", [])

        for r in results:
            finding = FindingNode(
                attack_id=r.get("attack_id", "unknown"),
                attack_name=r.get("name", "unknown"),
                category=r.get("category", "unknown"),
                severity=r.get("severity", "unknown"),
                impact_score=r.get("impact", {}).get("score", 0),
                target_name=target_name,
                timestamp=timestamp,
                evidence=r.get("evidence", []),
                mitre_techniques=r.get("mitre_techniques", []),
                tags=r.get("tags", []),
            )
            self.add_finding(finding)

    def clear(self) -> None:
        self.findings.clear()
        self.tools.clear()
        self.data.clear()
        self.edges.clear()


def get_knowledge_graph(
    uri: str | None = None,
    user: str | None = None,
    password: str | None = None,
) -> KnowledgeGraph | InMemoryKnowledgeGraph:
    """Get a knowledge graph instance (Neo4j if available, else in-memory)."""
    if uri and NEO4J_AVAILABLE:
        return KnowledgeGraph(uri, user or "neo4j", password or "password")
    return InMemoryKnowledgeGraph()