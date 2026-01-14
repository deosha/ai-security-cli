"""
Shared AST-Based Taint Tracking Module

Provides unified taint analysis for detecting data flows from sources to sinks.
Used by LLM01, LLM02, LLM07, LLM08, and Semantic Taint detectors.

Features:
- Single-hop and multi-hop variable resolution
- Sink-specific validation checks (parameterized SQL, shell=False, URL allowlists)
- Structural validation detection (sanitization wrapping)
- Confidence tiers based on flow type and evidence
- SEMANTIC TAINT: Track data flow through LLM API calls with influence decay
"""

import ast
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from aisentry.utils.ast_utils import (
    get_full_call_name,
    get_call_name,
    names_in_expr,
    resolve_single_hop,
)


class FlowType(Enum):
    """Type of taint flow between source and sink"""
    DIRECT = "direct"           # Source directly in sink call
    SINGLE_HOP = "single_hop"   # One variable assignment between source and sink
    TWO_HOP = "two_hop"         # Two variable assignments
    TRANSITIVE = "transitive"   # Multiple hops or ambiguous


class SinkType(Enum):
    """Categories of dangerous sinks"""
    LLM_PROMPT = "llm_prompt"       # LLM01: User input in LLM prompts
    XSS = "xss"                     # LLM02: HTML rendering
    COMMAND = "command_injection"   # LLM02: Shell commands
    SQL = "sql_injection"           # LLM02: SQL queries
    CODE_EXEC = "code_execution"    # LLM02: eval/exec
    PLUGIN = "plugin"               # LLM07: Plugin execution
    FILE = "file_access"            # LLM07: File operations
    HTTP = "http_request"           # LLM07/LLM08: HTTP requests


# =============================================================================
# SEMANTIC TAINT ANALYSIS
# Track data flow through LLM API calls with influence decay
# =============================================================================

class SemanticTaintType(Enum):
    """Types of taint for semantic analysis"""
    USER_INPUT = "user_input"           # Direct user input (request, input(), argv)
    LLM_OUTPUT = "llm_output"           # Output from LLM call
    SEMANTIC_INFLUENCE = "semantic"     # Indirect influence through LLM transformation
    FILE_INPUT = "file_input"           # External file data
    NETWORK_INPUT = "network_input"     # Network/API response data
    DATABASE_INPUT = "database_input"   # Database query results


class InfluenceStrength(Enum):
    """
    Strength of semantic influence through LLM calls.

    Rationale for values:
    - DIRECT: No transformation, full influence preserved
    - STRONG: User prompt is the primary input to LLM, high influence on output
    - MODERATE: Context/history influences LLM but not as directly
    - WEAK: System prompt can be overridden by user content
    - ATTENUATED: Multiple LLM hops significantly reduce certainty
    """
    DIRECT = 1.0        # Direct data flow (no LLM transformation)
    STRONG = 0.85       # Through LLM prompt argument (user message)
    MODERATE = 0.70     # Through LLM context/history
    WEAK = 0.50         # Through LLM system prompt
    ATTENUATED = 0.35   # Multiple LLM hops


@dataclass
class SemanticTaintNode:
    """
    Represents a node in the semantic taint graph.

    Each node tracks a variable that may carry tainted data,
    including data that has passed through LLM transformations.
    """
    id: str                                      # Unique identifier: file:line:var
    variable_name: str                           # Variable name
    line_number: int                             # Line where variable is defined/assigned
    file_path: str                               # Source file
    taint_types: Set[SemanticTaintType]          # Types of taint this node carries
    influence_strength: float                    # 0.0-1.0, decays through LLM hops
    source_nodes: List[str] = field(default_factory=list)  # Parent node IDs (data flow)
    llm_hops: int = 0                            # Number of LLM calls this taint passed through
    metadata: Dict[str, Any] = field(default_factory=dict)  # Additional context

    def has_semantic_influence(self) -> bool:
        """Check if this node carries semantic influence from LLM transformation."""
        return SemanticTaintType.SEMANTIC_INFLUENCE in self.taint_types

    def is_user_tainted(self) -> bool:
        """Check if this node is tainted by user input (directly or through LLM)."""
        return SemanticTaintType.USER_INPUT in self.taint_types


@dataclass
class SemanticTaintEdge:
    """
    Represents an edge in the semantic taint graph (data flow between nodes).
    """
    source_id: str                  # Source node ID
    target_id: str                  # Target node ID
    edge_type: str                  # "assignment", "llm_transform", "function_call", "return"
    propagation_rule: str           # Description of how taint propagates
    confidence_modifier: float = 1.0  # Multiplier applied to influence strength


class SemanticTaintGraph:
    """
    Graph-based semantic taint tracking that preserves influence through LLM calls.

    Key insight: When data passes through an LLM, the output carries "semantic influence"
    from the input - an attacker controlling the input can influence the output content,
    even though there's no direct data flow.

    Example:
        user_input = request.get("query")          # Tainted with USER_INPUT
        summary = llm.summarize(user_input)        # Carries SEMANTIC_INFLUENCE from user_input
        execute_command(summary)                   # VULNERABLE: Tainted data reaches sink
    """

    def __init__(self, file_path: str = ""):
        self.file_path = file_path
        self.nodes: Dict[str, SemanticTaintNode] = {}
        self.edges: List[SemanticTaintEdge] = []
        self._adjacency_forward: Dict[str, List[str]] = defaultdict(list)   # node -> children
        self._adjacency_backward: Dict[str, List[str]] = defaultdict(list)  # node -> parents

    def _make_node_id(self, var_name: str, line: int, file_path: str = "") -> str:
        """Generate unique node ID."""
        fp = file_path or self.file_path
        return f"{fp}:{line}:{var_name}"

    def add_source(
        self,
        var_name: str,
        line: int,
        taint_type: SemanticTaintType,
        file_path: str = "",
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Add a taint source (user input, file read, network response, etc.)

        Returns:
            Node ID for the created source node
        """
        fp = file_path or self.file_path
        node_id = self._make_node_id(var_name, line, fp)

        self.nodes[node_id] = SemanticTaintNode(
            id=node_id,
            variable_name=var_name,
            line_number=line,
            file_path=fp,
            taint_types={taint_type},
            influence_strength=1.0,  # Sources have full influence
            llm_hops=0,
            metadata=metadata or {}
        )

        return node_id

    def add_assignment(
        self,
        target_var: str,
        target_line: int,
        source_node_ids: List[str],
        file_path: str = ""
    ) -> Optional[str]:
        """
        Add a simple assignment propagation (no LLM transformation).

        The target inherits taint from all sources with no decay.

        Returns:
            Node ID for the created node, or None if no sources are tainted
        """
        if not source_node_ids:
            return None

        # Only consider nodes that exist in our graph
        valid_sources = [nid for nid in source_node_ids if nid in self.nodes]
        if not valid_sources:
            return None

        fp = file_path or self.file_path
        target_id = self._make_node_id(target_var, target_line, fp)

        # Combine taint types and take max influence
        combined_types: Set[SemanticTaintType] = set()
        max_strength = 0.0
        max_hops = 0

        for source_id in valid_sources:
            source_node = self.nodes[source_id]
            combined_types.update(source_node.taint_types)
            max_strength = max(max_strength, source_node.influence_strength)
            max_hops = max(max_hops, source_node.llm_hops)

            # Add edge
            edge = SemanticTaintEdge(
                source_id=source_id,
                target_id=target_id,
                edge_type="assignment",
                propagation_rule="direct_copy",
                confidence_modifier=1.0
            )
            self.edges.append(edge)
            self._adjacency_forward[source_id].append(target_id)
            self._adjacency_backward[target_id].append(source_id)

        self.nodes[target_id] = SemanticTaintNode(
            id=target_id,
            variable_name=target_var,
            line_number=target_line,
            file_path=fp,
            taint_types=combined_types,
            influence_strength=max_strength,
            source_nodes=valid_sources,
            llm_hops=max_hops
        )

        return target_id

    def propagate_through_llm(
        self,
        input_node_ids: List[str],
        output_var: str,
        output_line: int,
        input_positions: Dict[str, str],
        llm_function: str = "",
        file_path: str = ""
    ) -> Optional[str]:
        """
        Propagate taint through an LLM call with semantic influence tracking.

        This is the key innovation: we recognize that LLM output carries semantic
        influence from inputs, even though there's no direct data flow.

        Args:
            input_node_ids: Node IDs of tainted inputs flowing into LLM
            output_var: Variable name receiving LLM output
            output_line: Line number of the LLM call
            input_positions: Maps node_id to position ("prompt", "system", "context")
            llm_function: Name of the LLM function being called
            file_path: Source file path

        Returns:
            Node ID for the LLM output node, or None if no tainted inputs
        """
        if not input_node_ids:
            return None

        valid_inputs = [nid for nid in input_node_ids if nid in self.nodes]
        if not valid_inputs:
            return None

        fp = file_path or self.file_path
        output_id = self._make_node_id(output_var, output_line, fp)

        # LLM output always carries LLM_OUTPUT and SEMANTIC_INFLUENCE types
        combined_types: Set[SemanticTaintType] = {
            SemanticTaintType.LLM_OUTPUT,
            SemanticTaintType.SEMANTIC_INFLUENCE
        }

        # Calculate combined influence with position-based decay
        max_strength = 0.0
        max_hops = 0
        input_details = []

        for node_id in valid_inputs:
            input_node = self.nodes[node_id]
            position = input_positions.get(node_id, "context")

            # Position-based influence modifier
            position_modifier = {
                "prompt": InfluenceStrength.STRONG.value,      # 0.85
                "user_message": InfluenceStrength.STRONG.value,
                "system": InfluenceStrength.WEAK.value,        # 0.50
                "context": InfluenceStrength.MODERATE.value,   # 0.70
                "history": InfluenceStrength.MODERATE.value,
            }.get(position, InfluenceStrength.MODERATE.value)

            # Calculate strength with decay
            strength = input_node.influence_strength * position_modifier
            max_strength = max(max_strength, strength)

            # Inherit taint types from inputs
            combined_types.update(input_node.taint_types)
            max_hops = max(max_hops, input_node.llm_hops)

            input_details.append({
                "node_id": node_id,
                "position": position,
                "original_strength": input_node.influence_strength,
                "after_decay": strength
            })

            # Add edge with position-based confidence modifier
            edge = SemanticTaintEdge(
                source_id=node_id,
                target_id=output_id,
                edge_type="llm_transform",
                propagation_rule=f"llm_{position}_influence",
                confidence_modifier=position_modifier
            )
            self.edges.append(edge)
            self._adjacency_forward[node_id].append(output_id)
            self._adjacency_backward[output_id].append(node_id)

        # Create output node with attenuated strength
        self.nodes[output_id] = SemanticTaintNode(
            id=output_id,
            variable_name=output_var,
            line_number=output_line,
            file_path=fp,
            taint_types=combined_types,
            influence_strength=max_strength,
            source_nodes=valid_inputs,
            llm_hops=max_hops + 1,  # Increment LLM hop count
            metadata={
                "llm_function": llm_function,
                "input_details": input_details
            }
        )

        return output_id

    def find_node_by_var(self, var_name: str, max_line: int) -> Optional[str]:
        """
        Find the most recent taint node for a variable before a given line.

        Returns:
            Node ID if found, None otherwise
        """
        candidates = [
            (nid, node) for nid, node in self.nodes.items()
            if node.variable_name == var_name and node.line_number < max_line
        ]

        if not candidates:
            return None

        # Return the most recent (highest line number)
        return max(candidates, key=lambda x: x[1].line_number)[0]

    def find_paths_to_sink(
        self,
        sink_var: str,
        sink_line: int,
        max_depth: int = 10
    ) -> List[List[SemanticTaintNode]]:
        """
        Find all taint paths that could reach a sink.

        Uses BFS to find all paths from tainted sources to variables
        that match the sink variable name.

        Returns:
            List of paths (each path is a list of nodes from source to sink)
        """
        # Find node(s) that could flow to sink
        sink_candidates = [
            nid for nid, node in self.nodes.items()
            if node.variable_name == sink_var and node.line_number <= sink_line
        ]

        if not sink_candidates:
            return []

        all_paths = []

        for sink_node_id in sink_candidates:
            # BFS backwards from sink to find all source paths
            paths = self._find_paths_backward(sink_node_id, max_depth)
            all_paths.extend(paths)

        return all_paths

    def _find_paths_backward(
        self,
        target_id: str,
        max_depth: int
    ) -> List[List[SemanticTaintNode]]:
        """BFS backward traversal to find all paths to sources."""
        paths = []
        queue: List[Tuple[str, List[str]]] = [(target_id, [target_id])]
        visited_paths: Set[tuple] = set()

        while queue:
            current_id, path = queue.pop(0)

            if len(path) > max_depth:
                continue

            path_tuple = tuple(path)
            if path_tuple in visited_paths:
                continue
            visited_paths.add(path_tuple)

            # Get parents
            parents = self._adjacency_backward.get(current_id, [])

            if not parents:
                # Reached a source - this is a complete path
                node_path = [self.nodes[nid] for nid in reversed(path)]
                paths.append(node_path)
            else:
                for parent_id in parents:
                    if parent_id not in path:  # Avoid cycles
                        queue.append((parent_id, path + [parent_id]))

        return paths

    def calculate_path_confidence(self, path: List[SemanticTaintNode]) -> float:
        """
        Calculate confidence score for a taint path.

        Considers:
        - Final node's influence strength (accounts for decay)
        - Number of LLM hops (more hops = less certainty)
        - Path length (longer paths = more potential for sanitization)
        """
        if not path:
            return 0.0

        final_node = path[-1]
        base_confidence = final_node.influence_strength

        # Additional decay for LLM hops (compounding uncertainty)
        llm_hop_decay = 0.90 ** final_node.llm_hops

        # Small decay for path length
        length_decay = 0.98 ** (len(path) - 1)

        return base_confidence * llm_hop_decay * length_decay

    def get_semantic_flows_to_sink(
        self,
        sink_var: str,
        sink_line: int
    ) -> List[Dict[str, Any]]:
        """
        Get all semantic taint flows reaching a sink with analysis metadata.

        Returns flows that have passed through at least one LLM call
        (i.e., have SEMANTIC_INFLUENCE taint type).
        """
        paths = self.find_paths_to_sink(sink_var, sink_line)
        semantic_flows = []

        for path in paths:
            if not path:
                continue

            final_node = path[-1]

            # Only include if there's semantic influence (LLM hop)
            if not final_node.has_semantic_influence():
                continue

            confidence = self.calculate_path_confidence(path)

            semantic_flows.append({
                "path": path,
                "confidence": confidence,
                "llm_hops": final_node.llm_hops,
                "influence_strength": final_node.influence_strength,
                "source_var": path[0].variable_name if path else None,
                "source_line": path[0].line_number if path else None,
                "source_type": list(path[0].taint_types)[0].value if path else None,
                "has_user_input": any(n.is_user_tainted() for n in path),
            })

        return semantic_flows


@dataclass
class TaintSource:
    """Represents a source of tainted data"""
    var_name: str
    line: int
    source_type: str  # 'user_param', 'llm_output', 'external_input', etc.
    node: Optional[ast.AST] = None


@dataclass
class TaintSink:
    """Represents a dangerous sink"""
    func_name: str
    line: int
    sink_type: SinkType
    node: Optional[ast.AST] = None
    keyword_arg: Optional[str] = None  # e.g., 'shell', 'messages'


@dataclass
class TaintFlow:
    """Represents a flow from source to sink"""
    source: TaintSource
    sink: TaintSink
    flow_type: FlowType
    intermediate_vars: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)

    @property
    def base_confidence(self) -> float:
        """Get base confidence based on flow type"""
        confidence_map = {
            FlowType.DIRECT: 0.95,
            FlowType.SINGLE_HOP: 0.85,
            FlowType.TWO_HOP: 0.75,
            FlowType.TRANSITIVE: 0.65,
        }
        return confidence_map.get(self.flow_type, 0.60)


@dataclass
class SinkValidation:
    """Result of sink-specific validation checks"""
    is_safe: bool
    reason: Optional[str] = None
    confidence_adjustment: float = 0.0  # Negative reduces confidence


class TaintTracker:
    """
    AST-based taint tracking for security analysis.

    Tracks data flow from sources (user input, LLM output) to sinks
    (shell commands, SQL queries, HTML rendering, etc.)
    """

    # Sink patterns by type
    SINK_PATTERNS: Dict[SinkType, Set[str]] = {
        SinkType.COMMAND: {
            'subprocess.run', 'subprocess.call', 'subprocess.Popen',
            'subprocess.check_output', 'subprocess.check_call',
            'os.system', 'os.popen', 'os.exec', 'os.spawn',
            'commands.getoutput', 'commands.getstatusoutput',
        },
        SinkType.SQL: {
            'execute', 'executemany', 'cursor.execute',
            'raw', 'extra', 'RawSQL',
        },
        SinkType.XSS: {
            'render_template', 'render', 'render_to_string',
            'innerHTML', 'outerHTML', 'document.write',
            'dangerouslySetInnerHTML', 'Markup', 'mark_safe',
        },
        SinkType.CODE_EXEC: {
            'eval', 'exec', 'compile', '__import__',
            'importlib.import_module',
        },
        SinkType.FILE: {
            'open', 'read', 'write', 'unlink', 'remove',
            'shutil.rmtree', 'os.remove', 'os.unlink',
            'pathlib.Path.write_text', 'pathlib.Path.read_text',
        },
        SinkType.HTTP: {
            'requests.get', 'requests.post', 'requests.put',
            'requests.delete', 'requests.patch', 'requests.request',
            'httpx.get', 'httpx.post', 'httpx.Client',
            'urllib.request.urlopen', 'aiohttp.ClientSession',
        },
        SinkType.PLUGIN: {
            'importlib.import_module', '__import__',
            'exec', 'eval', 'load_module', 'runpy.run_module',
        },
    }

    # Sanitization patterns by sink type
    SANITIZATION_BY_SINK: Dict[SinkType, Set[str]] = {
        SinkType.COMMAND: {
            'shlex.quote', 'shlex.split', 'pipes.quote',
            'shell=False',  # Special: keyword arg check
        },
        SinkType.SQL: {
            'parameterized', '%s', '?',  # Placeholders
            'prepared', 'bind', 'params=',
        },
        SinkType.XSS: {
            'html.escape', 'cgi.escape', 'markupsafe.escape',
            'bleach.clean', 'nh3.clean', 'escape(',
            'autoescape', 'Markup.escape',
        },
        SinkType.CODE_EXEC: {
            'ast.literal_eval', 'json.loads',  # Safe alternatives
            'sandbox', 'restricted',
        },
        SinkType.FILE: {
            'os.path.basename', 'pathlib.Path.name',
            'secure_filename', 'validate_path',
        },
        SinkType.HTTP: {
            'allowlist', 'whitelist', 'allowed_domains',
            'validate_url', 'urlparse',
        },
    }

    # Validation patterns by sink type
    VALIDATION_PATTERNS: Dict[SinkType, Set[str]] = {
        SinkType.COMMAND: {'allowlist', 'whitelist', 'permitted_commands'},
        SinkType.SQL: {'validate', 'schema', 'pydantic'},
        SinkType.XSS: {'validate', 'strip_tags', 'clean'},
        SinkType.FILE: {'allowed_paths', 'base_dir', 'secure_filename'},
        SinkType.HTTP: {'allowed_hosts', 'allowed_domains', 'url_validator'},
    }

    def __init__(self, func_node: ast.FunctionDef, source_lines: List[str]):
        """
        Initialize taint tracker for a function.

        Args:
            func_node: AST node of the function to analyze
            source_lines: Source code lines for context
        """
        self.func_node = func_node
        self.source_lines = source_lines
        self.func_body = func_node.body

        # Cache assignments for faster lookup
        self._assignment_cache: Dict[str, List[Tuple[int, ast.AST]]] = {}
        self._build_assignment_cache()

    def _build_assignment_cache(self) -> None:
        """Build cache of variable assignments in function"""
        for stmt in ast.walk(self.func_node):
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id
                        if var_name not in self._assignment_cache:
                            self._assignment_cache[var_name] = []
                        self._assignment_cache[var_name].append(
                            (stmt.lineno, stmt.value)
                        )

    def trace_flows(
        self,
        sources: List[TaintSource],
        sink: TaintSink,
        max_hops: int = 2
    ) -> List[TaintFlow]:
        """
        Trace taint flows from sources to a sink.

        Args:
            sources: List of taint sources to track
            sink: The sink to check for tainted data
            max_hops: Maximum number of variable hops to track

        Returns:
            List of TaintFlow objects for detected flows
        """
        flows = []
        source_names = {s.var_name for s in sources}

        # Find the sink node
        sink_node = self._find_call_at_line(sink.line)
        if not sink_node:
            return flows

        # Extract variables used in sink
        sink_vars = self._extract_sink_vars(sink_node, sink.sink_type)

        # Check for direct flows (source directly in sink)
        direct_taints = sink_vars & source_names
        for var in direct_taints:
            source = next(s for s in sources if s.var_name == var)

            # Check sink-specific validation
            validation = self._check_sink_validation(sink_node, sink.sink_type)
            if validation.is_safe:
                continue

            flows.append(TaintFlow(
                source=source,
                sink=sink,
                flow_type=FlowType.DIRECT,
                intermediate_vars=[],
                evidence={
                    'operation': 'direct_usage',
                    'sink_validation': validation.reason,
                }
            ))

        # Check for single-hop flows
        intermediate_vars = sink_vars - source_names
        for var in intermediate_vars:
            resolved = resolve_single_hop(self.func_body, var, sink.line)
            if not resolved:
                continue

            resolved_names = names_in_expr(resolved)
            tainted_sources = resolved_names & source_names

            if tainted_sources:
                source_var = list(tainted_sources)[0]
                source = next(s for s in sources if s.var_name == source_var)

                # Check for sanitization wrapping
                if self._has_sanitization_wrapper(resolved, sink.sink_type):
                    continue

                # Check sink-specific validation
                validation = self._check_sink_validation(sink_node, sink.sink_type)
                if validation.is_safe:
                    continue

                flows.append(TaintFlow(
                    source=source,
                    sink=sink,
                    flow_type=FlowType.SINGLE_HOP,
                    intermediate_vars=[var],
                    evidence={
                        'operation': self._classify_operation(resolved),
                        'intermediate_var': var,
                        'sink_validation': validation.reason,
                    }
                ))
            elif max_hops >= 2:
                # Check two-hop flows
                for ref_var in resolved_names - source_names:
                    var_line = self._get_assignment_line(var, sink.line)
                    resolved2 = resolve_single_hop(self.func_body, ref_var, var_line)
                    if not resolved2:
                        continue

                    resolved2_names = names_in_expr(resolved2)
                    tainted_sources2 = resolved2_names & source_names

                    if tainted_sources2:
                        source_var = list(tainted_sources2)[0]
                        source = next(s for s in sources if s.var_name == source_var)

                        # Check for sanitization wrapping
                        if self._has_sanitization_wrapper(resolved, sink.sink_type):
                            continue
                        if self._has_sanitization_wrapper(resolved2, sink.sink_type):
                            continue

                        validation = self._check_sink_validation(sink_node, sink.sink_type)
                        if validation.is_safe:
                            continue

                        flows.append(TaintFlow(
                            source=source,
                            sink=sink,
                            flow_type=FlowType.TWO_HOP,
                            intermediate_vars=[ref_var, var],
                            evidence={
                                'operation': self._classify_operation(resolved),
                                'intermediate_vars': [ref_var, var],
                                'sink_validation': validation.reason,
                            }
                        ))
                        break

        return flows

    def _find_call_at_line(self, line: int) -> Optional[ast.Call]:
        """Find a Call node at a specific line"""
        for node in ast.walk(self.func_node):
            if isinstance(node, ast.Call) and hasattr(node, 'lineno'):
                if node.lineno == line:
                    return node
        return None

    def _extract_sink_vars(
        self,
        call_node: ast.Call,
        sink_type: SinkType
    ) -> Set[str]:
        """Extract variable names used in sink call arguments"""
        vars_used = set()

        # Get all variables from arguments
        for arg in call_node.args:
            vars_used.update(names_in_expr(arg))

        for kw in call_node.keywords:
            vars_used.update(names_in_expr(kw.value))

        return vars_used

    def _check_sink_validation(
        self,
        sink_node: ast.Call,
        sink_type: SinkType
    ) -> SinkValidation:
        """
        Check sink-specific validation patterns.

        Returns SinkValidation indicating if the sink is properly protected.
        """
        func_name = get_full_call_name(sink_node)

        # Command injection: check for shell=False or list arguments
        if sink_type == SinkType.COMMAND:
            return self._validate_command_sink(sink_node)

        # SQL injection: check for parameterized queries
        elif sink_type == SinkType.SQL:
            return self._validate_sql_sink(sink_node)

        # XSS: check for HTML escaping
        elif sink_type == SinkType.XSS:
            return self._validate_xss_sink(sink_node)

        # HTTP: check for URL allowlists
        elif sink_type == SinkType.HTTP:
            return self._validate_http_sink(sink_node)

        return SinkValidation(is_safe=False, reason="no_validation_detected")

    def _validate_command_sink(self, sink_node: ast.Call) -> SinkValidation:
        """
        Validate command injection sink.

        Safe patterns:
        - subprocess.run([cmd, arg1, arg2]) with list args
        - subprocess.run(..., shell=False)
        - shlex.quote() wrapping

        Unsafe patterns:
        - subprocess.run(cmd_string, shell=True)
        - os.system(cmd_string)
        """
        func_name = get_full_call_name(sink_node)

        # os.system always takes string - never safe with tainted data
        if 'os.system' in func_name or 'os.popen' in func_name:
            return SinkValidation(
                is_safe=False,
                reason="os.system/popen_always_unsafe"
            )

        # Check subprocess calls
        if 'subprocess' in func_name:
            # Check shell= keyword
            for kw in sink_node.keywords:
                if kw.arg == 'shell':
                    if isinstance(kw.value, ast.Constant):
                        if kw.value.value is True:
                            return SinkValidation(
                                is_safe=False,
                                reason="shell=True"
                            )
                        elif kw.value.value is False:
                            # shell=False is safe IF using list args
                            if sink_node.args and isinstance(sink_node.args[0], ast.List):
                                return SinkValidation(
                                    is_safe=True,
                                    reason="shell=False_with_list_args"
                                )

            # No shell= kwarg - check if first arg is a list
            if sink_node.args:
                first_arg = sink_node.args[0]
                if isinstance(first_arg, ast.List):
                    return SinkValidation(
                        is_safe=True,
                        reason="list_args_default_shell_false"
                    )

        return SinkValidation(is_safe=False, reason="no_shell_protection")

    def _validate_sql_sink(self, sink_node: ast.Call) -> SinkValidation:
        """
        Validate SQL injection sink.

        Safe patterns:
        - cursor.execute(query, (params,))  # Parameterized
        - cursor.execute(query, params=[...])

        Unsafe patterns:
        - cursor.execute(f"SELECT * FROM {table}")  # String interpolation
        - cursor.execute("SELECT * FROM " + table)  # Concatenation
        """
        # Check if there's a second argument (parameters)
        if len(sink_node.args) >= 2:
            return SinkValidation(
                is_safe=True,
                reason="parameterized_query"
            )

        # Check for params= keyword
        for kw in sink_node.keywords:
            if kw.arg in ('params', 'parameters', 'args'):
                return SinkValidation(
                    is_safe=True,
                    reason="parameterized_query_kwarg"
                )

        # Check if first arg is a simple string constant (no interpolation)
        if sink_node.args:
            first_arg = sink_node.args[0]
            if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                # Plain string - safe if no external vars
                return SinkValidation(
                    is_safe=True,
                    reason="constant_query"
                )

        return SinkValidation(is_safe=False, reason="no_parameterization")

    def _validate_xss_sink(self, sink_node: ast.Call) -> SinkValidation:
        """
        Validate XSS sink.

        Safe patterns:
        - html.escape(data)
        - bleach.clean(data)
        - Template with autoescape=True

        Note: Context matters - JSON API responses are safe even without escaping
        """
        # XSS validation is primarily done via wrapper detection
        # This function checks for template autoescape settings

        for kw in sink_node.keywords:
            if kw.arg == 'autoescape':
                if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    return SinkValidation(
                        is_safe=True,
                        reason="autoescape_enabled"
                    )

        return SinkValidation(is_safe=False, reason="no_html_escaping")

    def _validate_http_sink(self, sink_node: ast.Call) -> SinkValidation:
        """
        Validate HTTP request sink.

        Safe patterns:
        - URL from allowlist
        - URL validation before use
        - Hardcoded URL

        Unsafe patterns:
        - User-controlled URL without validation
        """
        # Check if URL is a constant
        if sink_node.args:
            first_arg = sink_node.args[0]
            if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                return SinkValidation(
                    is_safe=True,
                    reason="constant_url"
                )

        # Check for url= keyword with constant
        for kw in sink_node.keywords:
            if kw.arg == 'url':
                if isinstance(kw.value, ast.Constant):
                    return SinkValidation(
                        is_safe=True,
                        reason="constant_url_kwarg"
                    )

        return SinkValidation(is_safe=False, reason="dynamic_url")

    def _has_sanitization_wrapper(
        self,
        node: ast.AST,
        sink_type: SinkType
    ) -> bool:
        """
        Check if an expression is wrapped by a sanitization function.

        Examples:
        - shlex.quote(user_input) for command injection
        - html.escape(llm_output) for XSS
        - validate_url(url) for HTTP
        """
        if not isinstance(node, ast.Call):
            return False

        func_name = get_full_call_name(node)
        sanitizers = self.SANITIZATION_BY_SINK.get(sink_type, set())

        for sanitizer in sanitizers:
            if sanitizer in func_name.lower():
                return True

        return False

    def _classify_operation(self, node: ast.AST) -> str:
        """Classify the type of string operation"""
        if isinstance(node, ast.JoinedStr):
            return 'f-string'
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return 'concatenation'
        elif isinstance(node, ast.Call):
            func_name = get_call_name(node) or ''
            if 'format' in func_name.lower():
                return 'format_call'
            return 'call'
        return 'assignment'

    def _get_assignment_line(self, var_name: str, max_line: int) -> int:
        """Get the line number of the most recent assignment to a variable"""
        if var_name in self._assignment_cache:
            valid = [
                (line, _) for line, _ in self._assignment_cache[var_name]
                if line < max_line
            ]
            if valid:
                return max(valid, key=lambda x: x[0])[0]
        return max_line

    def check_structural_validation(
        self,
        source: TaintSource,
        sink: TaintSink
    ) -> bool:
        """
        Check if there's structural validation between source and sink.

        Looks for validation patterns like:
        - if not validate(source): return
        - assert is_valid(source)
        - try: validate(source) except: ...
        """
        validation_patterns = self.VALIDATION_PATTERNS.get(sink.sink_type, set())

        # Check statements between source and sink lines
        for stmt in self.func_body:
            if not hasattr(stmt, 'lineno'):
                continue

            # Only check between source and sink
            if not (source.line <= stmt.lineno < sink.line):
                continue

            # Check for validation in if statements
            if isinstance(stmt, ast.If):
                test_str = ast.dump(stmt.test).lower()
                for pattern in validation_patterns:
                    if pattern in test_str:
                        return True

            # Check for assert statements
            elif isinstance(stmt, ast.Assert):
                test_str = ast.dump(stmt.test).lower()
                for pattern in validation_patterns:
                    if pattern in test_str:
                        return True

            # Check for try/except with validation
            elif isinstance(stmt, ast.Try):
                for try_stmt in stmt.body:
                    if isinstance(try_stmt, ast.Expr) and isinstance(try_stmt.value, ast.Call):
                        func_name = get_full_call_name(try_stmt.value)
                        for pattern in validation_patterns:
                            if pattern in func_name.lower():
                                return True

        return False


def calculate_flow_confidence(
    flow: TaintFlow,
    has_structural_validation: bool = False
) -> float:
    """
    Calculate final confidence for a taint flow.

    Base confidence by flow type:
    - Direct: 0.95
    - Single-hop: 0.85
    - Two-hop: 0.75
    - Transitive: 0.65

    Adjustments:
    - Has sanitization wrapper: -0.30 (should not reach here)
    - Has structural validation: -0.20
    - f-string operation: +0.05 (clearer intent)
    - Assignment only: -0.10 (more ambiguous)
    """
    confidence = flow.base_confidence

    # Adjust for structural validation
    if has_structural_validation:
        confidence -= 0.20

    # Adjust based on operation type
    operation = flow.evidence.get('operation', '')
    if operation == 'f-string':
        confidence += 0.05
    elif operation == 'assignment':
        confidence -= 0.10

    return max(0.0, min(1.0, confidence))


def identify_sink_type(func_name: str) -> Optional[SinkType]:
    """
    Identify the sink type from a function name.

    Args:
        func_name: Full or partial function name

    Returns:
        SinkType if recognized, None otherwise
    """
    func_lower = func_name.lower()

    for sink_type, patterns in TaintTracker.SINK_PATTERNS.items():
        for pattern in patterns:
            if pattern.lower() in func_lower:
                return sink_type

    return None


# =============================================================================
# INTERPROCEDURAL ANALYSIS
# =============================================================================

# LLM API patterns to identify LLM calls
LLM_API_PATTERNS = {
    # OpenAI
    'openai', 'chatcompletion', 'chat.completions.create', 'completions.create',
    # Anthropic
    'anthropic', 'messages.create', 'claude',
    # LangChain
    'langchain', 'llm.invoke', 'chain.invoke', 'chain.run',
    # Ollama
    'ollama', 'chat', 'generate',
    # Generic
    'llm.', 'model.generate', 'model.complete',
}

# Patterns indicating LLM output extraction
LLM_OUTPUT_PATTERNS = {
    '.choices[', '.message.content', '.content', '.text',
    '.completion', '.output', '.response',
}


class InterproceduralAnalyzer:
    """
    Analyze module-level function relationships for interprocedural taint tracking.

    Identifies:
    1. Functions that return LLM output (directly or via intermediate vars)
    2. Functions that wrap LLM calls
    3. Helper functions that pass through tainted data
    """

    def __init__(self, tree: ast.Module, source_lines: List[str]):
        """
        Initialize interprocedural analyzer.

        Args:
            tree: AST of the entire module
            source_lines: Source code lines
        """
        self.tree = tree
        self.source_lines = source_lines

        # Cache of functions that return LLM output
        self._llm_output_functions: Set[str] = set()
        # Cache of all function definitions
        self._function_defs: Dict[str, ast.FunctionDef] = {}

        self._build_function_cache()
        self._analyze_llm_output_functions()

    def _build_function_cache(self) -> None:
        """Build cache of all function definitions in module."""
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef):
                self._function_defs[node.name] = node
            elif isinstance(node, ast.AsyncFunctionDef):
                self._function_defs[node.name] = node

    def _analyze_llm_output_functions(self) -> None:
        """
        Identify functions that return LLM output.

        A function returns LLM output if:
        1. It contains an LLM API call AND
        2. It returns a value derived from that call
        """
        for func_name, func_node in self._function_defs.items():
            if self._function_returns_llm_output(func_node):
                self._llm_output_functions.add(func_name)

    def _function_returns_llm_output(self, func_node: ast.FunctionDef) -> bool:
        """
        Check if a function returns LLM output.

        Tracks:
        1. Direct return of LLM call result
        2. Return of variable assigned from LLM call
        3. Return of derived variable (e.g., response.choices[0].message.content)
        """
        # Find all LLM-related assignments in function
        llm_vars = self._find_llm_output_vars(func_node)

        if not llm_vars:
            return False

        # Check if any return statement uses these variables
        for node in ast.walk(func_node):
            if isinstance(node, ast.Return) and node.value is not None:
                returned_vars = names_in_expr(node.value)
                if returned_vars & llm_vars:
                    return True

                # Also check if return contains LLM output pattern directly
                return_str = self._node_to_source(node.value)
                if any(pattern in return_str.lower() for pattern in LLM_OUTPUT_PATTERNS):
                    # Check if a tainted var is in the expression
                    if returned_vars & llm_vars:
                        return True

        return False

    def _find_llm_output_vars(self, func_node: ast.FunctionDef) -> Set[str]:
        """
        Find variables that hold LLM output in a function.

        Returns set of variable names that are tainted with LLM output.
        """
        llm_vars: Set[str] = set()

        # First pass: find direct LLM call assignments
        for node in ast.walk(func_node):
            if isinstance(node, ast.Assign):
                value_str = self._node_to_source(node.value)

                # Check if assignment is from LLM API call
                is_llm_call = any(
                    pattern in value_str.lower()
                    for pattern in LLM_API_PATTERNS
                )

                if is_llm_call:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            llm_vars.add(target.id)

        # Second pass: track derived variables
        for _ in range(3):  # Max 3 hops
            new_vars = set()
            for node in ast.walk(func_node):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name) and target.id not in llm_vars:
                            referenced = names_in_expr(node.value)
                            if referenced & llm_vars:
                                new_vars.add(target.id)
            llm_vars.update(new_vars)
            if not new_vars:
                break

        return llm_vars

    def _node_to_source(self, node: ast.AST) -> str:
        """Convert AST node back to source code string."""
        try:
            import sys
            if sys.version_info >= (3, 9):
                return ast.unparse(node)
            else:
                # Python 3.8 fallback
                try:
                    import astunparse
                    return astunparse.unparse(node)
                except ImportError:
                    return ast.dump(node)
        except Exception:
            return ast.dump(node)

    def get_llm_output_functions(self) -> Set[str]:
        """
        Get set of function names that return LLM output.

        Returns:
            Set of function names
        """
        return self._llm_output_functions.copy()

    def is_llm_output_function(self, func_name: str) -> bool:
        """
        Check if a function returns LLM output.

        Args:
            func_name: Name of the function to check

        Returns:
            True if function returns LLM output
        """
        return func_name in self._llm_output_functions

    def get_taint_sources_from_calls(
        self,
        func_node: ast.FunctionDef
    ) -> List[TaintSource]:
        """
        Get taint sources from calls to LLM-output-returning functions.

        For interprocedural analysis: if a function calls another function
        that returns LLM output, the call result is a taint source.

        Args:
            func_node: Function AST to analyze

        Returns:
            List of TaintSource from helper function calls
        """
        sources = []

        for node in ast.walk(func_node):
            if isinstance(node, ast.Assign):
                # Check if RHS is a call to an LLM output function
                if isinstance(node.value, ast.Call):
                    func_name = get_call_name(node.value)
                    if func_name and self.is_llm_output_function(func_name):
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                sources.append(TaintSource(
                                    var_name=target.id,
                                    line=node.lineno,
                                    source_type='llm_helper_function',
                                    node=node.value
                                ))

        return sources


# =============================================================================
# SEMANTIC TAINT PROPAGATOR
# Builds taint graph from parsed code data
# =============================================================================

# User input source patterns
USER_INPUT_PATTERNS = {
    # Web frameworks
    'request.get', 'request.form', 'request.args', 'request.json',
    'request.data', 'request.values', 'request.files',
    'request.query_params', 'request.body',
    # FastAPI/Starlette
    'query', 'body', 'form', 'path',
    # Django
    'request.GET', 'request.POST', 'request.body',
    # Standard input
    'input(', 'sys.stdin', 'sys.argv',
    # Environment (can be attacker-controlled in some contexts)
    'os.environ', 'os.getenv',
}

# Parameter names that typically indicate user input
USER_INPUT_PARAM_NAMES = {
    'user_input', 'query', 'message', 'prompt', 'text', 'content',
    'input', 'data', 'body', 'request', 'user_message', 'question',
    'user_query', 'user_text', 'user_prompt', 'payload',
}

# Extended LLM API patterns for detection
EXTENDED_LLM_PATTERNS = {
    # OpenAI
    'openai.chat.completions.create', 'openai.completions.create',
    'ChatCompletion.create', 'Completion.create',
    'client.chat.completions.create', 'client.completions.create',
    # Anthropic
    'anthropic.messages.create', 'client.messages.create',
    'anthropic.completions.create',
    # LangChain
    'llm.invoke', 'llm.predict', 'llm.generate', 'llm.call',
    'chain.invoke', 'chain.run', 'chain.call',
    'ChatOpenAI', 'ChatAnthropic', 'ChatVertexAI',
    # Ollama
    'ollama.chat', 'ollama.generate',
    # vLLM
    'vllm.generate', 'vllm.chat',
    # Generic patterns
    '.generate(', '.complete(', '.chat(',
}

# LLM argument positions mapping
LLM_ARG_POSITIONS = {
    # OpenAI-style
    'messages': 'prompt',
    'prompt': 'prompt',
    'system': 'system',
    'user': 'prompt',
    # Anthropic-style
    'system': 'system',
    # LangChain-style
    'input': 'prompt',
    'query': 'prompt',
    'question': 'prompt',
    'context': 'context',
    'history': 'history',
    'chat_history': 'history',
}


@dataclass
class LLMCallInfo:
    """Information about a detected LLM API call."""
    line: int
    function_name: str
    input_vars: List[str]           # Variables used as input
    input_positions: Dict[str, str]  # var_name -> position (prompt/system/context)
    output_var: Optional[str]        # Variable receiving output
    sdk: str                         # Detected SDK (openai, anthropic, langchain, etc.)


@dataclass
class DangerousSinkInfo:
    """Information about a detected dangerous sink."""
    line: int
    function_name: str
    category: str                    # code_execution, command_injection, sql, etc.
    severity: str                    # CRITICAL, HIGH, MEDIUM
    cwe_id: str                      # CWE reference
    arg_vars: List[str]              # Variables used as arguments


class SemanticTaintPropagator:
    """
    Builds a semantic taint graph from parsed Python code.

    This class analyzes parsed_data from PythonASTParser and constructs
    a SemanticTaintGraph that tracks data flow including through LLM calls.
    """

    # Dangerous sink patterns
    SINK_PATTERNS = {
        'code_execution': {
            'functions': {'eval', 'exec', 'compile', '__import__', 'importlib.import_module'},
            'severity': 'CRITICAL',
            'cwe': 'CWE-94',
        },
        'command_injection': {
            'functions': {
                'os.system', 'os.popen', 'os.spawn', 'os.exec',
                'subprocess.run', 'subprocess.call', 'subprocess.Popen',
                'subprocess.check_output', 'subprocess.check_call',
                'commands.getoutput', 'commands.getstatusoutput',
            },
            'severity': 'CRITICAL',
            'cwe': 'CWE-78',
        },
        'sql_injection': {
            'functions': {
                'execute', 'executemany', 'cursor.execute',
                'connection.execute', 'engine.execute', 'session.execute',
                'raw', 'extra', 'RawSQL',
            },
            'severity': 'HIGH',
            'cwe': 'CWE-89',
        },
        'xss': {
            'functions': {
                'render_template_string', 'Markup', 'mark_safe',
                'render', 'render_to_string', 'innerHTML',
            },
            'severity': 'HIGH',
            'cwe': 'CWE-79',
        },
        'path_traversal': {
            'functions': {
                'open', 'read', 'write', 'unlink', 'remove',
                'shutil.rmtree', 'os.remove', 'os.unlink',
                'Path.write_text', 'Path.read_text',
            },
            'severity': 'MEDIUM',
            'cwe': 'CWE-22',
        },
        'ssrf': {
            'functions': {
                'requests.get', 'requests.post', 'requests.put',
                'requests.delete', 'requests.patch', 'requests.request',
                'httpx.get', 'httpx.post', 'httpx.AsyncClient',
                'urllib.request.urlopen', 'aiohttp.ClientSession',
            },
            'severity': 'HIGH',
            'cwe': 'CWE-918',
        },
    }

    def __init__(self, parsed_data: Dict[str, Any]):
        """
        Initialize propagator with parsed AST data.

        Args:
            parsed_data: Output from PythonASTParser.parse()
        """
        self.parsed_data = parsed_data
        self.file_path = parsed_data.get('file_path', '')
        self.source_lines = parsed_data.get('source_lines', [])
        self.graph = SemanticTaintGraph(self.file_path)

        # Caches for analysis
        self._var_assignments: Dict[str, List[Tuple[int, Any]]] = defaultdict(list)
        self._llm_calls: List[LLMCallInfo] = []
        self._dangerous_sinks: List[DangerousSinkInfo] = []

    def build_taint_graph(self) -> SemanticTaintGraph:
        """
        Build complete semantic taint graph for the file.

        Steps:
        1. Identify user input sources
        2. Track variable assignments
        3. Identify and process LLM calls
        4. Propagate taint through assignments and LLM calls
        5. Identify dangerous sinks

        Returns:
            Populated SemanticTaintGraph
        """
        # Step 1: Find all taint sources (user input)
        self._identify_sources()

        # Step 2: Build assignment map for tracking
        self._build_assignment_map()

        # Step 3: Identify LLM calls
        self._identify_llm_calls()

        # Step 4: Propagate taint through assignments
        self._propagate_assignments()

        # Step 5: Process LLM calls with semantic propagation
        self._process_llm_calls()

        # Step 6: Identify dangerous sinks
        self._identify_dangerous_sinks()

        return self.graph

    def _identify_sources(self) -> None:
        """Identify and add taint sources to the graph."""
        # Check function parameters for user input patterns
        for func in self.parsed_data.get('functions', []):
            for arg in func.get('args', []):
                arg_name = arg if isinstance(arg, str) else arg.get('name', '')
                if arg_name.lower() in USER_INPUT_PARAM_NAMES:
                    self.graph.add_source(
                        var_name=arg_name,
                        line=func.get('line', 1),
                        taint_type=SemanticTaintType.USER_INPUT,
                        metadata={'source': 'function_parameter', 'function': func.get('name')}
                    )

        # Check assignments for user input patterns
        for assignment in self.parsed_data.get('assignments', []):
            value_str = str(assignment.get('value', '')).lower()

            # Check if value looks like user input
            is_user_input = any(
                pattern.lower() in value_str
                for pattern in USER_INPUT_PATTERNS
            )

            if is_user_input:
                var_name = assignment.get('target', '')
                if var_name:
                    self.graph.add_source(
                        var_name=var_name,
                        line=assignment.get('line', 1),
                        taint_type=SemanticTaintType.USER_INPUT,
                        metadata={'source': 'user_input_assignment', 'value': value_str[:100]}
                    )

        # Check structured calls for user input retrieval
        for call in self.parsed_data.get('structured_calls', []):
            func_name = call.get('function', '').lower()

            is_user_input_call = any(
                pattern.lower() in func_name
                for pattern in USER_INPUT_PATTERNS
            )

            if is_user_input_call:
                # Find the assignment target
                target = call.get('assignment_target')
                if target:
                    self.graph.add_source(
                        var_name=target,
                        line=call.get('line', 1),
                        taint_type=SemanticTaintType.USER_INPUT,
                        metadata={'source': 'user_input_call', 'function': func_name}
                    )

    def _build_assignment_map(self) -> None:
        """Build map of variable assignments for propagation tracking."""
        for assignment in self.parsed_data.get('assignments', []):
            target = assignment.get('target')
            if target:
                self._var_assignments[target].append((
                    assignment.get('line', 0),
                    assignment.get('value'),
                    assignment.get('value_vars', [])  # Variables referenced in value
                ))

    def _identify_llm_calls(self) -> None:
        """Identify all LLM API calls in the code."""
        # Check llm_api_calls from parser
        for call in self.parsed_data.get('llm_api_calls', []):
            llm_info = self._analyze_llm_call(call)
            if llm_info:
                self._llm_calls.append(llm_info)

        # Also check structured_calls for LLM patterns
        for call in self.parsed_data.get('structured_calls', []):
            func_name = call.get('function', '')
            if self._is_llm_call(func_name):
                llm_info = self._analyze_llm_call(call)
                if llm_info and llm_info not in self._llm_calls:
                    self._llm_calls.append(llm_info)

    def _is_llm_call(self, func_name: str) -> bool:
        """Check if a function name matches LLM API patterns."""
        func_lower = func_name.lower()
        return any(
            pattern.lower() in func_lower
            for pattern in EXTENDED_LLM_PATTERNS
        )

    def _analyze_llm_call(self, call: Dict[str, Any]) -> Optional[LLMCallInfo]:
        """Extract detailed information about an LLM call."""
        func_name = call.get('function', '')
        line = call.get('line', 0)

        # Extract input variables and their positions
        input_vars = []
        input_positions = {}

        # Check keyword arguments
        # keywords can be either a dict (from AST parser) or list (legacy)
        keywords = call.get('keywords', {})
        if isinstance(keywords, dict):
            # New format: {'model': 'gpt-4', 'messages': '[...]'}
            for kw_name, kw_value in keywords.items():
                # Get variables from the value
                value_vars = self._extract_vars_from_value(kw_value)

                for var in value_vars:
                    input_vars.append(var)
                    # Determine position based on keyword name
                    position = LLM_ARG_POSITIONS.get(kw_name.lower(), 'context')
                    input_positions[var] = position
        else:
            # Legacy format: list of {'arg': name, 'value': value}
            for kw in keywords:
                kw_name = kw.get('arg', '') if isinstance(kw, dict) else ''
                kw_value = kw.get('value', '') if isinstance(kw, dict) else ''

                # Get variables from the value
                value_vars = self._extract_vars_from_value(kw_value)

                for var in value_vars:
                    input_vars.append(var)
                    # Determine position based on keyword name
                    position = LLM_ARG_POSITIONS.get(kw_name.lower(), 'context')
                    input_positions[var] = position

        # Check positional arguments
        for i, arg in enumerate(call.get('args', [])):
            arg_vars = self._extract_vars_from_value(arg)
            for var in arg_vars:
                if var not in input_vars:
                    input_vars.append(var)
                    # First positional arg is usually the prompt
                    input_positions[var] = 'prompt' if i == 0 else 'context'

        # Find output variable (assignment target)
        output_var = call.get('assignment_target')

        # Detect SDK
        sdk = self._detect_sdk(func_name)

        return LLMCallInfo(
            line=line,
            function_name=func_name,
            input_vars=input_vars,
            input_positions=input_positions,
            output_var=output_var,
            sdk=sdk
        )

    def _extract_vars_from_value(self, value: Any) -> List[str]:
        """Extract variable names from a value (string representation or dict)."""
        if isinstance(value, str):
            # Simple heuristic: find words that look like variable names
            import re
            # Match Python identifiers that aren't keywords
            candidates = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', value)
            # Filter out common non-variable patterns
            keywords = {'True', 'False', 'None', 'and', 'or', 'not', 'in', 'is'}
            return [c for c in candidates if c not in keywords and not c.isupper()]
        elif isinstance(value, dict):
            # May have 'vars' or 'names' field
            return value.get('vars', value.get('names', []))
        elif isinstance(value, list):
            result = []
            for item in value:
                result.extend(self._extract_vars_from_value(item))
            return result
        return []

    def _detect_sdk(self, func_name: str) -> str:
        """Detect which LLM SDK is being used."""
        func_lower = func_name.lower()
        if 'openai' in func_lower or 'chatcompletion' in func_lower:
            return 'openai'
        elif 'anthropic' in func_lower or 'claude' in func_lower:
            return 'anthropic'
        elif 'langchain' in func_lower or 'chain' in func_lower:
            return 'langchain'
        elif 'ollama' in func_lower:
            return 'ollama'
        elif 'vllm' in func_lower:
            return 'vllm'
        return 'generic'

    def _propagate_assignments(self) -> None:
        """Propagate taint through simple assignments."""
        # Process assignments in order by line number
        all_assignments = []
        for var, assignments in self._var_assignments.items():
            for line, value, value_vars in assignments:
                all_assignments.append((line, var, value_vars))

        all_assignments.sort(key=lambda x: x[0])

        for line, target_var, source_vars in all_assignments:
            if not source_vars:
                continue

            # Find tainted source nodes for referenced variables
            source_node_ids = []
            for src_var in source_vars:
                node_id = self.graph.find_node_by_var(src_var, line)
                if node_id:
                    source_node_ids.append(node_id)

            if source_node_ids:
                self.graph.add_assignment(
                    target_var=target_var,
                    target_line=line,
                    source_node_ids=source_node_ids
                )

    def _process_llm_calls(self) -> None:
        """Process LLM calls with semantic taint propagation."""
        for llm_call in self._llm_calls:
            if not llm_call.output_var:
                continue

            # Find tainted inputs
            input_node_ids = []
            input_positions = {}

            for var in llm_call.input_vars:
                node_id = self.graph.find_node_by_var(var, llm_call.line)
                if node_id:
                    input_node_ids.append(node_id)
                    input_positions[node_id] = llm_call.input_positions.get(var, 'context')

            if input_node_ids:
                self.graph.propagate_through_llm(
                    input_node_ids=input_node_ids,
                    output_var=llm_call.output_var,
                    output_line=llm_call.line,
                    input_positions=input_positions,
                    llm_function=llm_call.function_name
                )

    def _identify_dangerous_sinks(self) -> None:
        """Identify dangerous sinks in the code."""
        for call in self.parsed_data.get('structured_calls', []):
            func_name = call.get('function', '')

            for category, info in self.SINK_PATTERNS.items():
                if self._matches_sink_pattern(func_name, info['functions']):
                    # Extract argument variables
                    arg_vars = []
                    for arg in call.get('args', []):
                        arg_vars.extend(self._extract_vars_from_value(arg))
                    for kw in call.get('keywords', []):
                        arg_vars.extend(self._extract_vars_from_value(kw.get('value', '')))

                    self._dangerous_sinks.append(DangerousSinkInfo(
                        line=call.get('line', 0),
                        function_name=func_name,
                        category=category,
                        severity=info['severity'],
                        cwe_id=info['cwe'],
                        arg_vars=arg_vars
                    ))
                    break  # Only match first category

    def _matches_sink_pattern(self, func_name: str, patterns: Set[str]) -> bool:
        """Check if function name matches any sink pattern."""
        func_lower = func_name.lower()
        for pattern in patterns:
            if pattern.lower() in func_lower:
                return True
        return False

    def get_dangerous_sinks(self) -> List[DangerousSinkInfo]:
        """Get all identified dangerous sinks."""
        return self._dangerous_sinks

    def get_llm_calls(self) -> List[LLMCallInfo]:
        """Get all identified LLM calls."""
        return self._llm_calls

    def analyze_sink_reachability(
        self,
        sink: DangerousSinkInfo
    ) -> List[Dict[str, Any]]:
        """
        Analyze if tainted data can reach a specific sink.

        Returns list of semantic flows that reach this sink.
        """
        flows = []

        for arg_var in sink.arg_vars:
            semantic_flows = self.graph.get_semantic_flows_to_sink(
                sink_var=arg_var,
                sink_line=sink.line
            )
            for flow in semantic_flows:
                flow['sink'] = sink
                flows.append(flow)

        return flows
