"""
Synthetic Data Generator for ML Training.

Generates labeled Python code samples for training the prompt injection classifier.
Uses templates to embed prompt injection patterns in realistic code structures.

This module is essential because:
1. HackAPrompt/TensorTrust contain prompts, not code samples
2. We need code with labeled vulnerabilities for AST feature extraction
3. Synthetic generation allows controlled, balanced datasets
"""

import random
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional


class VulnerabilityLabel(Enum):
    """Labels for training data."""
    SAFE = "safe"
    DIRECT = "direct"       # Direct user input to LLM
    INDIRECT = "indirect"   # External data influence
    STORED = "stored"       # Stored prompt injection


@dataclass
class CodeSample:
    """A generated code sample with labels."""
    code: str
    label: VulnerabilityLabel
    attack_vector: str
    has_mitigation: bool
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "label": self.label.value,
            "attack_vector": self.attack_vector,
            "has_mitigation": self.has_mitigation,
            "metadata": self.metadata,
        }


class SyntheticDataGenerator:
    """
    Generate synthetic Python code samples for training.

    Approach:
    1. Define code templates for different scenarios
    2. Fill templates with variable names, function names, etc.
    3. Label based on vulnerability patterns present
    """

    # LLM SDK patterns to use in generation
    LLM_SDKS = [
        ("openai", "client.chat.completions.create", "messages"),
        ("anthropic", "client.messages.create", "messages"),
        ("langchain", "llm.invoke", "input"),
    ]

    # User input source patterns
    INPUT_SOURCES = [
        "request.get('query')",
        "request.form['message']",
        "request.json.get('prompt')",
        "input('Enter text: ')",
        "sys.argv[1]",
        "os.environ.get('USER_INPUT')",
    ]

    # Dangerous sink patterns
    SINKS = [
        ("exec({output})", "code_execution"),
        ("subprocess.run({output}, shell=True)", "command_injection"),
        ("cursor.execute({output})", "sql_injection"),
        ("render_template_string({output})", "xss"),
    ]

    # Mitigation patterns
    MITIGATIONS = [
        "validated_{var} = validate_input({var})",
        "{var} = sanitize({var})",
        "{var} = bleach.clean({var})",
        "if not is_allowed({var}): raise ValueError()",
    ]

    # Variable name pools
    VAR_NAMES = {
        "user_input": ["user_input", "query", "message", "prompt", "text", "user_msg"],
        "llm_output": ["response", "result", "output", "answer", "completion", "generated"],
        "generic": ["data", "content", "value", "payload", "info"],
    }

    def __init__(self, seed: Optional[int] = None):
        """
        Initialize generator.

        Args:
            seed: Random seed for reproducibility
        """
        if seed is not None:
            random.seed(seed)

    def generate_dataset(
        self,
        num_samples: int = 1000,
        safe_ratio: float = 0.4,
        include_mitigations: float = 0.3
    ) -> List[CodeSample]:
        """
        Generate a balanced dataset of code samples.

        Args:
            num_samples: Total number of samples to generate
            safe_ratio: Proportion of safe (non-vulnerable) samples
            include_mitigations: Proportion of vulnerable samples with mitigations

        Returns:
            List of CodeSample objects
        """
        samples = []

        num_safe = int(num_samples * safe_ratio)
        num_vulnerable = num_samples - num_safe

        # Generate safe samples
        for _ in range(num_safe):
            samples.append(self._generate_safe_sample())

        # Generate vulnerable samples (balanced across attack vectors)
        vectors = [VulnerabilityLabel.DIRECT, VulnerabilityLabel.INDIRECT, VulnerabilityLabel.STORED]
        per_vector = num_vulnerable // len(vectors)

        for vector in vectors:
            for i in range(per_vector):
                has_mitigation = random.random() < include_mitigations
                samples.append(self._generate_vulnerable_sample(vector, has_mitigation))

        # Fill remaining with random vectors
        remaining = num_vulnerable - (per_vector * len(vectors))
        for _ in range(remaining):
            vector = random.choice(vectors)
            has_mitigation = random.random() < include_mitigations
            samples.append(self._generate_vulnerable_sample(vector, has_mitigation))

        random.shuffle(samples)
        return samples

    def _generate_safe_sample(self) -> CodeSample:
        """Generate a safe (non-vulnerable) code sample."""
        template_choice = random.randint(0, 3)

        if template_choice == 0:
            # Safe: Static prompt, no user input
            code = self._generate_static_prompt_sample()
        elif template_choice == 1:
            # Safe: Proper prompt template usage
            code = self._generate_template_sample()
        elif template_choice == 2:
            # Safe: Input validation before LLM
            code = self._generate_validated_sample()
        else:
            # Safe: No LLM usage at all
            code = self._generate_no_llm_sample()

        return CodeSample(
            code=code,
            label=VulnerabilityLabel.SAFE,
            attack_vector="none",
            has_mitigation=True,
            metadata={"template": f"safe_{template_choice}"}
        )

    def _generate_vulnerable_sample(
        self,
        vector: VulnerabilityLabel,
        has_mitigation: bool
    ) -> CodeSample:
        """Generate a vulnerable code sample."""
        if vector == VulnerabilityLabel.DIRECT:
            code = self._generate_direct_injection_sample(has_mitigation)
        elif vector == VulnerabilityLabel.INDIRECT:
            code = self._generate_indirect_injection_sample(has_mitigation)
        else:  # STORED
            code = self._generate_stored_injection_sample(has_mitigation)

        return CodeSample(
            code=code,
            label=vector,
            attack_vector=vector.value,
            has_mitigation=has_mitigation,
            metadata={"template": f"vuln_{vector.value}"}
        )

    def _generate_static_prompt_sample(self) -> str:
        """Generate sample with static prompt (safe)."""
        sdk, call, arg = random.choice(self.LLM_SDKS)
        func_name = self._random_func_name()

        return f'''
import {sdk}

def {func_name}():
    """Safe: Static prompt with no user input."""
    client = {sdk}.Client()

    response = {call}(
        model="gpt-4",
        {arg}=[
            {{"role": "system", "content": "You are a helpful assistant."}},
            {{"role": "user", "content": "Summarize the benefits of exercise."}}
        ]
    )

    return response.content
'''

    def _generate_template_sample(self) -> str:
        """Generate sample using proper prompt templates (safe)."""
        input_var = random.choice(self.VAR_NAMES["user_input"])
        output_var = random.choice(self.VAR_NAMES["llm_output"])

        return f'''
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain

def process_query({input_var}: str) -> str:
    """Safe: Uses PromptTemplate for structured prompts."""

    template = PromptTemplate(
        input_variables=["{input_var}"],
        template="Answer the following question: {{{input_var}}}"
    )

    chain = LLMChain(llm=llm, prompt=template)
    {output_var} = chain.run({input_var}={input_var})

    return {output_var}
'''

    def _generate_validated_sample(self) -> str:
        """Generate sample with input validation (safe)."""
        input_var = random.choice(self.VAR_NAMES["user_input"])
        sdk, call, arg = random.choice(self.LLM_SDKS)

        return f'''
import {sdk}
from pydantic import BaseModel, validator

class QueryInput(BaseModel):
    {input_var}: str

    @validator('{input_var}')
    def validate_query(cls, v):
        if len(v) > 500:
            raise ValueError('Query too long')
        if any(word in v.lower() for word in ['ignore', 'forget', 'disregard']):
            raise ValueError('Invalid query pattern')
        return v

def safe_query({input_var}: str) -> str:
    """Safe: Validated input before LLM call."""
    validated = QueryInput({input_var}={input_var})
    client = {sdk}.Client()

    response = {call}(
        model="gpt-4",
        {arg}=[{{"role": "user", "content": validated.{input_var}}}]
    )

    return response.content
'''

    def _generate_no_llm_sample(self) -> str:
        """Generate sample with no LLM usage (safe)."""
        input_var = random.choice(self.VAR_NAMES["generic"])

        return f'''
import json
from flask import Flask, request

app = Flask(__name__)

@app.route('/process')
def process_data():
    """Safe: No LLM usage in this code."""
    {input_var} = request.get_json()

    # Simple data processing without LLM
    result = {{
        "status": "processed",
        "length": len({input_var}.get("text", "")),
        "words": {input_var}.get("text", "").split()
    }}

    return json.dumps(result)
'''

    def _generate_direct_injection_sample(self, has_mitigation: bool) -> str:
        """Generate direct injection sample (user input -> LLM)."""
        input_var = random.choice(self.VAR_NAMES["user_input"])
        output_var = random.choice(self.VAR_NAMES["llm_output"])
        sdk, call, arg = random.choice(self.LLM_SDKS)
        input_source = random.choice(self.INPUT_SOURCES)

        mitigation = ""
        if has_mitigation:
            mit_template = random.choice(self.MITIGATIONS)
            mitigation = f"\n    {mit_template.format(var=input_var)}"

        # Choose construction pattern
        pattern = random.randint(0, 2)
        if pattern == 0:
            # F-string
            prompt_construction = f'f"Process this request: {{{input_var}}}"'
        elif pattern == 1:
            # Concatenation
            prompt_construction = f'"Process this: " + {input_var}'
        else:
            # Format
            prompt_construction = f'"Process: {{}}".format({input_var})'

        return f'''
import {sdk}
from flask import request

def handle_{input_var}():
    """VULNERABLE: Direct user input in LLM prompt."""
    client = {sdk}.Client()

    {input_var} = {input_source}{mitigation}

    prompt = {prompt_construction}

    {output_var} = {call}(
        model="gpt-4",
        {arg}=[{{"role": "user", "content": prompt}}]
    )

    return {output_var}.content
'''

    def _generate_indirect_injection_sample(self, has_mitigation: bool) -> str:
        """Generate indirect injection sample (LLM output -> sink)."""
        input_var = random.choice(self.VAR_NAMES["user_input"])
        output_var = random.choice(self.VAR_NAMES["llm_output"])
        sdk, call, arg = random.choice(self.LLM_SDKS)
        sink, sink_type = random.choice(self.SINKS)

        mitigation = ""
        if has_mitigation:
            mitigation = f"\n    {output_var} = sanitize({output_var})"

        return f'''
import {sdk}
import subprocess

def process_with_llm({input_var}: str):
    """VULNERABLE: LLM output flows to dangerous sink."""
    client = {sdk}.Client()

    # Get LLM response
    response = {call}(
        model="gpt-4",
        {arg}=[{{"role": "user", "content": {input_var}}}]
    )

    {output_var} = response.content{mitigation}

    # VULNERABLE: LLM output used in dangerous operation
    {sink.format(output=output_var)}
'''

    def _generate_stored_injection_sample(self, has_mitigation: bool) -> str:
        """Generate stored injection sample (DB/file -> LLM)."""
        output_var = random.choice(self.VAR_NAMES["llm_output"])
        sdk, call, arg = random.choice(self.LLM_SDKS)

        mitigation = ""
        if has_mitigation:
            mitigation = "\n    stored_prompt = validate_stored_prompt(stored_prompt)"

        return f'''
import {sdk}
from database import get_prompt_from_db

def execute_stored_prompt(prompt_id: int):
    """VULNERABLE: Executing prompts from untrusted storage."""
    client = {sdk}.Client()

    # Load prompt from database (could be attacker-controlled)
    stored_prompt = get_prompt_from_db(prompt_id){mitigation}

    # VULNERABLE: Executing stored prompt without validation
    {output_var} = {call}(
        model="gpt-4",
        {arg}=[{{"role": "user", "content": stored_prompt}}]
    )

    return {output_var}.content
'''

    def _random_func_name(self) -> str:
        """Generate a random function name."""
        prefixes = ["process", "handle", "execute", "run", "get", "fetch"]
        suffixes = ["query", "request", "data", "input", "message"]
        return f"{random.choice(prefixes)}_{random.choice(suffixes)}"

    def export_dataset(
        self,
        samples: List[CodeSample],
        output_path: str,
        format: str = "jsonl"
    ) -> None:
        """
        Export dataset to file.

        Args:
            samples: List of CodeSample objects
            output_path: Path to output file
            format: Output format ("jsonl" or "csv")
        """
        import json

        if format == "jsonl":
            with open(output_path, 'w') as f:
                for sample in samples:
                    f.write(json.dumps(sample.to_dict()) + '\n')
        elif format == "csv":
            import csv
            with open(output_path, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['code', 'label', 'attack_vector', 'has_mitigation'])
                writer.writeheader()
                for sample in samples:
                    writer.writerow({
                        'code': sample.code,
                        'label': sample.label.value,
                        'attack_vector': sample.attack_vector,
                        'has_mitigation': sample.has_mitigation,
                    })
