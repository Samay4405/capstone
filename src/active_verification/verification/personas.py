"""Synthetic persona profiles for safe, sandboxed active verification simulations."""

import random
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class SyntheticPersona(BaseModel):
    """Fictitious persona profile strictly confined to synthetic simulations."""

    persona_id: str
    full_name: str
    job_title: str
    department: str
    simulated_email: str
    communication_style: str
    canary_honeytoken: str
    role_description: str


# Pre-defined fictitious personas (all email addresses end in RFC 2606 reserved .example domains)
SYNTHETIC_PERSONAS: List[SyntheticPersona] = [
    SyntheticPersona(
        persona_id="persona_fin_01",
        full_name="Morgan Reed",
        job_title="Junior Accounts Payable Associate",
        department="Finance",
        simulated_email="morgan.reed@synthetic-corp.example",
        communication_style="polite, cautious, asks for clarification on payment routing",
        canary_honeytoken="CANARY-IBAN-DE89370400440532013000",
        role_description="Handles supplier invoices under $10,000, requests W9 and invoice verification.",
    ),
    SyntheticPersona(
        persona_id="persona_it_02",
        full_name="Jordan Vance",
        job_title="IT Helpdesk Specialist",
        department="Information Technology",
        simulated_email="jordan.vance@synthetic-corp.example",
        communication_style="technical, inquisitive, asks for ticket number and SSO error code",
        canary_honeytoken="CANARY-TICKET-SEC-89914",
        role_description="Assists employees with password resets and multi-factor authentication issues.",
    ),
    SyntheticPersona(
        persona_id="persona_hr_03",
        full_name="Alex Bailey",
        job_title="HR Operations Coordinator",
        department="Human Resources",
        simulated_email="alex.bailey@synthetic-corp.example",
        communication_style="formal, helpful, verifies employee ID and policy compliance",
        canary_honeytoken="CANARY-EMPID-HR-4029",
        role_description="Coordinates employee benefits, annual compliance sign-offs, and payroll enrollments.",
    ),
]


class PersonaManager:
    """Selects and manages synthetic personas for sandboxed simulations."""

    def __init__(self):
        self._personas: Dict[str, SyntheticPersona] = {p.persona_id: p for p in SYNTHETIC_PERSONAS}

    def select_persona_for_scenario(self, category: str = "general") -> SyntheticPersona:
        """Select the most contextually relevant synthetic persona for a simulated scenario."""
        category_lower = category.lower()
        if "finance" in category_lower or "invoice" in category_lower or "wire" in category_lower:
            return self._personas["persona_fin_01"]
        elif "it" in category_lower or "password" in category_lower or "sso" in category_lower:
            return self._personas["persona_it_02"]
        elif "hr" in category_lower or "payroll" in category_lower or "benefit" in category_lower:
            return self._personas["persona_hr_03"]
        return random.choice(list(self._personas.values()))

    def get_persona(self, persona_id: str) -> Optional[SyntheticPersona]:
        return self._personas.get(persona_id)


persona_manager = PersonaManager()

