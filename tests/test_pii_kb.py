import pytest
from pathlib import Path
from typing import List, Dict

from knowledge_base.network.schemas.kb_schemas import NormalizedPIIPattern
from pcap.schemas import PIIFact
from pcap.matchers.pii_matcher import PIIMatcher
from knowledge_base.dataset_manager import DatasetManager

def test_pii_matcher():
    patterns = [
        {
            "pattern_name": "Email Address",
            "category": "Identity",
            "regex": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "source_reference": ""
        },
        {
            "pattern_name": "IMEI",
            "category": "Hardware",
            "regex": r"\b[0-9]{15}\b",
            "source_reference": ""
        },
        {
            "pattern_name": "Bearer Token",
            "category": "Authentication",
            "regex": r"Bearer\s+([A-Za-z0-9\-\._~\+\/]+)",
            "source_reference": ""
        }
    ]
    matcher = PIIMatcher(patterns)
    
    # 1. Email Test
    facts = matcher.match("Contact us at user@example.com for info.", "HTTP Body")
    assert len(facts) == 1
    assert facts[0].pattern_name == "Email Address"
    assert facts[0].category == "Identity"
    assert facts[0].matched_value == "user@example.com"
    assert facts[0].source_location == "HTTP Body"
    
    # 2. IMEI Test
    facts = matcher.match("My IMEI is 490154203237518.", "URL")
    assert len(facts) == 1
    assert facts[0].pattern_name == "IMEI"
    assert facts[0].category == "Hardware"
    assert facts[0].matched_value == "490154203237518"
    
    # 3. Bearer Token Test
    facts = matcher.match("Authorization: Bearer eyJhbGciOiJIUz.eyJ.sdfsdf", "HTTP Header Value")
    assert len(facts) == 1
    assert facts[0].pattern_name == "Bearer Token"
    assert facts[0].category == "Authentication"
    assert facts[0].matched_value == "Bearer eyJhbGciOiJIUz.eyJ.sdfsdf"
    
    # 4. No Match Test
    facts = matcher.match("Hello World", "Body")
    assert len(facts) == 0

def test_dataset_manager_pii():
    manager = DatasetManager()
    patterns = manager.load_pii_patterns()
    assert len(patterns) > 0
    assert any(p["pattern_name"] == "Email Address" for p in patterns)

def test_pii_importer():
    from knowledge_base.network.importers.pii_importer import PIIImporter
    p = Path("knowledge_base/raw/pii/pii_rules.csv")
    if p.exists():
        importer = PIIImporter(p)
        models = list(importer.process())
        assert len(models) > 0
        assert hasattr(models[0], "pattern_name")

def test_validators():
    from pcap.matchers.pii_validators import (
        validate_luhn, validate_e164, validate_email, validate_uuid,
        validate_ipv4, validate_latitude, validate_longitude
    )
    # Luhn
    assert validate_luhn("490154203237518") == True
    assert validate_luhn("490154203237519") == False
    
    # E.164
    assert validate_e164("+14155552671") == True
    assert validate_e164("12345") == False
    
    # Email
    assert validate_email("user@example.com") == True
    assert validate_email("user@@example") == False
    
    # UUID
    assert validate_uuid("123e4567-e89b-12d3-a456-426614174000") == True
    assert validate_uuid("123e4567-e89b-12d3-a456-42661417400") == False
    
    # IP
    assert validate_ipv4("192.168.1.1") == True
    assert validate_ipv4("999.999.999.999") == False
    
    # Location
    assert validate_latitude("90.0") == True
    assert validate_latitude("91.0") == False
    assert validate_longitude("180.0") == True
    assert validate_longitude("181.0") == False
