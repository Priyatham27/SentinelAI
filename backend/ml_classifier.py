import math
from typing import Dict

# ═══════════════════════════════════════════════════
#  SentinelAI — Lightweight ML Classifier
#  TF-IDF Weighted Multi-Class Prompt Classifier
#
#  Classes: SAFE | INSTRUCTION_OVERRIDE |
#           DATA_EXFILTRATION | TOOL_MISUSE | JAILBREAK
#
#  How it works:
#  - Each class has a vocabulary of weighted terms
#  - We compute a TF-IDF-style score per class
#  - Softmax converts raw scores to probabilities
#  - Returns predicted class + confidence per class
# ═══════════════════════════════════════════════════

# Class vocabulary — term: weight (IDF-like importance score)
# Higher weight = stronger signal for that class
CLASS_VOCAB: Dict[str, Dict[str, float]] = {
    "INSTRUCTION_OVERRIDE": {
        "ignore": 2.8, "previous": 2.5, "instructions": 2.9,
        "forget": 2.6, "disregard": 3.1, "override": 3.0,
        "developer mode": 3.5, "unrestricted": 3.2, "reset": 2.0,
        "new instructions": 3.3, "you are now": 2.8, "act as": 2.2,
        "pretend": 1.8, "from now on": 2.4, "instead": 1.2,
        "your previous": 2.7, "earlier instructions": 3.0,
        "system prompt": 2.5, "persona": 2.1, "roleplay": 1.9,
    },
    "DATA_EXFILTRATION": {
        "api key": 3.5, "password": 3.2, "credentials": 3.4,
        "secret": 2.8, "token": 2.6, "reveal": 2.9, "show me": 1.5,
        "send to": 2.7, "leak": 3.0, "exfiltrate": 3.8,
        "confidential": 3.1, "private": 2.2, "internal": 2.0,
        "database": 2.3, "dump": 2.9, "extract": 2.4,
        "stored": 2.0, "access token": 3.5, "api keys": 3.6,
        "all users": 2.5, "user data": 2.8,
    },
    "TOOL_MISUSE": {
        "execute": 2.8, "run": 1.8, "command": 2.5, "shell": 3.2,
        "bash": 3.4, "rm -rf": 4.0, "delete": 2.0, "sudo": 3.3,
        "chmod": 3.1, "curl": 2.7, "wget": 2.9, "http://": 2.5,
        "/etc/": 3.5, "passwd": 3.6, "os.system": 3.8,
        "subprocess": 3.5, "eval": 2.8, "exec": 2.6,
        "file system": 2.4, "send output": 3.0, "pipe": 2.0,
    },
    "JAILBREAK": {
        "dan": 3.2, "jailbreak": 3.9, "no restrictions": 3.5,
        "no ethical": 3.4, "no guidelines": 3.3, "bypass": 2.8,
        "unfiltered": 3.6, "without limits": 3.2, "evil": 2.5,
        "harmful": 2.3, "illegal": 2.6, "simulate": 1.8,
        "unrestricted ai": 3.7, "no rules": 3.4, "anything goes": 3.1,
        "uncensored": 3.5, "freedom mode": 3.8, "enabled": 1.2,
    },
    "SAFE": {
        "summarize": 2.0, "explain": 2.0, "what is": 1.8,
        "how does": 1.8, "difference between": 2.0, "help me": 1.5,
        "can you": 1.2, "please": 1.0, "thank": 1.3, "question": 1.5,
        "understand": 1.7, "learn": 1.8, "example": 1.6,
        "define": 1.9, "describe": 1.8, "list": 1.4, "compare": 1.7,
        "write": 1.3, "create": 1.2, "generate": 1.1,
    }
}

# Class display names
CLASS_LABELS = {
    "SAFE": "Safe",
    "INSTRUCTION_OVERRIDE": "Instruction Override",
    "DATA_EXFILTRATION": "Data Exfiltration",
    "TOOL_MISUSE": "Tool Misuse",
    "JAILBREAK": "Jailbreak Attempt",
}


def _tokenize(text: str) -> list:
    """Simple tokenizer — lowercased words + bigrams."""
    text = text.lower()
    words = text.split()
    tokens = list(words)
    # Add bigrams
    for i in range(len(words) - 1):
        tokens.append(words[i] + " " + words[i + 1])
    return tokens


def _tf_score(tokens: list, vocab: Dict[str, float]) -> float:
    """Compute TF-IDF-like score for a class vocabulary."""
    score = 0.0
    token_set = set(tokens)
    token_str = " ".join(tokens)

    for term, weight in vocab.items():
        # Check exact phrase match in full string
        if term in token_str:
            # TF: how many times it appears (log-dampened)
            count = token_str.count(term)
            tf = 1 + math.log(1 + count)
            score += tf * weight

    return score


def _softmax(scores: Dict[str, float]) -> Dict[str, float]:
    """Convert raw scores to probability distribution."""
    vals = list(scores.values())
    max_v = max(vals) if vals else 0
    exps = {k: math.exp(v - max_v) for k, v in scores.items()}
    total = sum(exps.values())
    return {k: round(v / total * 100, 1) for k, v in exps.items()}


def classify(prompt: str) -> dict:
    """
    Main classification function.
    Returns predicted class, confidence, and per-class probabilities.
    """
    tokens = _tokenize(prompt)

    # Compute raw scores per class
    raw_scores = {}
    for cls, vocab in CLASS_VOCAB.items():
        raw_scores[cls] = _tf_score(tokens, vocab)

    # Add baseline for SAFE to avoid all-zero edge cases
    if raw_scores["SAFE"] == 0:
        raw_scores["SAFE"] = 0.5

    # Softmax → probabilities
    probs = _softmax(raw_scores)

    # Predicted class = highest probability
    predicted = max(probs, key=probs.get)
    confidence = probs[predicted]

    # Format output
    class_probs = [
        {
            "class": cls,
            "label": CLASS_LABELS[cls],
            "probability": prob,
        }
        for cls, prob in sorted(probs.items(), key=lambda x: -x[1])
    ]

    is_threat = predicted != "SAFE" and confidence > 30.0

    return {
        "predicted_class": predicted,
        "predicted_label": CLASS_LABELS[predicted],
        "confidence": round(confidence, 1),
        "is_threat": is_threat,
        "class_probabilities": class_probs,
        "top_threat": class_probs[0] if class_probs[0]["class"] != "SAFE" else (class_probs[1] if len(class_probs) > 1 else None),
    }