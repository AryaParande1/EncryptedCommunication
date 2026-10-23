"""Small rule-based set of prewritten server replies."""

import re


def generate_response(message: str) -> str:
    """Choose a fixed reply based on simple words or phrases."""
    if message.startswith("ENC1:"):
        return "Encrypted message received. Use the Decrypt Message window to read it."

    normalized = message.casefold().strip()
    words = set(re.findall(r"[a-z']+", normalized))

    if words.intersection({"hello", "hi", "hey"}):
        return "Hello! I'm the communication server. How can I help?"
    if "how are you" in normalized:
        return "I'm running normally and ready to receive messages."
    if words.intersection({"help", "commands"}) or "what can you do" in normalized:
        return "You can send a message to this server or chat with another connected client."
    if words.intersection({"thanks", "thank"}):
        return "You're welcome!"
    if words.intersection({"bye", "goodbye"}):
        return "Goodbye! Your connection will stay open until you disconnect."

    return "I don't have a preset reply for that yet. Try saying hello or asking for help."